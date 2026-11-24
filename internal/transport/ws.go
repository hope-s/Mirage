package transport

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsConn turns a WebSocket into a byte stream (binary frames).
type wsConn struct {
	net.Conn
	br     *bufio.Reader
	client bool

	rmu       sync.Mutex
	remaining int64
	mask      [4]byte
	masked    bool
	maskPos   int
	closed    bool

	wmu sync.Mutex
}

const wsMaxFrame = 32 * 1024

func (c *wsConn) writeFrame(op byte, p []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op
	n := 2
	l := len(p)
	switch {
	case l < 126:
		hdr[1] = byte(l)
	case l < 65536:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(l))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
		n = 10
	}
	buf := make([]byte, 0, n+4+l)
	if c.client {
		hdr[1] |= 0x80
		var key [4]byte
		_, _ = rand.Read(key[:])
		buf = append(buf, hdr[:n]...)
		buf = append(buf, key[:]...)
		start := len(buf)
		buf = append(buf, p...)
		for i := range p {
			buf[start+i] ^= key[i&3]
		}
	} else {
		buf = append(buf, hdr[:n]...)
		buf = append(buf, p...)
	}
	_, err := c.Conn.Write(buf)
	return err
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > wsMaxFrame {
			n = wsMaxFrame
		}
		if err := c.writeFrame(2, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *wsConn) readHeader() (op byte, length int64, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return
	}
	op = h[0] & 0x0f
	c.masked = h[1]&0x80 != 0
	length = int64(h[1] & 0x7f)
	switch length {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		length = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		length = int64(binary.BigEndian.Uint64(b[:]))
		if length < 0 || length > 1<<30 {
			err = errors.New("ws: frame too large")
			return
		}
	}
	if c.masked {
		if _, err = io.ReadFull(c.br, c.mask[:]); err != nil {
			return
		}
	}
	c.maskPos = 0
	return
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for c.remaining == 0 {
		if c.closed {
			return 0, io.EOF
		}
		op, l, err := c.readHeader()
		if err != nil {
			return 0, err
		}
		switch op {
		case 0, 1, 2:
			c.remaining = l
		case 8: // close
			if l > 0 {
				_, _ = io.CopyN(io.Discard, c.br, l)
			}
			c.closed = true
			c.wmu.Lock()
			_ = c.writeFrame(8, nil)
			c.wmu.Unlock()
			return 0, io.EOF
		case 9, 10: // ping / pong
			if l > 125 {
				return 0, errors.New("ws: bad control frame")
			}
			payload := make([]byte, l)
			if _, err := io.ReadFull(c.br, payload); err != nil {
				return 0, err
			}
			if c.masked {
				for i := range payload {
					payload[i] ^= c.mask[i&3]
				}
			}
			if op == 9 {
				c.wmu.Lock()
				err := c.writeFrame(10, payload)
				c.wmu.Unlock()
				if err != nil {
					return 0, err
				}
			}
		default:
			return 0, fmt.Errorf("ws: unknown opcode %d", op)
		}
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.br.Read(p)
	if c.masked {
		for i := 0; i < n; i++ {
			p[i] ^= c.mask[(c.maskPos+i)&3]
		}
		c.maskPos += n
	}
	c.remaining -= int64(n)
	return n, err
}

// wsClientHandshake upgrades conn to a WebSocket.
func wsClientHandshake(conn net.Conn, host, path string, timeout time.Duration) (net.Conn, error) {
	if path == "" {
		path = "/"
	}
	var kb [16]byte
	_, _ = rand.Read(kb[:])
	key := base64.StdEncoding.EncodeToString(kb[:])
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + chromeUA + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Pragma: no-cache\r\nCache-Control: no-cache\r\n\r\n"
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 64*1024)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("ws: upgrade refused: %s", resp.Status)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, errors.New("ws: bad accept key")
	}
	return &wsConn{Conn: conn, br: br, client: true}, nil
}

func isWSUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

// wsServerUpgrade hijacks the HTTP connection and returns the byte stream.
func wsServerUpgrade(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("ws: hijack unsupported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &wsConn{Conn: conn, br: rw.Reader}, nil
}
