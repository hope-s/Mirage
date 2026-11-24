package node

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"mirage/internal/mux"
)

// ---------- TCP port forward ----------

func (n *Node) serveTCPForward(ln net.Listener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go func() {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			st, err := n.pool.Open(targetTCP + target)
			if err != nil {
				n.log.debugf("forward %s: %v", target, err)
				c.Close()
				return
			}
			relay(c, st)
		}()
	}
}

// ---------- UDP port forward ----------

type udpPeer struct {
	ch   chan []byte
	last time.Time
}

func (n *Node) serveUDPForward(pc *net.UDPConn, target string) {
	var mu sync.Mutex
	peers := map[netip.AddrPort]*udpPeer{}
	buf := make([]byte, 65535)
	for {
		nr, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		pkt := append([]byte(nil), buf[:nr]...)
		mu.Lock()
		p := peers[from]
		if p == nil {
			p = &udpPeer{ch: make(chan []byte, 512)}
			peers[from] = p
			go func(from netip.AddrPort, p *udpPeer) {
				n.udpPeerLoop(pc, from, target, p, &mu)
				mu.Lock()
				delete(peers, from)
				mu.Unlock()
			}(from, p)
		}
		p.last = time.Now()
		mu.Unlock()
		select {
		case p.ch <- pkt:
		default: // queue full: drop like a congested link would
		}
	}
}

func (n *Node) udpPeerLoop(pc *net.UDPConn, from netip.AddrPort, target string, p *udpPeer, mu *sync.Mutex) {
	st, err := n.pool.Open(targetUDP)
	if err != nil {
		n.log.debugf("udp forward %s: %v", target, err)
		return
	}
	defer st.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			_, data, err := readDatagram(st, buf)
			if err != nil {
				return
			}
			mu.Lock()
			p.last = time.Now()
			mu.Unlock()
			_, _ = pc.WriteToUDPAddrPort(data, from)
		}
	}()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case pkt := <-p.ch:
			if err := writeDatagram(st, target, pkt); err != nil {
				return
			}
		case <-done:
			return
		case <-t.C:
			mu.Lock()
			idle := time.Since(p.last) > udpIdle
			mu.Unlock()
			if idle {
				return
			}
		}
	}
}

// ---------- SOCKS5 ----------

const (
	socksVer      = 5
	cmdConnect    = 1
	cmdAssociate  = 3
	atypIPv4      = 1
	atypDomain    = 3
	atypIPv6      = 4
	repOK         = 0
	repFail       = 1
	repHostUnreac = 4
	repCmdUnsupp  = 7
)

func (n *Node) serveSocks(ln net.Listener, cfg SocksConf) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go n.socksConn(c, cfg)
	}
}

func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom16(b).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("socks: bad address type")
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))), nil
}

func socksReply(w io.Writer, rep byte, bind netip.AddrPort) error {
	b := []byte{socksVer, rep, 0}
	if bind.Addr().Is6() && !bind.Addr().Is4In6() {
		a := bind.Addr().As16()
		b = append(b, atypIPv6)
		b = append(b, a[:]...)
	} else {
		a := bind.Addr().Unmap()
		if !a.IsValid() {
			a = netip.IPv4Unspecified()
		}
		a4 := a.As4()
		b = append(b, atypIPv4)
		b = append(b, a4[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, bind.Port())
	_, err := w.Write(b)
	return err
}

func (n *Node) socksConn(c net.Conn, cfg SocksConf) {
	defer func() {
		if c != nil {
			c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil || h[0] != socksVer {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	want := byte(0x00)
	if cfg.User != "" {
		want = 0x02
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		_, _ = c.Write([]byte{socksVer, 0xff})
		return
	}
	if _, err := c.Write([]byte{socksVer, want}); err != nil {
		return
	}
	if want == 0x02 {
		var v [2]byte
		if _, err := io.ReadFull(br, v[:]); err != nil || v[0] != 1 {
			return
		}
		u := make([]byte, v[1])
		if _, err := io.ReadFull(br, u); err != nil {
			return
		}
		var pl [1]byte
		if _, err := io.ReadFull(br, pl[:]); err != nil {
			return
		}
		pw := make([]byte, pl[0])
		if _, err := io.ReadFull(br, pw); err != nil {
			return
		}
		if string(u) != cfg.User || string(pw) != cfg.Pass {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return
		}
	}
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != socksVer {
		return
	}
	dest, err := readSocksAddr(br, req[3])
	if err != nil {
		return
	}
	zero := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	switch req[1] {
	case cmdConnect:
		st, err := n.pool.Open(targetTCP + dest)
		if err != nil {
			rep := byte(repFail)
			if errors.Is(err, mux.ErrRefused) {
				rep = repHostUnreac
			}
			_ = socksReply(c, rep, zero)
			return
		}
		if err := socksReply(c, repOK, zero); err != nil {
			st.Reset()
			return
		}
		_ = c.SetDeadline(time.Time{})
		// bytes the client pipelined after the request are in br
		conn := &bufConn{Conn: c, r: br}
		c = nil // relay owns it now
		relay(conn, st)
	case cmdAssociate:
		n.socksAssociate(c, br)
	default:
		_ = socksReply(c, repCmdUnsupp, zero)
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (n *Node) socksAssociate(c net.Conn, br *bufio.Reader) {
	local := c.LocalAddr().(*net.TCPAddr)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		_ = socksReply(c, repFail, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		return
	}
	defer pc.Close()
	clientIP, _ := netip.ParseAddr(c.RemoteAddr().(*net.TCPAddr).IP.String())
	clientIP = clientIP.Unmap()
	bind := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := socksReply(c, repOK, bind); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	var (
		mu     sync.Mutex
		client netip.AddrPort
		st     *mux.Stream
		wmu    sync.Mutex
	)
	stop := make(chan struct{})
	var once sync.Once
	end := func() { once.Do(func() { close(stop); pc.Close(); c.Close() }) }
	defer end()
	// The association lives as long as the TCP control connection.
	go func() { _, _ = io.Copy(io.Discard, br); end() }()

	startReader := func(s *mux.Stream) {
		go func() {
			defer end()
			buf := make([]byte, 65535)
			for {
				src, data, err := readDatagram(s, buf)
				if err != nil {
					return
				}
				ap, err := netip.ParseAddrPort(src)
				if err != nil {
					continue
				}
				hdr := []byte{0, 0, 0}
				if ap.Addr().Is4() || ap.Addr().Is4In6() {
					a := ap.Addr().Unmap().As4()
					hdr = append(hdr, atypIPv4)
					hdr = append(hdr, a[:]...)
				} else {
					a := ap.Addr().As16()
					hdr = append(hdr, atypIPv6)
					hdr = append(hdr, a[:]...)
				}
				hdr = binary.BigEndian.AppendUint16(hdr, ap.Port())
				mu.Lock()
				to := client
				mu.Unlock()
				_, _ = pc.WriteToUDPAddrPort(append(hdr, data...), to)
			}
		}()
	}

	buf := make([]byte, 65535)
	for {
		nr, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from.Addr() != clientIP {
			continue // only the client that asked may use this relay
		}
		if nr < 4 || buf[2] != 0 { // fragmentation unsupported
			continue
		}
		// header: RSV(2) FRAG(1) ATYP(1) ADDR PORT, then payload
		r := &sliceReader{b: buf[4:nr]}
		dest, err := readSocksAddr(r, buf[3])
		if err != nil {
			continue
		}
		payload := append([]byte(nil), r.b...)
		mu.Lock()
		client = from
		s := st
		mu.Unlock()
		if s == nil {
			s, err = n.pool.Open(targetUDP)
			if err != nil {
				return
			}
			mu.Lock()
			st = s
			mu.Unlock()
			defer s.Close()
			startReader(s)
		}
		wmu.Lock()
		err = writeDatagram(s, dest, payload)
		wmu.Unlock()
		if err != nil {
			return
		}
	}
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}
