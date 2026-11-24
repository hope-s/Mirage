package node

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"mirage/internal/mux"
)

// Stream targets carried in SYN frames.
const (
	targetTCP = "tcp "
	targetUDP = "udp"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Policy decides which destinations the exit node may reach. Public
// addresses are always allowed; loopback, private, link-local, CGNAT and
// similar ranges only when listed explicitly (protects the kharej server's
// own services such as the X-UI panel from being reached through SOCKS).
type Policy struct {
	allow map[netip.AddrPort]bool
}

// ParseAllowLocal parses entries like "2096", "127.0.0.1:2096", "10.0.0.5:80".
func ParseAllowLocal(list []string) (*Policy, error) {
	p := &Policy{allow: map[netip.AddrPort]bool{}}
	for _, e := range list {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if n, err := strconv.Atoi(e); err == nil {
			if n < 1 || n > 65535 {
				return nil, fmt.Errorf("allow_local: bad port %q", e)
			}
			p.allow[netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(n))] = true
			p.allow[netip.AddrPortFrom(netip.MustParseAddr("::1"), uint16(n))] = true
			continue
		}
		host, port, err := net.SplitHostPort(e)
		if err != nil {
			return nil, fmt.Errorf("allow_local: %q: %w", e, err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("allow_local: bad port in %q", e)
		}
		if host == "localhost" {
			p.allow[netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(n))] = true
			p.allow[netip.AddrPortFrom(netip.MustParseAddr("::1"), uint16(n))] = true
			continue
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("allow_local: %q must be an IP address", e)
		}
		p.allow[netip.AddrPortFrom(a.Unmap(), uint16(n))] = true
	}
	return p, nil
}

func restricted(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() ||
		(a.Is4() && (cgnat.Contains(a) || a.As4()[0] == 0 || a == netip.MustParseAddr("255.255.255.255")))
}

// Check returns an error if ap may not be contacted.
func (p *Policy) Check(ap netip.AddrPort) error {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if !restricted(ap.Addr()) || p.allow[ap] {
		return nil
	}
	return fmt.Errorf("destination %s blocked (add it to allow_local to permit)", ap)
}

func (p *Policy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	return p.Check(ap)
}

// DialTCP resolves and connects, checking every resolved address (the check
// runs on the final IP, so DNS rebinding cannot bypass it).
func (p *Policy) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: p.control}
	return d.DialContext(ctx, "tcp", addr)
}

// exit serves streams opened by the iran node on a kharej session.
type exit struct {
	policy *Policy
	log    *logger
}

func (e *exit) serve(s *mux.Session) {
	for {
		st, err := s.Accept()
		if err != nil {
			return
		}
		go e.handle(st)
	}
}

func (e *exit) handle(st *mux.Stream) {
	switch {
	case strings.HasPrefix(st.Target, targetTCP):
		addr := st.Target[len(targetTCP):]
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := e.policy.DialTCP(ctx, addr)
		cancel()
		if err != nil {
			e.log.debugf("exit: dial %s: %v", addr, err)
			if strings.Contains(err.Error(), "blocked") {
				e.log.infof("exit: %v", err)
			}
			_ = st.Accept(false)
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		if err := st.Accept(true); err != nil {
			c.Close()
			return
		}
		relay(c, st)
	case st.Target == targetSpeedUp || strings.HasPrefix(st.Target, targetSpeedDown):
		e.speed(st)
	case st.Target == targetUDP:
		_ = st.Accept(true)
		e.udp(st)
	default:
		_ = st.Accept(false)
	}
}

// UDP datagram framing over a stream: [alen u8][addr][dlen u16][data].
func writeDatagram(w io.Writer, addr string, data []byte) error {
	if len(addr) > 255 || len(data) > 65535 {
		return errors.New("datagram too large")
	}
	b := make([]byte, 1+len(addr)+2+len(data))
	b[0] = byte(len(addr))
	copy(b[1:], addr)
	binary.BigEndian.PutUint16(b[1+len(addr):], uint16(len(data)))
	copy(b[3+len(addr):], data)
	_, err := w.Write(b)
	return err
}

func readDatagram(r io.Reader, buf []byte) (addr string, data []byte, err error) {
	var l [1]byte
	if _, err = io.ReadFull(r, l[:]); err != nil {
		return
	}
	ab := make([]byte, l[0])
	if _, err = io.ReadFull(r, ab); err != nil {
		return
	}
	var dl [2]byte
	if _, err = io.ReadFull(r, dl[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(dl[:]))
	if n > len(buf) {
		buf = make([]byte, n)
	}
	if _, err = io.ReadFull(r, buf[:n]); err != nil {
		return
	}
	return string(ab), buf[:n], nil
}

const udpIdle = 2 * time.Minute

func (e *exit) udp(st *mux.Stream) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		st.Reset()
		return
	}
	var (
		mu       sync.Mutex
		resolved = map[string]netip.AddrPort{}
		sent     = map[netip.AddrPort]bool{}
		last     = time.Now()
	)
	touch := func() { mu.Lock(); last = time.Now(); mu.Unlock() }
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done); pc.Close(); st.Close() }) }
	defer stop()

	// replies: socket -> stream
	go func() {
		defer stop()
		buf := make([]byte, 65535)
		var wmu sync.Mutex
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			mu.Lock()
			ok := sent[from]
			mu.Unlock()
			if !ok {
				continue // only accept replies from peers we contacted
			}
			touch()
			wmu.Lock()
			err = writeDatagram(st, from.String(), buf[:n])
			wmu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	// idle watchdog
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				mu.Lock()
				idle := time.Since(last) > udpIdle
				mu.Unlock()
				if idle {
					stop()
					return
				}
			}
		}
	}()
	// requests: stream -> socket
	buf := make([]byte, 65535)
	for {
		addr, data, err := readDatagram(st, buf)
		if err != nil {
			return
		}
		touch()
		mu.Lock()
		ap, ok := resolved[addr]
		mu.Unlock()
		if !ok {
			ua, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				continue
			}
			ap = ua.AddrPort()
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			if err := e.policy.Check(ap); err != nil {
				e.log.infof("exit: udp %v", err)
				continue
			}
			mu.Lock()
			if len(resolved) > 4096 {
				resolved = map[string]netip.AddrPort{}
			}
			resolved[addr] = ap
			if len(sent) > 4096 {
				sent = map[netip.AddrPort]bool{}
			}
			sent[ap] = true
			mu.Unlock()
		}
		_, _ = pc.WriteToUDPAddrPort(data, ap)
	}
}

type closeWriter interface{ CloseWrite() error }

// relay copies both ways. When one direction ends cleanly the other is given
// a grace period; an error in either direction tears both down.
func relay(c net.Conn, st *mux.Stream) {
	type result struct{ err error }
	res := make(chan result, 2)
	go func() {
		_, err := io.Copy(st, c)
		_ = st.CloseWrite()
		res <- result{err}
	}()
	go func() {
		_, err := io.Copy(c, st)
		if cw, ok := c.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		res <- result{err}
	}()
	r := <-res
	if r.err == nil {
		select {
		case <-res:
		case <-time.After(2 * time.Minute):
		}
	}
	c.Close()
	st.Close()
}
