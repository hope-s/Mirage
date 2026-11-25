package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// tcpAddrConn mimics tcpraw: a packet socket that reports peers as
// *net.TCPAddr.
type tcpAddrConn struct{ *net.UDPConn }

func (c tcpAddrConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := c.UDPConn.ReadFromUDP(p)
	if a == nil {
		return n, nil, err
	}
	return n, &net.TCPAddr{IP: a.IP, Port: a.Port}, err
}

func (c tcpAddrConn) WriteTo(p []byte, a net.Addr) (int, error) {
	ua, err := net.ResolveUDPAddr("udp", a.String())
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteToUDP(p, ua)
}

// TestKCPOverTCPAddrConn guards the udpAddrs adapter used for fake TCP.
func TestKCPOverTCPAddrConn(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := kcpBlock("aes", []byte("k"))
	l, err := kcp.ServeConn(block, 10, 3, udpAddrs{tcpAddrConn{srv}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer srv.Close()
	go func() {
		c, err := l.AcceptKCP()
		if err != nil {
			return
		}
		io.Copy(c, c)
	}()
	s, err := kcp.NewConn4(7, srv.LocalAddr(), block, 10, 3, false, udpAddrs{tcpAddrConn{cli}})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	defer s.Close()
	tuneKCP(s, KCPOptions{}.WithDefaults())
	msg := bytes.Repeat([]byte("mirage"), 50_000)
	go s.Write(msg)
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatalf("no echo through a TCPAddr-reporting socket: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echo mismatch")
	}
}
