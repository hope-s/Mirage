package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mirage/internal/secure"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func addr(p int) string { return "127.0.0.1:" + strconv.Itoa(p) }

func tcpEcho(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func udpEcho(t *testing.T) int {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], a)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func key() string {
	k, _ := secure.NewPSK()
	return hex.EncodeToString(k[:])
}

func start(t *testing.T, c *Config) *Node {
	t.Helper()
	n, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return n
}

func waitSessions(t *testing.T, n *Node, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.Snapshot().Sessions) >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("only %d/%d sessions up: %+v", len(n.Snapshot().Sessions), want, n.Snapshot().Links)
}

func echoCheck(t *testing.T, a string, size int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", a, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	data := make([]byte, size)
	rand.Read(data)
	go func() { c.Write(data); c.(*net.TCPConn).CloseWrite() }()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("echo mismatch: got %d bytes want %d", len(got), len(data))
	}
}

// pair builds kharej+iran configs for direct or reverse mode with all
// transports, plus a TCP forward to an echo server on kharej's loopback.
func pair(t *testing.T, reverse bool, kinds []string) (*Config, *Config, int) {
	k := key()
	echo := tcpEcho(t)
	kh := &Config{Role: RoleKharej, Key: k, AllowLocal: []string{strconv.Itoa(echo)}}
	ir := &Config{Role: RoleIran, Key: k}
	for _, kind := range kinds {
		p := freePort(t)
		if reverse {
			ir.Listen = append(ir.Listen, ListenConf{Name: kind, Transport: kind, Addr: addr(p), Path: "/x"})
			kh.Dial = append(kh.Dial, DialConf{Name: kind, Transport: kind, Addrs: []string{addr(p)}, Path: "/x", Conns: 2, SNI: "example.com"})
		} else {
			kh.Listen = append(kh.Listen, ListenConf{Name: kind, Transport: kind, Addr: addr(p), Path: "/x"})
			ir.Dial = append(ir.Dial, DialConf{Name: kind, Transport: kind, Addrs: []string{addr(p)}, Path: "/x", Conns: 2, SNI: "example.com"})
		}
	}
	fp := freePort(t)
	ir.Forward = []ForwardConf{{Proto: "tcp", Listen: addr(fp), Target: addr(echo)}}
	return kh, ir, fp
}

var allKinds = []string{"tcp", "tls", "ws", "wss"}

func TestDirectAllTransports(t *testing.T) {
	for _, kind := range allKinds {
		t.Run(kind, func(t *testing.T) {
			kh, ir, fp := pair(t, false, []string{kind})
			start(t, kh)
			in := start(t, ir)
			waitSessions(t, in, 2)
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func(i int) { defer wg.Done(); echoCheck(t, addr(fp), 50_000+i*20_000) }(i)
			}
			wg.Wait()
			echoCheck(t, addr(fp), 8<<20)
		})
	}
}

func TestReverseAllTransports(t *testing.T) {
	for _, kind := range allKinds {
		t.Run(kind, func(t *testing.T) {
			kh, ir, fp := pair(t, true, []string{kind})
			in := start(t, ir) // iran listens first
			start(t, kh)
			waitSessions(t, in, 2)
			echoCheck(t, addr(fp), 2<<20)
		})
	}
}

func TestPolicyBlocksUnlistedLocal(t *testing.T) {
	kh, ir, _ := pair(t, false, []string{"tcp"})
	other := tcpEcho(t) // not in allow_local
	fp := freePort(t)
	ir.Forward = append(ir.Forward, ForwardConf{Proto: "tcp", Listen: addr(fp), Target: addr(other)})
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 2)
	c, err := net.Dial("tcp", addr(fp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	c.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err == nil {
		t.Fatal("blocked destination was reachable")
	}
}

// killProxy is a TCP relay whose connections can all be cut at once,
// simulating a link being blocked by the firewall.
type killProxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	dead  bool
}

func newKillProxy(t *testing.T, target string) *killProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	k := &killProxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			k.mu.Lock()
			if k.dead {
				k.mu.Unlock()
				c.Close()
				continue
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				k.mu.Unlock()
				c.Close()
				continue
			}
			k.conns = append(k.conns, c, u)
			k.mu.Unlock()
			go func() { io.Copy(u, c); u.Close() }()
			go func() { io.Copy(c, u); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return k
}

// blackhole stops forwarding without closing (like a DPI drop), so only
// keepalive timeouts can detect it.
func (k *killProxy) kill() {
	k.mu.Lock()
	k.dead = true
	for _, c := range k.conns {
		c.Close()
	}
	k.mu.Unlock()
}

func TestFailoverBetweenLinks(t *testing.T) {
	k := key()
	echo := tcpEcho(t)
	pA, pB := freePort(t), freePort(t)
	kh := &Config{Role: RoleKharej, Key: k, AllowLocal: []string{strconv.Itoa(echo)},
		Listen: []ListenConf{
			{Name: "a", Transport: "tls", Addr: addr(pA)},
			{Name: "b", Transport: "ws", Addr: addr(pB), Path: "/w"},
		}}
	start(t, kh)
	proxy := newKillProxy(t, addr(pA))
	fp := freePort(t)
	ir := &Config{Role: RoleIran, Key: k,
		Dial: []DialConf{
			{Name: "a", Transport: "tls", Addrs: []string{proxy.ln.Addr().String()}, Conns: 2},
			{Name: "b", Transport: "ws", Addrs: []string{addr(pB)}, Path: "/w", Conns: 1, Backup: true},
		},
		Forward: []ForwardConf{{Proto: "tcp", Listen: addr(fp), Target: addr(echo)}}}
	in := start(t, ir)
	waitSessions(t, in, 3)
	echoCheck(t, addr(fp), 100_000)
	proxy.kill()
	time.Sleep(300 * time.Millisecond)
	// link a is gone; everything must flow over backup link b
	for i := 0; i < 10; i++ {
		echoCheck(t, addr(fp), 100_000)
	}
	for _, s := range in.Snapshot().Sessions {
		if s.Link == "a" {
			t.Fatalf("dead link still listed: %+v", s)
		}
	}
}

func socksHandshake(t *testing.T, c net.Conn, cmd byte, dest netip.AddrPort) netip.AddrPort {
	t.Helper()
	c.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 {
		t.Fatalf("method: %v %v", r, err)
	}
	a := dest.Addr().As4()
	req := []byte{5, cmd, 0, 1}
	req = append(req, a[:]...)
	req = binary.BigEndian.AppendUint16(req, dest.Port())
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks reply %d", rep[1])
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(rep[4:8])), binary.BigEndian.Uint16(rep[8:10]))
}

func TestSocksConnectAndUDP(t *testing.T) {
	kh, ir, _ := pair(t, false, []string{"tcp"})
	ue := udpEcho(t)
	te, _ := strconv.Atoi(kh.AllowLocal[0])
	kh.AllowLocal = append(kh.AllowLocal, strconv.Itoa(ue))
	sp := freePort(t)
	ir.Socks = []SocksConf{{Listen: addr(sp)}}
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 2)

	// CONNECT
	c, err := net.Dial("tcp", addr(sp))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	socksHandshake(t, c, 1, netip.MustParseAddrPort(addr(te)))
	c.Write([]byte("hello socks"))
	buf := make([]byte, 11)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello socks" {
		t.Fatalf("connect echo: %q %v", buf, err)
	}
	c.Close()

	// UDP ASSOCIATE
	ctl, err := net.Dial("tcp", addr(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	ctl.SetDeadline(time.Now().Add(10 * time.Second))
	relayAddr := socksHandshake(t, ctl, 3, netip.MustParseAddrPort("0.0.0.0:0"))
	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relayAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	pkt := []byte{0, 0, 0, 1, 127, 0, 0, 1}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(ue))
	pkt = append(pkt, []byte("udp payload")...)
	got := make([]byte, 2048)
	ok := false
	for i := 0; i < 5 && !ok; i++ {
		uc.Write(pkt)
		uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := uc.Read(got)
		if err == nil && n >= 10 && string(got[10:n]) == "udp payload" && binary.BigEndian.Uint16(got[8:10]) == uint16(ue) {
			ok = true
		}
	}
	if !ok {
		t.Fatal("socks udp echo failed")
	}
}

func TestUDPForward(t *testing.T) {
	kh, ir, _ := pair(t, false, []string{"ws"})
	ue := udpEcho(t)
	kh.AllowLocal = append(kh.AllowLocal, strconv.Itoa(ue))
	fp := freePort(t)
	ir.Forward = append(ir.Forward, ForwardConf{Proto: "udp", Listen: addr(fp), Target: addr(ue)})
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 2)
	uc, err := net.Dial("udp", addr(fp))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	buf := make([]byte, 2048)
	for i := 0; i < 20; i++ {
		msg := fmt.Sprintf("dgram-%d", i)
		var got string
		for try := 0; try < 5 && got != msg; try++ {
			uc.Write([]byte(msg))
			uc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := uc.Read(buf)
			if err == nil {
				got = string(buf[:n])
			}
		}
		if got != msg {
			t.Fatalf("udp forward: want %q got %q", msg, got)
		}
	}
}

func TestProbesSeeDecoy(t *testing.T) {
	kh, _, _ := pair(t, false, []string{"tls"})
	start(t, kh)
	a := kh.Listen[0].Addr
	tr := &http.Transport{TLSClientConfig: insecureTLS()}
	cl := http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := cl.Get("https://" + a + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "maintenance") || resp.Header.Get("Server") != "nginx" {
		t.Fatalf("decoy not served: %d %q", resp.StatusCode, body)
	}

	// ws listener: wrong path -> 404 page, not an upgrade
	kh2, _, _ := pair(t, false, []string{"ws"})
	start(t, kh2)
	resp, err = http.Get("http://" + kh2.Listen[0].Addr + "/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("want 404 got %d", resp.StatusCode)
	}
}

func TestRawProbeGetsNoReply(t *testing.T) {
	kh, _, _ := pair(t, false, []string{"tcp"})
	start(t, kh)
	c, err := net.Dial("tcp", kh.Listen[0].Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	junk := make([]byte, 200)
	rand.Read(junk)
	junk[0] |= 0x80
	c.Write(junk)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(make([]byte, 10))
	if n != 0 {
		t.Fatal("server answered garbage")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected server to keep silent (timeout), got %v", err)
	}
}

func TestWrongKeyNeverConnects(t *testing.T) {
	kh, ir, _ := pair(t, false, []string{"tcp"})
	ir.Key = key()
	start(t, kh)
	in := start(t, ir)
	time.Sleep(2 * time.Second)
	if len(in.Snapshot().Sessions) != 0 {
		t.Fatal("wrong key connected")
	}
}

func TestRotation(t *testing.T) {
	old := minRotate
	minRotate = 1
	defer func() { minRotate = old }()
	kh, ir, fp := pair(t, false, []string{"tcp"})
	ir.RotateMin, ir.RotateMax = 1, 2
	ir.Dial[0].Conns = 1
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 1)
	// a long transfer keeps running across rotations
	c, err := net.Dial("tcp", addr(fp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	bw := bufio.NewWriter(c)
	for i := 0; i < 50; i++ {
		fmt.Fprintf(bw, "line %d\n", i)
		bw.Flush()
		time.Sleep(100 * time.Millisecond)
	}
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(got), "\n") != 50 {
		t.Fatalf("stream broken by rotation: %d lines", strings.Count(string(got), "\n"))
	}
	// new connections after rotation still work
	echoCheck(t, addr(fp), 10_000)
	time.Sleep(3 * time.Second)
	n := 0
	for _, s := range in.Snapshot().Sessions {
		if !s.Draining {
			n++
		}
	}
	if n < 1 {
		t.Fatal("no active session after rotation")
	}
	if len(in.Snapshot().Sessions) > 3 {
		t.Fatalf("drained sessions not cleaned: %d", len(in.Snapshot().Sessions))
	}
}

func insecureTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

func TestProfilesAndSpeedTest(t *testing.T) {
	for _, prof := range []string{"speed", "balanced", "stealth"} {
		t.Run(prof, func(t *testing.T) {
			kh, ir, fp := pair(t, false, []string{"tls"})
			kh.Profile, ir.Profile = prof, prof
			start(t, kh)
			in := start(t, ir)
			waitSessions(t, in, 2)
			echoCheck(t, addr(fp), 3<<20)
			res, err := in.SpeedTest(context.Background(), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if res.DownMbps < 10 || res.UpMbps < 10 {
				t.Fatalf("implausible speed on loopback: %+v", res)
			}
			t.Logf("%s: down %.0f up %.0f Mbps", prof, res.DownMbps, res.UpMbps)
		})
	}
}

func TestDisabledLinkAndAutoscale(t *testing.T) {
	old := healthEvery
	healthEvery = 300 * time.Millisecond
	defer func() { healthEvery = old }()
	kh, ir, fp := pair(t, false, []string{"tcp", "ws"})
	ir.Dial[0].Conns, ir.Dial[0].MaxConns = 1, 4
	ir.Dial[1].Disabled = true
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 1)
	time.Sleep(500 * time.Millisecond)
	for _, s := range in.Snapshot().Sessions {
		if s.Link == "ws" {
			t.Fatal("disabled link connected")
		}
	}
	// open many idle streams -> link should scale up
	var conns []net.Conn
	for i := 0; i < 40; i++ {
		c, err := net.Dial("tcp", addr(fp))
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("x"))
		io.ReadFull(c, make([]byte, 1))
		conns = append(conns, c)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(in.Snapshot().Sessions) < 2 {
		time.Sleep(100 * time.Millisecond)
	}
	if len(in.Snapshot().Sessions) < 2 {
		t.Fatal("did not scale up under load")
	}
	for _, c := range conns {
		c.Close()
	}
	echoCheck(t, addr(fp), 100_000)
}

// slowProxy forwards like killProxy but can add latency to its connections.
func TestSlowConnectionReplaced(t *testing.T) {
	old := healthEvery
	healthEvery = 200 * time.Millisecond
	defer func() { healthEvery = old }()
	kh, ir, fp := pair(t, false, []string{"tcp"})
	target := ir.Dial[0].Addrs[0]
	var delay atomic.Int64
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			slowAtConnect := delay.Load() // only connections made while slow stay slow
			cp := func(dst, src net.Conn, slow bool) {
				buf := make([]byte, 32*1024)
				for {
					n, err := src.Read(buf)
					if n > 0 {
						if slow && delay.Load() > 0 {
							time.Sleep(time.Duration(delay.Load()))
						}
						dst.Write(buf[:n])
					}
					if err != nil {
						dst.Close()
						return
					}
				}
			}
			go cp(u, c, slowAtConnect == 0)
			go cp(c, u, slowAtConnect == 0)
		}
	}()
	ir.Dial[0].Addrs = []string{ln.Addr().String()}
	ir.Dial[0].Conns, ir.Dial[0].MaxConns = 1, 1
	ir.Profile = "speed" // 3s pings
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 1)
	time.Sleep(7 * time.Second) // establish a baseline RTT
	first := in.Snapshot().Sessions[0].Remote
	_ = first
	firstAge := in.Snapshot().Sessions[0].AgeSec
	delay.Store(int64(400 * time.Millisecond)) // the existing connection gets throttled
	deadline := time.Now().Add(40 * time.Second)
	replaced := false
	for time.Now().Before(deadline) && !replaced {
		time.Sleep(500 * time.Millisecond)
		for _, s := range in.Snapshot().Sessions {
			if !s.Draining && s.AgeSec < firstAge {
				replaced = true
			}
		}
	}
	if !replaced {
		t.Fatalf("slow connection was not replaced: %+v", in.Snapshot().Sessions)
	}
	echoCheck(t, addr(fp), 50_000)
}
