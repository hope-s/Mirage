package node

import (
	mrand "math/rand/v2"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"mirage/internal/transport"
)

// lossyUDP relays datagrams between one client and target, dropping each
// packet with probability loss and delaying the rest by delay.
func lossyUDP(t *testing.T, target string, loss float64, delay time.Duration) int {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ta, _ := net.ResolveUDPAddr("udp", target)
	t.Cleanup(func() { front.Close() })
	var mu sync.Mutex
	backs := map[string]*net.UDPConn{}
	send := func(c *net.UDPConn, b []byte, to *net.UDPAddr) {
		if mrand.Float64() < loss {
			return
		}
		p := append([]byte(nil), b...)
		time.AfterFunc(delay, func() {
			if to == nil {
				c.Write(p)
			} else {
				c.WriteToUDP(p, to)
			}
		})
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			back := backs[from.String()]
			if back == nil {
				back, err = net.DialUDP("udp", nil, ta)
				if err != nil {
					mu.Unlock()
					continue
				}
				backs[from.String()] = back
				t.Cleanup(func() { back.Close() })
				go func(from *net.UDPAddr) {
					rb := make([]byte, 65535)
					for {
						n, err := back.Read(rb)
						if err != nil {
							return
						}
						send(front, rb[:n], from)
					}
				}(from)
			}
			mu.Unlock()
			send(back, buf[:n], nil)
		}
	}()
	return front.LocalAddr().(*net.UDPAddr).Port
}

func TestKCPUnderPacketLoss(t *testing.T) {
	cases := []struct {
		name string
		loss float64
		kcp  transport.KCPOptions
	}{
		{"10pct-fast2", 0.10, transport.KCPOptions{Mode: "fast2"}},
		{"20pct-fast3-fec", 0.20, transport.KCPOptions{Mode: "fast3", Data: 10, Parity: 5}},
		{"30pct-turbo-fec", 0.30, transport.KCPOptions{Mode: "turbo", Data: 8, Parity: 8}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := key()
			echo := tcpEcho(t)
			lp := freePort(t)
			ko := tc.kcp
			kh := &Config{Role: RoleKharej, Key: k, AllowLocal: []string{strconv.Itoa(echo)},
				Listen: []ListenConf{{Name: "kcp", Transport: "kcp", Addr: addr(lp), KCP: &ko}}}
			proxy := lossyUDP(t, addr(lp), tc.loss, 20*time.Millisecond)
			fp := freePort(t)
			ir := &Config{Role: RoleIran, Key: k,
				Dial:    []DialConf{{Name: "kcp", Transport: "kcp", Addrs: []string{addr(proxy)}, Conns: 1, KCP: &ko}},
				Forward: []ForwardConf{{Proto: "tcp", Listen: addr(fp), Target: addr(echo)}}}
			start(t, kh)
			in := start(t, ir)
			waitSessions(t, in, 1)
			t0 := time.Now()
			echoCheck(t, addr(fp), 1<<20)
			t.Logf("%.0f%% loss: 1 MiB echoed in %v", tc.loss*100, time.Since(t0).Round(time.Millisecond))
		})
	}
}

func TestKCPWrongKeyIsSilent(t *testing.T) {
	kh, ir, _ := pair(t, false, []string{"kcp"})
	ir.Key = key()
	start(t, kh)
	in := start(t, ir)
	time.Sleep(2 * time.Second)
	if len(in.Snapshot().Sessions) != 0 {
		t.Fatal("wrong key connected over kcp")
	}
}

func TestKCPOptionsValidate(t *testing.T) {
	bad := []transport.KCPOptions{
		{Mode: "warp"}, {Data: 10}, {Parity: 3}, {MTU: 100}, {SndWnd: 5}, {Crypt: "rot13"},
	}
	for _, o := range bad {
		if o.Validate() == nil {
			t.Errorf("%+v: expected error", o)
		}
	}
	if err := (transport.KCPOptions{Mode: "fast3", Data: 10, Parity: 3}).Validate(); err != nil {
		t.Fatal(err)
	}
}
