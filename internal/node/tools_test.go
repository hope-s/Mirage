package node

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// cdnPair has kharej listening with plain ws (the CDN origin) and iran
// dialing a CDN link whose current edge address is dead.
func cdnPair(t *testing.T) (*Config, *Config, string, int) {
	k := key()
	echo := tcpEcho(t)
	origin := addr(freePort(t))
	kh := &Config{Role: RoleKharej, Key: k, AllowLocal: []string{strconv.Itoa(echo)},
		Listen: []ListenConf{{Name: "cdn", Transport: "ws", Addr: origin, Path: "/p"}}}
	fp := freePort(t)
	ir := &Config{Role: RoleIran, Key: k,
		Dial: []DialConf{{Name: "cdn", Transport: "ws", Addrs: []string{addr(freePort(t))}, Path: "/p",
			Host: "cdn.example.com", CDN: "cdn.example.com", Conns: 1}},
		Forward: []ForwardConf{{Proto: "tcp", Listen: addr(fp), Target: addr(echo)}}}
	return kh, ir, origin, fp
}

func TestCDNScanAppliesBestEdge(t *testing.T) {
	kh, ir, origin, fp := cdnPair(t)
	dead := addr(freePort(t))
	scanCandidates = []string{dead, origin}
	t.Cleanup(func() { scanCandidates = nil })
	start(t, kh)
	n, err := New(ir)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var saved []string
	n.OnAddrs = func(_ string, a []string) { mu.Lock(); saved = a; mu.Unlock() }
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	rep, err := n.ScanCDN(context.Background(), "", 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Applied) != 1 || rep.Applied[0] != origin {
		t.Fatalf("applied %v, want [%s]; results %+v", rep.Applied, origin, rep.Results)
	}
	mu.Lock()
	if len(saved) != 1 || saved[0] != origin {
		t.Fatalf("OnAddrs got %v", saved)
	}
	mu.Unlock()
	waitSessions(t, n, 1)
	echoCheck(t, addr(fp), 1<<20)
}

func TestCDNAutoScanWhenDown(t *testing.T) {
	kh, ir, origin, fp := cdnPair(t)
	scanCandidates = []string{origin}
	oh, oa := healthEvery, autoScanAfter
	healthEvery, autoScanAfter = 300*time.Millisecond, time.Second
	t.Cleanup(func() { scanCandidates, healthEvery, autoScanAfter = nil, oh, oa })
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 1) // only possible once the auto scan found the origin
	echoCheck(t, addr(fp), 256<<10)
	if r := in.LastScan("cdn"); r == nil || !r.Auto {
		t.Fatalf("expected an automatic scan report, got %+v", r)
	}
}

func TestLinkTestAdvice(t *testing.T) {
	kh, ir, _ := pair(t, false, []string{"tcp", "kcp"})
	start(t, kh)
	in := start(t, ir)
	waitSessions(t, in, 4)
	res, err := in.LinkTest(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Links) != 2 {
		t.Fatalf("got %d reports", len(res.Links))
	}
	for _, l := range res.Links {
		if l.OK != 3 || l.UpMbps <= 0 {
			t.Fatalf("link %s not measured: %+v", l.Name, l)
		}
	}
	if res.Best == "" || len(res.Advice) == 0 || len(res.Advice) != len(res.AdviceFa) {
		t.Fatalf("no advice: %+v", res)
	}
	t.Logf("best=%s advice=%s", res.Best, strings.Join(res.Advice, " | "))
}

func TestEveryFingerprintAndCipher(t *testing.T) {
	for _, fp := range []string{"chrome", "firefox", "safari", "edge", "ios", "random", "go"} {
		for _, kind := range []string{"tls", "wss"} {
			t.Run(fp+"/"+kind, func(t *testing.T) {
				kh, ir, fp2 := pair(t, false, []string{kind})
				ir.Fingerprint = fp
				ir.Cipher = "chacha20-poly1305"
				start(t, kh)
				in := start(t, ir)
				waitSessions(t, in, 2)
				for _, s := range in.Snapshot().Sessions {
					if s.Cipher != "chacha20-poly1305" {
						t.Fatalf("cipher %q", s.Cipher)
					}
				}
				echoCheck(t, addr(fp2), 256<<10)
			})
		}
	}
}
