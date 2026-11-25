package cfscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRandomIPsInsideCloudflare(t *testing.T) {
	var ps []netip.Prefix
	for _, r := range Ranges {
		ps = append(ps, netip.MustParsePrefix(r))
	}
	ips := RandomIPs(500)
	if len(ips) != 500 {
		t.Fatalf("got %d ips", len(ips))
	}
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		if seen[ip] {
			t.Fatalf("duplicate %s", ip)
		}
		seen[ip] = true
		in := false
		for _, p := range ps {
			if p.Contains(ip) {
				in = true
			}
		}
		if !in {
			t.Fatalf("%s is outside cloudflare ranges", ip)
		}
	}
}

func TestScanRanksByRealCheck(t *testing.T) {
	var addrs []string
	for i := 0; i < 4; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		addrs = append(addrs, l.Addr().String())
	}
	// addrs[0] fails, addrs[1] is slow, addrs[2] is fastest
	lat := map[string]time.Duration{addrs[1]: 80 * time.Millisecond, addrs[2]: 5 * time.Millisecond, addrs[3]: 30 * time.Millisecond}
	res, err := Scan(context.Background(), Options{Candidates: addrs, Tries: 2,
		Check: func(ctx context.Context, a string) (time.Duration, error) {
			d, ok := lat[a]
			if !ok {
				return 0, errors.New("handshake failed")
			}
			return d, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 4 || res[0].Addr != addrs[2] || res[1].Addr != addrs[3] || res[3].Addr != addrs[0] || res[3].OK() {
		t.Fatalf("bad ranking: %+v", res)
	}
}
