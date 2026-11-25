// Package cfscan finds Cloudflare edge IPs that work well from this server.
//
// Stage 1 samples random addresses from Cloudflare's published ranges and
// measures plain TCP connect time to many of them in parallel. Stage 2 takes
// the fastest and runs the caller's Verify (normally a full tunnel
// handshake through that edge to our own origin) several times, so the
// final ranking reflects what the tunnel will actually get: latency,
// jitter and failure rate on the real path.
package cfscan

import (
	"context"
	"errors"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Ranges are Cloudflare's IPv4 ranges (https://www.cloudflare.com/ips-v4).
var Ranges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

// HTTPSPorts are the ports Cloudflare proxies with TLS.
var HTTPSPorts = []int{443, 2053, 2083, 2087, 2096, 8443}

// Options control a scan.
type Options struct {
	Port        int // edge port, default 443
	Sample      int // addresses probed in stage 1 (default 400)
	Verify      int // addresses verified in stage 2 (default 12)
	Tries       int // verify attempts per address (default 4)
	Concurrency int // parallel stage-1 probes (default 64)
	Timeout     time.Duration
	// Check runs one full test through addr ("ip:port") and returns its
	// latency. Nil means stage 1 only.
	Check func(ctx context.Context, addr string) (time.Duration, error)
	// Extra addresses (e.g. the ones in use now) always verified.
	Extra []string
	// Candidates replaces the random Cloudflare sample ("ip:port" list).
	Candidates []string
}

// Result describes one edge address.
type Result struct {
	Addr     string  `json:"addr"`
	ConnMs   float64 `json:"conn_ms"`   // stage-1 TCP connect time
	RTTms    float64 `json:"rtt_ms"`    // mean verified latency
	JitterMs float64 `json:"jitter_ms"` // stddev of verified latency
	Loss     float64 `json:"loss"`      // failed verify attempts, 0..1
	Score    float64 `json:"score"`     // lower is better
	Err      string  `json:"err,omitempty"`
}

// OK reports whether the address passed verification at least once.
func (r Result) OK() bool { return r.Loss < 1 }

func (o *Options) defaults() {
	if o.Port == 0 {
		o.Port = 443
	}
	if o.Sample <= 0 {
		o.Sample = 400
	}
	if o.Verify <= 0 {
		o.Verify = 12
	}
	if o.Tries <= 0 {
		o.Tries = 4
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
}

// RandomIPs returns n distinct random addresses from Ranges, spread over
// every range in proportion to its size (with a floor so small ranges are
// still tried).
func RandomIPs(n int) []netip.Addr {
	type pfx struct {
		p    netip.Prefix
		size float64
	}
	var ps []pfx
	total := 0.0
	for _, r := range Ranges {
		p := netip.MustParsePrefix(r)
		sz := math.Sqrt(math.Pow(2, float64(32-p.Bits())))
		ps = append(ps, pfx{p, sz})
		total += sz
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for guard := 0; len(out) < n && guard < n*20; guard++ {
		x := mrand.Float64() * total
		var p netip.Prefix
		for _, c := range ps {
			if x < c.size {
				p = c.p
				break
			}
			x -= c.size
		}
		if !p.IsValid() {
			p = ps[len(ps)-1].p
		}
		b := p.Addr().As4()
		host := mrand.Uint32N(1 << (32 - p.Bits()))
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
		a := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		last := a.As4()[3]
		if last == 0 || last == 255 || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// Scan runs both stages and returns verified results best first (stage-1
// results only when Check is nil).
func Scan(ctx context.Context, o Options) ([]Result, error) {
	o.defaults()
	port := strconv.Itoa(o.Port)
	addrs := o.Candidates
	if len(addrs) == 0 {
		for _, ip := range RandomIPs(o.Sample) {
			addrs = append(addrs, net.JoinHostPort(ip.String(), port))
		}
	}

	// stage 1: TCP connect time
	type conn struct {
		addr string
		d    time.Duration
	}
	var mu sync.Mutex
	var fast []conn
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for _, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(a string) {
			defer func() { <-sem; wg.Done() }()
			t0 := time.Now()
			d := net.Dialer{Timeout: o.Timeout}
			c, err := d.DialContext(ctx, "tcp", a)
			if err != nil {
				return
			}
			el := time.Since(t0)
			c.Close()
			mu.Lock()
			fast = append(fast, conn{a, el})
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(fast) == 0 && len(o.Extra) == 0 {
		return nil, errors.New("no cloudflare address answered: the edge may be filtered on this network, or the server has no outbound access on port " + port)
	}
	sort.Slice(fast, func(i, j int) bool { return fast[i].d < fast[j].d })

	if o.Check == nil {
		out := make([]Result, 0, len(fast))
		for _, f := range fast {
			ms := ms(f.d)
			out = append(out, Result{Addr: f.addr, ConnMs: ms, RTTms: ms, Score: ms})
		}
		return out, nil
	}

	// stage 2: real tunnel checks on the fastest candidates
	cands := map[string]float64{}
	var order []string
	for _, e := range o.Extra {
		if _, ok := cands[e]; !ok {
			cands[e] = 0
			order = append(order, e)
		}
	}
	for _, f := range fast {
		if len(order) >= o.Verify+len(o.Extra) {
			break
		}
		if _, ok := cands[f.addr]; !ok {
			cands[f.addr] = ms(f.d)
			order = append(order, f.addr)
		}
	}
	res := make([]Result, len(order))
	vsem := make(chan struct{}, 6)
	for i, a := range order {
		wg.Add(1)
		vsem <- struct{}{}
		go func(i int, a string) {
			defer func() { <-vsem; wg.Done() }()
			r := Result{Addr: a, ConnMs: cands[a]}
			var lat []float64
			for t := 0; t < o.Tries && ctx.Err() == nil; t++ {
				cctx, cancel := context.WithTimeout(ctx, 4*o.Timeout)
				d, err := o.Check(cctx, a)
				cancel()
				if err != nil {
					r.Err = err.Error()
					continue
				}
				lat = append(lat, ms(d))
			}
			r.Loss = 1 - float64(len(lat))/float64(o.Tries)
			if len(lat) > 0 {
				r.Err = ""
				r.RTTms, r.JitterMs = meanStd(lat)
			}
			r.Score = score(r)
			res[i] = r
		}(i, a)
	}
	wg.Wait()
	sort.SliceStable(res, func(i, j int) bool { return res[i].Score < res[j].Score })
	return res, ctx.Err()
}

// score ranks an address: latency, plus jitter (which hurts interactive
// traffic twice), plus a heavy penalty per failed attempt.
func score(r Result) float64 {
	if !r.OK() {
		return 1e9
	}
	return r.RTTms + 2*r.JitterMs + 2000*r.Loss
}

func meanStd(v []float64) (mean, std float64) {
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	for _, x := range v {
		std += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(std / float64(len(v)))
}

func ms(d time.Duration) float64 { return math.Round(float64(d.Microseconds())/10) / 100 }
