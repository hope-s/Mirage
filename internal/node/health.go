package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mirage/internal/mux"
	"mirage/internal/secure"
	"mirage/internal/transport"
)

// ---------- profiles ----------

type profile struct {
	pad int
	mux mux.Config
}

// profileFor maps a profile name to concrete knobs.
//
//	speed    - no padding, big windows, fast dead-link detection
//	balanced - pad small records only, 8 MiB windows (default)
//	stealth  - pad every record, smaller windows, slower keepalives
func profileFor(cfg *Config) profile {
	var p profile
	switch cfg.Profile {
	case "speed":
		p = profile{pad: secure.PadNone, mux: mux.Config{PingInterval: 3 * time.Second, IdleTimeout: 12 * time.Second, MaxWindow: 16 << 20}}
	case "stealth":
		p = profile{pad: secure.PadHeavy, mux: mux.Config{PingInterval: 7 * time.Second, IdleTimeout: 28 * time.Second, MaxWindow: 4 << 20}}
	default:
		p = profile{pad: secure.PadLight, mux: mux.Config{PingInterval: 4 * time.Second, IdleTimeout: 16 * time.Second, MaxWindow: 8 << 20}}
	}
	if cfg.WindowMB > 0 {
		p.mux.MaxWindow = cfg.WindowMB << 20
	}
	if cfg.KeepaliveS > 0 {
		p.mux.PingInterval = time.Duration(cfg.KeepaliveS) * time.Second
		p.mux.IdleTimeout = 4 * p.mux.PingInterval
	}
	return p
}

// ---------- dial links with health checks and autoscaling ----------

type slot struct {
	stop     chan struct{}
	kick     chan struct{}
	sess     atomic.Pointer[mux.Session]
	slow     int
	lastKick time.Time
}

type dialLink struct {
	n    *Node
	conf DialConf
	st   *linkState
	min  int
	max  int

	addrs atomic.Pointer[[]string] // current addresses; replaced live by CDN scans

	mu       sync.Mutex
	slots    []*slot
	base     time.Duration // best RTT seen recently (link baseline)
	baseAt   time.Time
	idle     int
	downAt   time.Time // when the link last had no live connection
	scanning atomic.Bool
	lastScan time.Time
}

func (dl *dialLink) opts() transport.DialOptions {
	d := dl.conf
	return transport.DialOptions{Kind: d.Transport, Addrs: *dl.addrs.Load(), SNI: d.SNI, Host: d.Host, Path: d.Path,
		KCP: kcpOpts(d.KCP), Key: dl.n.psk.PacketKey(), Fingerprint: dl.n.cfg.Fingerprint}
}

func (n *Node) startDialLink(d DialConf) {
	lo := d.Conns
	if lo <= 0 {
		lo = 2
	}
	hi := d.MaxConns
	if hi == 0 {
		hi = min(lo*3, 16)
	}
	hi = max(hi, lo)
	dl := &dialLink{n: n, conf: d, st: n.link(d.Name, "dial", d.Transport, lo), min: lo, max: hi, downAt: time.Now()}
	addrs := append([]string(nil), d.Addrs...)
	dl.addrs.Store(&addrs)
	dl.st.Min, dl.st.Backup = lo, d.Backup
	n.linksMu.Lock()
	n.dials[d.Name] = dl
	n.linksMu.Unlock()
	dl.mu.Lock()
	for i := 0; i < lo; i++ {
		dl.addSlotLocked()
	}
	dl.mu.Unlock()
	n.wg.Add(1)
	go dl.manage()
}

func (dl *dialLink) addSlotLocked() {
	s := &slot{stop: make(chan struct{}), kick: make(chan struct{}, 1)}
	idx := len(dl.slots)
	dl.slots = append(dl.slots, s)
	dl.st.mu.Lock()
	dl.st.Want = len(dl.slots)
	dl.st.mu.Unlock()
	dl.n.wg.Add(1)
	go dl.run(s, idx)
}

func (dl *dialLink) removeSlotLocked() {
	last := dl.slots[len(dl.slots)-1]
	close(last.stop)
	dl.slots = dl.slots[:len(dl.slots)-1]
	dl.st.mu.Lock()
	dl.st.Want = len(dl.slots)
	dl.st.mu.Unlock()
}

// run keeps one connection alive: reconnects with jittered exponential
// backoff, rotates it after its lifetime, replaces it when the health
// checker kicks it, and drains it gracefully when the slot is removed.
func (dl *dialLink) run(sl *slot, idx int) {
	n := dl.n
	defer n.wg.Done()
	if !n.sleep(time.Duration(idx*300+mrand.IntN(300)) * time.Millisecond) {
		return
	}
	backoff := time.Second
	d := dl.conf
	for n.ctx.Err() == nil {
		select {
		case <-sl.stop:
			return
		default:
		}
		s, di, err := n.dialOnce(dl.opts())
		if err != nil {
			dl.st.setErr(err)
			n.log.debugf("dial %s: %v", d.Name, err)
			jitter := time.Duration(mrand.Int64N(int64(backoff)/2 + 1))
			select {
			case <-n.ctx.Done():
				return
			case <-sl.stop:
				return
			case <-time.After(backoff + jitter):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		dl.st.setErr(nil)
		sl.sess.Store(s)
		started := time.Now()
		n.register(s, sessInfo{Link: d.Name, Transport: d.Transport, Remote: di.Remote, Backup: d.Backup, Dialed: true, Cipher: di.Cipher}, dl.st)
		var expire <-chan time.Time
		var timer *time.Timer
		if life := n.lifetime(); life > 0 {
			timer = time.NewTimer(life)
			expire = timer.C
		}
		retire := func(why string) {
			n.log.debugf("dial %s: %s", d.Name, why)
			s.GoAway()
			go drainAndClose(n.ctx, s)
			backoff = time.Second
		}
		select {
		case <-n.ctx.Done():
			s.Close()
		case <-sl.stop:
			retire("scaling down")
		case <-s.Done():
			if time.Since(started) > 30*time.Second {
				backoff = time.Second
			}
			n.log.debugf("dial %s: session lost: %v", d.Name, s.Err())
		case <-expire:
			retire("rotating connection")
		case <-sl.kick:
			n.log.infof("link %s: connection slow, replacing it", d.Name)
			retire("replaced slow connection")
		}
		if timer != nil {
			timer.Stop()
		}
		sl.sess.Store(nil)
		select {
		case <-sl.stop:
			return
		default:
		}
		if s.IsClosed() && time.Since(started) < 30*time.Second {
			// died young: back off before redialing
			if !n.sleep(backoff/2 + time.Duration(mrand.Int64N(int64(backoff)/2+1))) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
		}
	}
}

var (
	healthEvery   = 10 * time.Second
	autoScanAfter = 90 * time.Second
	autoScanEvery = 15 * time.Minute
)

// manage watches the link: replaces connections whose latency has degraded
// far beyond the link's baseline (typical of per-flow throttling), and
// scales the number of connections with load.
func (dl *dialLink) manage() {
	n := dl.n
	defer n.wg.Done()
	t := time.NewTicker(healthEvery)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			dl.mu.Lock()
			for len(dl.slots) > 0 {
				dl.removeSlotLocked()
			}
			dl.mu.Unlock()
			return
		case <-t.C:
		}
		dl.check()
	}
}

func (dl *dialLink) check() {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	type live struct {
		sl  *slot
		rtt time.Duration
	}
	var act []live
	streams := 0
	best := time.Duration(0)
	for _, sl := range dl.slots {
		s := sl.sess.Load()
		if s == nil || s.IsClosed() || s.Draining() {
			continue
		}
		r := s.RTT()
		streams += s.NumStreams()
		act = append(act, live{sl, r})
		if r > 0 && (best == 0 || r < best) {
			best = r
		}
	}
	// baseline: lowest RTT seen; re-anchored every 10 minutes so a route
	// change does not leave a stale, unreachable baseline.
	if best > 0 && (dl.base == 0 || best < dl.base || time.Since(dl.baseAt) > 10*time.Minute) {
		dl.base, dl.baseAt = best, time.Now()
	}
	if dl.base > 0 && len(act) > 0 {
		thresh := max(3*dl.base, dl.base+250*time.Millisecond)
		kicked := false
		for _, a := range act {
			if a.rtt > thresh {
				a.sl.slow++
			} else {
				a.sl.slow = 0
			}
			if !kicked && a.sl.slow >= 3 && time.Since(a.sl.lastKick) > 2*time.Minute {
				a.sl.slow = 0
				a.sl.lastKick = time.Now()
				select {
				case a.sl.kick <- struct{}{}:
				default:
				}
				kicked = true // at most one replacement per cycle
			}
		}
	}
	if len(act) > 0 {
		dl.downAt = time.Time{}
	} else if dl.downAt.IsZero() {
		dl.downAt = time.Now()
	}
	// a CDN link that has been down for a while probably sits on edge IPs
	// that got filtered: look for working ones in the background
	if dl.conf.CDN != "" && !dl.conf.NoAutoScan && !dl.downAt.IsZero() &&
		time.Since(dl.downAt) > autoScanAfter && time.Since(dl.lastScan) > autoScanEvery &&
		dl.scanning.CompareAndSwap(false, true) {
		dl.lastScan = time.Now()
		go dl.n.autoScan(dl)
	}
	// autoscale
	switch {
	case len(act) > 0 && streams > 16*len(act) && len(dl.slots) < dl.max:
		dl.addSlotLocked()
		dl.idle = 0
		dl.n.log.infof("link %s: load %d streams, scaling up to %d connections", dl.conf.Name, streams, len(dl.slots))
	case len(dl.slots) > dl.min && streams < 4*(len(dl.slots)-1):
		dl.idle++
		if dl.idle >= 6 {
			dl.removeSlotLocked()
			dl.idle = 0
			dl.n.log.infof("link %s: load dropped, scaling down to %d connections", dl.conf.Name, len(dl.slots))
		}
	default:
		dl.idle = 0
	}
}

// ---------- speed test ----------

const (
	targetSpeedDown = "spd down "
	targetSpeedUp   = "spd up"
	maxSpeedBytes   = 1 << 30
)

func (e *exit) speed(st *mux.Stream) {
	_ = st.Accept(true)
	defer st.Close()
	if st.Target == targetSpeedUp {
		n, _ := io.Copy(io.Discard, st)
		_, _ = fmt.Fprintf(st, "%d", n)
		_ = st.CloseWrite()
		return
	}
	n, err := strconv.ParseInt(strings.TrimPrefix(st.Target, targetSpeedDown), 10, 64)
	if err != nil || n <= 0 || n > maxSpeedBytes {
		return
	}
	buf := make([]byte, 32*1024)
	for n > 0 {
		c := int64(len(buf))
		if c > n {
			c = n
		}
		if _, err := st.Write(buf[:c]); err != nil {
			return
		}
		n -= c
	}
	_ = st.CloseWrite()
	_, _ = io.Copy(io.Discard, st)
}

// SpeedResult is the outcome of a tunnel speed test.
type SpeedResult struct {
	DownMbps float64 `json:"down_mbps"`
	UpMbps   float64 `json:"up_mbps"`
	RTTms    float64 `json:"rtt_ms"`
	Streams  int     `json:"streams"`
}

var errNotIran = errors.New("speed test runs on the iran node")

// SpeedTest measures throughput through the tunnel using parallel streams.
func (n *Node) SpeedTest(ctx context.Context, d time.Duration) (SpeedResult, error) {
	if n.pool == nil {
		return SpeedResult{}, errNotIran
	}
	if d <= 0 || d > 30*time.Second {
		d = 6 * time.Second
	}
	const par = 4
	var res SpeedResult
	res.Streams = par
	measure := func(up bool) (float64, error) {
		var total atomic.Int64
		var wg sync.WaitGroup
		var firstErr atomic.Value
		start := time.Now()
		deadline := start.Add(d)
		for i := 0; i < par; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				target := targetSpeedDown + strconv.Itoa(maxSpeedBytes)
				if up {
					target = targetSpeedUp
				}
				st, err := n.pool.Open(target)
				if err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				defer st.Reset()
				buf := make([]byte, 32*1024)
				for time.Now().Before(deadline) && ctx.Err() == nil {
					var m int
					if up {
						m, err = st.Write(buf)
					} else {
						m, err = st.Read(buf)
					}
					total.Add(int64(m))
					if err != nil {
						return
					}
				}
			}()
		}
		wg.Wait()
		el := time.Since(start).Seconds()
		if total.Load() == 0 {
			if e, ok := firstErr.Load().(error); ok {
				return 0, e
			}
			return 0, errors.New("no data transferred")
		}
		return float64(total.Load()) * 8 / el / 1e6, nil
	}
	var err error
	if res.DownMbps, err = measure(false); err != nil {
		return res, err
	}
	if res.UpMbps, err = measure(true); err != nil {
		return res, err
	}
	var rs []time.Duration
	for s := range n.pool.snapshot() {
		if r := s.RTT(); r > 0 {
			rs = append(rs, r)
		}
	}
	if len(rs) > 0 {
		best := rs[0]
		for _, r := range rs {
			best = min(best, r)
		}
		res.RTTms = float64(best.Microseconds()) / 1000
	}
	return res, nil
}
