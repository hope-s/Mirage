package node

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	"mirage/internal/cfscan"
	"mirage/internal/mux"
	"mirage/internal/transport"
)

// ---------- CDN edge scan ----------

// scanCandidates overrides the random Cloudflare sample (tests).
var scanCandidates []string

// ScanReport is the outcome of a CDN edge scan.
type ScanReport struct {
	Link    string          `json:"link"`
	At      int64           `json:"at"`
	Port    int             `json:"port"`
	Results []cfscan.Result `json:"results"`
	Applied []string        `json:"applied,omitempty"`
	Auto    bool            `json:"auto,omitempty"`
	Err     string          `json:"err,omitempty"`
}

// CDNLinks lists dial links that go through a CDN.
func (n *Node) CDNLinks() []string {
	n.linksMu.Lock()
	defer n.linksMu.Unlock()
	var out []string
	for name, dl := range n.dials {
		if dl.conf.CDN != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (n *Node) dialLinkByName(name string) (*dialLink, error) {
	n.linksMu.Lock()
	defer n.linksMu.Unlock()
	if name == "" {
		for _, dl := range n.dials {
			if dl.conf.CDN != "" {
				return dl, nil
			}
		}
		return nil, errors.New("no CDN link on this server (set one up with -cdn)")
	}
	dl := n.dials[name]
	if dl == nil {
		return nil, fmt.Errorf("no active dial link %q", name)
	}
	return dl, nil
}

// ScanCDN finds the best edge IPs for a CDN link by running real tunnel
// handshakes through each candidate. With apply, the link switches to the
// best few right away. port 0 keeps the link's current port.
func (n *Node) ScanCDN(ctx context.Context, link string, port, sample int, apply bool) (*ScanReport, error) {
	dl, err := n.dialLinkByName(link)
	if err != nil {
		return nil, err
	}
	if dl.conf.CDN == "" {
		return nil, fmt.Errorf("link %q does not go through a CDN", dl.conf.Name)
	}
	cur := *dl.addrs.Load()
	if port == 0 {
		port = 443
		if len(cur) > 0 {
			if _, p, err := net.SplitHostPort(cur[0]); err == nil {
				port, _ = strconv.Atoi(p)
			}
		}
	}
	var extra []string
	for _, a := range cur {
		if h, p, err := net.SplitHostPort(a); err == nil && net.ParseIP(h) != nil && p == strconv.Itoa(port) {
			extra = append(extra, a)
		}
	}
	base := dl.opts()
	check := func(ctx context.Context, addr string) (time.Duration, error) {
		o := base
		o.Addrs = []string{addr}
		t0 := time.Now()
		s, _, err := n.dialOnceCtx(ctx, o)
		if err != nil {
			return 0, err
		}
		el := time.Since(t0)
		s.Close()
		return el, nil
	}
	rep := &ScanReport{Link: dl.conf.Name, At: time.Now().Unix(), Port: port}
	res, err := cfscan.Scan(ctx, cfscan.Options{Port: port, Sample: sample, Check: check, Extra: extra, Candidates: scanCandidates})
	rep.Results = res
	if err != nil {
		rep.Err = err.Error()
	}
	if apply {
		var best []string
		for _, r := range res {
			if r.OK() && len(best) < 3 {
				best = append(best, r.Addr)
			}
		}
		if len(best) > 0 {
			n.setLinkAddrs(dl, best)
			rep.Applied = best
		} else if err == nil {
			rep.Err = "no edge address completed a tunnel handshake; the CDN domain, path or origin may be misconfigured"
		}
	}
	n.scanMu.Lock()
	n.scans[dl.conf.Name] = rep
	n.scanMu.Unlock()
	return rep, err
}

// LastScan returns the most recent scan of a link.
func (n *Node) LastScan(link string) *ScanReport {
	n.scanMu.Lock()
	defer n.scanMu.Unlock()
	return n.scans[link]
}

func (n *Node) setLinkAddrs(dl *dialLink, addrs []string) {
	cp := append([]string(nil), addrs...)
	dl.addrs.Store(&cp)
	n.log.infof("link %s: now using %v", dl.conf.Name, cp)
	// move live connections over gradually: the health loop's slots
	// redial on the new addresses when kicked
	dl.mu.Lock()
	for _, sl := range dl.slots {
		select {
		case sl.kick <- struct{}{}:
		default:
		}
	}
	dl.mu.Unlock()
	if n.OnAddrs != nil {
		n.OnAddrs(dl.conf.Name, cp)
	}
}

func (n *Node) autoScan(dl *dialLink) {
	defer dl.scanning.Store(false)
	n.log.infof("link %s: down for a while, scanning for working CDN edge IPs", dl.conf.Name)
	ctx, cancel := context.WithTimeout(n.ctx, 3*time.Minute)
	defer cancel()
	rep, err := n.ScanCDN(ctx, dl.conf.Name, 0, 0, true)
	if rep != nil {
		rep.Auto = true
	}
	if err != nil {
		n.log.infof("link %s: edge scan: %v", dl.conf.Name, err)
	}
}

// ---------- link test ----------

// LinkReport measures one link.
type LinkReport struct {
	Name        string  `json:"name"`
	Transport   string  `json:"transport"`
	Backup      bool    `json:"backup"`
	Tries       int     `json:"tries"`
	OK          int     `json:"ok"`
	HandshakeMs float64 `json:"handshake_ms"` // mean time to a working tunnel connection
	JitterMs    float64 `json:"jitter_ms"`
	RTTms       float64 `json:"rtt_ms"`  // live connections' ping
	UpMbps      float64 `json:"up_mbps"` // short single-connection upload
	Retrans     float64 `json:"retrans"` // kcp/ftcp retransmitted share during the upload, 0..1
	Score       float64 `json:"score"`   // lower is better
	Err         string  `json:"err,omitempty"`
}

// LinkTestResult is a full link test with advice.
type LinkTestResult struct {
	Links    []LinkReport `json:"links"`
	Best     string       `json:"best,omitempty"`
	Advice   []string     `json:"advice"`
	AdviceFa []string     `json:"advice_fa"`
}

// LinkTest measures every enabled dial link with fresh connections and a
// short upload, then recommends transports and KCP settings.
func (n *Node) LinkTest(ctx context.Context, tries int) (*LinkTestResult, error) {
	if tries <= 0 {
		tries = 6
	}
	n.linksMu.Lock()
	var dls []*dialLink
	for _, dl := range n.dials {
		dls = append(dls, dl)
	}
	n.linksMu.Unlock()
	if len(dls) == 0 {
		return nil, errors.New("this server opens no links (the other side dials in); run the test there")
	}
	sort.Slice(dls, func(i, j int) bool { return dls[i].conf.Name < dls[j].conf.Name })
	res := &LinkTestResult{}
	// sequential, so kcp retransmit counters can be attributed to one link
	for _, dl := range dls {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res.Links = append(res.Links, n.testLink(ctx, dl, tries))
	}
	advise(res)
	return res, nil
}

func (n *Node) testLink(ctx context.Context, dl *dialLink, tries int) LinkReport {
	r := LinkReport{Name: dl.conf.Name, Transport: dl.conf.Transport, Backup: dl.conf.Backup, Tries: tries}
	var lat []float64
	var keep *mux.Session
	for i := 0; i < tries && ctx.Err() == nil; i++ {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		t0 := time.Now()
		s, _, err := n.dialOnceCtx(cctx, dl.opts())
		cancel()
		if err != nil {
			r.Err = err.Error()
			continue
		}
		lat = append(lat, float64(time.Since(t0).Microseconds())/1000)
		if keep == nil {
			keep = s
		} else {
			s.Close()
		}
	}
	r.OK = len(lat)
	if len(lat) > 0 {
		r.Err = ""
		r.HandshakeMs, r.JitterMs = meanStd(lat)
	}
	n.allMu.Lock()
	var rtts []float64
	for s, info := range n.all {
		if info.Link == dl.conf.Name && s.RTT() > 0 {
			rtts = append(rtts, float64(s.RTT().Microseconds())/1000)
		}
	}
	n.allMu.Unlock()
	if len(rtts) > 0 {
		r.RTTms, _ = meanStd(rtts)
	}
	if keep != nil {
		before := kcp.DefaultSnmp.Copy()
		r.UpMbps = uploadProbe(ctx, keep, 3*time.Second)
		after := kcp.DefaultSnmp.Copy()
		if transport.IsPacket(dl.conf.Transport) && after.OutSegs > before.OutSegs {
			r.Retrans = float64(after.RetransSegs-before.RetransSegs) / float64(after.OutSegs-before.OutSegs)
		}
		keep.Close()
	}
	r.Score = linkScore(r)
	return r
}

// uploadProbe pushes data over one fresh session for d and returns Mbps.
func uploadProbe(ctx context.Context, s *mux.Session, d time.Duration) float64 {
	st, err := s.Open(targetSpeedUp)
	if err != nil {
		return 0
	}
	defer st.Reset()
	if st.WaitConnected(5*time.Second) != nil {
		return 0
	}
	buf := make([]byte, 32*1024)
	var total int
	start := time.Now()
	for time.Since(start) < d && ctx.Err() == nil {
		m, err := st.Write(buf)
		total += m
		if err != nil {
			break
		}
	}
	return float64(total) * 8 / time.Since(start).Seconds() / 1e6
}

func linkScore(r LinkReport) float64 {
	if r.OK == 0 {
		return 1e9
	}
	fail := 1 - float64(r.OK)/float64(r.Tries)
	lat := r.HandshakeMs
	if r.RTTms > 0 {
		lat = r.RTTms
	}
	return lat + 2*r.JitterMs + 2000*fail + 1000*r.Retrans - math.Min(r.UpMbps, 200)
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

// advise turns measurements into concrete suggestions.
func advise(res *LinkTestResult) {
	add := func(en, fa string) {
		res.Advice = append(res.Advice, en)
		res.AdviceFa = append(res.AdviceFa, fa)
	}
	var best *LinkReport
	var tcpOK, packetOK, packetTried bool
	maxLoss := 0.0
	for i := range res.Links {
		r := &res.Links[i]
		if r.OK > 0 && (best == nil || r.Score < best.Score) {
			best = r
		}
		if transport.IsPacket(r.Transport) {
			packetTried = true
			if r.OK > 0 {
				packetOK = true
				maxLoss = math.Max(maxLoss, r.Retrans)
			}
		} else if r.OK > 0 {
			tcpOK = true
		}
		if r.OK == 0 {
			add(fmt.Sprintf("%s: no connection succeeded - the port or protocol is probably blocked; disable it or change its port", r.Name),
				fmt.Sprintf("%s: هیچ اتصالی برقرار نشد. احتمالاً این پورت یا پروتکل بسته است؛ خاموشش کنید یا پورتش را عوض کنید", r.Name))
		} else if r.OK < r.Tries {
			add(fmt.Sprintf("%s: %d of %d connections failed - unstable path", r.Name, r.Tries-r.OK, r.Tries),
				fmt.Sprintf("%s: %d از %d اتصال ناموفق بود؛ مسیر ناپایدار است", r.Name, r.Tries-r.OK, r.Tries))
		}
		if r.OK > 1 && r.JitterMs > 0.5*r.HandshakeMs && r.JitterMs > 80 {
			add(fmt.Sprintf("%s: very uneven latency (jitter %.0f ms) - typical of throttling; kcp/ftcp handle this better", r.Name, r.JitterMs),
				fmt.Sprintf("%s: تأخیر خیلی نامنظم است (jitter %.0f ms) که نشانه‌ی محدودسازی است؛ kcp یا ftcp بهتر جواب می‌دهند", r.Name, r.JitterMs))
		}
	}
	if best != nil {
		res.Best = best.Name
		add("best link right now: "+best.Name, "بهترین لینک در حال حاضر: "+best.Name)
	}
	switch {
	case packetTried && !packetOK && tcpOK:
		add("UDP looks blocked: use ftcp (fake TCP) instead of kcp",
			"به نظر UDP بسته است: به‌جای kcp از ftcp (fake TCP) استفاده کنید")
	case !packetTried && tcpOK:
		add("tip: add a kcp link (-kcp PORT) so the tunnel survives packet loss and throttling",
			"پیشنهاد: یک لینک kcp اضافه کنید (-kcp PORT) تا تانل در پکت‌لاست و محدودسازی دوام بیاورد")
	}
	if packetOK {
		var en, fa string
		switch {
		case maxLoss < 0.02:
			en, fa = "packet loss is low (<2%): kcp mode fast2, FEC off (0) saves bandwidth",
				"پکت‌لاست کم است (زیر ۲٪): kcp با حالت fast2 و بدون FEC (0) پهنای باند کمتری مصرف می‌کند"
		case maxLoss < 0.08:
			en, fa = fmt.Sprintf("packet loss about %.0f%%: kcp mode fast3, FEC 10:3", maxLoss*100),
				fmt.Sprintf("پکت‌لاست حدود %.0f٪: kcp با حالت fast3 و FEC 10:3", maxLoss*100)
		case maxLoss < 0.2:
			en, fa = fmt.Sprintf("packet loss about %.0f%%: kcp mode turbo, FEC 10:5", maxLoss*100),
				fmt.Sprintf("پکت‌لاست حدود %.0f٪: kcp با حالت turbo و FEC 10:5", maxLoss*100)
		default:
			en, fa = fmt.Sprintf("heavy packet loss (%.0f%%): kcp mode turbo, FEC 8:8", maxLoss*100),
				fmt.Sprintf("پکت‌لاست شدید (%.0f٪): kcp با حالت turbo و FEC 8:8", maxLoss*100)
		}
		add(en, fa)
	}
}

// dialOnceCtx is dialOnce bounded by ctx as well as the node's lifetime.
func (n *Node) dialOnceCtx(ctx context.Context, o transport.DialOptions) (*mux.Session, dialInfo, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	return n.dialWith(ctx, o)
}
