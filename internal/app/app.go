// Package app runs one or more tunnels from config files and owns
// everything around them: hot reload, the local status API, the web panel,
// logs and traffic history.
//
// The main tunnel lives in the main config file (which also holds the panel
// and status settings). Extra tunnels, e.g. to more foreign servers, are
// full node configs in the "tunnels" directory next to it, one file each.
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mirage/internal/node"
)

// Version is set by main.
var Version = "dev"

// MainTunnel is the name of the tunnel in the main config file.
const MainTunnel = "main"

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidTunnelName reports whether s can name an extra tunnel.
func ValidTunnelName(s string) bool { return nameRE.MatchString(s) && s != MainTunnel }

// TunnelsDir returns the directory holding extra tunnels for a main config.
func TunnelsDir(mainPath string) string { return filepath.Join(filepath.Dir(mainPath), "tunnels") }

type tunnel struct {
	name      string
	path      string
	cfg       *node.Config
	node      *node.Node
	appliedAt time.Time
	healthy   time.Time
}

// App supervises the tunnels.
type App struct {
	path    string
	dir     string
	started time.Time
	Logs    *Ring

	mu      sync.Mutex
	tunnels []*tunnel // [0] is the main tunnel

	statusSrv *http.Server
	psMu      sync.Mutex // guards panelSrv and panelKey
	panelSrv  *http.Server
	panelKey  string // listen+tls+cert, to know when to restart the panel

	hist    *history
	ctx     context.Context
	cancel  context.CancelFunc
	reloadM sync.Mutex
	panel   *panel
}

// New prepares an app for the main config at path.
func New(path string) *App {
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{path: path, dir: TunnelsDir(path), started: time.Now(), Logs: NewRing(500), hist: newHistory(180), ctx: ctx, cancel: cancel}
	log.SetOutput(io.MultiWriter(os.Stderr, a.Logs))
	return a
}

// Start loads the configs and starts the tunnels, status API and panel.
// A broken extra tunnel is logged and skipped; a broken main tunnel fails.
func (a *App) Start() error {
	cfg, err := node.LoadConfig(a.path)
	if err != nil {
		return err
	}
	main := &tunnel{name: MainTunnel, path: a.path}
	if err := a.apply(main, cfg); err != nil {
		return err
	}
	a.mu.Lock()
	a.tunnels = []*tunnel{main}
	a.mu.Unlock()
	a.syncExtra()
	if err := a.startStatus(cfg); err != nil {
		a.closeTunnels()
		return err
	}
	a.panel = newPanel(a)
	if err := a.startPanel(cfg); err != nil {
		log.Printf("panel: %v", err)
	}
	go a.sample()
	return nil
}

func (a *App) closeTunnels() {
	a.mu.Lock()
	ts := a.tunnels
	a.mu.Unlock()
	for _, t := range ts {
		if t.node != nil {
			t.node.Close()
		}
	}
}

// Close stops everything.
func (a *App) Close() {
	a.cancel()
	if a.statusSrv != nil {
		_ = a.statusSrv.Close()
	}
	a.psMu.Lock()
	if a.panelSrv != nil {
		_ = a.panelSrv.Close()
	}
	a.psMu.Unlock()
	a.closeTunnels()
}

func (a *App) get(name string) *tunnel {
	if name == "" {
		name = MainTunnel
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tunnels {
		if t.name == name {
			return t
		}
	}
	return nil
}

// Node returns the main tunnel's node and config.
func (a *App) Node() (*node.Node, *node.Config) {
	n, c, _ := a.Tunnel(MainTunnel)
	return n, c
}

// Tunnel returns a tunnel's node and config ("" = main).
func (a *App) Tunnel(name string) (*node.Node, *node.Config, error) {
	t := a.get(name)
	if t == nil {
		return nil, nil, fmt.Errorf("no tunnel named %q", name)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if t.node == nil {
		return nil, t.cfg, fmt.Errorf("tunnel %q is not running", t.name)
	}
	return t.node, t.cfg, nil
}

// TunnelNames lists the tunnels, main first.
func (a *App) TunnelNames() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, t := range a.tunnels {
		out = append(out, t.name)
	}
	return out
}

// Reload re-reads every config and restarts the tunnels whose file changed
// (the main tunnel always). A failing new config brings the previous one
// back.
func (a *App) Reload() error {
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	cfg, err := node.LoadConfig(a.path)
	if err != nil {
		return err
	}
	main := a.get(MainTunnel)
	if err := a.apply(main, cfg); err != nil {
		return err
	}
	a.afterMainApply(cfg)
	a.syncExtra()
	return nil
}

// reloadTunnel restarts one tunnel from its file (watchdog / refresh).
func (a *App) reloadTunnel(t *tunnel) error {
	if t.name == MainTunnel {
		return a.Reload()
	}
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	cfg, err := loadExtra(t.path)
	if err != nil {
		return err
	}
	return a.apply(t, cfg)
}

// SaveAndReload validates cfg, writes it as the main config and applies it.
func (a *App) SaveAndReload(cfg *node.Config) error { return a.SaveTunnel(MainTunnel, cfg) }

// SaveTunnel validates cfg, applies it to the named tunnel and writes it.
func (a *App) SaveTunnel(name string, cfg *node.Config) error {
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	if err := cfg.Validate(); err != nil {
		return err
	}
	t := a.get(name)
	if t == nil {
		return fmt.Errorf("no tunnel named %q", name)
	}
	if t.name != MainTunnel && (cfg.Panel != nil || cfg.Status != "") {
		return errors.New("only the main tunnel has panel and status settings")
	}
	a.mu.Lock()
	old := t.cfg
	a.mu.Unlock()
	if err := a.apply(t, cfg); err != nil {
		return err
	}
	if err := cfg.Save(t.path); err != nil {
		_ = a.apply(t, old)
		return fmt.Errorf("saving config: %w", err)
	}
	if t.name == MainTunnel {
		a.afterMainApply(cfg)
	}
	return nil
}

// apply (re)starts a tunnel with cfg, restoring the previous config if the
// new one fails to start.
func (a *App) apply(t *tunnel, cfg *node.Config) error {
	a.mu.Lock()
	old, oldCfg := t.node, t.cfg
	a.mu.Unlock()
	if old != nil {
		old.Close() // free the ports
	}
	n, err := a.newNode(t, cfg)
	if err == nil {
		err = n.Start()
	}
	if err != nil {
		if old == nil {
			return err
		}
		log.Printf("tunnel %s: reload failed, restoring previous config: %v", t.name, err)
		if oldCfg != nil {
			if rn, rerr := a.newNode(t, oldCfg); rerr == nil && rn.Start() == nil {
				a.mu.Lock()
				t.node = rn
				a.mu.Unlock()
			}
		}
		return err
	}
	a.mu.Lock()
	t.node, t.cfg, t.appliedAt, t.healthy = n, cfg, time.Now(), time.Now()
	a.mu.Unlock()
	if old != nil {
		log.Printf("tunnel %s: config applied", t.name)
	}
	return nil
}

func (a *App) afterMainApply(cfg *node.Config) {
	a.mu.Lock()
	oldStatus := ""
	if a.statusSrv != nil {
		oldStatus = a.statusSrv.Addr
	}
	a.mu.Unlock()
	if cfg.Status != oldStatus {
		if a.statusSrv != nil {
			_ = a.statusSrv.Close()
		}
		if err := a.startStatus(cfg); err != nil {
			log.Printf("status: %v", err)
		}
	}
	a.psMu.Lock()
	changed := panelKey(cfg) != a.panelKey
	a.psMu.Unlock()
	if changed {
		// restart the panel a moment later so the HTTP reply that
		// triggered this reload can still be delivered
		go func() {
			time.Sleep(700 * time.Millisecond)
			if err := a.startPanel(cfg); err != nil {
				log.Printf("panel: %v", err)
			}
		}()
	}
}

func loadExtra(path string) (*node.Config, error) {
	cfg, err := node.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	if cfg.Panel != nil || cfg.Status != "" {
		return nil, fmt.Errorf("%s: extra tunnels cannot have panel or status settings (the main config owns them)", path)
	}
	return cfg, nil
}

// syncExtra starts new tunnel files, restarts changed ones and stops the
// ones whose file is gone.
func (a *App) syncExtra() {
	files, _ := filepath.Glob(filepath.Join(a.dir, "*.json"))
	want := map[string]string{}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		if !ValidTunnelName(name) {
			log.Printf("ignoring %s: tunnel names use a-z, 0-9 and -", f)
			continue
		}
		want[name] = f
	}
	a.mu.Lock()
	var gone []*tunnel
	keep := a.tunnels[:1]
	have := map[string]*tunnel{}
	for _, t := range a.tunnels[1:] {
		if _, ok := want[t.name]; ok {
			keep = append(keep, t)
			have[t.name] = t
		} else {
			gone = append(gone, t)
		}
	}
	a.tunnels = keep
	a.mu.Unlock()
	for _, t := range gone {
		if t.node != nil {
			t.node.Close()
		}
		log.Printf("tunnel %s: removed", t.name)
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		cfg, err := loadExtra(want[name])
		if err != nil {
			log.Printf("tunnel %s: %v", name, err)
			continue
		}
		t := have[name]
		if t != nil {
			a.mu.Lock()
			same := t.node != nil && sameConfig(t.cfg, cfg)
			a.mu.Unlock()
			if same {
				continue
			}
		} else {
			t = &tunnel{name: name, path: want[name]}
		}
		if err := a.apply(t, cfg); err != nil {
			log.Printf("tunnel %s: %v", name, err)
			if have[name] == nil {
				continue
			}
		}
		if have[name] == nil {
			a.mu.Lock()
			a.tunnels = append(a.tunnels, t)
			a.mu.Unlock()
			log.Printf("tunnel %s: started (%s)", name, cfg.Role)
		}
	}
}

func sameConfig(x, y *node.Config) bool {
	bx, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return bytes.Equal(bx, by)
}

func (a *App) newNode(t *tunnel, cfg *node.Config) (*node.Node, error) {
	n, err := node.New(cfg)
	if err != nil {
		return nil, err
	}
	n.OnAddrs = func(link string, addrs []string) { a.persistAddrs(t, link, addrs) }
	return n, nil
}

// persistAddrs saves edge IPs chosen by a CDN scan without restarting the
// tunnel (it already uses them).
func (a *App) persistAddrs(t *tunnel, link string, addrs []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if t.cfg == nil {
		return
	}
	cp := *t.cfg
	cp.Dial = append([]node.DialConf(nil), t.cfg.Dial...)
	for i := range cp.Dial {
		if cp.Dial[i].Name == link {
			cp.Dial[i].Addrs = append([]string(nil), addrs...)
		}
	}
	if err := cp.Save(t.path); err != nil {
		log.Printf("tunnel %s: saving new edge IPs: %v", t.name, err)
		return
	}
	t.cfg = &cp
}

// LinkTest runs a link test on a tunnel ("" = main).
func (a *App) LinkTest(ctx context.Context, name string) (*node.LinkTestResult, error) {
	n, _, err := a.Tunnel(name)
	if err != nil {
		return nil, err
	}
	return n.LinkTest(ctx, 0)
}

// ScanCDN runs a CDN edge scan on a tunnel ("" = main).
func (a *App) ScanCDN(ctx context.Context, name, link string, port, sample int, apply bool) (*node.ScanReport, error) {
	n, _, err := a.Tunnel(name)
	if err != nil {
		return nil, err
	}
	return n.ScanCDN(ctx, link, port, sample, apply)
}

func (a *App) speedTest(ctx context.Context, name string, d time.Duration) (node.SpeedResult, error) {
	n, _, err := a.Tunnel(name)
	if err != nil {
		return node.SpeedResult{}, err
	}
	return n.SpeedTest(ctx, d)
}

// ---------- local status API (used by the CLI) ----------

func (a *App) startStatus(cfg *node.Config) error {
	a.statusSrv = nil
	if cfg.Status == "" {
		return nil
	}
	ln, err := net.Listen("tcp", cfg.Status)
	if err != nil {
		return fmt.Errorf("status %s: %w", cfg.Status, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.StatusData())
	})
	mux.HandleFunc("POST /speedtest", func(w http.ResponseWriter, r *http.Request) {
		d, _ := strconv.Atoi(r.URL.Query().Get("d"))
		res, err := a.speedTest(r.Context(), r.URL.Query().Get("tunnel"), time.Duration(d)*time.Second)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("POST /linktest", func(w http.ResponseWriter, r *http.Request) {
		res, err := a.LinkTest(r.Context(), r.URL.Query().Get("tunnel"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("POST /cfscan", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		port, _ := strconv.Atoi(q.Get("port"))
		sample, _ := strconv.Atoi(q.Get("n"))
		rep, err := a.ScanCDN(r.Context(), q.Get("tunnel"), q.Get("link"), port, sample, q.Get("apply") == "1")
		if err != nil && rep == nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Reload(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	srv := &http.Server{Addr: cfg.Status, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	a.statusSrv = srv
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// TunnelStatus is one tunnel in the status document.
type TunnelStatus struct {
	Name         string   `json:"name"`
	Profile      string   `json:"profile"`
	Cipher       string   `json:"cipher,omitempty"`
	RefreshHours int      `json:"refresh_hours,omitempty"`
	Forwards     []string `json:"forwards"`
	Running      bool     `json:"running"`
	node.Status
}

// StatusData is the full status document. The embedded Status and the
// Profile/Forwards fields describe the main tunnel; Tunnels has all of them.
type StatusData struct {
	node.Status
	Version  string         `json:"version"`
	Profile  string         `json:"profile"`
	UptimeS  int            `json:"uptime_s"`
	History  []histPoint    `json:"history"`
	MemMB    float64        `json:"mem_mb"`
	Load     string         `json:"load"`
	Forwards []string       `json:"forwards"`
	Tunnels  []TunnelStatus `json:"tunnels"`
}

func tunnelStatus(t *tunnel) TunnelStatus {
	ts := TunnelStatus{Name: t.name, Profile: "balanced", Running: t.node != nil}
	if t.node != nil {
		ts.Status = t.node.Snapshot()
	}
	if c := t.cfg; c != nil {
		if c.Profile != "" {
			ts.Profile = c.Profile
		}
		ts.Cipher, ts.RefreshHours, ts.Role = c.Cipher, c.RefreshHours, c.Role
		for _, f := range c.Forward {
			ts.Forwards = append(ts.Forwards, fmt.Sprintf("%s %s → %s", f.Proto, f.Listen, f.Target))
		}
		for _, s := range c.Socks {
			ts.Forwards = append(ts.Forwards, "socks5 "+s.Listen)
		}
	}
	return ts
}

// StatusData collects everything the panel and CLI show.
func (a *App) StatusData() StatusData {
	sd := StatusData{Version: Version, UptimeS: int(time.Since(a.started).Seconds())}
	a.mu.Lock()
	ts := append([]*tunnel(nil), a.tunnels...)
	for _, t := range ts {
		sd.Tunnels = append(sd.Tunnels, tunnelStatus(t))
	}
	a.mu.Unlock()
	if len(sd.Tunnels) > 0 {
		m := sd.Tunnels[0]
		sd.Status, sd.Profile, sd.Forwards = m.Status, m.Profile, m.Forwards
	}
	sd.History = a.hist.points()
	sd.MemMB = memMB()
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			sd.Load = strings.Join(f[:3], " ")
		}
	}
	return sd
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- traffic history ----------

type histPoint struct {
	T   int64   `json:"t"`
	In  float64 `json:"in"`  // Mbps received over all tunnels
	Out float64 `json:"out"` // Mbps sent over all tunnels
}

type history struct {
	mu  sync.Mutex
	pts []histPoint
	max int
}

func newHistory(n int) *history { return &history{max: n} }

func (h *history) add(p histPoint) {
	h.mu.Lock()
	h.pts = append(h.pts, p)
	if len(h.pts) > h.max {
		h.pts = h.pts[len(h.pts)-h.max:]
	}
	h.mu.Unlock()
}

func (h *history) points() []histPoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]histPoint(nil), h.pts...)
}

func (a *App) sample() {
	const every = 2 * time.Second
	t := time.NewTicker(every)
	defer t.Stop()
	last := map[*node.Node][2]uint64{}
	ticks := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-t.C:
			a.mu.Lock()
			ts := append([]*tunnel(nil), a.tunnels...)
			a.mu.Unlock()
			var din, dout uint64
			seen := map[*node.Node][2]uint64{}
			for _, tn := range ts {
				a.mu.Lock()
				n, cfg, appliedAt := tn.node, tn.cfg, tn.appliedAt
				a.mu.Unlock()
				if n == nil {
					continue
				}
				a.watch(tn, n, cfg, appliedAt, now)
				in, out := n.Totals()
				seen[n] = [2]uint64{in, out}
				if prev, ok := last[n]; ok && in >= prev[0] && out >= prev[1] {
					din += in - prev[0]
					dout += out - prev[1]
				}
			}
			last = seen
			sec := every.Seconds()
			p := histPoint{T: now.Unix(), In: float64(din) * 8 / sec / 1e6, Out: float64(dout) * 8 / sec / 1e6}
			a.hist.add(p)
			// hand memory from traffic bursts back to the OS once quiet,
			// so small VPSes keep a low footprint
			ticks++
			if ticks%30 == 0 && p.In+p.Out < 1 {
				debug.FreeOSMemory()
			}
		}
	}
}

// watch runs the watchdog and the scheduled refresh for one tunnel.
func (a *App) watch(tn *tunnel, n *node.Node, cfg *node.Config, appliedAt, now time.Time) {
	restart := func(why string) {
		log.Printf("tunnel %s: %s", tn.name, why)
		a.mu.Lock()
		tn.healthy, tn.appliedAt = now, now // do not fire again while reloading
		a.mu.Unlock()
		go func() {
			if err := a.reloadTunnel(tn); err != nil {
				log.Printf("tunnel %s: reload: %v", tn.name, err)
			}
		}()
	}
	// Watchdog: a tunnel that dials out but has had no connection at all
	// for 3 minutes is rebuilt from scratch (fresh sockets, DNS, state).
	up := len(n.Snapshot().Sessions) > 0 || !dialsOut(cfg)
	a.mu.Lock()
	if up {
		tn.healthy = now
	}
	stale := now.Sub(tn.healthy) > 3*time.Minute
	a.mu.Unlock()
	if stale {
		restart("watchdog: no connection for 3 minutes, rebuilding")
		return
	}
	if cfg.RefreshHours > 0 && now.Sub(appliedAt) > time.Duration(cfg.RefreshHours)*time.Hour {
		restart(fmt.Sprintf("scheduled refresh (every %dh): rebuilding", cfg.RefreshHours))
	}
}

func dialsOut(cfg *node.Config) bool {
	if cfg == nil {
		return false
	}
	for _, d := range cfg.Dial {
		if !d.Disabled {
			return true
		}
	}
	return false
}

// ---------- log ring ----------

// Ring keeps the last N log lines.
type Ring struct {
	mu    sync.Mutex
	lines []string
	max   int
	part  string
}

// NewRing creates a ring of n lines.
func NewRing(n int) *Ring { return &Ring{max: n} }

func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.part + string(p)
	parts := strings.Split(s, "\n")
	r.part = parts[len(parts)-1]
	for _, l := range parts[:len(parts)-1] {
		r.lines = append(r.lines, l)
	}
	if len(r.lines) > r.max {
		r.lines = append([]string(nil), r.lines[len(r.lines)-r.max:]...)
	}
	return len(p), nil
}

// Lines returns the buffered lines.
func (r *Ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}
