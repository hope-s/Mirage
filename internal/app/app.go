// Package app runs a node from a config file and owns everything around it:
// hot reload, the local status API, the web panel, logs and traffic history.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"mirage/internal/node"
)

// Version is set by main.
var Version = "dev"

// App supervises one node.
type App struct {
	path    string
	started time.Time
	Logs    *Ring

	mu   sync.Mutex
	cfg  *node.Config
	node *node.Node

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

// New prepares an app for the config at path.
func New(path string) *App {
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{path: path, started: time.Now(), Logs: NewRing(500), hist: newHistory(180), ctx: ctx, cancel: cancel}
	log.SetOutput(io.MultiWriter(os.Stderr, a.Logs))
	return a
}

// Start loads the config and starts the node, status API and panel.
func (a *App) Start() error {
	cfg, err := node.LoadConfig(a.path)
	if err != nil {
		return err
	}
	n, err := node.New(cfg)
	if err != nil {
		return err
	}
	if err := n.Start(); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg, a.node = cfg, n
	a.mu.Unlock()
	if err := a.startStatus(cfg); err != nil {
		n.Close()
		return err
	}
	a.panel = newPanel(a)
	if err := a.startPanel(cfg); err != nil {
		log.Printf("panel: %v", err)
	}
	go a.sample()
	return nil
}

// Close stops everything.
func (a *App) Close() {
	a.cancel()
	a.mu.Lock()
	n := a.node
	a.mu.Unlock()
	if a.statusSrv != nil {
		_ = a.statusSrv.Close()
	}
	a.psMu.Lock()
	if a.panelSrv != nil {
		_ = a.panelSrv.Close()
	}
	a.psMu.Unlock()
	if n != nil {
		n.Close()
	}
}

// Node returns the running node.
func (a *App) Node() (*node.Node, *node.Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.node, a.cfg
}

// Reload re-reads the config file and restarts the node with it. If the new
// config fails to start, the previous one is brought back.
func (a *App) Reload() error {
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	cfg, err := node.LoadConfig(a.path)
	if err != nil {
		return err
	}
	return a.apply(cfg)
}

// SaveAndReload validates cfg, writes it and applies it.
func (a *App) SaveAndReload(cfg *node.Config) error {
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	if err := cfg.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	old := a.cfg
	a.mu.Unlock()
	if err := a.apply(cfg); err != nil {
		return err
	}
	if err := cfg.Save(a.path); err != nil {
		_ = a.apply(old)
		return fmt.Errorf("saving config: %w", err)
	}
	return nil
}

func (a *App) apply(cfg *node.Config) error {
	a.mu.Lock()
	old, oldCfg := a.node, a.cfg
	a.mu.Unlock()
	if old != nil {
		old.Close() // free the ports
	}
	n, err := node.New(cfg)
	if err == nil {
		err = n.Start()
	}
	if err != nil {
		log.Printf("reload failed, restoring previous config: %v", err)
		if oldCfg != nil {
			if rn, rerr := node.New(oldCfg); rerr == nil && rn.Start() == nil {
				a.mu.Lock()
				a.node = rn
				a.mu.Unlock()
			}
		}
		return err
	}
	a.mu.Lock()
	a.node, a.cfg = n, cfg
	a.mu.Unlock()
	log.Printf("config applied")
	if cfg.Status != oldCfg.Status {
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
	return nil
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
		res, err := a.speedTest(r.Context(), time.Duration(d)*time.Second)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Reload(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	a.statusSrv = srv
	go func() { _ = srv.Serve(ln) }()
	return nil
}

func (a *App) speedTest(ctx context.Context, d time.Duration) (node.SpeedResult, error) {
	n, _ := a.Node()
	if n == nil {
		return node.SpeedResult{}, errors.New("not running")
	}
	return n.SpeedTest(ctx, d)
}

// StatusData is the full status document.
type StatusData struct {
	node.Status
	Version  string      `json:"version"`
	Profile  string      `json:"profile"`
	UptimeS  int         `json:"uptime_s"`
	History  []histPoint `json:"history"`
	MemMB    float64     `json:"mem_mb"`
	Load     string      `json:"load"`
	Forwards []string    `json:"forwards"`
}

// StatusData collects everything the panel and CLI show.
func (a *App) StatusData() StatusData {
	n, cfg := a.Node()
	sd := StatusData{Version: Version, UptimeS: int(time.Since(a.started).Seconds())}
	if n != nil {
		sd.Status = n.Snapshot()
	}
	if cfg != nil {
		sd.Profile = cfg.Profile
		if sd.Profile == "" {
			sd.Profile = "balanced"
		}
		for _, f := range cfg.Forward {
			sd.Forwards = append(sd.Forwards, fmt.Sprintf("%s %s → %s", f.Proto, f.Listen, f.Target))
		}
		for _, s := range cfg.Socks {
			sd.Forwards = append(sd.Forwards, "socks5 "+s.Listen)
		}
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
	In  float64 `json:"in"`  // Mbps received over the tunnel
	Out float64 `json:"out"` // Mbps sent over the tunnel
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
	var lastN *node.Node
	var lin, lout uint64
	healthy := time.Now()
	ticks := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-t.C:
			n, cfg := a.Node()
			if n == nil {
				continue
			}
			// Watchdog: a node that dials out but has had no tunnel at
			// all for 3 minutes is rebuilt from scratch (fresh sockets,
			// fresh DNS, fresh state).
			if len(n.Snapshot().Sessions) > 0 || !dialsOut(cfg) {
				healthy = now
			} else if now.Sub(healthy) > 3*time.Minute {
				log.Printf("watchdog: no tunnel for 3 minutes, restarting the node")
				healthy = now
				go func() {
					if err := a.Reload(); err != nil {
						log.Printf("watchdog reload: %v", err)
					}
				}()
			}
			in, out := n.Totals()
			if n != lastN || in < lin || out < lout {
				lastN, lin, lout = n, in, out
				continue
			}
			sec := every.Seconds()
			p := histPoint{T: now.Unix(),
				In:  float64(in-lin) * 8 / sec / 1e6,
				Out: float64(out-lout) * 8 / sec / 1e6}
			a.hist.add(p)
			lin, lout = in, out
			// hand memory from traffic bursts back to the OS once quiet,
			// so small VPSes keep a low footprint
			ticks++
			if ticks%30 == 0 && p.In+p.Out < 1 {
				debug.FreeOSMemory()
			}
		}
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
