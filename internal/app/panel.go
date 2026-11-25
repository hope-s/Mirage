package app

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"mirage/internal/node"
	"mirage/internal/transport"
)

//go:embed panel.html
var panelHTML []byte

func memMB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Sys-m.HeapReleased) / (1 << 20)
}

func panelKey(cfg *node.Config) string {
	if cfg == nil || cfg.Panel == nil {
		return ""
	}
	p := cfg.Panel
	return fmt.Sprint(p.Listen, "|", p.TLS, "|", p.Cert, "|", p.Key)
}

type panel struct {
	a *App

	mu       sync.Mutex
	sessions map[string]time.Time // session id -> expiry
	fails    map[string][]time.Time
}

func newPanel(a *App) *panel {
	return &panel{a: a, sessions: map[string]time.Time{}, fails: map[string][]time.Time{}}
}

func (a *App) startPanel(cfg *node.Config) error {
	a.psMu.Lock()
	defer a.psMu.Unlock()
	if a.panelSrv != nil {
		_ = a.panelSrv.Close()
		a.panelSrv = nil
	}
	a.panelKey = panelKey(cfg)
	if cfg.Panel == nil {
		return nil
	}
	pc := cfg.Panel
	ln, err := net.Listen("tcp", pc.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", pc.Listen, err)
	}
	if pc.TLS {
		var cert tls.Certificate
		if pc.Cert != "" && pc.Key != "" {
			cert, err = tls.LoadX509KeyPair(pc.Cert, pc.Key)
		} else {
			var c, k []byte
			c, k, err = transport.GenerateCert("mirage-panel")
			if err == nil {
				cert, err = tls.X509KeyPair(c, k)
			}
		}
		if err != nil {
			ln.Close()
			return fmt.Errorf("panel tls: %w", err)
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	srv := &http.Server{
		Handler:           a.panel.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	a.panelSrv = srv
	go func() { _ = srv.Serve(ln) }()
	scheme := "http"
	if pc.TLS {
		scheme = "https"
	}
	log.Printf("panel on %s://%s%s/", scheme, pc.Listen, pc.Path)
	return nil
}

func (p *panel) cfg() *node.PanelConf {
	_, cfg := p.a.Node()
	if cfg == nil {
		return nil
	}
	return cfg.Panel
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// tooManyFails limits password guessing: 5 failures per IP per 10 minutes.
func (p *panel) tooManyFails(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	var keep []time.Time
	for _, t := range p.fails[ip] {
		if time.Since(t) < 10*time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(p.fails, ip)
	} else {
		p.fails[ip] = keep
	}
	return len(keep) >= 5
}

func (p *panel) addFail(ip string) {
	p.mu.Lock()
	p.fails[ip] = append(p.fails[ip], time.Now())
	if len(p.fails) > 10000 { // bound memory under a scan
		p.fails = map[string][]time.Time{}
	}
	p.mu.Unlock()
}

func (p *panel) authed(r *http.Request) bool {
	c, err := r.Cookie("mirage_sid")
	if err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	exp, ok := p.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(p.sessions, c.Value)
		return false
	}
	return true
}

func (p *panel) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pc := p.cfg()
		if pc == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		base := pc.Path
		if base == "/" {
			base = ""
		}
		path := r.URL.Path
		if !strings.HasPrefix(path, base+"/") && path != base {
			// wrong secret path: look like an empty nginx
			w.Header().Set("Server", "nginx")
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(path, base)
		if rel == "" {
			http.Redirect(w, r, base+"/", http.StatusFound)
			return
		}
		if rel == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
			_, _ = w.Write(panelHTML)
			return
		}
		if strings.HasPrefix(rel, "/font/") {
			p.a.serveFont(w, r, strings.TrimPrefix(rel, "/font/"))
			return
		}
		if !strings.HasPrefix(rel, "/api/") {
			http.NotFound(w, r)
			return
		}
		// CSRF guard: browsers cannot add custom headers cross-site
		// without a CORS preflight, which we never approve.
		if r.Header.Get("X-Mirage") != "1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		api := strings.TrimPrefix(rel, "/api/")
		if api == "login" && r.Method == http.MethodPost {
			p.login(w, r, pc, base)
			return
		}
		if !p.authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p.api(w, r, api, base)
	})
}

func (p *panel) login(w http.ResponseWriter, r *http.Request, pc *node.PanelConf, base string) {
	ip := clientIP(r)
	if p.tooManyFails(ip) {
		http.Error(w, "too many attempts, wait 10 minutes", http.StatusTooManyRequests)
		return
	}
	var req struct{ User, Pass string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	uOK := subtle.ConstantTimeCompare([]byte(req.User), []byte(pc.User)) == 1
	pOK := subtle.ConstantTimeCompare([]byte(req.Pass), []byte(pc.Pass)) == 1
	if !uOK || !pOK {
		p.addFail(ip)
		time.Sleep(time.Second)
		http.Error(w, "wrong username or password", http.StatusUnauthorized)
		return
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	sid := hex.EncodeToString(b)
	p.mu.Lock()
	now := time.Now()
	for k, v := range p.sessions {
		if now.After(v) {
			delete(p.sessions, k)
		}
	}
	p.sessions[sid] = now.Add(12 * time.Hour)
	p.mu.Unlock()
	cookiePath := base + "/"
	http.SetCookie(w, &http.Cookie{Name: "mirage_sid", Value: sid, Path: cookiePath, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	writeJSON(w, map[string]bool{"ok": true})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (p *panel) api(w http.ResponseWriter, r *http.Request, api, base string) {
	fail := func(err error, code int) { http.Error(w, err.Error(), code) }
	tn := r.URL.Query().Get("tunnel")
	if tn == "" {
		tn = MainTunnel
	}
	switch {
	case api == "logout" && r.Method == http.MethodPost:
		if c, err := r.Cookie("mirage_sid"); err == nil {
			p.mu.Lock()
			delete(p.sessions, c.Value)
			p.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "mirage_sid", Value: "", Path: base + "/", MaxAge: -1})
		writeJSON(w, map[string]bool{"ok": true})
	case api == "status" && r.Method == http.MethodGet:
		writeJSON(w, p.a.StatusData())
	case api == "logs" && r.Method == http.MethodGet:
		writeJSON(w, p.a.Logs.Lines())
	case api == "config" && r.Method == http.MethodGet:
		_, cfg, _ := p.a.Tunnel(tn)
		if cfg == nil {
			fail(fmt.Errorf("no tunnel named %q", tn), 404)
			return
		}
		writeJSON(w, cfg)
	case api == "config" && r.Method == http.MethodPut:
		var cfg node.Config
		if err := readJSON(r, &cfg); err != nil {
			fail(fmt.Errorf("invalid JSON: %w", err), 400)
			return
		}
		if tn == MainTunnel && cfg.Panel == nil {
			fail(errors.New("refusing to remove the panel from the panel; edit the file on the server instead"), 400)
			return
		}
		if err := p.a.SaveTunnel(tn, &cfg); err != nil {
			fail(err, 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	case api == "reload" && r.Method == http.MethodPost:
		if err := p.a.Reload(); err != nil {
			fail(err, 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	case api == "speedtest" && r.Method == http.MethodPost:
		res, err := p.a.speedTest(r.Context(), tn, 6*time.Second)
		if err != nil {
			fail(err, 500)
			return
		}
		writeJSON(w, res)
	case api == "linktest" && r.Method == http.MethodPost:
		res, err := p.a.LinkTest(r.Context(), tn)
		if err != nil {
			fail(err, 500)
			return
		}
		writeJSON(w, res)
	case api == "cfscan" && r.Method == http.MethodPost:
		var req struct {
			Link  string
			Port  int
			Apply bool
		}
		if err := readJSON(r, &req); err != nil {
			fail(err, 400)
			return
		}
		rep, err := p.a.ScanCDN(r.Context(), tn, req.Link, req.Port, 0, req.Apply)
		if err != nil && rep == nil {
			fail(err, 500)
			return
		}
		writeJSON(w, rep)
	case api == "cdnlinks" && r.Method == http.MethodGet:
		n, _, err := p.a.Tunnel(tn)
		if err != nil {
			fail(err, 404)
			return
		}
		type item struct {
			Name string           `json:"name"`
			Last *node.ScanReport `json:"last"`
		}
		out := []item{}
		for _, l := range n.CDNLinks() {
			out = append(out, item{l, n.LastScan(l)})
		}
		writeJSON(w, out)
	case api == "settings" && r.Method == http.MethodPost:
		var req struct {
			Profile      *string
			Cipher       *string
			Fingerprint  *string
			RefreshHours *int
			WindowMB     *int
			KeepaliveS   *int
		}
		if err := readJSON(r, &req); err != nil {
			fail(err, 400)
			return
		}
		p.editConfig(w, tn, func(c *node.Config) error {
			if req.Profile != nil {
				c.Profile = *req.Profile
			}
			if req.Cipher != nil {
				c.Cipher = *req.Cipher
			}
			if req.Fingerprint != nil {
				c.Fingerprint = *req.Fingerprint
			}
			if req.RefreshHours != nil {
				c.RefreshHours = *req.RefreshHours
			}
			if req.WindowMB != nil {
				c.WindowMB = *req.WindowMB
			}
			if req.KeepaliveS != nil {
				c.KeepaliveS = *req.KeepaliveS
			}
			return nil
		})
	case api == "profile" && r.Method == http.MethodPost:
		var req struct{ Profile string }
		if err := readJSON(r, &req); err != nil {
			fail(err, 400)
			return
		}
		p.editConfig(w, tn, func(c *node.Config) error { c.Profile = req.Profile; return nil })
	case api == "link" && r.Method == http.MethodPost:
		var req struct {
			Name     string
			Disabled *bool
			Backup   *bool
			Conns    *int
			MaxConns *int
			KCPMode  *string
			FEC      *string // "10:3", "0" = off
		}
		if err := readJSON(r, &req); err != nil {
			fail(err, 400)
			return
		}
		p.editConfig(w, tn, func(c *node.Config) error {
			kcpEdit := func(k **transport.KCPOptions, kind string) error {
				if req.KCPMode == nil && req.FEC == nil {
					return nil
				}
				if !transport.IsPacket(kind) {
					return errors.New("speed mode and FEC apply to kcp/ftcp links only")
				}
				o := transport.KCPOptions{}
				if *k != nil {
					o = **k
				}
				if req.KCPMode != nil {
					o.Mode = *req.KCPMode
				}
				if req.FEC != nil {
					d, pp, err := parseFEC(*req.FEC)
					if err != nil {
						return err
					}
					o.Data, o.Parity = d, pp
				}
				*k = &o
				return nil
			}
			for i := range c.Dial {
				d := &c.Dial[i]
				if d.Name != req.Name {
					continue
				}
				if req.Disabled != nil {
					d.Disabled = *req.Disabled
				}
				if req.Backup != nil {
					d.Backup = *req.Backup
				}
				if req.Conns != nil {
					d.Conns = *req.Conns
					if d.MaxConns != 0 && d.MaxConns < *req.Conns {
						d.MaxConns = *req.Conns
					}
				}
				if req.MaxConns != nil {
					d.MaxConns = *req.MaxConns
				}
				return kcpEdit(&d.KCP, d.Transport)
			}
			for i := range c.Listen {
				l := &c.Listen[i]
				if l.Name != req.Name {
					continue
				}
				if req.Backup != nil {
					l.Backup = *req.Backup
				}
				if req.Disabled != nil || req.Conns != nil || req.MaxConns != nil {
					return errors.New("this server listens on that link; connections are controlled by the other side")
				}
				return kcpEdit(&l.KCP, l.Transport)
			}
			return fmt.Errorf("no link named %q", req.Name)
		})
	case api == "forwards" && r.Method == http.MethodPut:
		var req struct {
			Forward []node.ForwardConf
			Socks   []node.SocksConf
		}
		if err := readJSON(r, &req); err != nil {
			fail(err, 400)
			return
		}
		p.editConfig(w, tn, func(c *node.Config) error {
			if c.Role != node.RoleIran {
				return errors.New("forwards are configured on the iran node")
			}
			c.Forward, c.Socks = req.Forward, req.Socks
			return nil
		})
	case api == "allow" && r.Method == http.MethodPut:
		var req struct{ AllowLocal []string }
		if err := readJSON(r, &req); err != nil {
			fail(err, 400)
			return
		}
		p.editConfig(w, tn, func(c *node.Config) error {
			if c.Role != node.RoleKharej {
				return errors.New("allow_local is configured on the kharej node")
			}
			c.AllowLocal = req.AllowLocal
			return nil
		})
	case api == "token" && r.Method == http.MethodGet:
		_, cfg, _ := p.a.Tunnel(tn)
		if cfg == nil {
			fail(fmt.Errorf("no tunnel named %q", tn), 404)
			return
		}
		writeJSON(w, map[string]string{"token": cfg.Token})
	default:
		http.NotFound(w, r)
	}
}

// parseFEC parses "10:3" (data:parity); "0", "off" or "" disables FEC.
func parseFEC(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" || s == "off" {
		return 0, 0, nil
	}
	a, b, ok := strings.Cut(s, ":")
	d, err1 := strconv.Atoi(a)
	p, err2 := strconv.Atoi(b)
	if !ok || err1 != nil || err2 != nil || d < 1 || p < 1 {
		return 0, 0, errors.New("FEC must look like 10:3 (data:parity) or 0")
	}
	return d, p, nil
}

// editConfig copies a tunnel's config, applies fn, then saves and reloads.
func (p *panel) editConfig(w http.ResponseWriter, tn string, fn func(*node.Config) error) {
	_, cur, _ := p.a.Tunnel(tn)
	if cur == nil {
		http.Error(w, fmt.Sprintf("no tunnel named %q", tn), 404)
		return
	}
	b, _ := json.Marshal(cur)
	var c node.Config
	_ = json.Unmarshal(b, &c)
	if err := fn(&c); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := p.a.SaveTunnel(tn, &c); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
