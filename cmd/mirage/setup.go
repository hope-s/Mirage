package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mirage/internal/node"
	"mirage/internal/secure"
	"mirage/internal/transport"
)

// ---------- pairing token ----------

const tokenPrefix = "MRG1."

type tokenLink struct {
	Name   string   `json:"n"`
	T      string   `json:"t"`
	Mode   string   `json:"m"` // d = iran dials, r = kharej dials (iran listens)
	Addrs  []string `json:"a"`
	SNI    string   `json:"s,omitempty"`
	Host   string   `json:"h,omitempty"`
	Path   string   `json:"p,omitempty"`
	Conns  int      `json:"c,omitempty"`
	Backup bool     `json:"b,omitempty"`

	KCP *transport.KCPOptions `json:"k,omitempty"`
}

type token struct {
	V       int         `json:"v"`
	Key     string      `json:"k"`
	Links   []tokenLink `json:"l"`
	Rotate  [2]int      `json:"r"`
	Profile string      `json:"pf,omitempty"`
}

func encodeToken(t token) (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeToken(s string) (token, error) {
	var t token
	s = strings.Join(strings.Fields(s), "") // tolerate line breaks from copy/paste
	if !strings.HasPrefix(s, tokenPrefix) {
		return t, errors.New("not a mirage token (it should start with " + tokenPrefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(s[len(tokenPrefix):])
	if err != nil {
		return t, fmt.Errorf("token is damaged or incomplete: %w", err)
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return t, fmt.Errorf("token is damaged: %w", err)
	}
	if t.V != 1 || len(t.Links) == 0 {
		return t, errors.New("unsupported or empty token")
	}
	return t, nil
}

// ---------- helpers ----------

func parsePorts(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", p)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randInt(lo, hi int) int {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	return lo + int(v.Int64())
}

func parseRotate(s string) (int, int, error) {
	if s == "0" || s == "off" {
		return 0, 0, nil
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, errors.New("rotate must look like 20-60 (minutes) or 0")
	}
	lo, err1 := strconv.Atoi(parts[0])
	hi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || lo < 1 || hi < lo {
		return 0, 0, errors.New("rotate must look like 20-60 (minutes) or 0")
	}
	return lo * 60, hi * 60, nil
}

// portFree reports whether a TCP port can be bound on this machine.
func portFree(p int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// udpFree reports whether a UDP port can be bound on this machine.
func udpFree(p int) bool {
	c, err := net.ListenPacket("udp", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// kindPortFree checks the port in the protocol the transport binds.
func kindPortFree(kind string, p int) bool {
	if kind == transport.KCP {
		return udpFree(p)
	}
	return portFree(p)
}

// parseFEC parses "10:3" (data:parity shards); "0" or "" disables FEC.
func parseFEC(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" || s == "off" {
		return 0, 0, nil
	}
	a, b, ok := strings.Cut(s, ":")
	d, err1 := strconv.Atoi(a)
	p, err2 := strconv.Atoi(b)
	if !ok || err1 != nil || err2 != nil || d < 1 || p < 1 {
		return 0, 0, errors.New("fec must look like 10:3 (data:parity) or 0 to disable")
	}
	return d, p, nil
}

func freeRandomPort() int {
	for i := 0; i < 50; i++ {
		p := randInt(20000, 60000)
		if portFree(p) {
			return p
		}
	}
	return randInt(20000, 60000)
}

// outboundIP guesses this server's public-facing address (no packet is sent).
func outboundIP() string {
	c, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func newPanel(enabled bool) *node.PanelConf {
	if !enabled {
		return nil
	}
	return &node.PanelConf{
		Listen: ":" + strconv.Itoa(freeRandomPort()),
		Path:   "/" + randHex(6),
		User:   "admin",
		Pass:   randHex(8),
		TLS:    true,
	}
}

func printPanel(cfg *node.Config, host string) {
	if cfg.Panel == nil {
		fmt.Println("web panel: disabled")
		return
	}
	p := cfg.Panel
	if host == "" {
		host = outboundIP()
		if host == "" {
			host = "SERVER_IP"
		}
	}
	_, port, _ := net.SplitHostPort(p.Listen)
	h, _, _ := net.SplitHostPort(p.Listen)
	if h != "" && h != "0.0.0.0" && h != "::" {
		host = h
	}
	scheme := "http"
	if p.TLS {
		scheme = "https"
	}
	fmt.Printf("web panel: %s://%s%s/\n", scheme, net.JoinHostPort(host, port), p.Path)
	fmt.Printf("  user: %s\n  pass: %s\n", p.User, p.Pass)
	if p.TLS && p.Cert == "" {
		fmt.Println("  (self-signed certificate: accept the browser warning once)")
	}
}

func writeConfig(cfg *node.Config, path string, force bool) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("generated config is invalid: %w", err)
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use -force to overwrite)", path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return cfg.Save(path)
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// ---------- setup kharej ----------

func cmdSetupKharej(args []string) error {
	fs := flag.NewFlagSet("setup kharej", flag.ExitOnError)
	ip := fs.String("ip", "", "public IP (or domain) of THIS kharej server (direct mode; auto-detected if empty)")
	reverse := fs.String("reverse", "", "reverse mode: IP of the IRAN server; kharej connects to iran (use when iran cannot reach kharej)")
	tcpPorts := fs.String("tcp", "", "raw TCP ports, comma separated (e.g. 8443,2087 = automatic port hopping)")
	tlsPorts := fs.String("tls", "443", "TLS ports, comma separated (empty to disable)")
	wsPorts := fs.String("ws", "", "WebSocket ports (plain HTTP)")
	wssPorts := fs.String("wss", "", "WebSocket-over-TLS ports")
	kcpPorts := fs.String("kcp", "", "KCP over UDP ports: best on links with packet loss")
	ftcpPorts := fs.String("ftcp", "", "KCP over fake-TCP ports (linux + root on both servers): for links where UDP is blocked and TCP collapses under loss")
	kcpMode := fs.String("kcp-mode", "fast2", "kcp/ftcp speed preset: normal | fast | fast2 | fast3 | turbo")
	fec := fs.String("fec", "10:3", "kcp/ftcp forward error correction data:parity shards; 0 to disable")
	kcpCrypt := fs.String("kcp-crypt", "aes", "kcp/ftcp packet obfuscation: aes | aes-128 | salsa20 | none")
	backups := fs.String("backup", "", "transports used only when the others fail, e.g. ws,wss (cdn is always backup)")
	sni := fs.String("sni", "www.bing.com", "TLS server name shown on the wire")
	path := fs.String("path", "", "WebSocket path (default: random)")
	cdn := fs.String("cdn", "", "CDN domain (e.g. t.example.com proxied by Cloudflare) - adds a backup link through the CDN")
	cdnOrigin := fs.Int("cdn-origin-port", 80, "port this server listens on for the CDN (80 for Flexible SSL, 443 with -cdn-origin-tls)")
	cdnOriginTLS := fs.Bool("cdn-origin-tls", false, "CDN talks TLS to this server (Cloudflare Full SSL)")
	conns := fs.Int("conns", 2, "minimum parallel connections per link (scales up automatically)")
	allow := fs.String("allow-local", "", "local ports/addresses reachable through the tunnel, e.g. 2096,127.0.0.1:2097 (your X-UI inbound ports)")
	fallback := fs.String("fallback", "", "send probes to this real web server (host:port) instead of the built-in decoy")
	rotate := fs.String("rotate", "20-60", "replace connections after a random number of minutes in this range; 0 to disable")
	profile := fs.String("profile", "balanced", "speed | balanced | stealth")
	panel := fs.Bool("panel", true, "enable the web panel")
	status := fs.String("status", "127.0.0.1:7788", "local status address (empty to disable)")
	out := fs.String("c", defaultConfig, "where to write the config")
	force := fs.Bool("force", false, "overwrite an existing config")
	noPortCheck := fs.Bool("no-port-check", false, "skip checking that ports are free")
	_ = fs.Parse(args)

	direct := *reverse == ""
	if direct && *ip == "" {
		*ip = outboundIP()
		if *ip == "" {
			return errors.New("could not detect this server's IP; pass -ip")
		}
		fmt.Printf("detected server IP: %s (use -ip to change)\n", *ip)
	}
	if !direct && *cdn != "" {
		return errors.New("-cdn works only in direct mode")
	}
	if *conns < 1 || *conns > 64 {
		return errors.New("-conns must be 1..64")
	}
	switch *profile {
	case "speed", "balanced", "stealth":
	default:
		return errors.New("-profile must be speed, balanced or stealth")
	}
	rmin, rmax, err := parseRotate(*rotate)
	if err != nil {
		return err
	}
	fd, fp, err := parseFEC(*fec)
	if err != nil {
		return err
	}
	kcpOpt := transport.KCPOptions{Mode: *kcpMode, Data: fd, Parity: fp, Crypt: *kcpCrypt}
	if err := kcpOpt.Validate(); err != nil {
		return err
	}
	if *path == "" {
		*path = "/api/" + randHex(6)
	}
	if !strings.HasPrefix(*path, "/") {
		*path = "/" + *path
	}
	isBackup := map[string]bool{}
	for _, b := range splitList(*backups) {
		isBackup[b] = true
	}
	psk, err := secure.NewPSK()
	if err != nil {
		return err
	}
	dir := filepath.Dir(*out)
	cfg := &node.Config{
		Role: node.RoleKharej, Key: hex.EncodeToString(psk[:]), Profile: *profile,
		RotateMin: rmin, RotateMax: rmax, Status: *status, AllowLocal: splitList(*allow),
		Panel: newPanel(*panel),
	}
	tk := token{V: 1, Key: cfg.Key, Rotate: [2]int{rmin, rmax}, Profile: *profile}

	kinds := []struct {
		kind  string
		ports string
	}{{"tls", *tlsPorts}, {"tcp", *tcpPorts}, {"kcp", *kcpPorts}, {"ftcp", *ftcpPorts}, {"ws", *wsPorts}, {"wss", *wssPorts}}
	usedPorts := map[int]string{}
	for _, k := range kinds {
		ports, err := parsePorts(k.ports)
		if err != nil {
			return fmt.Errorf("-%s: %w", k.kind, err)
		}
		if len(ports) == 0 {
			continue
		}
		for _, p := range ports {
			if other, dup := usedPorts[p]; dup {
				return fmt.Errorf("port %d used by both %s and %s", p, other, k.kind)
			}
			usedPorts[p] = k.kind
			if direct && !*noPortCheck && !kindPortFree(k.kind, p) {
				return fmt.Errorf("port %d is already in use on this server (X-UI?). choose another, e.g. -%s %d", p, k.kind, p+1)
			}
		}
		tl := tokenLink{Name: k.kind, T: k.kind, Conns: *conns, Backup: isBackup[k.kind]}
		var ko *transport.KCPOptions
		if transport.IsPacket(k.kind) {
			o := kcpOpt
			ko, tl.KCP = &o, &o
		}
		if k.kind == "tls" || k.kind == "wss" {
			tl.SNI = *sni
		}
		if k.kind == "ws" || k.kind == "wss" {
			tl.Path = *path
			tl.Host = *sni
		}
		if direct {
			tl.Mode = "d"
			for _, p := range ports {
				tl.Addrs = append(tl.Addrs, net.JoinHostPort(*ip, strconv.Itoa(p)))
				lc := node.ListenConf{
					Name: fmt.Sprintf("%s-%d", k.kind, p), Transport: k.kind,
					Addr: ":" + strconv.Itoa(p), SNI: *sni, Path: *path, Fallback: *fallback, KCP: ko,
				}
				if k.kind == "tls" || k.kind == "wss" {
					lc.Cert = filepath.Join(dir, "cert.pem")
					lc.CertKey = filepath.Join(dir, "key.pem")
				}
				cfg.Listen = append(cfg.Listen, lc)
			}
		} else {
			tl.Mode = "r"
			dc := node.DialConf{Name: k.kind, Transport: k.kind, SNI: tl.SNI, Host: tl.Host, Path: tl.Path,
				Conns: *conns, Backup: tl.Backup, KCP: ko}
			for _, p := range ports {
				tl.Addrs = append(tl.Addrs, ":"+strconv.Itoa(p))
				dc.Addrs = append(dc.Addrs, net.JoinHostPort(*reverse, strconv.Itoa(p)))
			}
			cfg.Dial = append(cfg.Dial, dc)
		}
		tk.Links = append(tk.Links, tl)
	}
	if *cdn != "" {
		kind := "ws"
		if *cdnOriginTLS {
			kind = "wss"
		}
		if other, dup := usedPorts[*cdnOrigin]; dup && other != kind {
			return fmt.Errorf("cdn origin port %d is already used by %s", *cdnOrigin, other)
		}
		if _, dup := usedPorts[*cdnOrigin]; !dup {
			if !*noPortCheck && !portFree(*cdnOrigin) {
				return fmt.Errorf("cdn origin port %d is already in use on this server", *cdnOrigin)
			}
			lc := node.ListenConf{Name: fmt.Sprintf("cdn-%d", *cdnOrigin), Transport: kind,
				Addr: ":" + strconv.Itoa(*cdnOrigin), SNI: *cdn, Path: *path, Fallback: *fallback}
			if kind == "wss" {
				lc.Cert = filepath.Join(dir, "cdn-cert.pem")
				lc.CertKey = filepath.Join(dir, "cdn-key.pem")
			}
			cfg.Listen = append(cfg.Listen, lc)
		}
		tk.Links = append(tk.Links, tokenLink{
			Name: "cdn", T: "wss", Mode: "d", Addrs: []string{net.JoinHostPort(*cdn, "443")},
			SNI: *cdn, Host: *cdn, Path: *path, Conns: *conns, Backup: true,
		})
	}
	if len(tk.Links) == 0 {
		return errors.New("no transport enabled; set at least one of -tcp -tls -kcp -ftcp -ws -wss -cdn")
	}
	allBackup := true
	for _, l := range tk.Links {
		if !l.Backup {
			allBackup = false
		}
	}
	if allBackup {
		return errors.New("every link is marked backup; leave at least one primary")
	}
	t, err := encodeToken(tk)
	if err != nil {
		return err
	}
	cfg.Token = t
	if err := writeConfig(cfg, *out, *force); err != nil {
		return err
	}
	fmt.Printf("\nkharej config written to %s\n", *out)
	if !direct {
		fmt.Printf("reverse mode: this server connects to the iran server at %s\n", *reverse)
	}
	fmt.Printf("\n===== PAIRING TOKEN (copy all of it to the iran server) =====\n%s\n=============================================================\n\n", t)
	printPanel(cfg, *ip)
	if *kcpPorts != "" {
		fmt.Printf("\nnote: kcp uses UDP - open UDP port(s) %s in this server's firewall\n", *kcpPorts)
	}
	if *ftcpPorts != "" {
		fmt.Println("\nnote: ftcp needs root and iptables on BOTH servers (linux only)")
	}
	if len(cfg.AllowLocal) == 0 {
		fmt.Println("\nnote: no -allow-local ports. Port forwards to services on THIS server (e.g. an X-UI inbound on 2096)")
		fmt.Println("      are blocked until you add them (flag, panel, or config).")
	}
	return nil
}

// ---------- setup iran ----------

func parseForwards(s, proto string) []node.ForwardConf {
	var out []node.ForwardConf
	for _, item := range splitList(s) {
		l, r, ok := strings.Cut(item, "=")
		if !ok {
			l, r = item, item // "443" = local 443 -> kharej 127.0.0.1:443
		}
		l, r = strings.TrimSpace(l), strings.TrimSpace(r)
		if _, err := strconv.Atoi(l); err == nil {
			l = ":" + l
		}
		if _, err := strconv.Atoi(r); err == nil {
			r = "127.0.0.1:" + r
		}
		out = append(out, node.ForwardConf{Proto: proto, Listen: l, Target: r})
	}
	return out
}

func cmdSetupIran(args []string) error {
	fs := flag.NewFlagSet("setup iran", flag.ExitOnError)
	tok := fs.String("token", "", "pairing token printed by the kharej setup")
	fwd := fs.String("forward", "", "TCP forwards LOCAL=TARGET, comma separated. TARGET is reached from kharej; a bare port means 127.0.0.1:PORT on kharej. e.g. 443=2096,8443=2097")
	fwdUDP := fs.String("forward-udp", "", "UDP forwards, same syntax as -forward")
	socks := fs.String("socks", "", "SOCKS5 listen address for an X-UI outbound, e.g. 127.0.0.1:40001")
	user := fs.String("socks-user", "", "SOCKS5 username (optional)")
	pass := fs.String("socks-pass", "", "SOCKS5 password (optional)")
	conns := fs.Int("conns", 0, "override minimum parallel connections per link")
	profile := fs.String("profile", "", "override the profile from the token: speed | balanced | stealth")
	panel := fs.Bool("panel", true, "enable the web panel")
	status := fs.String("status", "127.0.0.1:7788", "local status address (empty to disable)")
	out := fs.String("c", defaultConfig, "where to write the config")
	force := fs.Bool("force", false, "overwrite an existing config")
	noPortCheck := fs.Bool("no-port-check", false, "skip checking that ports are free")
	_ = fs.Parse(args)

	if *tok == "" {
		return errors.New("-token is required")
	}
	t, err := decodeToken(*tok)
	if err != nil {
		return err
	}
	prof := t.Profile
	if *profile != "" {
		prof = *profile
	}
	cfg := &node.Config{Role: node.RoleIran, Key: t.Key, Status: *status, Profile: prof,
		RotateMin: t.Rotate[0], RotateMax: t.Rotate[1], Panel: newPanel(*panel)}
	dir := filepath.Dir(*out)
	var listenPorts []string
	for _, l := range t.Links {
		c := l.Conns
		if *conns > 0 {
			c = *conns
		}
		switch l.Mode {
		case "d":
			cfg.Dial = append(cfg.Dial, node.DialConf{Name: l.Name, Transport: l.T, Addrs: l.Addrs,
				SNI: l.SNI, Host: l.Host, Path: l.Path, Conns: c, Backup: l.Backup, KCP: l.KCP})
		case "r":
			for _, a := range l.Addrs {
				_, port, _ := net.SplitHostPort(a)
				listenPorts = append(listenPorts, l.T+":"+port)
				lc := node.ListenConf{Name: l.Name + "-" + port, Transport: l.T, Addr: a,
					SNI: l.SNI, Path: l.Path, Backup: l.Backup, KCP: l.KCP}
				if l.T == "tls" || l.T == "wss" {
					lc.Cert = filepath.Join(dir, "cert.pem")
					lc.CertKey = filepath.Join(dir, "key.pem")
				}
				cfg.Listen = append(cfg.Listen, lc)
			}
		default:
			return fmt.Errorf("token link %q has unknown mode %q", l.Name, l.Mode)
		}
	}
	f1 := parseForwards(*fwd, "tcp")
	for _, u := range parseForwards(*fwdUDP, "udp") {
		merged := false
		for i := range f1 {
			if f1[i].Listen == u.Listen && f1[i].Target == u.Target {
				f1[i].Proto = "both"
				merged = true
			}
		}
		if !merged {
			f1 = append(f1, u)
		}
	}
	cfg.Forward = f1
	if *socks != "" {
		s := *socks
		if _, err := strconv.Atoi(s); err == nil {
			s = "127.0.0.1:" + s
		}
		cfg.Socks = []node.SocksConf{{Listen: s, User: *user, Pass: *pass}}
	}
	if len(cfg.Forward) == 0 && len(cfg.Socks) == 0 {
		return errors.New("nothing to serve: set -forward and/or -socks")
	}
	if !*noPortCheck {
		check := func(addr string) error {
			_, p, _ := net.SplitHostPort(addr)
			n, _ := strconv.Atoi(p)
			if n > 0 && !portFree(n) {
				return fmt.Errorf("port %d is already in use on this server", n)
			}
			return nil
		}
		for _, f := range cfg.Forward {
			if f.Proto != "udp" {
				if err := check(f.Listen); err != nil {
					return err
				}
			}
		}
		for _, s := range cfg.Socks {
			if err := check(s.Listen); err != nil {
				return err
			}
		}
		for _, lp := range listenPorts {
			kind, p, _ := strings.Cut(lp, ":")
			if n, _ := strconv.Atoi(p); n > 0 && !kindPortFree(kind, n) {
				return fmt.Errorf("port %d is already in use on this server", n)
			}
		}
	}
	if err := writeConfig(cfg, *out, *force); err != nil {
		return err
	}
	fmt.Printf("\niran config written to %s\n", *out)
	for _, f := range cfg.Forward {
		fmt.Printf("  forward %-4s %s -> (kharej) %s\n", f.Proto, f.Listen, f.Target)
	}
	for _, s := range cfg.Socks {
		fmt.Printf("  socks5 %s   (X-UI outbound: socks, address %s)\n", s.Listen, s.Listen)
	}
	if len(listenPorts) > 0 {
		fmt.Printf("  reverse mode: kharej will connect to this server on %s - open them in the firewall\n", strings.Join(listenPorts, ", "))
	}
	fmt.Println()
	printPanel(cfg, "")
	return nil
}
