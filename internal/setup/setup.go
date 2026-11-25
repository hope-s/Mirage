// Package setup builds matching kharej/iran configs and the pairing token
// that carries the kharej side's links to the iran side. The CLI flags, the
// terminal UI and the web panel all go through here.
package setup

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"mirage/internal/node"
	"mirage/internal/secure"
	"mirage/internal/transport"
)

// ---------- pairing token ----------

const tokenPrefix = "MRG1."

type Link struct {
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
	CDN bool                  `json:"cd,omitempty"` // link goes through a CDN (dialer may scan edge IPs)
	Opt bool                  `json:"o,omitempty"`  // reverse listener the iran side may skip when its port is busy
}

type Token struct {
	V       int    `json:"v"`
	Key     string `json:"k"`
	Links   []Link `json:"l"`
	Rotate  [2]int `json:"r"`
	Profile string `json:"pf,omitempty"`
	Refresh int    `json:"rf,omitempty"`
	Cipher  string `json:"ci,omitempty"`
	FP      string `json:"fp,omitempty"`
}

func EncodeToken(t Token) (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func DecodeToken(s string) (Token, error) {
	var t Token
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

// Describe lists a token's links in one line each, e.g. "tls 1.2.3.4:443".
func (t Token) Describe() []string {
	var out []string
	for _, l := range t.Links {
		dir := "iran → kharej"
		if l.Mode == "r" {
			dir = "kharej → iran"
		}
		s := fmt.Sprintf("%-4s %s  (%s)", l.T, strings.Join(l.Addrs, ", "), dir)
		if l.CDN {
			s += " via CDN"
		}
		if l.Backup {
			s += " backup"
		}
		out = append(out, s)
	}
	return out
}

// ---------- helpers ----------

func ParsePorts(s string) ([]int, error) {
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

func RandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randInt(lo, hi int) int {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	return lo + int(v.Int64())
}

// ParseRotate turns "20-60" (minutes) into seconds; "0" disables rotation.
func ParseRotate(s string) (int, int, error) {
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

// PortFree reports whether a TCP port can be bound on this machine.
func PortFree(p int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// UDPFree reports whether a UDP port can be bound on this machine.
func UDPFree(p int) bool {
	c, err := net.ListenPacket("udp", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// KindPortFree checks the port in the protocol the transport binds.
func KindPortFree(kind string, p int) bool {
	if kind == transport.KCP {
		return UDPFree(p)
	}
	return PortFree(p)
}

// ParseFEC parses "10:3" (data:parity shards); "0" or "" disables FEC.
func ParseFEC(s string) (int, int, error) {
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

func FreeRandomPort() int {
	for i := 0; i < 50; i++ {
		p := randInt(20000, 60000)
		if PortFree(p) {
			return p
		}
	}
	return randInt(20000, 60000)
}

// FirstFree returns the first candidate TCP port that is free (or a random one).
func FirstFree(cands ...int) int {
	for _, p := range cands {
		if PortFree(p) {
			return p
		}
	}
	return FreeRandomPort()
}

// FirstFreeUDP is FirstFree for UDP ports.
func FirstFreeUDP(cands ...int) int {
	for _, p := range cands {
		if UDPFree(p) {
			return p
		}
	}
	return FreeRandomPort()
}

// OutboundIP guesses this server's public-facing address (no packet is sent).
func OutboundIP() string {
	c, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func NewPanel(https bool) *node.PanelConf {
	return &node.PanelConf{
		Listen: ":" + strconv.Itoa(FreeRandomPort()),
		Path:   "/" + RandHex(6),
		User:   "admin",
		Pass:   RandHex(8),
		TLS:    https,
	}
}

// PanelURL is the address to open the panel at; host "" guesses this
// server's IP.
func PanelURL(p *node.PanelConf, host string) string {
	if host == "" {
		if host = OutboundIP(); host == "" {
			host = "SERVER_IP"
		}
	}
	h, port, _ := net.SplitHostPort(p.Listen)
	if h != "" && h != "0.0.0.0" && h != "::" {
		host = h
	}
	scheme := "http"
	if p.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s/", scheme, net.JoinHostPort(host, port), p.Path)
}

func SplitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// ParseForwards parses "443=2096, 8443, 9000=10.0.0.2:80". A bare port on
// the left listens on all addresses; on the right it means 127.0.0.1:PORT
// on kharej.
func ParseForwards(s, proto string) []node.ForwardConf {
	var out []node.ForwardConf
	for _, item := range SplitList(s) {
		l, r, ok := strings.Cut(item, "=")
		if !ok {
			l, r = item, item
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

// Forwards parses TCP and UDP forward lists, merging identical pairs into
// proto "both".
func Forwards(tcp, udp string) []node.ForwardConf {
	fwd := ParseForwards(tcp, "tcp")
	for _, u := range ParseForwards(udp, "udp") {
		merged := false
		for i := range fwd {
			if fwd[i].Listen == u.Listen && fwd[i].Target == u.Target {
				fwd[i].Proto = "both"
				merged = true
			}
		}
		if !merged {
			fwd = append(fwd, u)
		}
	}
	return fwd
}

// FormatForwards is the inverse of Forwards: it returns the TCP and UDP
// lists in the short "443=2096" form where possible.
func FormatForwards(fs []node.ForwardConf) (tcp, udp string) {
	short := func(f node.ForwardConf) string {
		l := strings.TrimPrefix(f.Listen, ":")
		r := strings.TrimPrefix(f.Target, "127.0.0.1:")
		if l == r {
			return l
		}
		return l + "=" + r
	}
	var t, u []string
	for _, f := range fs {
		if f.Proto != "udp" {
			t = append(t, short(f))
		}
		if f.Proto == "udp" || f.Proto == "both" {
			u = append(u, short(f))
		}
	}
	return strings.Join(t, ","), strings.Join(u, ",")
}

// Ports lists the ports a config binds on this machine, so re-running setup
// over it does not report them as taken.
func Ports(cfg *node.Config) map[int]bool {
	out := map[int]bool{}
	add := func(addr string) {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				out[n] = true
			}
		}
	}
	if cfg == nil {
		return out
	}
	for _, l := range cfg.Listen {
		add(l.Addr)
	}
	for _, f := range cfg.Forward {
		add(f.Listen)
	}
	for _, s := range cfg.Socks {
		add(s.Listen)
	}
	return out
}

// Note is a hint shown after setup, in English and Persian.
type Note struct {
	En string `json:"en"`
	Fa string `json:"fa"`
}

// Result is a generated config plus what the user should know about it.
type Result struct {
	Config *node.Config `json:"-"`
	Token  string       `json:"token,omitempty"`
	Notes  []Note       `json:"notes"`
}

func (r *Result) note(en, fa string) { r.Notes = append(r.Notes, Note{en, fa}) }

// ---------- kharej ----------

// KharejOptions mirrors the "mirage setup kharej" flags. Port lists are
// comma separated; empty disables the transport.
type KharejOptions struct {
	IP      string // public IP/domain of this server (direct mode; detected if empty)
	Reverse string // iran server IP: kharej connects to iran

	TLS, TCP, KCP, FTCP, WS, WSS string

	KCPMode, FEC, KCPCrypt string
	Backup                 []string // transports used only when the others fail
	SNI, Path              string

	CDN           string // CDN domain proxied by Cloudflare (backup link)
	CDNOriginPort int    // 0 = auto: ws on 80 (Flexible SSL) and wss on 443 (Full SSL)
	CDNOriginTLS  bool   // with an explicit port: the CDN talks TLS to the origin

	Conns       int
	AllowLocal  []string
	Fallback    string
	Rotate      string
	Profile     string
	Refresh     int
	Fingerprint string
	Cipher      string

	Panel  *node.PanelConf
	Status string
	Dir    string // directory for generated certificates

	CheckPorts bool
	Skip       map[int]bool // ports already owned by the config being replaced
}

// KharejDefaults are the settings the wizards start from.
func KharejDefaults() KharejOptions {
	return KharejOptions{
		TLS: "443", KCPMode: "fast2", FEC: "10:3", KCPCrypt: "aes", SNI: "www.bing.com",
		Conns: 2, Rotate: "20-60", Profile: "balanced", Fingerprint: "chrome", Cipher: "auto",
		Status: "127.0.0.1:7788", CheckPorts: true,
	}
}

func (o *KharejOptions) free(kind string, p int) bool {
	return !o.CheckPorts || o.Skip[p] || KindPortFree(kind, p)
}

// Kharej builds the kharej config and the pairing token for the iran side.
func Kharej(o KharejOptions) (*Result, error) {
	res := &Result{}
	direct := o.Reverse == ""
	if direct && o.IP == "" {
		if o.IP = OutboundIP(); o.IP == "" {
			return nil, errors.New("could not detect this server's IP; enter it")
		}
		res.note("detected server IP: "+o.IP, "IP سرور شناسایی شد: "+o.IP)
	}
	if o.Conns == 0 {
		o.Conns = 2
	}
	if o.Conns < 1 || o.Conns > 64 {
		return nil, errors.New("connections per link must be 1..64")
	}
	switch o.Profile {
	case "":
		o.Profile = "balanced"
	case "speed", "balanced", "stealth":
	default:
		return nil, errors.New("profile must be speed, balanced or stealth")
	}
	if o.Fingerprint == "" {
		o.Fingerprint = "chrome"
	}
	if !transport.ValidFingerprint(o.Fingerprint) {
		return nil, fmt.Errorf("fingerprint must be one of %v", transport.Fingerprints)
	}
	if o.Cipher == "" {
		o.Cipher = secure.CipherAuto
	}
	if !secure.ValidCipher(o.Cipher) {
		return nil, errors.New("cipher must be aes-256-gcm, chacha20-poly1305 or auto")
	}
	if o.Refresh < 0 || o.Refresh > 720 {
		return nil, errors.New("refresh must be 0..720 hours")
	}
	if o.Rotate == "" {
		o.Rotate = "20-60"
	}
	rmin, rmax, err := ParseRotate(o.Rotate)
	if err != nil {
		return nil, err
	}
	fd, fp, err := ParseFEC(o.FEC)
	if err != nil {
		return nil, err
	}
	kcpOpt := transport.KCPOptions{Mode: o.KCPMode, Data: fd, Parity: fp, Crypt: o.KCPCrypt}
	if err := kcpOpt.Validate(); err != nil {
		return nil, err
	}
	if o.SNI == "" {
		o.SNI = "www.bing.com"
	}
	if o.Path == "" {
		o.Path = "/api/" + RandHex(6)
	}
	if !strings.HasPrefix(o.Path, "/") {
		o.Path = "/" + o.Path
	}
	isBackup := map[string]bool{}
	for _, b := range o.Backup {
		isBackup[b] = true
	}
	psk, err := secure.NewPSK()
	if err != nil {
		return nil, err
	}
	cfg := &node.Config{
		Role: node.RoleKharej, Key: hex.EncodeToString(psk[:]), Profile: o.Profile,
		RotateMin: rmin, RotateMax: rmax, Status: o.Status, AllowLocal: o.AllowLocal,
		Panel: o.Panel, RefreshHours: o.Refresh, Cipher: o.Cipher, Fingerprint: o.Fingerprint,
	}
	tk := Token{V: 1, Key: cfg.Key, Rotate: [2]int{rmin, rmax}, Profile: o.Profile, Refresh: o.Refresh, Cipher: o.Cipher, FP: o.Fingerprint}

	kinds := []struct{ kind, ports string }{
		{"tls", o.TLS}, {"tcp", o.TCP}, {"kcp", o.KCP}, {"ftcp", o.FTCP}, {"ws", o.WS}, {"wss", o.WSS},
	}
	usedPorts := map[int]string{}
	for _, k := range kinds {
		ports, err := ParsePorts(k.ports)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.kind, err)
		}
		if len(ports) == 0 {
			continue
		}
		for _, p := range ports {
			if other, dup := usedPorts[p]; dup {
				return nil, fmt.Errorf("port %d used by both %s and %s", p, other, k.kind)
			}
			usedPorts[p] = k.kind
			if direct && !o.free(k.kind, p) {
				return nil, fmt.Errorf("%s port %d is already in use on this server (X-UI?); choose another, e.g. %d", k.kind, p, p+1)
			}
		}
		tl := Link{Name: k.kind, T: k.kind, Conns: o.Conns, Backup: isBackup[k.kind]}
		var ko *transport.KCPOptions
		if transport.IsPacket(k.kind) {
			x := kcpOpt
			ko, tl.KCP = &x, &x
		}
		if k.kind == "tls" || k.kind == "wss" {
			tl.SNI = o.SNI
		}
		if k.kind == "ws" || k.kind == "wss" {
			tl.Path = o.Path
			tl.Host = o.SNI
		}
		if direct {
			tl.Mode = "d"
			for _, p := range ports {
				tl.Addrs = append(tl.Addrs, net.JoinHostPort(o.IP, strconv.Itoa(p)))
				lc := node.ListenConf{
					Name: fmt.Sprintf("%s-%d", k.kind, p), Transport: k.kind,
					Addr: ":" + strconv.Itoa(p), SNI: o.SNI, Path: o.Path, Fallback: o.Fallback, KCP: ko,
				}
				if k.kind == "tls" || k.kind == "wss" {
					lc.Cert = filepath.Join(o.Dir, "cert.pem")
					lc.CertKey = filepath.Join(o.Dir, "key.pem")
				}
				cfg.Listen = append(cfg.Listen, lc)
			}
		} else {
			tl.Mode = "r"
			dc := node.DialConf{Name: k.kind, Transport: k.kind, SNI: tl.SNI, Host: tl.Host, Path: tl.Path,
				Conns: o.Conns, Backup: tl.Backup, KCP: ko}
			for _, p := range ports {
				tl.Addrs = append(tl.Addrs, ":"+strconv.Itoa(p))
				dc.Addrs = append(dc.Addrs, net.JoinHostPort(o.Reverse, strconv.Itoa(p)))
			}
			cfg.Dial = append(cfg.Dial, dc)
		}
		tk.Links = append(tk.Links, tl)
	}
	if o.CDN != "" {
		if err := o.addCDN(cfg, &tk, res, usedPorts, direct); err != nil {
			return nil, err
		}
	}
	if len(tk.Links) == 0 {
		return nil, errors.New("no transport enabled; enable at least one of tls, tcp, kcp, ftcp, ws, wss or a CDN domain")
	}
	allBackup := true
	for _, l := range tk.Links {
		if !l.Backup {
			allBackup = false
		}
	}
	if allBackup {
		return nil, errors.New("every link is marked backup; leave at least one primary")
	}
	if res.Token, err = EncodeToken(tk); err != nil {
		return nil, err
	}
	cfg.Token = res.Token
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("generated config is invalid: %w", err)
	}
	res.Config = cfg
	if !direct {
		res.note("reverse mode: this server connects to the iran server at "+o.Reverse,
			"حالت معکوس: این سرور به سرور ایران ("+o.Reverse+") وصل می‌شود")
	}
	if o.KCP != "" {
		res.note("kcp uses UDP: open UDP port(s) "+o.KCP+" in the firewall",
			"KCP روی UDP کار می‌کند: پورت UDP "+o.KCP+" را در فایروال باز کنید")
	}
	if o.FTCP != "" {
		res.note("ftcp needs linux, root and iptables on BOTH servers",
			"ftcp روی هر دو سرور به لینوکس، دسترسی root و iptables نیاز دارد")
	}
	if len(cfg.AllowLocal) == 0 {
		res.note("no allowed local ports yet: forwards to services on this server (e.g. an X-UI inbound) are blocked until you add them",
			"هنوز پورت مجازی تعریف نشده؛ تا پورت اینباند X-UI را اضافه نکنید، فوروارد به این سرور بسته است")
	}
	return res, nil
}

// CFHTTPSPorts are the HTTPS ports Cloudflare proxies. In Full SSL mode it
// reaches the origin on the same port the client connected to, so a busy
// 443 on the origin can be avoided without an Origin Rule.
var CFHTTPSPorts = []int{443, 2053, 2083, 2087, 2096, 8443}

// addCDN adds the backup link through Cloudflare. The server the domain
// points at (kharej in direct mode, iran in reverse) listens on the origin
// port; the other side dials wss to the CDN on 443.
func (o *KharejOptions) addCDN(cfg *node.Config, tk *Token, res *Result, usedPorts map[int]string, direct bool) error {
	type origin struct {
		port int
		kind string
	}
	var origins []origin
	auto := o.CDNOriginPort == 0
	if auto {
		origins = []origin{{80, "ws"}, {443, "wss"}}
	} else {
		kind := "ws"
		if o.CDNOriginTLS {
			kind = "wss"
		}
		origins = []origin{{o.CDNOriginPort, kind}}
	}
	// the dialing side connects to Cloudflare on 443, or on the origin's
	// own port for Full SSL on one of Cloudflare's other HTTPS ports
	dialPort := "443"
	full := !auto && o.CDNOriginTLS && slices.Contains(CFHTTPSPorts, o.CDNOriginPort)
	if full {
		dialPort = strconv.Itoa(o.CDNOriginPort)
	}
	if !direct {
		if !auto {
			if other, dup := usedPorts[o.CDNOriginPort]; dup {
				return fmt.Errorf("cdn origin port %d is already used by the %s link on the iran server", o.CDNOriginPort, other)
			}
		}
		cfg.Dial = append(cfg.Dial, node.DialConf{Name: "cdn", Transport: "wss",
			Addrs: []string{net.JoinHostPort(o.CDN, dialPort)}, SNI: o.CDN, Host: o.CDN, Path: o.Path,
			Conns: o.Conns, Backup: true, CDN: o.CDN})
		for _, x := range origins {
			tk.Links = append(tk.Links, Link{Name: "cdn", T: x.kind, Mode: "r", Addrs: []string{":" + strconv.Itoa(x.port)},
				SNI: o.CDN, Path: o.Path, Backup: true, CDN: true, Opt: auto})
		}
		res.note("in Cloudflare point "+o.CDN+" (orange cloud) at the IRAN server's IP",
			"در Cloudflare دامنهٔ "+o.CDN+" را (ابر نارنجی) به IP سرور ایران وصل کنید")
		o.sslNote(res, auto, full)
		return nil
	}
	var ok []origin
	for _, x := range origins {
		if other, dup := usedPorts[x.port]; dup {
			if other == x.kind {
				ok = append(ok, x) // an existing ws/wss listener serves the CDN too
				continue
			}
			if auto {
				continue
			}
			return fmt.Errorf("cdn origin port %d is already used by %s", x.port, other)
		}
		if !o.free(x.kind, x.port) {
			if auto {
				continue
			}
			return fmt.Errorf("cdn origin port %d is already in use on this server", x.port)
		}
		usedPorts[x.port] = x.kind
		lc := node.ListenConf{Name: fmt.Sprintf("cdn-%d", x.port), Transport: x.kind,
			Addr: ":" + strconv.Itoa(x.port), SNI: o.CDN, Path: o.Path, Fallback: o.Fallback, Backup: true}
		if x.kind == "wss" {
			lc.Cert = filepath.Join(o.Dir, "cdn-cert.pem")
			lc.CertKey = filepath.Join(o.Dir, "cdn-key.pem")
		}
		cfg.Listen = append(cfg.Listen, lc)
		ok = append(ok, x)
	}
	if len(ok) == 0 {
		return errors.New("ports 80 and 443 are both busy, so Cloudflare cannot reach this server; free one or set a CDN origin port with an Origin Rule")
	}
	tk.Links = append(tk.Links, Link{
		Name: "cdn", T: "wss", Mode: "d", Addrs: []string{net.JoinHostPort(o.CDN, dialPort)},
		SNI: o.CDN, Host: o.CDN, Path: o.Path, Conns: o.Conns, Backup: true, CDN: true,
	})
	res.note("in Cloudflare point "+o.CDN+" (orange cloud) at THIS server's IP",
		"در Cloudflare دامنهٔ "+o.CDN+" را (ابر نارنجی) به IP همین سرور (خارج) وصل کنید")
	var modes, modesFa []string
	for _, x := range ok {
		switch {
		case x.port == 80 && x.kind == "ws":
			modes, modesFa = append(modes, "Flexible"), append(modesFa, "Flexible")
		case x.kind == "wss" && slices.Contains(CFHTTPSPorts, x.port):
			modes, modesFa = append(modes, "Full"), append(modesFa, "Full")
		default:
			res.note(fmt.Sprintf("origin port is %d: add Rules > Origin Rules > Destination port = %d for this hostname", x.port, x.port),
				fmt.Sprintf("پورت مبدأ %d است: در Cloudflare از Rules > Origin Rules مقدار Destination port را %d بگذارید", x.port, x.port))
		}
	}
	if len(modes) > 0 {
		res.note("works with Cloudflare SSL/TLS mode: "+strings.Join(modes, " or ")+" (not Full strict)",
			"با حالت SSL/TLS کلودفلر "+strings.Join(modesFa, " یا ")+" کار می‌کند (نه Full strict)")
	}
	return nil
}

// ---------- iran ----------

// IranOptions mirrors the "mirage setup iran" flags.
type IranOptions struct {
	Token      string
	Forward    string // LOCAL=TARGET, comma separated
	ForwardUDP string
	Socks      string // listen address or bare port (127.0.0.1)
	SocksUser  string
	SocksPass  string
	Conns      int    // override per-link minimum connections
	Profile    string // override the token's profile

	Panel  *node.PanelConf
	Status string
	Dir    string

	CheckPorts bool
	Skip       map[int]bool
}

// Iran builds the iran config from a pairing token.
func Iran(o IranOptions) (*Result, error) {
	res := &Result{}
	if o.Token == "" {
		return nil, errors.New("the pairing token is required")
	}
	t, err := DecodeToken(o.Token)
	if err != nil {
		return nil, err
	}
	prof := t.Profile
	if o.Profile != "" {
		prof = o.Profile
	}
	free := func(kind string, p int) bool { return !o.CheckPorts || o.Skip[p] || KindPortFree(kind, p) }
	cfg := &node.Config{Role: node.RoleIran, Key: t.Key, Status: o.Status, Profile: prof,
		RotateMin: t.Rotate[0], RotateMax: t.Rotate[1], Panel: o.Panel, RefreshHours: t.Refresh, Cipher: t.Cipher, Fingerprint: t.FP}
	var listenPorts []string
	optCDN, optCDNUp := 0, 0
	for _, l := range t.Links {
		c := l.Conns
		if o.Conns > 0 {
			c = o.Conns
		}
		switch l.Mode {
		case "d":
			dc := node.DialConf{Name: l.Name, Transport: l.T, Addrs: l.Addrs,
				SNI: l.SNI, Host: l.Host, Path: l.Path, Conns: c, Backup: l.Backup, KCP: l.KCP}
			if l.CDN {
				dc.CDN = l.Host
			}
			cfg.Dial = append(cfg.Dial, dc)
		case "r":
			for _, a := range l.Addrs {
				_, port, _ := net.SplitHostPort(a)
				n, _ := strconv.Atoi(port)
				if l.Opt {
					optCDN++
					if !free(l.T, n) {
						continue
					}
					optCDNUp++
				} else if n > 0 && !free(l.T, n) {
					return nil, fmt.Errorf("port %d (%s link) is already in use on this server", n, l.T)
				}
				listenPorts = append(listenPorts, l.T+":"+port)
				lc := node.ListenConf{Name: l.Name + "-" + port, Transport: l.T, Addr: a,
					SNI: l.SNI, Path: l.Path, Backup: l.Backup, KCP: l.KCP}
				if l.T == "tls" || l.T == "wss" {
					lc.Cert = filepath.Join(o.Dir, "cert.pem")
					lc.CertKey = filepath.Join(o.Dir, "key.pem")
				}
				if l.CDN {
					lc.Name = "cdn-" + port
				}
				cfg.Listen = append(cfg.Listen, lc)
			}
		default:
			return nil, fmt.Errorf("token link %q has unknown mode %q", l.Name, l.Mode)
		}
	}
	if optCDN > 0 && optCDNUp == 0 {
		res.note("ports 80 and 443 are both busy here, so the CDN backup link is off",
			"پورت‌های 80 و 443 این سرور اشغال است؛ لینک پشتیبان CDN خاموش ماند")
	}
	cfg.Forward = Forwards(o.Forward, o.ForwardUDP)
	if o.Socks != "" {
		s := o.Socks
		if _, err := strconv.Atoi(s); err == nil {
			s = "127.0.0.1:" + s
		}
		cfg.Socks = []node.SocksConf{{Listen: s, User: o.SocksUser, Pass: o.SocksPass}}
	}
	if len(cfg.Forward) == 0 && len(cfg.Socks) == 0 {
		return nil, errors.New("nothing to serve: add a port forward and/or a SOCKS5 port")
	}
	check := func(addr string) error {
		_, p, _ := net.SplitHostPort(addr)
		n, _ := strconv.Atoi(p)
		if n > 0 && !free("tcp", n) {
			return fmt.Errorf("port %d is already in use on this server", n)
		}
		return nil
	}
	for _, f := range cfg.Forward {
		if f.Proto != "udp" {
			if err := check(f.Listen); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range cfg.Socks {
		if err := check(s.Listen); err != nil {
			return nil, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("generated config is invalid: %w", err)
	}
	res.Config = cfg
	for _, l := range t.Links {
		if l.CDN && l.Mode == "r" {
			res.note("in Cloudflare point "+l.SNI+" (orange cloud) at THIS server's IP",
				"در Cloudflare دامنهٔ "+l.SNI+" را (ابر نارنجی) به IP همین سرور (ایران) وصل کنید")
			break
		}
	}
	if len(listenPorts) > 0 {
		res.note("reverse mode: kharej connects to this server on "+strings.Join(listenPorts, ", ")+"; open them in the firewall",
			"حالت معکوس: سرور خارج روی "+strings.Join(listenPorts, "، ")+" به این سرور وصل می‌شود؛ در فایروال باز کنید")
	}
	return res, nil
}

// sslNote says which Cloudflare SSL mode a reverse CDN link needs.
func (o *KharejOptions) sslNote(res *Result, auto, full bool) {
	switch {
	case auto:
		res.note("Cloudflare SSL/TLS mode: Flexible, or Full if port 443 is free on the iran server (not Full strict)",
			"حالت SSL/TLS کلودفلر: Flexible، یا Full اگر پورت 443 سرور ایران آزاد باشد (نه Full strict)")
	case full:
		res.note(fmt.Sprintf("Cloudflare SSL/TLS mode: Full (not strict); open port %d on the iran server", o.CDNOriginPort),
			fmt.Sprintf("حالت SSL/TLS کلودفلر: Full (نه strict)؛ پورت %d را روی سرور ایران باز کنید", o.CDNOriginPort))
	case o.CDNOriginPort == 80 && !o.CDNOriginTLS:
		res.note("Cloudflare SSL/TLS mode: Flexible", "حالت SSL/TLS کلودفلر: Flexible")
	default:
		res.note(fmt.Sprintf("origin port is %d: add Rules > Origin Rules > Destination port = %d for this hostname", o.CDNOriginPort, o.CDNOriginPort),
			fmt.Sprintf("پورت مبدأ %d است: در Cloudflare از Rules > Origin Rules مقدار Destination port را %d بگذارید", o.CDNOriginPort, o.CDNOriginPort))
	}
}
