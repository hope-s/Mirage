package node

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"mirage/internal/secure"
	"mirage/internal/transport"
)

// Roles.
const (
	RoleIran   = "iran"
	RoleKharej = "kharej"
)

// Config is the on-disk configuration of one node.
type Config struct {
	Role string `json:"role"`
	Key  string `json:"key"` // 64 hex chars

	// Profile trades speed against stealth: "speed", "balanced" (default)
	// or "stealth". See profileFor.
	Profile string `json:"profile,omitempty"`
	// Cipher is the session cipher this node asks for when it dials:
	// aes-256-gcm (default), chacha20-poly1305, or auto.
	Cipher string `json:"cipher,omitempty"`
	// Fingerprint is the TLS ClientHello tls/wss links present when this
	// node dials: chrome (default), firefox, safari, edge, ios, random, go.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Listen accepts tunnel connections from the other node.
	Listen []ListenConf `json:"listen,omitempty"`
	// Dial opens tunnel connections to the other node.
	Dial []DialConf `json:"dial,omitempty"`

	// Iran only: user-facing entry points.
	Forward []ForwardConf `json:"forward,omitempty"`
	Socks   []SocksConf   `json:"socks,omitempty"`

	// Kharej only: loopback/private destinations that may be reached
	// through the tunnel ("2096" means 127.0.0.1:2096).
	AllowLocal []string `json:"allow_local,omitempty"`

	// Seconds; a dialed connection is replaced after a random lifetime in
	// [RotateMin, RotateMax]. 0 disables rotation.
	RotateMin int `json:"rotate_min,omitempty"`
	RotateMax int `json:"rotate_max,omitempty"`

	// RefreshHours rebuilds the whole tunnel core every N hours (0 = off),
	// for routes that slowly degrade until reconnected.
	RefreshHours int `json:"refresh_hours,omitempty"`
	// WindowMB caps each stream's receive window ("channel size"); 0
	// uses the profile's value. KeepaliveS overrides the ping interval.
	WindowMB   int `json:"window_mb,omitempty"`
	KeepaliveS int `json:"keepalive_s,omitempty"`

	Status string `json:"status,omitempty"` // 127.0.0.1:7788
	Debug  bool   `json:"debug,omitempty"`

	Panel *PanelConf `json:"panel,omitempty"`

	// Token is the pairing token (kharej only, informational).
	Token string `json:"token,omitempty"`
}

// ListenConf is a tunnel listener.
type ListenConf struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Addr      string `json:"addr"`
	SNI       string `json:"sni,omitempty"`
	Cert      string `json:"cert,omitempty"`
	CertKey   string `json:"cert_key,omitempty"`
	Path      string `json:"path,omitempty"`
	Fallback  string `json:"fallback,omitempty"`
	Backup    bool   `json:"backup,omitempty"`
	// KCP tunes kcp/ftcp links.
	KCP *transport.KCPOptions `json:"kcp,omitempty"`
}

// DialConf is an outgoing tunnel link.
type DialConf struct {
	Name      string   `json:"name"`
	Transport string   `json:"transport"`
	Addrs     []string `json:"addrs"`
	SNI       string   `json:"sni,omitempty"`
	Host      string   `json:"host,omitempty"`
	Path      string   `json:"path,omitempty"`
	Conns     int      `json:"conns,omitempty"`     // minimum parallel connections (default 2)
	MaxConns  int      `json:"max_conns,omitempty"` // autoscale ceiling (default 3x conns, max 16)
	Backup    bool     `json:"backup,omitempty"`
	Disabled  bool     `json:"disabled,omitempty"`
	// KCP tunes kcp/ftcp links.
	KCP *transport.KCPOptions `json:"kcp,omitempty"`
	// CDN is the domain when this link goes through a CDN (ws/wss);
	// Addrs then hold edge IPs that a scan may replace.
	CDN        string `json:"cdn,omitempty"`
	NoAutoScan bool   `json:"no_autoscan,omitempty"`
}

func kcpOpts(k *transport.KCPOptions) transport.KCPOptions {
	if k == nil {
		return transport.KCPOptions{}
	}
	return *k
}

// PanelConf configures the web management panel.
type PanelConf struct {
	Listen string `json:"listen"`         // :24680
	Path   string `json:"path"`           // secret base path, e.g. /a1b2c3
	User   string `json:"user"`           // login user
	Pass   string `json:"pass"`           // login password
	TLS    bool   `json:"tls,omitempty"`  // serve HTTPS with a self-signed cert
	Cert   string `json:"cert,omitempty"` // optional cert/key files for HTTPS
	Key    string `json:"key,omitempty"`
}

// ForwardConf forwards a local port to a destination reached from kharej.
type ForwardConf struct {
	Proto  string `json:"proto"` // tcp | udp | both
	Listen string `json:"listen"`
	Target string `json:"target"`
}

// SocksConf is a SOCKS5 entry point (CONNECT + UDP ASSOCIATE).
type SocksConf struct {
	Listen string `json:"listen"`
	User   string `json:"user,omitempty"`
	Pass   string `json:"pass,omitempty"`
}

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Save writes the config with restrictive permissions.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// PSK decodes the key.
func (c *Config) PSK() (secure.PSK, error) {
	var k secure.PSK
	b, err := hex.DecodeString(c.Key)
	if err != nil || len(b) != len(k) {
		return k, errors.New("key must be 64 hex characters")
	}
	copy(k[:], b)
	return k, nil
}

func checkHostPort(s string, needHost bool) error {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if needHost && h == "" {
		return fmt.Errorf("%q: missing host", s)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q: bad port", s)
	}
	return nil
}

// Validate checks the config for mistakes.
func (c *Config) Validate() error {
	if c.Role != RoleIran && c.Role != RoleKharej {
		return fmt.Errorf("role must be %q or %q", RoleIran, RoleKharej)
	}
	if _, err := c.PSK(); err != nil {
		return err
	}
	if len(c.Listen) == 0 && len(c.Dial) == 0 {
		return errors.New("need at least one listen or dial entry")
	}
	names := map[string]bool{}
	for i, l := range c.Listen {
		if l.Name == "" {
			return fmt.Errorf("listen[%d]: name required", i)
		}
		if names[l.Name] {
			return fmt.Errorf("duplicate link name %q", l.Name)
		}
		names[l.Name] = true
		if !transport.Valid(l.Transport) {
			return fmt.Errorf("listen %q: unknown transport %q", l.Name, l.Transport)
		}
		if err := checkHostPort(l.Addr, false); err != nil {
			return fmt.Errorf("listen %q: %w", l.Name, err)
		}
		if l.Fallback != "" {
			if err := checkHostPort(l.Fallback, true); err != nil {
				return fmt.Errorf("listen %q fallback: %w", l.Name, err)
			}
		}
		if (l.Transport == transport.WS || l.Transport == transport.WSS) && l.Path != "" && !strings.HasPrefix(l.Path, "/") {
			return fmt.Errorf("listen %q: path must start with /", l.Name)
		}
		if err := kcpOpts(l.KCP).Validate(); err != nil {
			return fmt.Errorf("listen %q: %w", l.Name, err)
		}
	}
	for i, d := range c.Dial {
		if d.Name == "" {
			return fmt.Errorf("dial[%d]: name required", i)
		}
		if names[d.Name] {
			return fmt.Errorf("duplicate link name %q", d.Name)
		}
		names[d.Name] = true
		if !transport.Valid(d.Transport) {
			return fmt.Errorf("dial %q: unknown transport %q", d.Name, d.Transport)
		}
		if len(d.Addrs) == 0 {
			return fmt.Errorf("dial %q: addrs required", d.Name)
		}
		for _, a := range d.Addrs {
			if err := checkHostPort(a, true); err != nil {
				return fmt.Errorf("dial %q: %w", d.Name, err)
			}
		}
		if d.Conns < 0 || d.Conns > 64 {
			return fmt.Errorf("dial %q: conns must be 1..64", d.Name)
		}
		if d.MaxConns < 0 || d.MaxConns > 64 || (d.MaxConns > 0 && d.MaxConns < d.Conns) {
			return fmt.Errorf("dial %q: max_conns must be 0 or between conns and 64", d.Name)
		}
		if (d.Transport == transport.WS || d.Transport == transport.WSS) && d.Path != "" && !strings.HasPrefix(d.Path, "/") {
			return fmt.Errorf("dial %q: path must start with /", d.Name)
		}
		if err := kcpOpts(d.KCP).Validate(); err != nil {
			return fmt.Errorf("dial %q: %w", d.Name, err)
		}
		if d.CDN != "" && d.Transport != transport.WS && d.Transport != transport.WSS {
			return fmt.Errorf("dial %q: cdn links must use ws or wss", d.Name)
		}
	}
	if c.Role == RoleKharej && (len(c.Forward) > 0 || len(c.Socks) > 0) {
		return errors.New("forward/socks are only valid on the iran node")
	}
	if c.Role == RoleIran && len(c.AllowLocal) > 0 {
		return errors.New("allow_local is only valid on the kharej node")
	}
	for i, f := range c.Forward {
		switch f.Proto {
		case "tcp", "udp", "both":
		default:
			return fmt.Errorf("forward[%d]: proto must be tcp, udp or both", i)
		}
		if err := checkHostPort(f.Listen, false); err != nil {
			return fmt.Errorf("forward[%d] listen: %w", i, err)
		}
		if err := checkHostPort(f.Target, true); err != nil {
			return fmt.Errorf("forward[%d] target: %w", i, err)
		}
	}
	for i, s := range c.Socks {
		if err := checkHostPort(s.Listen, false); err != nil {
			return fmt.Errorf("socks[%d]: %w", i, err)
		}
		if (s.User == "") != (s.Pass == "") {
			return fmt.Errorf("socks[%d]: set both user and pass, or neither", i)
		}
		if len(s.User) > 255 || len(s.Pass) > 255 {
			return fmt.Errorf("socks[%d]: user/pass too long", i)
		}
	}
	if _, err := ParseAllowLocal(c.AllowLocal); err != nil {
		return err
	}
	if c.RotateMin < 0 || c.RotateMax < c.RotateMin {
		return errors.New("need 0 <= rotate_min <= rotate_max")
	}
	if c.RotateMin > 0 && c.RotateMin < minRotate {
		return errors.New("rotate_min must be at least 60 seconds")
	}
	if !secure.ValidCipher(c.Cipher) {
		return errors.New("cipher must be aes-256-gcm, chacha20-poly1305 or auto")
	}
	if !transport.ValidFingerprint(c.Fingerprint) {
		return fmt.Errorf("fingerprint must be one of %v", transport.Fingerprints)
	}
	if c.RefreshHours < 0 || c.RefreshHours > 24*30 {
		return errors.New("refresh_hours must be 0..720")
	}
	if c.WindowMB < 0 || c.WindowMB > 64 {
		return errors.New("window_mb must be 0..64")
	}
	if c.KeepaliveS < 0 || c.KeepaliveS > 60 {
		return errors.New("keepalive_s must be 0..60")
	}
	switch c.Profile {
	case "", "speed", "balanced", "stealth":
	default:
		return fmt.Errorf("profile must be speed, balanced or stealth")
	}
	if c.Panel != nil {
		p := c.Panel
		if err := checkHostPort(p.Listen, false); err != nil {
			return fmt.Errorf("panel listen: %w", err)
		}
		if !strings.HasPrefix(p.Path, "/") || strings.HasSuffix(p.Path, "/") && p.Path != "/" {
			return errors.New("panel path must start with / and not end with /")
		}
		if len(p.User) == 0 || len(p.Pass) < 8 {
			return errors.New("panel needs a user and a password of at least 8 characters")
		}
	}
	if c.Status != "" {
		if err := checkHostPort(c.Status, false); err != nil {
			return fmt.Errorf("status: %w", err)
		}
		h, _, _ := net.SplitHostPort(c.Status)
		if ip := net.ParseIP(h); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("status must listen on 127.0.0.1 (it has no password); use the panel for remote access")
		}
	}
	return nil
}

// minRotate is the smallest allowed rotation lifetime in seconds (tests lower it).
var minRotate = 60
