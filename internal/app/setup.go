package app

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"mirage/internal/node"
	"mirage/internal/setup"
)

// PutTunnel saves cfg as tunnel name and (re)starts it. The main tunnel
// keeps its panel and status settings; a new extra tunnel is created.
func (a *App) PutTunnel(name string, cfg *node.Config) error {
	if name == MainTunnel {
		_, cur := a.Node()
		if cur != nil {
			cfg.Panel, cfg.Status = cur.Panel, cur.Status
		}
		return a.SaveTunnel(MainTunnel, cfg)
	}
	if !ValidTunnelName(name) {
		return errors.New(`tunnel names use a-z, 0-9 and - (and cannot be "main")`)
	}
	cfg.Panel, cfg.Status = nil, ""
	if a.get(name) != nil {
		return a.SaveTunnel(name, cfg)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	t := &tunnel{name: name, path: filepath.Join(a.dir, name+".json")}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	if err := a.apply(t, cfg); err != nil {
		return err
	}
	if err := cfg.Save(t.path); err != nil {
		t.node.Close()
		return fmt.Errorf("saving config: %w", err)
	}
	a.mu.Lock()
	a.tunnels = append(a.tunnels, t)
	a.mu.Unlock()
	log.Printf("tunnel %s: created (%s)", name, cfg.Role)
	return nil
}

// RemoveTunnel stops an extra tunnel and deletes its file.
func (a *App) RemoveTunnel(name string) error {
	if name == MainTunnel {
		return errors.New("the main tunnel cannot be removed from the panel")
	}
	t := a.get(name)
	if t == nil {
		return fmt.Errorf("no tunnel named %q", name)
	}
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	if err := os.Remove(t.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	a.syncExtra()
	return nil
}

// SetupDefaults suggests values for a new tunnel on this server.
type SetupDefaults struct {
	IP    string   `json:"ip"`
	TLS   string   `json:"tls"`
	TCP   string   `json:"tcp"`
	KCP   string   `json:"kcp"`
	FTCP  string   `json:"ftcp"`
	WS    string   `json:"ws"`
	Socks string   `json:"socks"`
	Names []string `json:"names"`
}

func (a *App) SetupDefaults() SetupDefaults {
	p := func(ports ...int) string { return strconv.Itoa(setup.FirstFree(ports...)) }
	return SetupDefaults{
		IP:  setup.OutboundIP(),
		TLS: p(443, 2053, 2083, 8443, 2087), TCP: p(8880, 2095, 9443),
		KCP: strconv.Itoa(setup.FirstFreeUDP(443, 8443, 2053)), FTCP: p(2087, 2096, 8443),
		WS: p(8080, 2052, 2082), Socks: p(40001, 40002, 40003), Names: a.TunnelNames(),
	}
}

// KharejRequest is the panel's kharej setup form.
type KharejRequest struct {
	Name    string
	Replace bool
	Reverse string // iran IP for reverse mode; empty = direct
	IP      string

	TLS, TCP, KCP, FTCP, WS string
	CDN                     string

	KCPMode, FEC string
	AllowLocal   string
	Profile      string
	Cipher       string
	Fingerprint  string
	Refresh      int
}

// IranRequest is the panel's iran setup form.
type IranRequest struct {
	Name       string
	Replace    bool
	Token      string
	Forward    string
	ForwardUDP bool
	Socks      string
}

// replaceable returns the ports of tunnel name, refusing to overwrite it
// unless asked.
func (a *App) replaceable(name string, replace bool) (map[int]bool, error) {
	if name == "" {
		return nil, errors.New("enter a tunnel name")
	}
	_, cur, _ := a.Tunnel(name)
	if cur == nil {
		return nil, nil
	}
	if !replace {
		return nil, fmt.Errorf("tunnel %q exists; confirm to replace it", name)
	}
	return setup.Ports(cur), nil
}

func (a *App) SetupKharej(r KharejRequest) (*setup.Result, error) {
	skip, err := a.replaceable(r.Name, r.Replace)
	if err != nil {
		return nil, err
	}
	o := setup.KharejDefaults()
	o.IP, o.Reverse = r.IP, r.Reverse
	o.TLS, o.TCP, o.KCP, o.FTCP, o.WS, o.CDN = r.TLS, r.TCP, r.KCP, r.FTCP, r.WS, r.CDN
	if r.WS != "" && (r.TLS != "" || r.TCP != "" || r.KCP != "" || r.FTCP != "") {
		o.Backup = []string{"ws"}
	}
	if r.KCPMode != "" {
		o.KCPMode = r.KCPMode
	}
	if r.FEC != "" {
		o.FEC = r.FEC
	}
	o.AllowLocal = setup.SplitList(r.AllowLocal)
	o.Profile, o.Cipher, o.Fingerprint, o.Refresh = r.Profile, r.Cipher, r.Fingerprint, r.Refresh
	o.Dir, o.Skip, o.Panel, o.Status = filepath.Dir(a.path), skip, nil, ""
	res, err := setup.Kharej(o)
	if err != nil {
		return nil, err
	}
	if err := a.PutTunnel(r.Name, res.Config); err != nil {
		return nil, err
	}
	return res, nil
}

func (a *App) SetupIran(r IranRequest) (*setup.Result, error) {
	skip, err := a.replaceable(r.Name, r.Replace)
	if err != nil {
		return nil, err
	}
	o := setup.IranOptions{Token: r.Token, Forward: r.Forward, Socks: r.Socks,
		Dir: filepath.Dir(a.path), CheckPorts: true, Skip: skip}
	if r.ForwardUDP {
		o.ForwardUDP = r.Forward
	}
	res, err := setup.Iran(o)
	if err != nil {
		return nil, err
	}
	if err := a.PutTunnel(r.Name, res.Config); err != nil {
		return nil, err
	}
	return res, nil
}
