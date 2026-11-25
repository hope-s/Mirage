package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"mirage/internal/node"
	"mirage/internal/setup"
)

func newPanel(enabled, https bool) *node.PanelConf {
	if !enabled {
		return nil
	}
	return setup.NewPanel(https)
}

func printPanel(cfg *node.Config, host string) {
	if cfg.Panel == nil {
		fmt.Println(sDim.Render("web panel: disabled"))
		return
	}
	p := cfg.Panel
	rows := [][2]string{
		{"address", setup.PanelURL(p, host)},
		{"user", p.User},
		{"password", p.Pass},
	}
	if p.TLS && p.Cert == "" {
		rows = append(rows, [2]string{"", "self-signed certificate: accept the browser warning once"})
	}
	fmt.Println(card("Web panel", kv(rows)))
}

func writeConfig(cfg *node.Config, path string, force bool) error {
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

// ---------- setup kharej ----------

func cmdSetupKharej(args []string) error {
	d := setup.KharejDefaults()
	fs := flag.NewFlagSet("setup kharej", flag.ExitOnError)
	ip := fs.String("ip", "", "public IP (or domain) of THIS kharej server (direct mode; auto-detected if empty)")
	reverse := fs.String("reverse", "", "reverse mode: IP of the IRAN server; kharej connects to iran (use when iran cannot reach kharej)")
	tcpPorts := fs.String("tcp", "", "raw TCP ports, comma separated (e.g. 8443,2087 = automatic port hopping)")
	tlsPorts := fs.String("tls", d.TLS, "TLS ports, comma separated (empty to disable)")
	wsPorts := fs.String("ws", "", "WebSocket ports (plain HTTP)")
	wssPorts := fs.String("wss", "", "WebSocket-over-TLS ports")
	kcpPorts := fs.String("kcp", "", "KCP over UDP ports: best on links with packet loss")
	ftcpPorts := fs.String("ftcp", "", "KCP over fake-TCP ports (linux + root on both servers): for links where UDP is blocked and TCP collapses under loss")
	kcpMode := fs.String("kcp-mode", d.KCPMode, "kcp/ftcp speed preset: normal | fast | fast2 | fast3 | turbo")
	fec := fs.String("fec", d.FEC, "kcp/ftcp forward error correction data:parity shards; 0 to disable")
	kcpCrypt := fs.String("kcp-crypt", d.KCPCrypt, "kcp/ftcp packet obfuscation: aes | aes-128 | salsa20 | none")
	backups := fs.String("backup", "", "transports used only when the others fail, e.g. ws,wss (cdn is always backup)")
	sni := fs.String("sni", d.SNI, "TLS server name shown on the wire")
	path := fs.String("path", "", "WebSocket path (default: random)")
	cdn := fs.String("cdn", "", "CDN domain (e.g. t.example.com proxied by Cloudflare) - adds a backup link through the CDN")
	cdnOrigin := fs.Int("cdn-origin-port", 0, "port the CDN reaches the origin on; 0 = auto (ws on 80 for Flexible SSL and wss on 443 for Full SSL)")
	cdnOriginTLS := fs.Bool("cdn-origin-tls", false, "with -cdn-origin-port: the CDN talks TLS to the origin (Cloudflare Full SSL)")
	conns := fs.Int("conns", d.Conns, "minimum parallel connections per link (scales up automatically)")
	allow := fs.String("allow-local", "", "local ports/addresses reachable through the tunnel, e.g. 2096,127.0.0.1:2097 (your X-UI inbound ports)")
	fallback := fs.String("fallback", "", "send probes to this real web server (host:port) instead of the built-in decoy")
	rotate := fs.String("rotate", d.Rotate, "replace connections after a random number of minutes in this range; 0 to disable")
	profile := fs.String("profile", d.Profile, "speed | balanced | stealth")
	refresh := fs.Int("refresh", 0, "rebuild the tunnel every N hours (0 = off); also applied on the iran side")
	fingerprint := fs.String("fingerprint", d.Fingerprint, "TLS fingerprint for tls/wss links: chrome | firefox | safari | edge | ios | random | go")
	cipherName := fs.String("cipher", d.Cipher, "session cipher: aes-256-gcm | chacha20-poly1305 | auto (chacha20 on CPUs without AES acceleration)")
	panel := fs.Bool("panel", true, "enable the web panel")
	panelHTTPS := fs.Bool("panel-https", false, "serve the panel over HTTPS (self-signed) instead of plain HTTP")
	status := fs.String("status", d.Status, "local status address (empty to disable)")
	out := fs.String("c", defaultConfig, "where to write the config")
	force := fs.Bool("force", false, "overwrite an existing config")
	noPortCheck := fs.Bool("no-port-check", false, "skip checking that ports are free")
	_ = fs.Parse(args)

	o := setup.KharejOptions{
		IP: *ip, Reverse: *reverse,
		TLS: *tlsPorts, TCP: *tcpPorts, KCP: *kcpPorts, FTCP: *ftcpPorts, WS: *wsPorts, WSS: *wssPorts,
		KCPMode: *kcpMode, FEC: *fec, KCPCrypt: *kcpCrypt, Backup: setup.SplitList(*backups),
		SNI: *sni, Path: *path, CDN: *cdn, CDNOriginPort: *cdnOrigin, CDNOriginTLS: *cdnOriginTLS,
		Conns: *conns, AllowLocal: setup.SplitList(*allow), Fallback: *fallback, Rotate: *rotate,
		Profile: *profile, Refresh: *refresh, Fingerprint: *fingerprint, Cipher: *cipherName,
		Panel: newPanel(*panel, *panelHTTPS), Status: *status, Dir: filepath.Dir(*out),
		CheckPorts: !*noPortCheck,
	}
	if *force {
		o.Skip = existingPorts(*out)
	}
	res, err := setup.Kharej(o)
	if err != nil {
		return err
	}
	if err := writeConfig(res.Config, *out, *force); err != nil {
		return err
	}
	printKharejResult(res, *out, o.IP)
	return nil
}

// existingPorts are the ports of the config about to be replaced; its
// running tunnel holds them, so they count as free.
func existingPorts(path string) map[int]bool {
	c, err := node.LoadConfig(path)
	if err != nil {
		return nil
	}
	return setup.Ports(c)
}

func printKharejResult(res *setup.Result, path, ip string) {
	fmt.Println()
	fmt.Println(sOK.Render("✓ kharej config written to " + path))
	fmt.Println()
	fmt.Println(tokenBox(res.Token))
	if res.Config.Panel != nil {
		printPanel(res.Config, ip)
	}
	printNotes(res.Notes)
}

// ---------- setup iran ----------

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
	panelHTTPS := fs.Bool("panel-https", false, "serve the panel over HTTPS (self-signed) instead of plain HTTP")
	status := fs.String("status", "127.0.0.1:7788", "local status address (empty to disable)")
	out := fs.String("c", defaultConfig, "where to write the config")
	force := fs.Bool("force", false, "overwrite an existing config")
	noPortCheck := fs.Bool("no-port-check", false, "skip checking that ports are free")
	_ = fs.Parse(args)

	o := setup.IranOptions{
		Token: *tok, Forward: *fwd, ForwardUDP: *fwdUDP, Socks: *socks, SocksUser: *user, SocksPass: *pass,
		Conns: *conns, Profile: *profile, Panel: newPanel(*panel, *panelHTTPS), Status: *status,
		Dir: filepath.Dir(*out), CheckPorts: !*noPortCheck,
	}
	if *force {
		o.Skip = existingPorts(*out)
	}
	res, err := setup.Iran(o)
	if err != nil {
		return err
	}
	if err := writeConfig(res.Config, *out, *force); err != nil {
		return err
	}
	printIranResult(res, *out)
	return nil
}

func printIranResult(res *setup.Result, path string) {
	cfg := res.Config
	fmt.Println()
	fmt.Println(sOK.Render("✓ iran config written to " + path))
	var rows [][2]string
	for _, f := range cfg.Forward {
		rows = append(rows, [2]string{"forward " + f.Proto, f.Listen + "  →  (kharej) " + f.Target})
	}
	for _, s := range cfg.Socks {
		rows = append(rows, [2]string{"socks5", s.Listen + "  (X-UI outbound: socks)"})
	}
	if len(rows) > 0 {
		fmt.Println(card("Users connect through", kv(rows)))
	}
	if cfg.Panel != nil {
		printPanel(cfg, "")
	}
	printNotes(res.Notes)
}
