package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

	"mirage/internal/app"
	"mirage/internal/node"
	"mirage/internal/setup"
)

func wizardSetup() error {
	role := "kharej"
	err := form(huh.NewGroup(
		huh.NewSelect[string]().Title("What is this server?").
			Description("Set up the KHAREJ server first: it prints a token you paste on the IRAN server.").
			Options(
				huh.NewOption("KHAREJ  — foreign / exit server (your X-UI is here)", "kharej"),
				huh.NewOption("IRAN    — entry server your users connect to", "iran"),
			).Value(&role),
	)).Run()
	if err != nil {
		return errCancelled
	}
	if role == "kharej" {
		return wizardKharej(defaultConfig)
	}
	return wizardIran(defaultConfig)
}

func confirmOverwrite(path string) bool {
	if c := existing(path); c != nil && !c.Empty() {
		return confirm("Replace the current settings?", path+" already exists. The tunnel restarts with the new settings.", false)
	}
	return true
}

// portsInput is a text field for a comma separated port list; check
// reports whether a port can be used.
func portsInput(title, desc string, v *string, check func(int) bool) *huh.Input {
	return huh.NewInput().Title(title).Description(desc).Value(v).Validate(func(s string) error {
		ps, err := setup.ParsePorts(s)
		if err != nil {
			return err
		}
		if len(ps) == 0 {
			return errors.New("enter at least one port")
		}
		for _, p := range ps {
			if check != nil && !check(p) {
				return fmt.Errorf("port %d is already in use on this server", p)
			}
		}
		return nil
	})
}

func step(n, total int, title string) string {
	return fmt.Sprintf("%s  %s", title, sDim.Render(fmt.Sprintf("step %d/%d", n, total)))
}

// existing returns the config at path, if any.
func existing(path string) *node.Config {
	c, _ := node.LoadConfig(path)
	return c
}

func wizardKharej(path string) error {
	if err := needRoot(); err != nil {
		return err
	}
	if !confirmOverwrite(path) {
		return errCancelled
	}
	main := path == defaultConfig
	old := existing(path)
	skip := setup.Ports(old)
	free := func(kind string) func(int) bool {
		return func(p int) bool { return skip[p] || setup.KindPortFree(kind, p) }
	}
	d := setup.KharejDefaults()

	// 1. who connects to whom
	mode, ip, iranIP := "direct", setup.OutboundIP(), ""
	err := form(
		huh.NewGroup(
			huh.NewSelect[string]().Title(step(1, 4, "Connection direction")).
				Options(
					huh.NewOption("Direct   — iran connects to this server (normal)", "direct"),
					huh.NewOption("Reverse  — this server connects to iran (iran cannot reach kharej)", "reverse"),
				).Value(&mode),
		),
		huh.NewGroup(
			huh.NewInput().Title("Public IP or domain of THIS server").Value(&ip).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New("required")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return mode != "direct" }),
		huh.NewGroup(
			huh.NewInput().Title("IP of the IRAN server").Description("This server will connect to it.").Value(&iranIP).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New("required")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return mode != "reverse" }),
	).Run()
	if err != nil {
		return errCancelled
	}
	direct := mode == "direct"

	// 2. transports
	kinds := []string{"tls", "tcp"}
	err = form(huh.NewGroup(
		huh.NewMultiSelect[string]().Title(step(2, 4, "Transports")).
			Description("Pick several: Mirage keeps them all ready and switches automatically.  space = toggle").
			Options(
				huh.NewOption("TLS        looks like HTTPS, hard to detect", "tls").Selected(true),
				huh.NewOption("TCP        fastest, lowest CPU", "tcp").Selected(true),
				huh.NewOption("KCP/UDP    best when packets get lost", "kcp"),
				huh.NewOption("Fake-TCP   KCP disguised as TCP, when UDP is blocked (linux root)", "ftcp"),
				huh.NewOption("WebSocket  plain HTTP, passes more filters", "ws"),
				huh.NewOption("CDN        backup route through Cloudflare (needs a domain)", "cdn"),
			).Value(&kinds).
			Validate(func(v []string) error {
				if len(v) == 0 || (len(v) == 1 && v[0] == "cdn") {
					return errors.New("pick at least one transport besides CDN")
				}
				return nil
			}),
	)).Run()
	if err != nil {
		return errCancelled
	}
	has := func(k string) bool { return slices.Contains(kinds, k) }

	// 3. ports and transport options
	o := d
	o.Dir = filepath.Dir(path)
	tlsDef := []int{443, 2053, 2083, 8443}
	if has("cdn") {
		tlsDef = []int{2053, 8443, 2083, 2087} // leave 443 for the CDN (Full SSL)
	}
	o.TLS = ""
	tlsP := strconv.Itoa(setup.FirstFree(tlsDef...))
	tcpP := strconv.Itoa(setup.FirstFree(8880, 2095, 9443))
	kcpP := strconv.Itoa(setup.FirstFreeUDP(443, 8443, 2053))
	ftcpP := strconv.Itoa(setup.FirstFree(2087, 2096, 8443))
	wsP := strconv.Itoa(setup.FirstFree(8080, 2052, 2082))
	cdnDomain := ""
	var fields []huh.Field
	check := func(kind string) func(int) bool {
		if !direct {
			return nil // ports are opened on the iran server
		}
		return free(kind)
	}
	if has("tls") {
		fields = append(fields, portsInput("TLS port(s)", "comma separated; several ports = automatic port hopping", &tlsP, check("tls")))
	}
	if has("tcp") {
		fields = append(fields, portsInput("TCP port(s)", "", &tcpP, check("tcp")))
	}
	if has("kcp") {
		fields = append(fields, portsInput("KCP port(s) (UDP)", "open these as UDP in the firewall", &kcpP, check("kcp")))
	}
	if has("ftcp") {
		fields = append(fields, portsInput("Fake-TCP port(s)", "", &ftcpP, check("ftcp")))
	}
	if has("ws") {
		fields = append(fields, portsInput("WebSocket port(s)", "", &wsP, check("ws")))
	}
	if has("cdn") {
		target := "THIS server"
		if !direct {
			target = "the IRAN server"
		}
		fields = append(fields, huh.NewInput().Title("CDN domain").
			Description("A subdomain with the orange cloud ON in Cloudflare, pointing at "+target+".\n"+
				"Works with SSL mode Flexible or Full: Mirage listens on 80 and 443.").
			Placeholder("cdn.example.com").Value(&cdnDomain).
			Validate(func(s string) error {
				if !strings.Contains(strings.TrimSpace(s), ".") {
					return errors.New("enter a domain like cdn.example.com")
				}
				return nil
			}))
	}
	groups := []*huh.Group{huh.NewGroup(fields...).Title(step(3, 4, "Ports"))}
	kcpMode, fec := d.KCPMode, d.FEC
	if has("kcp") || has("ftcp") {
		groups = append(groups, huh.NewGroup(
			huh.NewSelect[string]().Title("KCP speed").
				Description("Faster = lower ping on bad links, but more bandwidth").
				Options(
					huh.NewOption("normal   gentle, saves bandwidth", "normal"),
					huh.NewOption("fast", "fast"),
					huh.NewOption("fast2    recommended", "fast2"),
					huh.NewOption("fast3    aggressive", "fast3"),
					huh.NewOption("turbo    lowest latency, most bandwidth", "turbo"),
				).Value(&kcpMode),
			huh.NewSelect[string]().Title("Error correction (FEC)").
				Description("Extra parity packets rebuild lost ones without waiting").
				Options(
					huh.NewOption("off", "0"),
					huh.NewOption("light   10:3   recommended", "10:3"),
					huh.NewOption("medium  10:5   for 10-20% loss", "10:5"),
					huh.NewOption("heavy    5:5   for 20%+ loss", "5:5"),
				).Value(&fec),
		).Title("KCP tuning"))
	}
	if err := form(groups...).Run(); err != nil {
		return errCancelled
	}

	// 4. services and security
	allow := ""
	if old != nil {
		allow = strings.Join(old.AllowLocal, ",")
	}
	profile, cipher, fp, refresh := d.Profile, d.Cipher, d.Fingerprint, "0"
	sec := []huh.Field{
		huh.NewInput().Title(step(4, 4, "X-UI inbound ports on this server")).
			Description("Which local ports may iran forward to? e.g. 2096,2097 (you can add more later)").
			Placeholder("2096").Value(&allow),
		huh.NewSelect[string]().Title("Profile").
			Options(
				huh.NewOption("balanced   good speed, light padding (recommended)", "balanced"),
				huh.NewOption("speed      lowest ping and CPU", "speed"),
				huh.NewOption("stealth    hardest to detect, a bit slower", "stealth"),
			).Value(&profile),
		huh.NewSelect[string]().Title("Encryption").
			Options(
				huh.NewOption("auto                fastest for this CPU (recommended)", "auto"),
				huh.NewOption("AES-256-GCM", "aes-256-gcm"),
				huh.NewOption("ChaCha20-Poly1305   best on CPUs without AES", "chacha20-poly1305"),
			).Value(&cipher),
	}
	if has("tls") || has("cdn") {
		sec = append(sec, huh.NewSelect[string]().Title("TLS fingerprint").
			Description("The browser the iran side imitates").
			Options(huh.NewOptions("chrome", "firefox", "safari", "edge", "ios", "random", "go")...).Value(&fp))
	}
	sec = append(sec, huh.NewSelect[string]().Title("Auto refresh").
		Description("Rebuild every connection on both servers on a schedule").
		Options(
			huh.NewOption("off", "0"), huh.NewOption("every hour", "1"), huh.NewOption("every 6 hours", "6"),
			huh.NewOption("every 12 hours", "12"), huh.NewOption("every day", "24"),
		).Value(&refresh))
	if err := form(huh.NewGroup(sec...)).Run(); err != nil {
		return errCancelled
	}

	if direct {
		o.IP = strings.TrimSpace(ip)
	} else {
		o.Reverse = strings.TrimSpace(iranIP)
	}
	set := func(k string, dst *string, v string) {
		if has(k) {
			*dst = v
		}
	}
	set("tls", &o.TLS, tlsP)
	set("tcp", &o.TCP, tcpP)
	set("kcp", &o.KCP, kcpP)
	set("ftcp", &o.FTCP, ftcpP)
	set("ws", &o.WS, wsP)
	if has("ws") && len(kinds) > 1 {
		o.Backup = []string{"ws"}
	}
	o.CDN = strings.TrimSpace(cdnDomain)
	o.KCPMode, o.FEC = kcpMode, fec
	o.AllowLocal = setup.SplitList(allow)
	o.Profile, o.Cipher, o.Fingerprint = profile, cipher, fp
	o.Refresh, _ = strconv.Atoi(refresh)
	o.Skip = skip
	if main {
		o.Panel = keepPanel(old)
		if old != nil {
			o.Status = old.Status
		}
	} else {
		o.Panel, o.Status = nil, ""
	}
	res, err := setup.Kharej(o)
	if err != nil {
		return err
	}
	tk, _ := setup.DecodeToken(res.Token)
	rows := [][2]string{{"server", "KHAREJ"}, {"direction", map[bool]string{true: "iran → this server", false: "this server → iran " + o.Reverse}[direct]}}
	for i, l := range tk.Describe() {
		rows = append(rows, [2]string{map[bool]string{true: "links", false: ""}[i == 0], l})
	}
	rows = append(rows, [2]string{"allowed ports", orDefault(allow, "none yet")}, [2]string{"profile", profile + " · " + cipher})
	fmt.Println(card("Summary", kv(rows)))
	if !confirm("Save and start the tunnel?", "", true) {
		return errCancelled
	}
	if err := writeConfig(res.Config, path, true); err != nil {
		return err
	}
	if err := applyService(path); err != nil {
		return err
	}
	printKharejResult(res, path, o.IP)
	fmt.Println("\n" + sAccent.Render("next ") + "on the IRAN server run " + sBold.Render("mirage") + " → Set up this server → IRAN, and paste the token.")
	return nil
}

// keepPanel reuses the panel login when setup runs again over a config.
func keepPanel(old *node.Config) *node.PanelConf {
	if old != nil && old.Panel != nil {
		return old.Panel
	}
	return setup.NewPanel(false)
}

func wizardIran(path string) error {
	if err := needRoot(); err != nil {
		return err
	}
	if !confirmOverwrite(path) {
		return errCancelled
	}
	main := path == defaultConfig
	old := existing(path)
	skip := setup.Ports(old)

	tok := ""
	var parsed setup.Token
	err := form(huh.NewGroup(
		huh.NewText().Title(step(1, 3, "Pairing token")).
			Description("Paste the token printed on the KHAREJ server (starts with MRG1.)").
			CharLimit(8000).Lines(5).Value(&tok).
			Validate(func(s string) error {
				t, err := setup.DecodeToken(s)
				if err == nil {
					parsed = t
				}
				return err
			}),
	)).Run()
	if err != nil {
		return errCancelled
	}

	how := "forward"
	err = form(huh.NewGroup(
		huh.NewNote().Title("Token OK").Description(strings.Join(parsed.Describe(), "\n")),
		huh.NewSelect[string]().Title(step(2, 3, "How do users reach the tunnel?")).
			Options(
				huh.NewOption("Port forward   iran port → X-UI inbound on kharej", "forward"),
				huh.NewOption("SOCKS5         for an X-UI outbound on this server", "socks"),
				huh.NewOption("Both", "both"),
			).Value(&how),
	)).Run()
	if err != nil {
		return errCancelled
	}

	fwd, udp, socks := "", false, strconv.Itoa(setup.FirstFree(40001, 40002, 40003))
	if old != nil {
		fwd, _ = setup.FormatForwards(old.Forward)
	}
	var fields []huh.Field
	if how != "socks" {
		fields = append(fields,
			huh.NewInput().Title(step(3, 3, "Port forwards")).
				Description("LOCAL=KHAREJ_PORT, comma separated, e.g. 443=2096,8443=2097\n"+
					"a single number like 2096 uses the same port on both sides").
				Placeholder("443=2096").Value(&fwd).
				Validate(func(s string) error {
					fs := setup.ParseForwards(s, "tcp")
					if len(fs) == 0 {
						return errors.New("enter at least one forward")
					}
					for _, f := range fs {
						_, p, err := splitPort(f.Listen)
						if err != nil {
							return fmt.Errorf("bad forward %q", f.Listen)
						}
						if !skip[p] && !setup.PortFree(p) {
							return fmt.Errorf("port %d is already in use on this server", p)
						}
					}
					return nil
				}),
			huh.NewConfirm().Title("Forward UDP on the same ports too?").Value(&udp))
	}
	if how != "forward" {
		fields = append(fields, portsInput("SOCKS5 port (local only, 127.0.0.1)", "", &socks,
			func(p int) bool { return skip[p] || setup.PortFree(p) }))
	}
	if err := form(huh.NewGroup(fields...)).Run(); err != nil {
		return errCancelled
	}
	o := setup.IranOptions{Token: tok, Dir: filepath.Dir(path), CheckPorts: true, Skip: skip, Status: "127.0.0.1:7788"}
	if how != "socks" {
		o.Forward = fwd
		if udp {
			o.ForwardUDP = fwd
		}
	}
	if how != "forward" {
		o.Socks = socks
	}
	if main {
		o.Panel = keepPanel(old)
		if old != nil {
			o.Status = old.Status
		}
	} else {
		o.Status = ""
	}
	res, err := setup.Iran(o)
	if err != nil {
		return err
	}
	if err := writeConfig(res.Config, path, true); err != nil {
		return err
	}
	if err := applyService(path); err != nil {
		return err
	}
	printIranResult(res, path)
	fmt.Println("\n" + sAccent.Render("next ") + "open " + sBold.Render("Live dashboard") + " to watch the links come up, then run a " + sBold.Render("Speed test") + ".")
	return nil
}

func splitPort(addr string) (string, int, error) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return "", 0, errors.New("no port")
	}
	p, err := strconv.Atoi(addr[i+1:])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, errors.New("bad port")
	}
	return addr[:i], p, nil
}

// ---------- tunnels ----------

// tunnelFiles lists every tunnel on this server with its config path.
func tunnelFiles() (names, paths []string) {
	if c := existing(defaultConfig); c != nil && !c.Empty() {
		names, paths = append(names, app.MainTunnel), append(paths, defaultConfig)
	}
	files, _ := filepath.Glob(filepath.Join(app.TunnelsDir(defaultConfig), "*.json"))
	for _, f := range files {
		names, paths = append(names, strings.TrimSuffix(filepath.Base(f), ".json")), append(paths, f)
	}
	return
}

// pickTunnel asks which tunnel to use when there is more than one.
func pickTunnel(title string, filter func(*node.Config) bool) (string, string, error) {
	names, paths := tunnelFiles()
	var opts []huh.Option[int]
	for i, n := range names {
		c, err := node.LoadConfig(paths[i])
		if err != nil || (filter != nil && !filter(c)) {
			continue
		}
		opts = append(opts, huh.NewOption(fmt.Sprintf("%-10s %s", n, strings.ToUpper(c.Role)), i))
	}
	switch len(opts) {
	case 0:
		return "", "", errors.New("no matching tunnel on this server")
	case 1:
		i := opts[0].Value
		return names[i], paths[i], nil
	}
	sel := opts[0].Value
	if err := form(huh.NewGroup(huh.NewSelect[int]().Title(title).Options(opts...).Value(&sel))).Run(); err != nil {
		return "", "", errCancelled
	}
	return names[sel], paths[sel], nil
}

// tunnelFlag returns -tunnel NAME for commands that act on one tunnel.
func tunnelFlag() []string {
	name, _, err := pickTunnel("Which tunnel?", nil)
	if err != nil || name == app.MainTunnel {
		return nil
	}
	return []string{"-tunnel", name}
}

func tunnelTable() string {
	names, paths := tunnelFiles()
	if len(names) == 0 {
		return sDim.Render("no tunnels yet")
	}
	var rows [][]string
	for i, n := range names {
		c, err := node.LoadConfig(paths[i])
		if err != nil {
			rows = append(rows, []string{n, "-", sErr.Render(trunc(err.Error(), 60))})
			continue
		}
		var links []string
		for _, l := range c.Listen {
			links = append(links, l.Transport)
		}
		for _, d := range c.Dial {
			links = append(links, d.Transport)
		}
		rows = append(rows, []string{sBold.Render(n), strings.ToUpper(c.Role), strings.Join(links, " ")})
	}
	return grid([]string{"TUNNEL", "ROLE", "LINKS"}, rows)
}

func tunnelScreen() error {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(card("Tunnels on this server", tunnelTable()))
		act := "kharej"
		err := form(huh.NewGroup(huh.NewSelect[string]().Title("Tunnels").
			Description("Extra tunnels run inside the same service, each with its own key and ports.").
			Options(
				huh.NewOption("Add a tunnel as KHAREJ", "kharej"),
				huh.NewOption("Add a tunnel as IRAN", "iran"),
				huh.NewOption("Show a tunnel's pairing token", "token"),
				huh.NewOption("Remove a tunnel", "remove"),
				huh.NewOption("Back", "back"),
			).Value(&act))).Run()
		if err != nil || act == "back" {
			return nil
		}
		switch err := tunnelAction(act); err {
		case errCancelled:
			continue
		case nil:
		default:
			uiErr(err)
		}
		pause()
	}
}

// tunnelAction runs one entry of the tunnels screen; errCancelled means
// there is nothing to show.
func tunnelAction(act string) error {
	switch act {
	case "kharej", "iran":
		if _, err := os.Stat(defaultConfig); err != nil {
			return errors.New("set up this server first (Set up this server)")
		}
		name := ""
		if form(huh.NewGroup(huh.NewInput().Title("Name for the new tunnel").Description("a-z, 0-9 and -, e.g. de2").
			Value(&name).Validate(func(s string) error {
			if !app.ValidTunnelName(s) {
				return errors.New(`use a-z, 0-9 and - (not "main")`)
			}
			if _, err := os.Stat(tunnelPath(s)); err == nil {
				return errors.New("a tunnel with this name exists")
			}
			return nil
		}))).Run() != nil {
			return errCancelled
		}
		fmt.Print("\033[H\033[2J")
		p := tunnelPath(name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if act == "kharej" {
			return wizardKharej(p)
		}
		return wizardIran(p)
	case "token":
		return tokenScreen()
	case "remove":
		return removeScreen()
	}
	return errCancelled
}

// removeScreen deletes one tunnel after a confirmation that says what
// keeps running.
func removeScreen() error {
	names, _ := tunnelFiles()
	if len(names) == 0 {
		return errors.New("there are no tunnels on this server")
	}
	name, _, err := pickTunnel("Remove which tunnel?", nil)
	if err != nil {
		return err
	}
	desc := "Its settings are deleted and its ports close. Other tunnels keep running."
	if len(names) == 1 {
		desc = "This is the only tunnel. The service and web panel keep running, so you can set up a new tunnel any time (or choose Uninstall to remove everything)."
	}
	if !confirm("Remove tunnel "+name+"?", desc, false) {
		return errCancelled
	}
	return removeTunnel(name)
}

func tokenScreen() error {
	_, path, err := pickTunnel("Token of which tunnel?", func(c *node.Config) bool { return c.Token != "" })
	if err != nil {
		if err != errCancelled {
			return errors.New("tokens are created on the KHAREJ server; this server has none")
		}
		return err
	}
	c, err := node.LoadConfig(path)
	if err != nil {
		return err
	}
	fmt.Println(tokenBox(c.Token))
	return nil
}

// ---------- panel ----------

func panelScreen() error {
	cfg, err := node.LoadConfig(defaultConfig)
	if err != nil {
		return err
	}
	if cfg.Panel == nil {
		if !confirm("The web panel is off. Turn it on?", "", true) {
			return errCancelled
		}
		cfg.Panel = setup.NewPanel(false)
		return savePanel(cfg)
	}
	printPanel(cfg, "")
	other, otherLbl := "-https", "Switch to HTTPS (self-signed certificate)"
	if cfg.Panel.TLS {
		other, otherLbl = "-http", "Switch to HTTP"
	}
	act := "back"
	if form(huh.NewGroup(huh.NewSelect[string]().Title("Web panel").Options(
		huh.NewOption("Back", "back"),
		huh.NewOption(otherLbl, other),
		huh.NewOption("New random password", "-reset-password"),
		huh.NewOption("Move to a new random port and path", "move"),
	).Value(&act))).Run() != nil || act == "back" {
		return errCancelled
	}
	if act == "move" {
		cfg.Panel.Listen = ":" + strconv.Itoa(setup.FreeRandomPort())
		cfg.Panel.Path = "/" + setup.RandHex(6)
		return savePanel(cfg)
	}
	fmt.Println()
	return cmdPanel([]string{act})
}

func savePanel(cfg *node.Config) error {
	if err := cfg.Save(defaultConfig); err != nil {
		return err
	}
	if err := reloadRunning(defaultConfig); err != nil {
		fmt.Println(sWarn.Render("saved; restart the service to apply: ") + err.Error())
	} else {
		fmt.Println(sOK.Render("✓ applied"))
	}
	printPanel(cfg, "")
	return nil
}

// ---------- settings ----------

func settingsScreen() error {
	name, path, err := pickTunnel("Settings of which tunnel?", nil)
	if err != nil {
		return err
	}
	c, err := node.LoadConfig(path)
	if err != nil {
		return err
	}
	profile, cipher, fp := orDefault(c.Profile, "balanced"), orDefault(c.Cipher, "auto"), orDefault(c.Fingerprint, "chrome")
	refresh := strconv.Itoa(c.RefreshHours)
	allow := strings.Join(c.AllowLocal, ",")
	tcpF, udpF := setup.FormatForwards(c.Forward)
	fields := []huh.Field{
		huh.NewSelect[string]().Title("Profile").Options(
			huh.NewOption("balanced", "balanced"), huh.NewOption("speed", "speed"), huh.NewOption("stealth", "stealth"),
		).Value(&profile),
		huh.NewSelect[string]().Title("Encryption").Description("both servers agree automatically; the dialing side's choice wins").Options(
			huh.NewOption("auto", "auto"), huh.NewOption("AES-256-GCM", "aes-256-gcm"), huh.NewOption("ChaCha20-Poly1305", "chacha20-poly1305"),
		).Value(&cipher),
		huh.NewSelect[string]().Title("TLS fingerprint").Options(huh.NewOptions("chrome", "firefox", "safari", "edge", "ios", "random", "go")...).Value(&fp),
		huh.NewInput().Title("Auto refresh (hours, 0 = off)").Value(&refresh).Validate(func(s string) error {
			if n, err := strconv.Atoi(s); err != nil || n < 0 || n > 720 {
				return errors.New("0..720")
			}
			return nil
		}),
	}
	if c.Role == node.RoleKharej {
		fields = append(fields, huh.NewInput().Title("Allowed local ports").Description("X-UI inbound ports iran may forward to, e.g. 2096,2097").Value(&allow))
	} else {
		fields = append(fields,
			huh.NewInput().Title("TCP forwards").Description("LOCAL=KHAREJ_PORT, comma separated").Value(&tcpF),
			huh.NewInput().Title("UDP forwards").Description("same syntax; empty = none").Value(&udpF))
	}
	if err := form(huh.NewGroup(fields...).Title("Settings · tunnel " + name)).Run(); err != nil {
		return errCancelled
	}
	c.Profile, c.Cipher, c.Fingerprint = profile, cipher, fp
	c.RefreshHours, _ = strconv.Atoi(refresh)
	if c.Role == node.RoleKharej {
		c.AllowLocal = setup.SplitList(allow)
	} else {
		c.Forward = setup.Forwards(tcpF, udpF)
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := c.Save(path); err != nil {
		return err
	}
	if err := reloadRunning(defaultConfig); err != nil {
		fmt.Println(sWarn.Render("saved; restart the service to apply: ") + err.Error())
		return nil
	}
	fmt.Println(sOK.Render("✓ saved and applied"))
	return nil
}
