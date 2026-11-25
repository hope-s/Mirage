// Command mirage is a multi-transport, self-healing tunnel linking an
// Iran-side server with a foreign (kharej) exit server.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"mirage/internal/app"
	"mirage/internal/node"
)

const version = "2.0.1"

const defaultConfig = "/etc/mirage/config.json"

func usage() {
	fmt.Fprintf(os.Stderr, `Mirage %s - multi-transport self-healing tunnel

  mirage                        interactive menu (easiest)
  mirage install                install as a system service (+ BBR tuning)
  mirage setup kharej [flags]   configure the foreign server, prints a pairing token
  mirage setup iran   [flags]   configure the iran server from a pairing token
  mirage status                 live links and connections (all tunnels)
  mirage tunnel list|add|remove extra tunnels on this server, e.g.
                                mirage tunnel add de2 iran -token MRG1... -forward 8443=2096
  mirage speedtest              measure tunnel speed (iran)
  mirage linktest               test every link and recommend settings
  mirage cfscan [-apply]        find the best Cloudflare edge IPs for CDN links
  mirage panel [-http|-https]   show web panel address and login (or switch protocol)
  mirage token                  show the pairing token again (kharej)
  mirage update                 download and install the latest release
  mirage backup [file]          save all settings (default /root/mirage-backup-DATE.tar.gz)
  mirage restore FILE           restore settings from a backup and restart
  mirage restart | logs | uninstall
  mirage run [-c file]          run in the foreground (used by the service)
  mirage check [-c file]        validate a config

All commands accept -c FILE (default %s).
`, version, defaultConfig)
}

func main() {
	app.Version = version
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		if err := menu(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "run":
		err = cmdRun(args)
	case "setup":
		if len(args) < 1 {
			usage()
			os.Exit(2)
		}
		switch args[0] {
		case "kharej", "foreign":
			err = cmdSetupKharej(args[1:])
		case "iran":
			err = cmdSetupIran(args[1:])
		default:
			usage()
			os.Exit(2)
		}
	case "status":
		err = cmdStatus(args)
	case "speedtest":
		err = cmdSpeedtest(args)
	case "tunnel", "tunnels":
		err = cmdTunnel(args)
	case "linktest":
		err = cmdLinktest(args)
	case "cfscan":
		err = cmdCFScan(args)
	case "check":
		err = cmdCheck(args)
	case "token":
		err = cmdToken(args)
	case "panel":
		err = cmdPanel(args)
	case "install":
		err = cmdInstall()
	case "update":
		err = cmdUpdate(args)
	case "backup":
		err = cmdBackup(args)
	case "restore":
		err = cmdRestore(args)
	case "uninstall":
		err = cmdUninstall()
	case "restart":
		err = systemctl("restart", service)
		if err == nil {
			fmt.Println("restarted")
		}
	case "logs":
		err = cmdLogs()
	case "menu":
		err = menu()
	case "version", "-v", "--version":
		fmt.Println("mirage", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("c", defaultConfig, "config file")
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := configFlag(fs)
	_ = fs.Parse(args)
	a := app.New(*cfgPath)
	if err := a.Start(); err != nil {
		return err
	}
	_, cfg := a.Node()
	log.Printf("mirage %s running as %s (profile %s)", version, cfg.Role, orDefault(cfg.Profile, "balanced"))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			log.Printf("SIGHUP: reloading config")
			if err := a.Reload(); err != nil {
				log.Printf("reload: %v", err)
			}
			continue
		}
		break
	}
	log.Printf("shutting down")
	done := make(chan struct{})
	go func() { a.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := configFlag(fs)
	_ = fs.Parse(args)
	cfg, err := node.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("config OK (%s)\n", cfg.Role)
	return nil
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	cfgPath := configFlag(fs)
	_ = fs.Parse(args)
	cfg, err := node.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Token == "" {
		return errors.New("this config has no pairing token (tokens are created on the kharej server)")
	}
	fmt.Println(cfg.Token)
	return nil
}

func cmdPanel(args []string) error {
	fs := flag.NewFlagSet("panel", flag.ExitOnError)
	cfgPath := configFlag(fs)
	toHTTP := fs.Bool("http", false, "switch the panel to plain HTTP")
	toHTTPS := fs.Bool("https", false, "switch the panel to HTTPS (self-signed certificate)")
	newPass := fs.Bool("reset-password", false, "set a new random panel password")
	_ = fs.Parse(args)
	cfg, err := node.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Panel == nil {
		return errors.New("the panel is disabled in this config")
	}
	if *toHTTP || *toHTTPS || *newPass {
		if *toHTTP || *toHTTPS {
			cfg.Panel.TLS = *toHTTPS
		}
		if *newPass {
			cfg.Panel.Pass = randHex(8)
		}
		if err := cfg.Save(*cfgPath); err != nil {
			return err
		}
		if err := reloadRunning(*cfgPath); err != nil {
			fmt.Println("saved; restart the service to apply:", err)
		} else {
			fmt.Println("✓ applied")
		}
	}
	printPanel(cfg, "")
	return nil
}

// reloadRunning asks the running service to re-read its config.
func reloadRunning(cfgPath string) error {
	u, err := statusURL(cfgPath)
	if err != nil {
		return err
	}
	cl := http.Client{Timeout: 30 * time.Second}
	resp, err := cl.Post(u+"/reload", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return errors.New(strings.TrimSpace(string(b)))
	}
	return nil
}

func human(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func statusURL(path string) (string, error) {
	cfg, err := node.LoadConfig(path)
	if err != nil {
		return "", err
	}
	if cfg.Status == "" {
		return "", errors.New("status endpoint disabled in config (set \"status\")")
	}
	return "http://" + cfg.Status, nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := configFlag(fs)
	asJSON := fs.Bool("json", false, "raw JSON output")
	_ = fs.Parse(args)
	u, err := statusURL(*cfgPath)
	if err != nil {
		return err
	}
	cl := http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Get(u + "/")
	if err != nil {
		return fmt.Errorf("service not reachable - is it running? (mirage logs) %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if *asJSON {
		fmt.Println(string(body))
		return nil
	}
	var st app.StatusData
	if err := json.Unmarshal(body, &st); err != nil {
		return err
	}
	var in, out float64
	if h := st.History; len(h) > 0 {
		in, out = h[len(h)-1].In, h[len(h)-1].Out
	}
	fmt.Printf("Mirage %s  role=%s  profile=%s  up=%s  mem=%.0fMB  traffic: in %.2f / out %.2f Mbps\n\n",
		st.Version, st.Role, st.Profile, (time.Duration(st.UptimeS) * time.Second).String(), st.MemMB, in, out)
	tunnels := st.Tunnels
	if len(tunnels) == 0 {
		tunnels = []app.TunnelStatus{{Name: app.MainTunnel, Status: st.Status}}
	}
	for _, t := range tunnels {
		if len(tunnels) > 1 {
			fmt.Printf("%s== tunnel %s (%s, %s) ==%s\n", cBold, t.Name, t.Role, t.Profile, cReset)
		}
		printTunnel(t.Status)
		fmt.Println()
	}
	return nil
}

func printTunnel(st node.Status) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LINK\tKIND\tTRANSPORT\tUP\tNOTE")
	for _, l := range st.Links {
		up := strconv.Itoa(int(l.Up))
		if l.Want > 0 {
			up += "/" + strconv.Itoa(l.Want)
		}
		note := l.LastError
		if l.Disabled {
			note = "disabled"
		} else if l.Backup && note == "" {
			note = "backup"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", l.Name, l.Kind, l.Transport, up, note)
	}
	tw.Flush()
	fmt.Println()
	tw = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LINK\tREMOTE\tRTT\tCIPHER\tSTREAMS\tAGE\tIN\tOUT\tSTATE")
	for _, s := range st.Sessions {
		state := "active"
		if s.Draining {
			state = "draining"
		}
		rtt := "-"
		if s.RTTms > 0 {
			rtt = fmt.Sprintf("%.0fms", s.RTTms)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", s.Link, s.Remote, rtt, s.Cipher, s.Streams,
			(time.Duration(s.AgeSec) * time.Second).String(), human(s.BytesIn), human(s.BytesOut), state)
	}
	tw.Flush()
	if len(st.Sessions) == 0 {
		fmt.Println("(no live connections yet)")
	}
}

func cmdSpeedtest(args []string) error {
	fs := flag.NewFlagSet("speedtest", flag.ExitOnError)
	cfgPath := configFlag(fs)
	secs := fs.Int("t", 6, "seconds per direction")
	tunnel := fs.String("tunnel", "", "tunnel to test (default: main)")
	_ = fs.Parse(args)
	u, err := statusURL(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("testing download and upload through the tunnel (%ds each)...\n", *secs)
	cl := http.Client{Timeout: time.Duration(*secs*2+30) * time.Second}
	resp, err := cl.Post(u+"/speedtest?d="+strconv.Itoa(*secs)+"&tunnel="+url.QueryEscape(*tunnel), "application/json", nil)
	if err != nil {
		return fmt.Errorf("service not reachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return errors.New(string(body))
	}
	var r node.SpeedResult
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	fmt.Printf("download: %.1f Mbps\nupload:   %.1f Mbps\nping:     %.0f ms\n", r.DownMbps, r.UpMbps, r.RTTms)
	return nil
}
