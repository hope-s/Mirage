package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"mirage/internal/node"
)

var in = bufio.NewReader(os.Stdin)

const (
	cReset = "\033[0m"
	cBold  = "\033[1m"
	cCyan  = "\033[36m"
	cGreen = "\033[32m"
	cYel   = "\033[33m"
	cRed   = "\033[31m"
)

func ask(q, def string) string {
	if def != "" {
		fmt.Printf("%s %s[%s]%s: ", q, cCyan, def, cReset)
	} else {
		fmt.Printf("%s: ", q)
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askYN(q string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	a := strings.ToLower(ask(q+" ("+d+")", ""))
	if a == "" {
		return def
	}
	return a == "y" || a == "yes"
}

func pause() { ask("\npress Enter to continue", "") }

func firstFree(cands ...int) int {
	for _, p := range cands {
		if portFree(p) {
			return p
		}
	}
	return freeRandomPort()
}

func menu() error {
	for {
		role := ""
		if c, err := node.LoadConfig(defaultConfig); err == nil {
			role = c.Role
		}
		fmt.Printf("\n%s%s  Mirage %s%s  multi-transport self-healing tunnel\n", cBold, cCyan, version, cReset)
		if role != "" {
			fmt.Printf("  this server: %s%s%s\n", cGreen, role, cReset)
		} else {
			fmt.Printf("  this server: %snot configured%s\n", cYel, cReset)
		}
		fmt.Println(`
  1) Setup KHAREJ (foreign / exit) server
  2) Setup IRAN (entry) server
  3) Tunnels - add more tunnels on this server / list / remove
  4) Status
  5) Speed test
  6) Link test - measure every link and get advice
  7) Cloudflare clean IP scan (CDN links)
  8) Web panel address & login
  9) Show pairing token (kharej)
 10) Restart service
 11) Live logs
 12) Update Mirage to the latest version
 13) Backup / restore settings
 14) Uninstall
  0) Exit`)
		var err error
		switch ask("\nchoose", "") {
		case "1":
			err = wizardKharej(defaultConfig)
		case "2":
			err = wizardIran(defaultConfig)
		case "3":
			err = tunnelMenu()
		case "4":
			err = cmdStatus(nil)
		case "5":
			err = cmdSpeedtest(nil)
		case "6":
			err = cmdLinktest(nil)
		case "7":
			err = cmdCFScan([]string{"-apply=" + strconv.FormatBool(askYN("switch the link to the best IPs found?", true))})
		case "8":
			if err = cmdPanel(nil); err == nil {
				switch ask("\n  1) switch to HTTP   2) switch to HTTPS   3) new password   Enter) back", "") {
				case "1":
					err = cmdPanel([]string{"-http"})
				case "2":
					err = cmdPanel([]string{"-https"})
				case "3":
					err = cmdPanel([]string{"-reset-password"})
				}
			}
		case "9":
			err = cmdToken(nil)
		case "10":
			if err = systemctl("restart", service); err == nil {
				fmt.Println(cGreen + "restarted" + cReset)
			}
		case "11":
			err = cmdLogs()
		case "12":
			err = cmdUpdate(nil)
		case "13":
			err = backupMenu()
		case "14":
			if askYN(cRed+"remove mirage completely (service, config, binary)?"+cReset, false) {
				err = cmdUninstall()
				if err == nil {
					return nil
				}
			}
		case "0", "q", "exit":
			return nil
		default:
			continue
		}
		if err != nil {
			fmt.Printf("%serror: %v%s\n", cRed, err, cReset)
		}
		pause()
	}
}

func confirmOverwrite(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return askYN(cYel+"a config already exists and will be replaced. continue?"+cReset, false)
	}
	return true
}

// wizardKharej sets up the main tunnel (path = defaultConfig) or an extra
// one in the tunnels directory.
func wizardKharej(path string) error {
	if err := needRoot(); err != nil {
		return err
	}
	if !confirmOverwrite(path) {
		return nil
	}
	fmt.Printf("\n%s-- KHAREJ server setup --%s\n", cBold, cReset)
	fmt.Println("Who opens the connection?")
	fmt.Println("  1) iran -> kharej  (direct, normal case)")
	fmt.Println("  2) kharej -> iran  (reverse, when iran cannot reach this server)")
	mode := ask("mode", "1")
	args := append(extraArgs(path), "-force")
	if mode == "2" {
		args = append(args, "-reverse", ask("IRAN server IP", ""))
	} else {
		args = append(args, "-ip", ask("public IP of THIS server", outboundIP()))
	}
	fmt.Println("\nTransports (comma separated ports, empty = off). More than one = automatic switching.")
	tlsDef := strconv.Itoa(firstFree(443, 2053, 2083, 8443))
	tls := ask("  TLS ports (looks like HTTPS)", tlsDef)
	tcp := ask("  raw TCP ports (fastest)", strconv.Itoa(firstFree(8880, 2095, 9443)))
	kcp := ask("  KCP/UDP ports (best when packets get lost)", "")
	ftcp := ask("  fake-TCP ports (linux root on both; when UDP is blocked)", "")
	ws := ask("  WebSocket ports (plain, works through more filters)", "")
	args = append(args, "-tls", tls, "-tcp", tcp, "-kcp", kcp, "-ftcp", ftcp, "-ws", ws)
	if kcp != "" || ftcp != "" {
		fmt.Println("  KCP speed: normal < fast < fast2 < fast3 < turbo (faster = lower ping on bad links, more bandwidth)")
		args = append(args, "-kcp-mode", ask("  KCP speed", "fast2"))
		args = append(args, "-fec", ask("  error correction data:parity (more parity = survives more loss; 0 = off)", "10:3"))
	}
	cdnQ := "  CDN domain proxied by Cloudflare, pointing at THIS server (optional backup)"
	if mode == "2" {
		cdnQ = "  CDN domain proxied by Cloudflare, pointing at the IRAN server (optional backup)"
	}
	if cdn := ask(cdnQ, ""); cdn != "" {
		args = append(args, "-cdn", cdn, "-cdn-origin-port", ask("  origin port on this server for the CDN", "80"))
	}
	if ws != "" && askYN("  use WebSocket only as backup?", true) {
		args = append(args, "-backup", "ws")
	}
	fmt.Println("\nWhich X-UI inbound ports on THIS server should iran forward to? (e.g. 2096,2097)")
	args = append(args, "-allow-local", ask("  local ports", ""))
	fmt.Println("\nProfile: speed (lowest ping/cpu) | balanced | stealth (hardest to detect)")
	args = append(args, "-profile", ask("  profile", "balanced"))
	args = append(args, "-refresh", ask("  rebuild the tunnel every N hours on both servers (0 = off)", "0"))
	fmt.Println("\nEncryption: auto (picks the fastest for this CPU) | aes-256-gcm | chacha20-poly1305")
	args = append(args, "-cipher", ask("  cipher", "auto"))
	if err := cmdSetupKharej(args); err != nil {
		return err
	}
	fmt.Println()
	if err := applyService(path); err != nil {
		return err
	}
	fmt.Printf("\n%sdone.%s copy the token above, then on the iran server run: mirage  -> option 2\n", cGreen, cReset)
	return nil
}

func wizardIran(path string) error {
	if err := needRoot(); err != nil {
		return err
	}
	if !confirmOverwrite(path) {
		return nil
	}
	fmt.Printf("\n%s-- IRAN server setup --%s\n", cBold, cReset)
	tok := ask("paste the pairing token from the kharej server", "")
	if _, err := decodeToken(tok); err != nil {
		return err
	}
	fmt.Println("\nHow will users reach the tunnel?")
	fmt.Println("  1) port forward: iran port -> X-UI inbound on kharej (like Backhaul)")
	fmt.Println("  2) SOCKS5 for an X-UI outbound on this server (like Hedioum)")
	fmt.Println("  3) both")
	how := ask("choose", "1")
	args := append(extraArgs(path), "-force", "-token", tok)
	if how == "1" || how == "3" {
		fmt.Println("\nforwards as LOCAL=KHAREJ_PORT, comma separated. e.g. 443=2096,8443=2097")
		fmt.Println("(a single number like 2096 means the same port on both sides)")
		f := ask("  forwards", "")
		args = append(args, "-forward", f)
		if askYN("  also forward UDP on the same ports?", false) {
			args = append(args, "-forward-udp", f)
		}
	}
	if how == "2" || how == "3" {
		args = append(args, "-socks", "127.0.0.1:"+ask("  SOCKS5 port (local only)", strconv.Itoa(firstFree(40001, 40002, 40003))))
	}
	if err := cmdSetupIran(args); err != nil {
		return err
	}
	fmt.Println()
	if err := applyService(path); err != nil {
		return err
	}
	fmt.Printf("\n%sdone.%s check the tunnel with option 3 (status) or 4 (speed test).\n", cGreen, cReset)
	return nil
}
