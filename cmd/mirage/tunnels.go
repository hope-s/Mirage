package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"mirage/internal/app"
	"mirage/internal/node"
)

func tunnelPath(name string) string {
	return filepath.Join(app.TunnelsDir(defaultConfig), name+".json")
}

// extraArgs adds the flags an extra tunnel's setup needs: its own file and
// no panel/status (the main config owns those).
func extraArgs(path string) []string {
	if path == defaultConfig {
		return nil
	}
	return []string{"-c", path, "-panel=false", "-status", ""}
}

// applyService starts the service for the main tunnel, or asks the running
// service to pick up an extra tunnel.
func applyService(path string) error {
	if path == defaultConfig {
		return startService()
	}
	if _, err := os.Stat(defaultConfig); err != nil {
		return errors.New("set up the main tunnel first (menu options 1/2); extra tunnels run inside its service")
	}
	if u, err := statusURL(defaultConfig); err == nil {
		cl := http.Client{Timeout: 30 * time.Second}
		if resp, err := cl.Post(u+"/reload", "application/json", nil); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Println("✓ tunnel started")
				return nil
			}
		}
	}
	return startService()
}

func cmdTunnel(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		return tunnelList()
	case "add":
		if len(args) < 3 || (args[2] != "kharej" && args[2] != "iran") {
			return errors.New("usage: mirage tunnel add NAME kharej|iran [setup flags]")
		}
		name := args[1]
		if !app.ValidTunnelName(name) {
			return errors.New("tunnel names use a-z, 0-9 and - (and cannot be \"main\")")
		}
		path := tunnelPath(name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		rest := append(extraArgs(path), args[3:]...)
		var err error
		if args[2] == "kharej" {
			err = cmdSetupKharej(rest)
		} else {
			err = cmdSetupIran(rest)
		}
		if err != nil {
			return err
		}
		return applyService(path)
	case "remove", "rm":
		if len(args) < 2 || !app.ValidTunnelName(args[1]) {
			return errors.New("usage: mirage tunnel remove NAME")
		}
		if err := os.Remove(tunnelPath(args[1])); err != nil {
			return err
		}
		fmt.Println("removed", args[1])
		return applyService(tunnelPath(args[1]))
	case "token":
		if len(args) < 2 {
			return errors.New("usage: mirage tunnel token NAME")
		}
		return cmdToken([]string{"-c", tunnelPath(args[1])})
	}
	return errors.New("usage: mirage tunnel list | add NAME kharej|iran [flags] | remove NAME | token NAME")
}

func tunnelList() error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TUNNEL\tROLE\tLINKS\tFILE")
	row := func(name, path string) {
		c, err := node.LoadConfig(path)
		if err != nil {
			fmt.Fprintf(tw, "%s\t-\t%v\t%s\n", name, err, path)
			return
		}
		var links []string
		for _, l := range c.Listen {
			links = append(links, l.Transport)
		}
		for _, d := range c.Dial {
			links = append(links, d.Transport)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, c.Role, strings.Join(links, ","), path)
	}
	if _, err := os.Stat(defaultConfig); err == nil {
		row(app.MainTunnel, defaultConfig)
	}
	files, _ := filepath.Glob(filepath.Join(app.TunnelsDir(defaultConfig), "*.json"))
	for _, f := range files {
		row(strings.TrimSuffix(filepath.Base(f), ".json"), f)
	}
	return tw.Flush()
}

func tunnelMenu() error {
	for {
		fmt.Println()
		_ = tunnelList()
		fmt.Println(`
  1) Add a tunnel on this server as KHAREJ
  2) Add a tunnel on this server as IRAN
  3) Show a tunnel's pairing token
  4) Remove a tunnel
  0) Back`)
		var err error
		switch c := ask("\nchoose", ""); c {
		case "1", "2":
			name := ask("name for the new tunnel (a-z, 0-9, -)", "")
			if !app.ValidTunnelName(name) {
				err = errors.New("invalid name: use a-z, 0-9 and - (not \"main\")")
				break
			}
			path := tunnelPath(name)
			if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				break
			}
			if c == "1" {
				err = wizardKharej(path)
			} else {
				err = wizardIran(path)
			}
		case "3":
			err = cmdTunnel([]string{"token", ask("tunnel name", "")})
		case "4":
			name := ask("tunnel name to remove", "")
			if app.ValidTunnelName(name) && askYN(cRed+"remove tunnel "+name+"?"+cReset, false) {
				err = cmdTunnel([]string{"remove", name})
			}
		case "0", "q", "":
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
