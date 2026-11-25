package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
				fmt.Println(sOK.Render("✓ applied to the running service"))
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
		if len(args) < 2 || (args[1] != app.MainTunnel && !app.ValidTunnelName(args[1])) {
			return errors.New("usage: mirage tunnel remove NAME")
		}
		return removeTunnel(args[1])
	case "token":
		if len(args) < 2 {
			return errors.New("usage: mirage tunnel token NAME")
		}
		return cmdToken([]string{"-c", tunnelPath(args[1])})
	}
	return errors.New("usage: mirage tunnel list | add NAME kharej|iran [flags] | remove NAME | token NAME")
}

func tunnelList() error {
	fmt.Println(tunnelTable())
	return nil
}

// removeTunnel stops one tunnel. Removing main keeps only the panel and
// status settings in the main config, so the service, the panel and the
// other tunnels keep running.
func removeTunnel(name string) error {
	if name != app.MainTunnel {
		if err := os.Remove(tunnelPath(name)); err != nil {
			return err
		}
		fmt.Println(sOK.Render("✓ removed tunnel " + name))
		return applyService(tunnelPath(name))
	}
	cur, err := node.LoadConfig(defaultConfig)
	if err != nil {
		return err
	}
	if cur.Empty() {
		return errors.New("there is no main tunnel")
	}
	empty := &node.Config{Panel: cur.Panel, Status: cur.Status}
	if err := empty.Save(defaultConfig); err != nil {
		return err
	}
	fmt.Println(sOK.Render("✓ removed tunnel main"))
	if err := reloadRunning(defaultConfig); err != nil {
		return systemctl("restart", service)
	}
	return nil
}
