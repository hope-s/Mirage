package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"mirage/internal/app"
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
				fmt.Println(sOK.Render("✓ tunnel started"))
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
		fmt.Println(sOK.Render("✓ removed " + args[1]))
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
	fmt.Println(tunnelTable())
	return nil
}
