package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
)

const releaseURL = "https://github.com/hope-s/Mirage/releases/latest/download/"

// cmdUpdate downloads the latest release binary for this CPU and installs
// it (the service restarts with the same config).
func cmdUpdate(args []string) error {
	if err := needRoot(); err != nil {
		return err
	}
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7"
	}
	url := releaseURL + "mirage-linux-" + arch
	fmt.Println("downloading", url)
	cl := http.Client{Timeout: 5 * time.Minute}
	resp, err := cl.Get(url)
	if err != nil {
		return fmt.Errorf("download failed (no access to GitHub? copy the release file manually): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	tmp, err := os.CreateTemp("", "mirage-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, resp.Body)
	tmp.Close()
	if err != nil {
		return err
	}
	if n < 1<<20 {
		return errors.New("downloaded file is too small; not a mirage binary")
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	out, err := exec.Command(tmp.Name(), "version").Output()
	if err != nil {
		return fmt.Errorf("downloaded binary does not run on this server: %w", err)
	}
	newVer := strings.TrimSpace(strings.TrimPrefix(string(out), "mirage "))
	if newVer == version && !(len(args) > 0 && args[0] == "-force") {
		fmt.Println("already up to date:", version)
		return nil
	}
	fmt.Printf("updating %s -> %s\n", version, newVer)
	return run(tmp.Name(), "install")
}

func backupDir() string { return "/root" }

// cmdBackup writes every config, certificate and tunnel file to a tar.gz.
func cmdBackup(args []string) error {
	dst := filepath.Join(backupDir(), "mirage-backup-"+time.Now().Format("20060102-150405")+".tar.gz")
	if len(args) > 0 {
		dst = args[0]
	}
	if err := writeBackup(filepath.Dir(defaultConfig), dst); err != nil {
		return err
	}
	fmt.Println("backup written:", dst)
	fmt.Println("restore on any server with:  mirage restore", dst)
	return nil
}

func writeBackup(src, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			_, err = tw.Write(b)
			return err
		}
		return nil
	})
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
		err = gz.Close()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
	}
	return err
}

// cmdRestore replaces the config directory with a backup and restarts.
func cmdRestore(args []string) error {
	if err := needRoot(); err != nil {
		return err
	}
	if len(args) < 1 {
		return errors.New("usage: mirage restore FILE.tar.gz")
	}
	if err := restoreBackup(args[0], filepath.Dir(defaultConfig)); err != nil {
		return err
	}
	fmt.Println("✓ settings restored")
	return startService()
}

// restoreBackup replaces dst with the backup's contents, keeping the old
// directory next to it.
func restoreBackup(file, dst string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a mirage backup: %w", err)
	}
	tr := tar.NewReader(gz)
	type entry struct {
		name string
		mode os.FileMode
		dir  bool
		data []byte
	}
	var entries []entry
	hasMain := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("damaged backup: %w", err)
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe path in backup: %s", h.Name)
		}
		e := entry{name: name, mode: os.FileMode(h.Mode).Perm(), dir: h.Typeflag == tar.TypeDir}
		if h.Typeflag == tar.TypeReg {
			if e.data, err = io.ReadAll(io.LimitReader(tr, 16<<20)); err != nil {
				return err
			}
		} else if !e.dir {
			continue
		}
		if name == filepath.Base(defaultConfig) {
			hasMain = true
		}
		entries = append(entries, e)
	}
	if !hasMain {
		return errors.New("backup has no config.json; not a mirage backup")
	}
	if _, err := os.Stat(dst); err == nil {
		old := dst + ".before-restore-" + time.Now().Format("20060102-150405")
		if err := os.Rename(dst, old); err != nil {
			return err
		}
		fmt.Println("previous settings kept in", old)
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(dst, e.name)
		if e.dir {
			if err := os.MkdirAll(p, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, e.data, e.mode|0o600); err != nil {
			return err
		}
	}
	return nil
}

func backupMenu() error {
	act := "backup"
	files, _ := filepath.Glob(filepath.Join(backupDir(), "mirage-backup-*.tar.gz"))
	err := form(huh.NewGroup(huh.NewSelect[string]().Title("Backup / restore").Options(
		huh.NewOption("Create a backup now", "backup"),
		huh.NewOption("Restore from a backup file", "restore"),
		huh.NewOption("Back", "back"),
	).Value(&act))).Run()
	if err != nil || act == "back" {
		return errCancelled
	}
	if act == "backup" {
		return cmdBackup(nil)
	}
	p := ""
	if len(files) > 0 {
		p = files[len(files)-1]
	}
	var opts []huh.Option[string]
	for i := len(files) - 1; i >= 0; i-- {
		opts = append(opts, huh.NewOption(filepath.Base(files[i]), files[i]))
	}
	opts = append(opts, huh.NewOption("another file…", "other"))
	if form(huh.NewGroup(huh.NewSelect[string]().Title("Restore which backup?").Options(opts...).Value(&p))).Run() != nil {
		return errCancelled
	}
	if p == "other" || p == "" {
		p = ""
		if form(huh.NewGroup(huh.NewInput().Title("Path to the backup file").Value(&p))).Run() != nil || p == "" {
			return errCancelled
		}
	}
	if !confirm("Replace the current settings with "+filepath.Base(p)+"?", "The current settings are kept next to them as a copy.", false) {
		return errCancelled
	}
	return cmdRestore([]string{p})
}
