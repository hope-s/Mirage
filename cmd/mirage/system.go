package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	service   = "mirage"
	binPath   = "/usr/local/bin/mirage"
	unitPath  = "/etc/systemd/system/mirage.service"
	sysctlCfg = "/etc/sysctl.d/99-mirage.conf"
)

const unit = `[Unit]
Description=Mirage tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mirage run -c /etc/mirage/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
LimitNOFILE=1048576
TasksMax=infinity
# keep the Go runtime lean on small VPSes
Environment=GOGC=80

[Install]
WantedBy=multi-user.target
`

// Network tuning for long fat pipes and many connections. BBR + fq gives
// much better throughput and latency on lossy international links.
const sysctls = `# written by mirage
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65000
net.ipv4.tcp_keepalive_time = 600
fs.file-max = 2097152
`

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("run this as root (sudo)")
	}
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func quiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func systemctl(args ...string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd not found; run 'mirage run' under your own supervisor")
	}
	return run("systemctl", args...)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst) // atomic: safe even while the old binary runs
}

// cmdInstall installs the binary, systemd unit and kernel tuning. It is
// idempotent and doubles as "update" when run from a newer binary.
func cmdInstall() error {
	if err := needRoot(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	if self != binPath {
		if err := copyFile(self, binPath, 0o755); err != nil {
			return fmt.Errorf("installing binary: %w", err)
		}
	}
	fmt.Println("✓ binary installed:", binPath)
	if err := os.MkdirAll("/etc/mirage", 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	_ = quiet("modprobe", "tcp_bbr")
	if err := os.WriteFile(sysctlCfg, []byte(sysctls), 0o644); err == nil {
		_ = quiet("sysctl", "-p", sysctlCfg)
		out, _ := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output()
		if strings.TrimSpace(string(out)) == "bbr" {
			fmt.Println("✓ network tuned (BBR + fq, larger buffers)")
		} else {
			fmt.Println("! network buffers tuned; BBR not available on this kernel")
		}
	}
	// the handshake rejects clocks that are >2 min apart; keep time synced
	_ = quiet("timedatectl", "set-ntp", "true")
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	_ = quiet("systemctl", "enable", service)
	fmt.Println("✓ service installed (starts on boot)")
	if _, err := os.Stat(defaultConfig); err == nil {
		if err := systemctl("restart", service); err != nil {
			return err
		}
		fmt.Println("✓ service (re)started")
	} else {
		fmt.Println("next: run 'mirage' and choose setup, or 'mirage setup kharej' / 'mirage setup iran'")
	}
	return nil
}

func cmdUninstall() error {
	if err := needRoot(); err != nil {
		return err
	}
	_ = quiet("systemctl", "disable", "--now", service)
	_ = os.Remove(unitPath)
	_ = quiet("systemctl", "daemon-reload")
	_ = os.Remove(sysctlCfg)
	_ = os.RemoveAll("/etc/mirage")
	_ = os.Remove(binPath)
	fmt.Println("mirage removed (service, config, binary)")
	return nil
}

func cmdLogs() error {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return errors.New("journalctl not found")
	}
	return run("journalctl", "-u", service, "-n", "100", "-f", "--no-hostname", "-o", "cat")
}

// startService installs (if needed) and (re)starts the service after setup.
func startService() error {
	if _, err := os.Stat(unitPath); err != nil {
		return cmdInstall()
	}
	return systemctl("restart", service)
}
