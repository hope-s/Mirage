package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"mirage/internal/app"
	"mirage/internal/node"
	"mirage/internal/setup"
)

type menuItem struct {
	id, title, desc, group string
}

var menuItems = []menuItem{
	{"setup", "Set up this server", "Make this server KHAREJ or IRAN in a few guided steps", "SETUP"},
	{"tunnels", "Tunnels", "Add, list or remove tunnels (including main)", "SETUP"},
	{"settings", "Tunnel settings", "Profile, encryption, auto refresh, allowed ports and forwards", "SETUP"},
	{"dash", "Live dashboard", "Links, connections and traffic, updated every second", "MONITOR"},
	{"speed", "Speed test", "Download, upload and ping through the tunnel (iran side)", "MONITOR"},
	{"linktest", "Link test", "Measure every link and get tuning advice", "MONITOR"},
	{"cfscan", "Cloudflare IP scan", "Find the fastest clean edge IPs for CDN links", "MONITOR"},
	{"panel", "Web panel", "Address and login, HTTP or HTTPS, new password", "MANAGE"},
	{"token", "Pairing token", "Show the token to paste on the iran server", "MANAGE"},
	{"restart", "Restart service", "Restart every tunnel on this server", "SYSTEM"},
	{"logs", "Live logs", "Follow the service log (Ctrl-C to stop)", "SYSTEM"},
	{"update", "Update Mirage", "Download and install the latest release", "SYSTEM"},
	{"backup", "Backup / restore", "Save or restore every setting and tunnel", "SYSTEM"},
	{"uninstall", "Uninstall", "Remove the service, settings and binary", "SYSTEM"},
	{"quit", "Exit", "", ""},
}

type statusMsg struct {
	st  app.StatusData
	err error
}

type menuModel struct {
	cursor        int
	width, height int
	cfg           *node.Config
	st            *app.StatusData
	stErr         error
	chosen        string
}

func newMenu(cursor int) menuModel {
	m := menuModel{cursor: cursor}
	m.cfg, _ = node.LoadConfig(defaultConfig)
	return m
}

func pollStatus(delay time.Duration) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(delay)
		st, err := fetchStatus(defaultConfig)
		return statusMsg{st, err}
	}
}

func (m menuModel) Init() tea.Cmd {
	if m.cfg == nil {
		return nil
	}
	return pollStatus(0)
}

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case statusMsg:
		if msg.err != nil {
			m.st, m.stErr = nil, msg.err
		} else {
			m.st, m.stErr = &msg.st, nil
		}
		return m, pollStatus(2 * time.Second)
	case tea.KeyMsg:
		switch k := msg.String(); k {
		case "ctrl+c", "q", "esc":
			m.chosen = "quit"
			return m, tea.Quit
		case "up", "k", "shift+tab":
			m.cursor = (m.cursor - 1 + len(menuItems)) % len(menuItems)
		case "down", "j", "tab":
			m.cursor = (m.cursor + 1) % len(menuItems)
		case "home", "g":
			m.cursor = 0
		case "end", "G":
			m.cursor = len(menuItems) - 1
		case "enter", " ", "right", "l":
			m.chosen = menuItems[m.cursor].id
			return m, tea.Quit
		default:
			if n, err := strconv.Atoi(k); err == nil && n >= 1 && n <= 9 {
				m.cursor = n - 1
				m.chosen = menuItems[m.cursor].id
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

const logo = `█▀▄▀█ █ █▀█ ▄▀█ █▀▀ █▀▀
█ ▀ █ █ █▀▄ █▀█ █▄█ ██▄`

func (m menuModel) header() string {
	w := m.width
	if w == 0 {
		w = 80
	}
	lg := lipgloss.NewStyle().Foreground(cAccent).Bold(true).Render(logo)
	tag := sDim.Render("v"+version) + "\n" + sDim.Render("self-healing multi-transport tunnel")
	top := lipgloss.JoinHorizontal(lipgloss.Center, lg, "   ", tag)

	var lines []string
	switch {
	case m.cfg == nil:
		lines = append(lines, sWarn.Render("● this server is not set up yet"),
			sDim.Render("choose ")+sBold.Render("Set up this server")+sDim.Render(" to start"))
	default:
		n := 1
		if m.st != nil {
			n = len(m.st.Tunnels)
		}
		head := sBold.Render(strings.ToUpper(m.cfg.Role)+" server") + sDim.Render(fmt.Sprintf(" · %d tunnel%s", n, plural(n)))
		if m.cfg.Empty() {
			head = sBold.Render("Mirage server") + sDim.Render(fmt.Sprintf(" · %d tunnel%s", n, plural(n)))
		}
		lines = append(lines, head)
		switch {
		case m.stErr != nil:
			lines = append(lines, sErr.Render("● service not running")+sDim.Render(" · choose Restart service or Live logs"))
		case m.st == nil:
			lines = append(lines, sDim.Render("● checking…"))
		default:
			for _, t := range m.st.Tunnels {
				lines = append(lines, sDim.Render(fmt.Sprintf("%-8s ", t.Name))+healthBadge(t))
			}
			if len(m.st.Tunnels) == 0 {
				lines = append(lines, sWarn.Render("● no tunnels yet")+sDim.Render(" · choose Set up this server, Tunnels or the web panel"))
			}
			in, out := lastRate(*m.st)
			lines = append(lines, sAccent.Render(fmt.Sprintf("↓ %.2f  ↑ %.2f Mbps", in, out))+
				sDim.Render(fmt.Sprintf("   up %s · mem %.0fMB", (time.Duration(m.st.UptimeS)*time.Second).String(), m.st.MemMB)))
		}
		if m.cfg.Panel != nil {
			lines = append(lines, sDim.Render("panel ")+sAccent.Render(setup.PanelURL(m.cfg.Panel, "")))
		}
	}
	box := sCard.Width(min(w-2, 76)).Render(strings.Join(lines, "\n"))
	return top + "\n\n" + box
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (m menuModel) View() string {
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n")
	group := ""
	for i, it := range menuItems {
		if it.group != group {
			group = it.group
			if group != "" {
				b.WriteString("\n " + lipgloss.NewStyle().Foreground(cAccent2).Bold(true).Render(group) + "\n")
			} else {
				b.WriteString("\n")
			}
		}
		num := "  "
		if i < 9 {
			num = strconv.Itoa(i + 1)
			num = strings.Repeat(" ", 2-len(num)) + num
		}
		if i == m.cursor {
			line := sKey.Render(" ▸ ") + sDim.Render(num) + " " + lipgloss.NewStyle().Foreground(cAccent).Bold(true).Render(it.title)
			if it.desc != "" {
				line += sDim.Render("  " + it.desc)
			}
			b.WriteString(line + "\n")
		} else {
			b.WriteString("   " + sDim.Render(num) + " " + sBold.UnsetBold().Render(it.title) + "\n")
		}
	}
	b.WriteString("\n" + sDim.Render(" ↑↓ move · enter select · 1-9 jump · q quit"))
	return b.String()
}

// menu is the interactive home screen; each choice runs in the normal
// terminal and comes back here.
func menu() error {
	if !isTTY() {
		usage()
		return nil
	}
	cursor := 0
	for {
		res, err := tea.NewProgram(newMenu(cursor), tea.WithAltScreen()).Run()
		if err != nil {
			return err
		}
		m := res.(menuModel)
		cursor = m.cursor
		if m.chosen == "quit" || m.chosen == "" {
			return nil
		}
		fmt.Print("\033[H\033[2J")
		back, err := runAction(m.chosen)
		if err != nil && err != errCancelled {
			uiErr(err)
		}
		if back && err != errCancelled {
			pause()
		}
		if m.chosen == "uninstall" && err == nil {
			if _, e := os.Stat(defaultConfig); e != nil {
				return nil
			}
		}
	}
}

// runAction runs one menu entry. back reports whether to wait for Enter
// before returning to the menu (screens that print results).
func runAction(id string) (back bool, err error) {
	switch id {
	case "setup":
		return true, wizardSetup()
	case "tunnels":
		return false, tunnelScreen()
	case "settings":
		return true, settingsScreen()
	case "dash":
		return false, dashboard()
	case "speed":
		return true, cmdSpeedtest(tunnelFlag())
	case "linktest":
		return true, cmdLinktest(tunnelFlag())
	case "cfscan":
		args := tunnelFlag()
		if confirm("Switch the CDN link to the best IPs found?", "The choice is saved and the link reconnects through them.", true) {
			args = append(args, "-apply")
		}
		return true, cmdCFScan(args)
	case "panel":
		return true, panelScreen()
	case "token":
		return true, tokenScreen()
	case "restart":
		err := spin("restarting the service", func() error { return quiet("systemctl", "restart", service) })
		if err == nil {
			fmt.Println(sOK.Render("✓ restarted"))
		}
		return true, err
	case "logs":
		return true, cmdLogs()
	case "update":
		if !confirm("Update Mirage to the latest release?", "The service restarts with the same settings.", true) {
			return false, nil
		}
		return true, cmdUpdate(nil)
	case "backup":
		return true, backupMenu()
	case "uninstall":
		if !confirm("Remove Mirage completely?", "Service, every tunnel's settings and the binary are deleted. This cannot be undone.", false) {
			return false, nil
		}
		return true, cmdUninstall()
	}
	return false, nil
}
