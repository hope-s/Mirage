package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"mirage/internal/app"
	"mirage/internal/node"
)

// grid renders rows as a borderless table with a dim header.
func grid(headers []string, rows [][]string) string {
	return table.New().
		Border(lipgloss.HiddenBorder()).BorderTop(false).BorderBottom(false).
		BorderLeft(false).BorderRight(false).BorderColumn(false).BorderHeader(false).
		Headers(headers...).Rows(rows...).
		StyleFunc(func(row, _ int) lipgloss.Style {
			s := lipgloss.NewStyle().PaddingRight(2)
			if row == table.HeaderRow {
				return s.Foreground(cMuted).Bold(true)
			}
			return s
		}).String()
}

func fetchStatus(cfgPath string) (app.StatusData, error) {
	var st app.StatusData
	u, err := statusURL(cfgPath)
	if err != nil {
		return st, err
	}
	cl := http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get(u + "/")
	if err != nil {
		return st, fmt.Errorf("service not reachable - is it running? (%w)", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(body, &st)
	if len(st.Tunnels) == 0 {
		st.Tunnels = []app.TunnelStatus{{Name: app.MainTunnel, Status: st.Status, Profile: st.Profile, Running: true}}
	}
	return st, err
}

// linkState classifies a link for display.
func linkState(l linkView) (dot, label string) {
	switch {
	case l.Disabled:
		return sDim.Render("○"), sDim.Render("disabled")
	case l.Up > 0 && (l.Want == 0 || int(l.Up) >= l.Want):
		return sOK.Render("●"), sOK.Render("healthy")
	case l.Up > 0:
		return sWarn.Render("●"), sWarn.Render("partial")
	case l.Kind == "listen":
		return sDim.Render("○"), sDim.Render("waiting")
	case l.Backup:
		return sDim.Render("○"), sDim.Render("standby")
	default:
		return sErr.Render("●"), sErr.Render("down")
	}
}

// linkView is the JSON shape of node.Status links (the node type is unexported).
type linkView struct {
	Name, Kind, Transport, LastError string
	Want                             int
	Backup, Disabled                 bool
	Up                               int32
}

func linksOf(st node.Status) []linkView {
	var out []linkView
	b, _ := json.Marshal(st.Links)
	var raw []struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Transport string `json:"transport"`
		Want      int    `json:"want"`
		Backup    bool   `json:"backup"`
		Disabled  bool   `json:"disabled"`
		Up        int32  `json:"up"`
		LastError string `json:"last_error"`
	}
	_ = json.Unmarshal(b, &raw)
	for _, r := range raw {
		out = append(out, linkView{r.Name, r.Kind, r.Transport, r.LastError, r.Want, r.Backup, r.Disabled, r.Up})
	}
	return out
}

// linkRTT is the best ping among a link's live connections.
func linkRTT(st node.Status, name string) float64 {
	best := 0.0
	for _, s := range st.Sessions {
		if s.Link == name && s.RTTms > 0 && (best == 0 || s.RTTms < best) {
			best = s.RTTms
		}
	}
	return best
}

func ms(v float64) string {
	if v <= 0 {
		return sDim.Render("-")
	}
	s := fmt.Sprintf("%.0fms", v)
	if v < 1 {
		s = "<1ms"
	}
	switch {
	case v < 120:
		return sOK.Render(s)
	case v < 300:
		return sWarn.Render(s)
	}
	return sErr.Render(s)
}

func trunc(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func renderLinks(st node.Status, width int) string {
	var rows [][]string
	for _, l := range linksOf(st) {
		dot, label := linkState(l)
		up := strconv.Itoa(int(l.Up))
		if l.Want > 0 {
			up += "/" + strconv.Itoa(l.Want)
		}
		role := l.Kind
		if l.Backup {
			role += " · backup"
		}
		note := ""
		if l.LastError != "" && l.Up == 0 && !l.Disabled {
			note = sDim.Render(trunc(l.LastError, max(20, width-70)))
		}
		rows = append(rows, []string{dot + " " + sBold.Render(l.Name), l.Transport, sDim.Render(role), label, up, ms(linkRTT(st, l.Name)), note})
	}
	if len(rows) == 0 {
		return sDim.Render("no links")
	}
	return grid([]string{"LINK", "TRANSPORT", "SIDE", "STATE", "CONNS", "PING", ""}, rows)
}

func renderSessions(st node.Status) string {
	var rows [][]string
	for _, s := range st.Sessions {
		state := sOK.Render("active")
		if s.Draining {
			state = sDim.Render("draining")
		}
		rows = append(rows, []string{s.Link, s.Remote, ms(s.RTTms), s.Cipher, strconv.Itoa(s.Streams),
			(time.Duration(s.AgeSec) * time.Second).String(), human(s.BytesIn), human(s.BytesOut), state})
	}
	if len(rows) == 0 {
		return sDim.Render("(no live connections yet)")
	}
	return grid([]string{"LINK", "REMOTE", "PING", "CIPHER", "STREAMS", "AGE", "IN", "OUT", "STATE"}, rows)
}

// tunnelHealth summarises a tunnel as "3/4 links up".
func tunnelHealth(st node.Status) (up, total int) {
	for _, l := range linksOf(st) {
		if l.Disabled {
			continue
		}
		total++
		if l.Up > 0 {
			up++
		}
	}
	return
}

func healthBadge(t app.TunnelStatus) string {
	if !t.Running {
		return sErr.Render("● stopped")
	}
	up, total := tunnelHealth(t.Status)
	s := fmt.Sprintf("%d/%d links up", up, total)
	listenOnly := true
	for _, l := range linksOf(t.Status) {
		if l.Kind != "listen" {
			listenOnly = false
		}
	}
	switch {
	case len(t.Sessions) == 0 && listenOnly:
		return sWarn.Render("● waiting for the other server") + sDim.Render(" · "+s)
	case len(t.Sessions) == 0:
		return sErr.Render("● no connection") + sDim.Render(" · "+s)
	case up == total:
		return sOK.Render("● connected") + sDim.Render(" · "+s)
	}
	return sWarn.Render("● degraded") + sDim.Render(" · "+s)
}

func lastRate(st app.StatusData) (in, out float64) {
	if h := st.History; len(h) > 0 {
		return h[len(h)-1].In, h[len(h)-1].Out
	}
	return 0, 0
}

func renderTunnelCard(t app.TunnelStatus, width int, sessions bool) string {
	head := sTitle.Render("tunnel "+t.Name) + "  " + sDim.Render(strings.ToUpper(orDefault(t.Role, "?"))+" · "+orDefault(t.Profile, "balanced")) +
		"   " + healthBadge(t)
	parts := []string{head, "", renderLinks(t.Status, width)}
	if len(t.Forwards) > 0 {
		parts = append(parts, "", sDim.Render("serves  ")+strings.Join(t.Forwards, sDim.Render("  ·  ")))
	}
	if sessions {
		parts = append(parts, "", renderSessions(t.Status))
	}
	return sCard.Width(min(width, 120) - 2).Render(strings.Join(parts, "\n"))
}

func renderStatus(st app.StatusData, width int) string {
	in, out := lastRate(st)
	head := sTitle.Render("MIRAGE "+st.Version) + sDim.Render(fmt.Sprintf("   up %s · mem %.0fMB", (time.Duration(st.UptimeS)*time.Second).String(), st.MemMB)) +
		"   " + sAccent.Render(fmt.Sprintf("↓ %.2f  ↑ %.2f Mbps", in, out))
	parts := []string{head}
	for _, t := range st.Tunnels {
		parts = append(parts, renderTunnelCard(t, width, true))
	}
	return strings.Join(parts, "\n")
}

func renderSpeed(r node.SpeedResult) string {
	bar := func(v float64) string {
		n := min(int(v/5), 30) // one block per 5 Mbps
		return sAccent.Render(strings.Repeat("█", n)) + sDim.Render(strings.Repeat("░", 30-n))
	}
	return card("Speed test", kv([][2]string{
		{"download", fmt.Sprintf("%7.1f Mbps  ", r.DownMbps) + bar(r.DownMbps)},
		{"upload", fmt.Sprintf("%7.1f Mbps  ", r.UpMbps) + bar(r.UpMbps)},
		{"ping", fmt.Sprintf("%7.0f ms", r.RTTms)},
	}))
}

func renderLinkTest(r node.LinkTestResult) string {
	var rows [][]string
	for _, l := range r.Links {
		ok := fmt.Sprintf("%d/%d", l.OK, l.Tries)
		switch {
		case l.OK == l.Tries && l.Tries > 0:
			ok = sOK.Render(ok)
		case l.OK == 0:
			ok = sErr.Render(ok)
		default:
			ok = sWarn.Render(ok)
		}
		retrans := sDim.Render("-")
		if l.Retrans > 0 || l.Transport == "kcp" || l.Transport == "ftcp" {
			retrans = fmt.Sprintf("%.1f%%", l.Retrans*100)
		}
		name := l.Name
		if l.Name == r.Best {
			name = sOK.Render("★ " + name)
		}
		rows = append(rows, []string{name, l.Transport, ok, ms(l.HandshakeMs), fmt.Sprintf("%.0fms", l.JitterMs), ms(l.RTTms),
			fmt.Sprintf("%.1f Mbps", l.UpMbps), retrans})
	}
	var b strings.Builder
	b.WriteString(grid([]string{"LINK", "TRANSPORT", "OK", "CONNECT", "JITTER", "PING", "UPLOAD", "RETRANS"}, rows))
	if len(r.Advice) > 0 {
		b.WriteString("\n\n" + sTitle.Render("Advice"))
		for _, a := range r.Advice {
			b.WriteString("\n" + sAccent.Render("› ") + a)
		}
	}
	return card("Link test", b.String())
}

func renderScan(r node.ScanReport, applied bool) string {
	var rows [][]string
	for i, x := range r.Results {
		if i >= 15 {
			break
		}
		note := ""
		if !x.OK() {
			note = sDim.Render(trunc(x.Err, 50))
		}
		addr := x.Addr
		if i == 0 && x.OK() {
			addr = sOK.Render("★ " + addr)
		}
		rows = append(rows, []string{addr, ms(x.ConnMs), ms(x.RTTms), fmt.Sprintf("%.0fms", x.JitterMs), fmt.Sprintf("%.0f%%", x.Loss*100), note})
	}
	var b strings.Builder
	b.WriteString(grid([]string{"ADDRESS", "TCP", "TUNNEL", "JITTER", "FAILED", ""}, rows))
	if r.Err != "" {
		b.WriteString("\n\n" + sWarn.Render("! ") + r.Err)
	}
	if len(r.Applied) > 0 {
		b.WriteString("\n\n" + sOK.Render("✓ link "+r.Link+" now uses ") + strings.Join(r.Applied, ", "))
	} else if !applied {
		b.WriteString("\n\n" + sDim.Render("run with -apply to switch the link to the best IPs"))
	}
	return card("Cloudflare edge scan · link "+r.Link, b.String())
}
