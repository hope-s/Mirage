package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"mirage/internal/app"
)

type dashModel struct {
	st            *app.StatusData
	err           error
	width, height int
	sessions      bool
	tunnel        int // -1 = all
}

func (m dashModel) Init() tea.Cmd { return pollStatus(0) }

func (m dashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case statusMsg:
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.st, m.err = &msg.st, nil
		}
		return m, pollStatus(time.Second)
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c", "left", "h":
			return m, tea.Quit
		case "c":
			m.sessions = !m.sessions
		case "tab", "right", "l":
			if m.st != nil && len(m.st.Tunnels) > 1 {
				m.tunnel++
				if m.tunnel >= len(m.st.Tunnels) {
					m.tunnel = -1
				}
			}
		}
	}
	return m, nil
}

var sparks = []rune("▁▂▃▄▅▆▇█")

// sparkline draws the last width values scaled to their maximum.
func sparkline(vals []float64, width int) string {
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	top := 1.0 // Mbps; keeps idle keepalive traffic flat
	for _, v := range vals {
		top = max(top, v)
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", width-len(vals)))
	for _, v := range vals {
		i := 0
		if top > 0 {
			i = int(v / top * float64(len(sparks)-1))
		}
		b.WriteRune(sparks[i])
	}
	return b.String()
}

func (m dashModel) View() string {
	w := m.width
	if w == 0 {
		w = 100
	}
	title := lipgloss.NewStyle().Foreground(cAccent).Bold(true).Render("MIRAGE") + sDim.Render(" · live dashboard")
	if m.st == nil {
		msg := sDim.Render("connecting to the service…")
		if m.err != nil {
			msg = sErr.Render("● ") + m.err.Error()
		}
		return title + "\n\n" + msg + "\n\n" + sDim.Render(" q back")
	}
	st := *m.st
	info := sDim.Render(fmt.Sprintf("%s · up %s · mem %.0fMB", strings.ToUpper(st.Role), (time.Duration(st.UptimeS) * time.Second).String(), st.MemMB))
	if st.Load != "" {
		info += sDim.Render(" · load " + st.Load)
	}
	if m.err != nil {
		info += "  " + sErr.Render("● stale: "+m.err.Error())
	}
	head := title + "   " + info

	var in, out []float64
	for _, p := range st.History {
		in, out = append(in, p.In), append(out, p.Out)
	}
	ci, co := lastRate(st)
	pi, po := 0.0, 0.0
	for i := range in {
		pi, po = max(pi, in[i]), max(po, out[i])
	}
	sw := min(w-34, 90)
	traffic := lipgloss.JoinVertical(lipgloss.Left,
		sAccent.Render(fmt.Sprintf("↓ in  %7.2f Mbps ", ci))+lipgloss.NewStyle().Foreground(cAccent).Render(sparkline(in, sw))+sDim.Render(fmt.Sprintf(" peak %.1f", pi)),
		lipgloss.NewStyle().Foreground(cAccent2).Render(fmt.Sprintf("↑ out %7.2f Mbps ", co))+lipgloss.NewStyle().Foreground(cAccent2).Render(sparkline(out, sw))+sDim.Render(fmt.Sprintf(" peak %.1f", po)),
	)
	parts := []string{head, "", sCard.Width(min(w, 120) - 2).Render(traffic)}
	for i, t := range st.Tunnels {
		if m.tunnel >= 0 && i != m.tunnel {
			continue
		}
		parts = append(parts, renderTunnelCard(t, w, m.sessions))
	}
	if len(st.Tunnels) == 0 {
		parts = append(parts, sDim.Render("no tunnels on this server yet"))
	}
	keys := " q back · c connections"
	if len(st.Tunnels) > 1 {
		keys += " · tab switch tunnel"
	}
	parts = append(parts, sDim.Render(keys))
	return strings.Join(parts, "\n")
}

func dashboard() error {
	_, err := tea.NewProgram(dashModel{tunnel: -1}, tea.WithAltScreen()).Run()
	return err
}
