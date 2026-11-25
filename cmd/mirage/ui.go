package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"

	"mirage/internal/setup"
)

// ---------- palette and styles ----------

var (
	cAccent  = lipgloss.AdaptiveColor{Light: "#0E7490", Dark: "#22D3EE"}
	cAccent2 = lipgloss.AdaptiveColor{Light: "#7C3AED", Dark: "#A78BFA"}
	cGood    = lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#4ADE80"}
	cWarn    = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}
	cBad     = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"}
	cMuted   = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#9CA3AF"}
	cFaint   = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#374151"}
	cText    = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#F3F4F6"}
)

var (
	sTitle  = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sBold   = lipgloss.NewStyle().Bold(true).Foreground(cText)
	sDim    = lipgloss.NewStyle().Foreground(cMuted)
	sOK     = lipgloss.NewStyle().Foreground(cGood).Bold(true)
	sWarn   = lipgloss.NewStyle().Foreground(cWarn)
	sErr    = lipgloss.NewStyle().Foreground(cBad).Bold(true)
	sAccent = lipgloss.NewStyle().Foreground(cAccent)
	sKey    = lipgloss.NewStyle().Foreground(cAccent2).Bold(true)
	sCard   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cFaint).Padding(0, 2)
)

// isTTY reports whether we can run the interactive UI.
func isTTY() bool {
	return term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd())
}

func termWidth() int {
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// card draws a titled rounded box.
func card(title, body string) string {
	s := body
	if title != "" {
		s = sTitle.Render(title) + "\n" + body
	}
	return sCard.Render(s)
}

// kv renders aligned "key  value" rows.
func kv(rows [][2]string) string {
	w := 0
	for _, r := range rows {
		w = max(w, lipgloss.Width(r[0]))
	}
	var b strings.Builder
	for i, r := range rows {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(sDim.Render(r[0]+strings.Repeat(" ", w-lipgloss.Width(r[0]))) + "  " + sBold.Render(r[1]))
	}
	return b.String()
}

// tokenBox shows the pairing token so it can be selected and copied in one
// piece (no border characters on its lines).
func tokenBox(tok string) string {
	line := sAccent.Render(strings.Repeat("─", min(termWidth(), 72)))
	return sTitle.Render("PAIRING TOKEN") + sDim.Render("  copy all of it to the iran server") + "\n" +
		line + "\n" + tok + "\n" + line
}

func printNotes(notes []setup.Note) {
	for _, n := range notes {
		fmt.Println(sWarn.Render("! ") + n.En)
	}
}

func uiErr(err error) {
	fmt.Println(sErr.Render("✗ ") + err.Error())
}

// pause waits for any key so the user can read a result.
func pause() {
	if !isTTY() {
		return
	}
	fmt.Print(sDim.Render("\npress any key to go back "))
	if st, err := term.MakeRaw(os.Stdin.Fd()); err == nil {
		var b [16]byte
		_, _ = os.Stdin.Read(b[:])
		_ = term.Restore(os.Stdin.Fd(), st)
	} else {
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	fmt.Println()
}

// theme is the form style used by every wizard.
func theme() *huh.Theme {
	t := huh.ThemeCharm()
	t.Focused.Title = t.Focused.Title.Foreground(cAccent)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(cAccent)
	t.Focused.Base = t.Focused.Base.BorderForeground(cAccent)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(cAccent2)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(cAccent2)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(cGood)
	t.Focused.SelectedPrefix = t.Focused.SelectedPrefix.Foreground(cGood)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Background(cAccent).Foreground(lipgloss.Color("#0B1220"))
	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(cAccent2)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(cAccent2)
	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	return t
}

// keymap makes Esc leave a form (like Ctrl-C) and drops list filtering.
func keymap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("ctrl+c", "esc"), key.WithHelp("esc", "back"))
	km.Select.Filter.SetEnabled(false)
	km.MultiSelect.Filter.SetEnabled(false)
	return km
}

func form(groups ...*huh.Group) *huh.Form {
	return huh.NewForm(groups...).WithTheme(theme()).WithKeyMap(keymap()).WithWidth(min(termWidth(), 90))
}

// confirm asks a yes/no question; Esc or Ctrl-C answers no.
func confirm(title, desc string, def bool) bool {
	v := def
	err := form(huh.NewGroup(huh.NewConfirm().Title(title).Description(desc).
		Affirmative("Yes").Negative("No").Value(&v))).Run()
	return err == nil && v
}

// ---------- spinner ----------

type spinDone struct{ err error }

type spinModel struct {
	sp    spinner.Model
	title string
	err   error
	done  bool
	run   func() error
}

func (m spinModel) Init() tea.Cmd {
	return tea.Batch(m.sp.Tick, func() tea.Msg { return spinDone{m.run()} })
}

func (m spinModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinDone:
		m.done, m.err = true, msg.err
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.done, m.err = true, errCancelled
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.sp, cmd = m.sp.Update(msg)
	return m, cmd
}

func (m spinModel) View() string {
	if m.done {
		return ""
	}
	return m.sp.View() + " " + m.title + "\n"
}

var errCancelled = fmt.Errorf("cancelled")

// spin runs fn while showing an animated spinner (plain text without a TTY).
// fn must not print.
func spin(title string, fn func() error) error {
	if !isTTY() {
		fmt.Println(title + "...")
		return fn()
	}
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(sAccent))
	res, err := tea.NewProgram(spinModel{sp: sp, title: title, run: fn}).Run()
	if err != nil {
		return err
	}
	return res.(spinModel).err
}
