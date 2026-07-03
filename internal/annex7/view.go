package annex7

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	valueStyle    = lipgloss.NewStyle().Bold(true)
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	doneMarkStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	pendingStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	footerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true)
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Italic(true)
)

// View renders the current wizard step: the section overview, or the field
// currently being prompted for.
func (m Model) View() string {
	if m.step == stepOverview {
		return m.viewOverview()
	}
	return m.viewField()
}

func (m Model) viewOverview() string {
	done, total := Completion(m.doc)

	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf(
		"CRA Annex VII Technical File — %s — %d/%d sections complete", m.doc.Product, done, total,
	)))
	b.WriteString("\n" + progressBar(done, total, 30) + "\n\n")

	for i, s := range sections {
		mark := pendingStyle.Render("[ ]")
		if SectionComplete(m.doc, i) {
			mark = doneMarkStyle.Render("[x]")
		}
		line := fmt.Sprintf("%s %2d. %s", mark, s.number, s.title)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("> "+line) + "\n")
			continue
		}
		b.WriteString("  " + line + "\n")
	}

	b.WriteString("\n" + footerStyle.Render("[up/down] move    [enter] edit section    [q] save & quit"))
	return b.String()
}

func (m Model) viewField() string {
	s := sections[m.activeSection]
	f := s.fields[m.fieldIndex]

	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf(
		"Section %d: %s — field %d/%d", s.number, s.title, m.fieldIndex+1, len(s.fields),
	)))
	b.WriteString("\n\n")

	if f.help != "" {
		b.WriteString(helpStyle.Render(f.help) + "\n")
	}

	if f.isChoice() {
		b.WriteString(renderOptions(f.label, f.choiceOptions(), m.selectCursor))
	} else {
		b.WriteString(renderTextInput(f.label, m.textBuffer))
	}

	b.WriteString("\n" + footerStyle.Render("[enter] confirm/next    [esc] back to sections    [ctrl+c] quit without saving this field"))
	return b.String()
}

func renderOptions(title string, options []string, cursor int) string {
	var b strings.Builder
	b.WriteString(labelStyle.Render(title) + "\n")
	for i, opt := range options {
		if i == cursor {
			b.WriteString(selectedStyle.Render("> "+opt) + "\n")
			continue
		}
		b.WriteString("  " + opt + "\n")
	}
	return b.String()
}

func renderTextInput(label, value string) string {
	return fmt.Sprintf("%s\n%s%s\n", labelStyle.Render(label), value, valueStyle.Render("_"))
}

func progressBar(done, total, width int) string {
	if total == 0 {
		return ""
	}
	filled := done * width / total
	if filled > width {
		filled = width
	}
	return doneMarkStyle.Render(strings.Repeat("█", filled)) + pendingStyle.Render(strings.Repeat("░", width-filled))
}
