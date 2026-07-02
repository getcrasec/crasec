package vextriage

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/getcrasec/crasec/internal/vulnscan"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	cardStyle  = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1).
			MarginBottom(1)
	labelStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	valueStyle     = lipgloss.NewStyle().Bold(true)
	selectedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	exploitedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	errorStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	footerStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true)
	doneStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
)

func (m Model) View() string {
	if len(m.queue) == 0 {
		return doneStyle.Render(fmt.Sprintf("\nAll findings triaged (%d confirmed). Progress saved to %s.\n", m.confirmed, m.draftPath))
	}

	g := m.groups[m.queue[0]]
	f := g.components[0]

	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf(
		"VEX Triage — %d confirmed / %d total (%d pending, %d skipped this session)",
		m.confirmed, len(m.groups), len(m.queue), m.skipped,
	)))
	b.WriteString("\n\n")

	card := fmt.Sprintf(
		"%s %s\n%s %s\n%s %.1f (%s)   %s %.1f [%s]%s",
		labelStyle.Render("Vulnerability:"), valueStyle.Render(g.id),
		labelStyle.Render("Component:   "), valueStyle.Render(describeComponents(g.components)),
		labelStyle.Render("CVSS:"), f.CVSSScore, f.Severity,
		labelStyle.Render("CRA score:"), f.CRARelevanceScore, f.CRACategory,
		exploitedSuffix(f),
	)
	b.WriteString(cardStyle.Render(card))
	b.WriteString("\n")

	switch m.step {
	case stepStatus:
		b.WriteString(renderOptions("Status", statusLabels(), m.statusCursor))
	case stepJustification:
		b.WriteString(renderOptions("Justification (why not_affected?)", justificationLabels(), m.justCursor))
	case stepActionStatement:
		b.WriteString(renderTextInput("Action statement (required) — what are you doing about this?", m.textBuffer.String()))
	case stepFixedVersion:
		b.WriteString(renderTextInput("Fixed version (required)", m.textBuffer.String()))
	case stepNotes:
		b.WriteString(renderTextInput("Notes (optional, additional context)", m.textBuffer.String()))
	}

	if m.validationMsg != "" {
		b.WriteString("\n" + errorStyle.Render(m.validationMsg) + "\n")
	}

	b.WriteString("\n" + footerStyle.Render("[enter] confirm/next    [tab] skip, come back later    [q] save & quit"))
	return b.String()
}

func describeComponents(components []vulnscan.Finding) string {
	f := components[0]
	if len(components) == 1 {
		return fmt.Sprintf("%s@%s", f.PackageName, f.PackageVersion)
	}
	return fmt.Sprintf("%s@%s (+%d more)", f.PackageName, f.PackageVersion, len(components)-1)
}

func exploitedSuffix(f vulnscan.Finding) string {
	if !f.ActivelyExploited {
		return ""
	}
	return "  " + exploitedStyle.Render("ACTIVELY EXPLOITED (KEV)")
}

func statusLabels() []string {
	labels := make([]string, len(statusOptions))
	for i, s := range statusOptions {
		labels[i] = statusDescriptions[s]
	}
	return labels
}

func justificationLabels() []string {
	labels := make([]string, len(justificationOptions))
	for i, j := range justificationOptions {
		labels[i] = justificationDescriptions[j]
	}
	return labels
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
