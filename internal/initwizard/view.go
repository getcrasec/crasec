package initwizard

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	valueStyle    = lipgloss.NewStyle().Bold(true)
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	footerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true)
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Italic(true)
)

func (m Model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("crasec init — %s", filepath.Base(m.cwd))))
	b.WriteString("\n")
	b.WriteString(footerStyle.Render(fmt.Sprintf("Step %d of %d", m.stepNumber(), m.totalSteps())))
	b.WriteString("\n\n")

	switch m.step {
	case stepEcosystem:
		b.WriteString(m.viewEcosystemStep())
	case stepReview:
		b.WriteString(m.viewReviewStep())
	default:
		b.WriteString(m.viewTextStep())
	}

	return b.String()
}

func (m Model) stepNumber() int {
	n := 0
	if !m.skipEcosystemStep {
		n++
		if m.step == stepEcosystem {
			return n
		}
	}
	for _, s := range []step{stepProductName, stepProductVersion, stepManufacturerName, stepManufacturerAddress, stepScanTarget, stepReview} {
		n++
		if m.step == s {
			return n
		}
	}
	return n
}

func (m Model) totalSteps() int {
	if m.skipEcosystemStep {
		return 6
	}
	return 7
}

func (m Model) viewEcosystemStep() string {
	var b strings.Builder
	if len(m.detected) == 0 {
		b.WriteString(labelStyle.Render("No go.mod / package.json / pom.xml / Cargo.toml / requirements.txt found here.") + "\n")
	} else {
		names := make([]string, len(m.detected))
		for i, d := range m.detected {
			names[i] = d.Manifest
		}
		b.WriteString(labelStyle.Render("Found: "+strings.Join(names, ", ")+" — more than one ecosystem detected.") + "\n")
	}
	b.WriteString("\nWhich is the primary language/ecosystem?\n")
	for i, e := range KnownEcosystems {
		if i == m.ecosystemCursor {
			b.WriteString(selectedStyle.Render("> "+e) + "\n")
			continue
		}
		b.WriteString("  " + e + "\n")
	}
	b.WriteString("\n" + footerStyle.Render("[up/down] choose    [enter] confirm    [ctrl+c] quit"))
	return b.String()
}

func (m Model) viewTextStep() string {
	label, help := m.currentLabel()

	var b strings.Builder
	if help != "" {
		b.WriteString(helpStyle.Render(help) + "\n")
	}
	b.WriteString(renderTextInput(label, m.textBuffer))
	if m.validationMsg != "" {
		b.WriteString("\n" + errorStyle.Render(m.validationMsg) + "\n")
	}
	b.WriteString("\n" + footerStyle.Render("[enter] confirm/next    [ctrl+c] quit"))
	return b.String()
}

func (m Model) currentLabel() (label, help string) {
	switch m.step {
	case stepProductName:
		return "Product name", "Becomes --product across crasec commands, and part of every generated filename."
	case stepProductVersion:
		return "Product version", "Optional; stored for reference (e.g. \"1.0.0\")."
	case stepManufacturerName:
		return "Manufacturer name", "The legal entity issuing the EU Declaration of Conformity."
	case stepManufacturerAddress:
		return "Manufacturer address", "Must be an EU-registered address — required by CRA Annex V for the Declaration of Conformity."
	case stepScanTarget:
		return "Scan target", `Passed to "crasec sbom generate --target"; usually "." for the current directory.`
	default:
		return "", ""
	}
}

func (m Model) viewReviewStep() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Review") + "\n\n")

	rows := [][2]string{
		{"Ecosystem", m.ecosystem},
		{"Product name", m.productName},
		{"Product version", orDash(m.productVersion)},
		{"Manufacturer", m.manufacturerName},
		{"Manufacturer address", m.manufacturerAddress},
		{"Scan target", m.scanTarget},
	}
	for _, r := range rows {
		b.WriteString(labelStyle.Render(padLabel(r[0])) + " " + valueStyle.Render(r[1]) + "\n")
	}

	b.WriteString("\n" + footerStyle.Render("[enter] write .crasec.yaml    [b] back to make changes    [q] quit without saving"))
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func padLabel(s string) string {
	return fmt.Sprintf("%-22s", s+":")
}

func renderTextInput(label, value string) string {
	return fmt.Sprintf("%s\n%s%s\n", labelStyle.Render(label), value, valueStyle.Render("_"))
}
