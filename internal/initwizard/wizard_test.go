package initwizard

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func enter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func down() tea.KeyMsg  { return tea.KeyMsg{Type: tea.KeyDown} }
func runes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestDetectEcosystems_FindsGoMod(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	found := DetectEcosystems(dir)
	if len(found) != 1 || found[0].Ecosystem != "go" {
		t.Fatalf("expected exactly [go], got %v", found)
	}
}

func TestDetectEcosystems_MonorepoFindsBoth(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644)

	found := DetectEcosystems(dir)
	if len(found) != 2 {
		t.Fatalf("expected 2 ecosystems detected, got %v", found)
	}
}

func TestNewModel_SkipsEcosystemStepOnSingleDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)

	m := newModel(dir, nil)
	if !m.skipEcosystemStep || m.ecosystem != "go" {
		t.Fatalf("expected ecosystem step skipped with ecosystem=go, got skip=%v ecosystem=%q", m.skipEcosystemStep, m.ecosystem)
	}
	if m.step != stepProductName {
		t.Fatalf("expected to land on stepProductName, got %v", m.step)
	}
	if m.productName != filepath.Base(dir) {
		t.Fatalf("expected product name defaulted to dir basename %q, got %q", filepath.Base(dir), m.productName)
	}
}

func TestNewModel_AsksWhenAmbiguous(t *testing.T) {
	dir := t.TempDir() // no manifests at all
	m := newModel(dir, nil)
	if m.skipEcosystemStep {
		t.Fatal("expected the ecosystem step to be asked when nothing was detected")
	}
	if m.step != stepEcosystem {
		t.Fatalf("expected to land on stepEcosystem, got %v", m.step)
	}
}

func TestFullFlow_CollectsAllFieldsAndReturnsConfig(t *testing.T) {
	dir := t.TempDir() // ambiguous: forces the ecosystem step
	m := newModel(dir, nil)

	// Ecosystem: move down once (node), confirm.
	tm, _ := m.Update(down())
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)
	if m.ecosystem != KnownEcosystems[1] {
		t.Fatalf("expected ecosystem %q, got %q", KnownEcosystems[1], m.ecosystem)
	}
	if m.step != stepProductName {
		t.Fatalf("expected stepProductName next, got %v", m.step)
	}

	// Product name: clear the pre-filled default and type a real one.
	for range m.textBuffer {
		tm, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		m = tm.(Model)
	}
	tm, _ = m.Update(runes("myapp"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)

	// Product version: accept the pre-filled default as-is.
	tm, _ = m.Update(enter())
	m = tm.(Model)

	// Manufacturer name.
	tm, _ = m.Update(runes("Acme Corp"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)

	// Manufacturer address.
	tm, _ = m.Update(runes("1 Rue de la Paix, 75002 Paris, France"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)

	// Scan target: accept default ".".
	tm, _ = m.Update(enter())
	m = tm.(Model)

	if m.step != stepReview {
		t.Fatalf("expected stepReview after the last field, got %v", m.step)
	}

	// Confirm at review.
	tm, cmd := m.Update(enter())
	m = tm.(Model)
	if cmd == nil {
		t.Fatal("expected confirming the review step to issue tea.Quit")
	}
	if m.quit {
		t.Fatal("expected quit=false on a completed (not aborted) wizard")
	}

	if m.productName != "myapp" || m.manufacturerName != "Acme Corp" || m.scanTarget != "." {
		t.Fatalf("unexpected final field values: %+v", m)
	}
}

func TestRequiredFieldValidation_BlocksEmptyProductName(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
	m := newModel(dir, nil) // lands on stepProductName with a pre-filled default

	for range m.textBuffer {
		tm, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		m = tm.(Model)
	}
	tm, _ := m.Update(enter())
	m = tm.(Model)

	if m.step != stepProductName {
		t.Fatalf("expected to stay on stepProductName when it's blank, got %v", m.step)
	}
	if m.validationMsg == "" {
		t.Fatal("expected a validation message for a required-but-empty field")
	}
}

func TestReviewStep_BackReturnsToStartWithValuesPreserved(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
	m := newModel(dir, nil)
	m.step = stepReview
	m.productName = "myapp"

	tm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("b")})
	m = tm.(Model)

	if m.step != stepProductName {
		t.Fatalf("expected 'b' to return to stepProductName (ecosystem already settled), got %v", m.step)
	}
	if m.productName != "myapp" {
		t.Fatal("expected product name to survive going back")
	}
}

func TestQuit_ReportsIncomplete(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
	m := newModel(dir, nil)

	tm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = tm.(Model)
	if cmd == nil || !m.quit {
		t.Fatal("expected Ctrl+C to quit with quit=true")
	}
}
