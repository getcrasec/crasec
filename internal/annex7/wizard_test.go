package annex7

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func enter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func down() tea.KeyMsg  { return tea.KeyMsg{Type: tea.KeyDown} }
func esc() tea.KeyMsg   { return tea.KeyMsg{Type: tea.KeyEsc} }
func runes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestCompletion_EmptyDocIsZeroOfTen(t *testing.T) {
	doc := New("myapp")
	done, total := Completion(doc)
	if total != 10 {
		t.Fatalf("expected 10 sections, got %d", total)
	}
	if done != 0 {
		t.Fatalf("expected 0 complete sections for a fresh scaffold, got %d", done)
	}
}

func TestSectionComplete_Section5_StandardsNotRequiredWhenAssessedDirectly(t *testing.T) {
	doc := New("myapp")
	doc.Standards.AssessedToAnnexIDirectly = true
	if !SectionComplete(doc, 4) { // section index 4 == section number 5
		t.Fatal("expected section 5 complete when assessed_to_annex_i_directly is true and standards is empty")
	}

	doc.Standards.AssessedToAnnexIDirectly = false
	if SectionComplete(doc, 4) {
		t.Fatal("expected section 5 incomplete when not assessed directly and standards is empty")
	}
	doc.Standards.Standards = []string{"IEC 62443"}
	if !SectionComplete(doc, 4) {
		t.Fatal("expected section 5 complete once standards is populated")
	}
}

func TestSectionComplete_Section8_NotifiedBodyOnlyRequiredWhenNotSelfAssessed(t *testing.T) {
	doc := New("myapp")
	doc.Conformity.Class = ClassDefault
	doc.Conformity.SelfAssessment = true
	if !SectionComplete(doc, 7) { // section index 7 == section number 8
		t.Fatal("expected section 8 complete for a self-assessed default-class product")
	}

	doc.Conformity.SelfAssessment = false
	if SectionComplete(doc, 7) {
		t.Fatal("expected section 8 incomplete once not self-assessed and notified body fields are empty")
	}
	doc.Conformity.NotifiedBodyName = "TÜV"
	doc.Conformity.NotifiedBodyID = "1234"
	doc.Conformity.CertificateReference = "CERT-1"
	if !SectionComplete(doc, 7) {
		t.Fatal("expected section 8 complete once notified body fields are filled")
	}
}

func TestSectionComplete_Section10_EitherEmbeddedOrLinked(t *testing.T) {
	doc := New("myapp")
	if SectionComplete(doc, 9) { // section index 9 == section number 10
		t.Fatal("expected section 10 incomplete when neither embedded_text nor link_path is set")
	}
	doc.DoCCopy.LinkPath = "https://example.com/doc.pdf"
	if !SectionComplete(doc, 9) {
		t.Fatal("expected section 10 complete once link_path is set")
	}
	doc.DoCCopy.LinkPath = ""
	doc.DoCCopy.EmbeddedText = "This product conforms to..."
	if !SectionComplete(doc, 9) {
		t.Fatal("expected section 10 complete once embedded_text is set")
	}
}

func TestWizard_FillSection1_PersistsAfterEveryField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "annex7-myapp.json")
	doc := New("myapp")
	if err := Save(doc, path); err != nil {
		t.Fatal(err)
	}
	m := newModel(doc, path)

	// Overview -> open section 1 (cursor starts at 0, i.e. section 1).
	tm, _ := m.Update(enter())
	m = tm.(Model)
	if m.step != stepField || m.activeSection != 0 {
		t.Fatalf("expected to be editing section 0 (section 1), got step=%v activeSection=%d", m.step, m.activeSection)
	}

	// product_name field is pre-filled from New("myapp"); confirm as-is.
	if got := m.textBuffer; got != "myapp" {
		t.Fatalf("expected product_name pre-filled with %q, got %q", "myapp", got)
	}
	tm, _ = m.Update(enter())
	m = tm.(Model)

	// After confirming, the file on disk should already reflect it (saved
	// per-field, not just at the end of the section).
	saved, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.General.ProductName != "myapp" {
		t.Fatalf("expected product_name persisted immediately, got %q", saved.General.ProductName)
	}

	// product_version
	tm, _ = m.Update(runes("1.0.0"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)

	// purpose
	tm, _ = m.Update(runes("does things"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)

	// intended_use_environment: last field of section 1; confirming should
	// drop back to the overview.
	tm, _ = m.Update(runes("cloud"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)

	if m.step != stepOverview {
		t.Fatalf("expected to return to overview after the last field of section 1, got step=%v", m.step)
	}
	if !SectionComplete(m.doc, 0) {
		t.Fatal("expected section 1 complete after filling all 4 fields")
	}

	saved, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.General.ProductVersion != "1.0.0" || saved.General.Purpose != "does things" || saved.General.IntendedUseEnvironment != "cloud" {
		t.Fatalf("expected all section 1 fields persisted, got %+v", saved.General)
	}
}

func TestWizard_Esc_ReturnsToOverviewWithoutLosingPriorFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "annex7-myapp.json")
	doc := New("myapp")
	m := newModel(doc, path)

	tm, _ := m.Update(enter()) // open section 1
	m = tm.(Model)
	tm, _ = m.Update(enter()) // confirm product_name ("myapp", pre-filled)
	m = tm.(Model)
	if m.step != stepField || m.fieldIndex != 1 {
		t.Fatalf("expected to be on field 1 (product_version), got step=%v fieldIndex=%d", m.step, m.fieldIndex)
	}

	tm, _ = m.Update(esc())
	m = tm.(Model)
	if m.step != stepOverview {
		t.Fatalf("expected esc to return to overview, got step=%v", m.step)
	}
	if m.doc.General.ProductName != "myapp" {
		t.Fatal("expected the already-confirmed product_name field to survive esc")
	}
}

func TestWizard_BoolField_ToggleWithArrowsAndConfirm(t *testing.T) {
	doc := New("myapp")
	m := newModel(doc, filepath.Join(t.TempDir(), "annex7-myapp.json"))
	m.step = stepField
	m.activeSection = 4 // section 5: applicable standards
	m.fieldIndex = 0    // assessed_to_annex_i_directly (bool)
	m = m.prepareCurrentField()

	if m.selectCursor != 0 {
		t.Fatalf("expected default selection to be 'no' (index 0), got %d", m.selectCursor)
	}
	tm, _ := m.Update(down())
	m = tm.(Model)
	if m.selectCursor != 1 {
		t.Fatalf("expected 'down' to move to 'yes' (index 1), got %d", m.selectCursor)
	}
	tm, _ = m.Update(enter())
	m = tm.(Model)

	if !m.doc.Standards.AssessedToAnnexIDirectly {
		t.Fatal("expected confirming 'yes' to set AssessedToAnnexIDirectly")
	}
}

func TestRun_QuitImmediatelyStillWritesScaffoldFile(t *testing.T) {
	// Run() saves once before launching the TUI program; this exercises
	// that initial save directly (the interactive tea.Program itself needs
	// a real terminal and isn't driven here).
	path := filepath.Join(t.TempDir(), "annex7-myapp.json")
	doc := New("myapp")
	if err := Save(doc, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected scaffold file to exist after Save, got: %v", err)
	}
}
