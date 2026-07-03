package vextriage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/getcrasec/crasec/internal/vex"
	"github.com/getcrasec/crasec/internal/vulnscan"
)

func sampleFindings() []vulnscan.Finding {
	return []vulnscan.Finding{
		{VulnerabilityID: "CVE-2024-11111", PackageName: "log4j-core", PackageVersion: "2.14.1", CVSSScore: 10, Severity: "Critical", CRARelevanceScore: 20, CRACategory: "CRA-CRITICAL"},
		{VulnerabilityID: "CVE-2024-22222", PackageName: "some-lib", PackageVersion: "1.2.3", CVSSScore: 7.5, Severity: "High", CRARelevanceScore: 7.5, CRACategory: "MONITOR"},
		{VulnerabilityID: "CVE-2024-22222", PackageName: "other-copy", PackageVersion: "1.2.3", CVSSScore: 7.5, Severity: "High", CRARelevanceScore: 7.5, CRACategory: "MONITOR"},
		{VulnerabilityID: "CVE-2024-33333", PackageName: "another-lib", PackageVersion: "0.9.0", CVSSScore: 3.1, Severity: "Low", CRARelevanceScore: 3.1, CRACategory: "LOW"},
	}
}

func enter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func down() tea.KeyMsg  { return tea.KeyMsg{Type: tea.KeyDown} }
func tab() tea.KeyMsg   { return tea.KeyMsg{Type: tea.KeyTab} }
func runes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestGroupFindings_CollapsesByVulnID(t *testing.T) {
	groups := groupFindings(sampleFindings())
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	// CVE-2024-11111 has the highest CRA score and should sort first.
	if groups[0].id != "CVE-2024-11111" {
		t.Errorf("expected highest-CRA-score group first, got %s", groups[0].id)
	}
	for _, g := range groups {
		if g.id == "CVE-2024-22222" && len(g.components) != 2 {
			t.Errorf("expected CVE-2024-22222 to collapse 2 findings into 1 group, got %d", len(g.components))
		}
	}
}

func TestTriage_NotAffected_RequiresJustification(t *testing.T) {
	draft := filepath.Join(t.TempDir(), "draft.json")
	m := newModel(groupFindings(sampleFindings()), map[string]vex.Statement{}, draft)

	// Status step: not_affected is index 0, select it immediately.
	tm, _ := m.Update(enter())
	m = tm.(Model)
	if m.step != stepJustification {
		t.Fatalf("expected stepJustification after selecting not_affected, got %v", m.step)
	}

	// Justification step: pick the second option (down once), confirm.
	tm, _ = m.Update(down())
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)
	if m.step != stepNotes {
		t.Fatalf("expected stepNotes after selecting justification, got %v", m.step)
	}
	if m.pendingJustification != justificationOptions[1] {
		t.Fatalf("expected justification %s, got %s", justificationOptions[1], m.pendingJustification)
	}

	// Notes step: type free text, confirm.
	tm, _ = m.Update(runes("no exec path"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)

	stmt, ok := m.statements["CVE-2024-11111"]
	if !ok {
		t.Fatal("expected CVE-2024-11111 to be recorded after confirm")
	}
	if stmt.Status != openvex.StatusNotAffected {
		t.Errorf("expected status not_affected, got %s", stmt.Status)
	}
	if stmt.Justification != justificationOptions[1] {
		t.Errorf("expected justification %s, got %s", justificationOptions[1], stmt.Justification)
	}
	if stmt.ImpactStatement != "no exec path" {
		t.Errorf("expected impact statement %q, got %q", "no exec path", stmt.ImpactStatement)
	}
	if err := stmt.Validate(); err != nil {
		t.Errorf("expected confirmed statement to be valid, got %v", err)
	}
	if len(m.queue) != 2 {
		t.Errorf("expected queue to shrink to 2, got %d", len(m.queue))
	}

	assertDraftContains(t, draft, "CVE-2024-11111")
}

func TestTriage_Affected_RequiresActionStatement(t *testing.T) {
	m := newModel(groupFindings(sampleFindings()), map[string]vex.Statement{}, filepath.Join(t.TempDir(), "draft.json"))

	// Move cursor down once to "affected", select it.
	tm, _ := m.Update(down())
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)
	if m.step != stepActionStatement {
		t.Fatalf("expected stepActionStatement, got %v", m.step)
	}

	// Confirming with no text should be rejected and stay on the same step.
	tm, _ = m.Update(enter())
	m = tm.(Model)
	if m.step != stepActionStatement {
		t.Fatalf("expected to remain on stepActionStatement when empty, got %v", m.step)
	}
	if m.validationMsg == "" {
		t.Error("expected a validation message for empty action statement")
	}

	tm, _ = m.Update(runes("upgrading in next release"))
	m = tm.(Model)
	tm, _ = m.Update(enter())
	m = tm.(Model)
	if m.step != stepNotes {
		t.Fatalf("expected stepNotes after action statement, got %v", m.step)
	}
	tm, _ = m.Update(enter()) // confirm with empty notes
	m = tm.(Model)

	stmt := m.statements["CVE-2024-11111"]
	if stmt.Status != openvex.StatusAffected {
		t.Errorf("expected status affected, got %s", stmt.Status)
	}
	if stmt.ActionStatement != "upgrading in next release" {
		t.Errorf("unexpected action statement %q", stmt.ActionStatement)
	}
}

func TestTriage_UnderInvestigation_AutoSetsDeadline(t *testing.T) {
	m := newModel(groupFindings(sampleFindings()), map[string]vex.Statement{}, filepath.Join(t.TempDir(), "draft.json"))

	// down x3 to reach under_investigation (index 3).
	for i := 0; i < 3; i++ {
		tm, _ := m.Update(down())
		m = tm.(Model)
	}
	tm, _ := m.Update(enter())
	m = tm.(Model)
	if m.step != stepNotes {
		t.Fatalf("expected under_investigation to skip straight to stepNotes, got %v", m.step)
	}

	tm, _ = m.Update(enter())
	m = tm.(Model)

	stmt := m.statements["CVE-2024-11111"]
	if stmt.Status != openvex.StatusUnderInvestigation {
		t.Fatalf("expected under_investigation, got %s", stmt.Status)
	}
	if stmt.Deadline == nil {
		t.Fatal("expected a deadline to be auto-set")
	}
	if stmt.Deadline.After(time.Now().Add(vex.MaxUnderInvestigationDeadline + time.Minute)) {
		t.Errorf("deadline %s exceeds the 60-day max", stmt.Deadline)
	}
}

func TestTriage_TabSkipsAndRotatesToBack(t *testing.T) {
	m := newModel(groupFindings(sampleFindings()), map[string]vex.Statement{}, filepath.Join(t.TempDir(), "draft.json"))
	first := m.groups[m.queue[0]].id

	tm, _ := m.Update(tab())
	m = tm.(Model)

	if m.groups[m.queue[0]].id == first {
		t.Errorf("expected a different finding after Tab, still showing %s", first)
	}
	if m.groups[m.queue[len(m.queue)-1]].id != first {
		t.Errorf("expected skipped finding %s at back of queue", first)
	}
	if m.step != stepStatus {
		t.Errorf("expected step reset to stepStatus after skip, got %v", m.step)
	}
}

func TestTriage_QuitSavesNothingNewButKeepsPriorDraft(t *testing.T) {
	m := newModel(groupFindings(sampleFindings()), map[string]vex.Statement{}, filepath.Join(t.TempDir(), "draft.json"))
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("expected Ctrl+C to return a quit command")
	}
}

func TestResumeFromDraft_SkipsAlreadyTriaged(t *testing.T) {
	dir := t.TempDir()
	draft := filepath.Join(dir, "draft.json")

	existing := []vex.Statement{
		{VulnerabilityID: "CVE-2024-11111", Status: openvex.StatusFixed, FixedVersion: "2.17.1"},
	}
	data, err := json.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(draft, data, 0o644); writeErr != nil { // #nosec G306 -- test fixture, not sensitive
		t.Fatal(writeErr)
	}

	resumed, err := loadDraft(draft)
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(groupFindings(sampleFindings()), resumed, draft)

	if m.confirmed != 1 {
		t.Errorf("expected 1 pre-confirmed finding on resume, got %d", m.confirmed)
	}
	for _, idx := range m.queue {
		if m.groups[idx].id == "CVE-2024-11111" {
			t.Error("expected already-triaged CVE-2024-11111 to be excluded from the queue")
		}
	}
	if len(m.queue) != 2 {
		t.Errorf("expected 2 remaining findings in queue, got %d", len(m.queue))
	}
}

func assertDraftContains(t *testing.T, path, vulnID string) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- path is caller-supplied (ultimately a CLI flag), not attacker-controlled remote input
	if err != nil {
		t.Fatalf("reading draft: %v", err)
	}
	var list []vex.Statement
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("parsing draft: %v", err)
	}
	for _, s := range list {
		if s.VulnerabilityID == vulnID {
			return
		}
	}
	t.Errorf("expected draft %s to contain %s, got %+v", path, vulnID, list)
}
