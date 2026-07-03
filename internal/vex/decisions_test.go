package vex

import (
	"os"
	"path/filepath"
	"testing"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/getcrasec/crasec/internal/vulnscan"
)

func writeDecisions(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "decisions.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { // #nosec G306 -- test fixture, not sensitive
		t.Fatal(err)
	}
	return path
}

func TestLoadDecisionsFile_ParsesAllStatuses(t *testing.T) {
	path := writeDecisions(t, `
- cve: CVE-2024-11111
  component: log4j-core@2.14.1
  status: not_affected
  justification: vulnerable_code_not_present
  notes: "JNDI lookup disabled via LOG4J_FORMAT_MSG_NO_LOOKUPS=true"
- cve: CVE-2023-22222
  component: axios@0.21.1
  status: fixed
  fixed_version: "1.6.0"
- cve: CVE-2024-33333
  status: affected
  action_statement: "patching in next release"
- cve: CVE-2024-44444
  status: under_investigation
`)

	decisions, statements, err := LoadDecisionsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decisions) != 4 {
		t.Fatalf("expected 4 decisions, got %d", len(decisions))
	}
	if len(statements) != 4 {
		t.Fatalf("expected 4 statements, got %d", len(statements))
	}

	na := statements["CVE-2024-11111"]
	if na.Status != openvex.StatusNotAffected || na.Justification != openvex.VulnerableCodeNotPresent {
		t.Errorf("unexpected not_affected statement: %+v", na)
	}
	if na.ImpactStatement == "" {
		t.Error("expected notes to become the impact statement for not_affected")
	}

	fixed := statements["CVE-2023-22222"]
	if fixed.Status != openvex.StatusFixed || fixed.FixedVersion != "1.6.0" {
		t.Errorf("unexpected fixed statement: %+v", fixed)
	}

	affected := statements["CVE-2024-33333"]
	if affected.Status != openvex.StatusAffected || affected.ActionStatement != "patching in next release" {
		t.Errorf("unexpected affected statement: %+v", affected)
	}

	ui := statements["CVE-2024-44444"]
	if ui.Status != openvex.StatusUnderInvestigation || ui.Deadline == nil {
		t.Errorf("expected under_investigation to get an auto-computed deadline, got %+v", ui)
	}

	for id, stmt := range statements {
		if err := stmt.Validate(); err != nil {
			t.Errorf("%s: expected valid statement, got %v", id, err)
		}
	}
}

func TestLoadDecisionsFile_RejectsInvalidStatement(t *testing.T) {
	path := writeDecisions(t, `
- cve: CVE-2024-11111
  status: affected
`)
	if _, _, err := LoadDecisionsFile(path); err == nil {
		t.Fatal("expected an error for an affected decision missing action_statement")
	}
}

func TestLoadDecisionsFile_RejectsMissingCVE(t *testing.T) {
	path := writeDecisions(t, `
- status: fixed
  fixed_version: "1.0.0"
`)
	if _, _, err := LoadDecisionsFile(path); err == nil {
		t.Fatal("expected an error for a decision missing cve")
	}
}

func TestLoadDecisionsFile_RejectsBadDeadline(t *testing.T) {
	path := writeDecisions(t, `
- cve: CVE-2024-11111
  status: under_investigation
  deadline: "not-a-date"
`)
	if _, _, err := LoadDecisionsFile(path); err == nil {
		t.Fatal("expected an error for an unparseable deadline")
	}
}

func TestStaleDecisions_FlagsComponentMismatchOnly(t *testing.T) {
	decisions := []Decision{
		{CVE: "CVE-2024-11111", Component: "brand-new-lib@2.9.0"}, // stale: findings have 3.0.0
		{CVE: "CVE-2023-22222", Component: "axios@0.21.1"},        // matches
		{CVE: "CVE-2024-99999", Component: "gone@1.0.0"},          // CVE no longer present: not flagged
	}
	findings := []vulnscan.Finding{
		{VulnerabilityID: "CVE-2024-11111", PackageName: "brand-new-lib", PackageVersion: "3.0.0"},
		{VulnerabilityID: "CVE-2023-22222", PackageName: "axios", PackageVersion: "0.21.1"},
	}

	stale := StaleDecisions(decisions, findings)
	if len(stale) != 1 || stale[0].CVE != "CVE-2024-11111" {
		t.Fatalf("expected only CVE-2024-11111 flagged as stale, got %+v", stale)
	}
}
