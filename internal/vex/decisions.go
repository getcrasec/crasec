package vex

import (
	"fmt"
	"os"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"gopkg.in/yaml.v3"

	"github.com/getcrasec/crasec/internal/vulnscan"
)

// Decision is one entry in a version-controlled bulk triage decisions file
// (YAML) — the CI-pipeline alternative to interactive triage: teams encode
// their VEX decisions once, check the file into source control alongside
// the code, and replay it on every release without human intervention.
type Decision struct {
	CVE string `yaml:"cve"`

	// Component is informational only (not used to match against findings):
	// name@version of the component this decision was made against, so a
	// human reading the file later knows what was actually triaged. See
	// StaleDecisions, which flags entries whose Component no longer matches
	// any current finding for that CVE.
	Component string `yaml:"component,omitempty"`

	Status          openvex.Status        `yaml:"status"`
	Justification   openvex.Justification `yaml:"justification,omitempty"`
	ActionStatement string                `yaml:"action_statement,omitempty"`
	FixedVersion    string                `yaml:"fixed_version,omitempty"`

	// Deadline is YYYY-MM-DD or RFC3339. Only meaningful (and only
	// required) for status under_investigation; left empty it defaults to
	// 60 days from generation time, same as the interactive TUI.
	Deadline string `yaml:"deadline,omitempty"`

	Notes string `yaml:"notes,omitempty"`
}

// toStatement converts a Decision into the Statement type GenerateDocument
// consumes, applying the same notes-to-impact-statement mapping the
// interactive TUI uses for not_affected (see internal/vextriage).
func (d Decision) toStatement() (Statement, error) {
	stmt := Statement{
		VulnerabilityID: d.CVE,
		Status:          d.Status,
		Justification:   d.Justification,
		ActionStatement: d.ActionStatement,
		FixedVersion:    d.FixedVersion,
		Notes:           d.Notes,
	}

	switch d.Status {
	case openvex.StatusNotAffected:
		stmt.ImpactStatement = d.Notes
		stmt.Notes = ""
	case openvex.StatusUnderInvestigation:
		deadline, err := d.deadline()
		if err != nil {
			return Statement{}, err
		}
		stmt.Deadline = deadline
	}
	return stmt, nil
}

func (d Decision) deadline() (*time.Time, error) {
	if d.Deadline == "" {
		t := time.Now().Add(MaxUnderInvestigationDeadline)
		return &t, nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, d.Deadline); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("%s: invalid deadline %q, expected YYYY-MM-DD or RFC3339", d.CVE, d.Deadline)
}

// LoadDecisionsFile parses a bulk triage decisions YAML file and returns
// both the raw entries (for cross-checking against current findings, e.g.
// StaleDecisions) and the derived Statement map GenerateDocument expects,
// keyed by vulnerability ID. Every decision is validated with the same
// per-status rules interactive triage enforces (Statement.Validate) —
// a decisions file with an "affected" entry missing action_statement, for
// example, fails to load rather than silently producing an invalid VEX
// document.
func LoadDecisionsFile(path string) ([]Decision, map[string]Statement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading decisions file %s: %w", path, err)
	}

	var decisions []Decision
	if err := yaml.Unmarshal(data, &decisions); err != nil {
		return nil, nil, fmt.Errorf("parsing decisions file %s: %w", path, err)
	}

	statements := make(map[string]Statement, len(decisions))
	for i, d := range decisions {
		if d.CVE == "" {
			return nil, nil, fmt.Errorf("decisions file %s: entry %d is missing \"cve\"", path, i)
		}
		stmt, err := d.toStatement()
		if err != nil {
			return nil, nil, fmt.Errorf("decisions file %s: %w", path, err)
		}
		if err := stmt.Validate(); err != nil {
			return nil, nil, fmt.Errorf("decisions file %s: %w", path, err)
		}
		statements[d.CVE] = stmt
	}
	return decisions, statements, nil
}

// StaleDecisions returns decisions whose Component field doesn't match any
// current finding for that CVE — a sign the decision was made against an
// older version of the component and may need a fresh look, even though it
// still technically covers the CVE. Decisions for CVEs no longer present in
// findings at all are not flagged: an outdated decision for a vulnerability
// that's gone is harmless.
func StaleDecisions(decisions []Decision, findings []vulnscan.Finding) []Decision {
	componentsByVuln := map[string]map[string]bool{}
	for _, f := range findings {
		set, ok := componentsByVuln[f.VulnerabilityID]
		if !ok {
			set = map[string]bool{}
			componentsByVuln[f.VulnerabilityID] = set
		}
		set[fmt.Sprintf("%s@%s", f.PackageName, f.PackageVersion)] = true
	}

	var stale []Decision
	for _, d := range decisions {
		if d.Component == "" {
			continue
		}
		components, ok := componentsByVuln[d.CVE]
		if !ok {
			continue // CVE no longer present at all; not our concern here
		}
		if !components[d.Component] {
			stale = append(stale, d)
		}
	}
	return stale
}
