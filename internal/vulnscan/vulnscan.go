// Package vulnscan correlates a CycloneDX SBOM against vulnerability
// databases (NVD, GHSA, distro advisories, etc.) using Grype as a Go
// library. It produces a structured slice of Finding that downstream
// workflows (VEX triage, the ENISA report) consume directly, without
// re-parsing Grype's own output formats.
package vulnscan

import (
	"context"
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// dbIdentification names the vulnerability DB cache so it lands in the same
// location ("~/.cache/grype/db" or platform equivalent) a standalone grype
// install would use, avoiding a redundant download.
var dbIdentification = clio.Identification{Name: "grype"}

// Names used in Finding.Scanners to identify which tool reported a finding.
const (
	ScannerGrype = "grype"
	ScannerOSV   = "osv-scanner"
)

// Finding is one matched vulnerability/component pair, scoped to exactly the
// fields needed by VEX triage and the ENISA report workflow: identity of the
// vulnerability and affected component, its severity/CVSS, whether a fix is
// available, and where the data came from.
type Finding struct {
	VulnerabilityID string   `json:"vulnerabilityId"`    // e.g. CVE-2023-12345 or GHSA-....
	AliasIDs        []string `json:"aliasIds,omitempty"` // other IDs (GHSA, OSV, etc.) known to refer to the same vulnerability
	PackageName     string   `json:"packageName"`
	PackageVersion  string   `json:"packageVersion"`
	PackagePURL     string   `json:"packagePurl,omitempty"`
	Severity        string   `json:"severity"`
	CVSSScore       float64  `json:"cvssScore,omitempty"`
	CVSSVector      string   `json:"cvssVector,omitempty"`
	FixVersions     []string `json:"fixVersions,omitempty"`
	FixState        string   `json:"fixState"`
	DataSource      string   `json:"dataSource,omitempty"`
	// Scanners lists which tool(s) reported this finding (e.g. "grype",
	// "osv-scanner"), for auditability once findings from multiple scanners
	// have been merged.
	Scanners []string `json:"scanners,omitempty"`

	// ActivelyExploited is true when the vulnerability ID (or one of its
	// aliases) appears in CISA's Known Exploited Vulnerabilities catalog.
	// This is the "ACTIVELY EXPLOITED" flag, and the trigger for CRA
	// Article 14's 24-hour ENISA reporting requirement.
	ActivelyExploited bool   `json:"activelyExploited"`
	KEVDateAdded      string `json:"kevDateAdded,omitempty"`
	KEVDueDate        string `json:"kevDueDate,omitempty"`

	// CRARelevanceScore is a 0-100 triage heuristic (not a certified
	// compliance score): CVSS base score scaled to 0-100, forced to 100 on
	// a KEV match. Article14ReportRequired is set once it crosses
	// Article14Threshold, which a KEV match always does.
	CRARelevanceScore       float64 `json:"craRelevanceScore"`
	Article14ReportRequired bool    `json:"article14ReportRequired"`
}

// Correlate matches the CycloneDX SBOM at sbomPath against Grype's
// vulnerability database (updating the local DB cache first, same as a
// standalone "grype" run) and returns one Finding per matched
// vulnerability/component pair.
func Correlate(ctx context.Context, sbomPath string) ([]Finding, error) {
	packages, pkgContext, _, err := grypePkg.Provide(sbomPath, grypePkg.ProviderConfig{})
	if err != nil {
		return nil, fmt.Errorf("reading SBOM %s: %w", sbomPath, err)
	}

	store, _, err := grype.LoadVulnerabilityDB(v6dist.DefaultConfig(), v6inst.DefaultConfig(dbIdentification), true)
	if err != nil {
		return nil, fmt.Errorf("loading vulnerability database: %w", err)
	}
	defer store.Close()

	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: store,
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{}),
		// Findings report a CVE ID whenever one exists for the match (e.g. a
		// GHSA advisory that maps to an upstream CVE record), falling back to
		// the vulnerability's native ID (GHSA, etc.) only when no CVE exists.
		NormalizeByCVE: true,
	}

	matches, _, err := vm.FindMatchesContext(ctx, packages, pkgContext)
	if err != nil {
		return nil, fmt.Errorf("matching vulnerabilities: %w", err)
	}

	findings := make([]Finding, 0, matches.Count())
	for m := range matches.Enumerate() {
		f, err := toFinding(m, store)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// toFinding flattens a Grype match (plus its vulnerability metadata, which
// carries CVSS/severity/data source) into a Finding.
func toFinding(m match.Match, metadataProvider vulnerability.MetadataProvider) (Finding, error) {
	f := Finding{
		VulnerabilityID: m.Vulnerability.ID,
		PackageName:     m.Package.Name,
		PackageVersion:  m.Package.Version,
		PackagePURL:     m.Package.PURL,
		FixVersions:     m.Vulnerability.Fix.Versions,
		FixState:        string(m.Vulnerability.Fix.State),
		Scanners:        []string{ScannerGrype},
	}

	// vulnerability.Vulnerability should always carry Metadata, but fall back
	// to the provider lookup for mocks/edge cases, matching Grype's own
	// presenter behavior.
	metadata := m.Vulnerability.Metadata
	if metadata == nil {
		var err error
		metadata, err = metadataProvider.VulnerabilityMetadata(m.Vulnerability.Reference) //nolint:staticcheck // deprecated API still used internally by grype itself
		if err != nil {
			return Finding{}, fmt.Errorf("fetching metadata for %s: %w", m.Vulnerability.ID, err)
		}
	}
	if metadata != nil {
		f.Severity = metadata.Severity
		f.DataSource = metadata.DataSource
		f.CVSSScore, f.CVSSVector = bestCVSS(metadata.Cvss)
	}

	return f, nil
}

// bestCVSS picks the highest CVSS base score across all reported sources
// (e.g. NVD and a vendor score can disagree) and returns it with its vector.
func bestCVSS(scores []vulnerability.Cvss) (float64, string) {
	var bestScore float64
	var bestVector string
	for _, s := range scores {
		if s.Metrics.BaseScore > bestScore {
			bestScore = s.Metrics.BaseScore
			bestVector = s.Vector
		}
	}
	return bestScore, bestVector
}
