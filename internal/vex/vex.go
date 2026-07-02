// Package vex builds CycloneDX VEX (Vulnerability Exploitability eXchange)
// documents from vulnscan.Finding data and manufacturer triage decisions.
//
// VEX is the CRA's mechanism for a manufacturer to state, per vulnerability,
// whether it is actually exploitable in their product: "CVE-2024-XXXXX
// affects log4j which is in our product, but our code does NOT call the
// vulnerable JNDI lookup path, therefore we are not_affected." This package
// uses github.com/openvex/go-vex's status/justification vocabulary and
// validation rules as the source of truth for what a valid triage decision
// looks like, but writes it out as CycloneDX VEX JSON (a CycloneDX BOM whose
// vulnerabilities carry an analysis block) rather than OpenVEX's own JSON-LD
// format, since CycloneDX VEX is what downstream auditors and
// market-surveillance authorities expect.
package vex

import (
	"fmt"
	"sort"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/getcrasec/crasec/internal/vulnscan"
)

// MaxUnderInvestigationDeadline is the CRA-recommended ceiling on how far
// out an "under_investigation" triage deadline may be set.
const MaxUnderInvestigationDeadline = 60 * 24 * time.Hour

// Statement is one manufacturer triage decision for a single vulnerability.
// Which fields are required depends on Status; see Validate.
type Statement struct {
	VulnerabilityID string `json:"vulnerabilityId"`

	// Status is one of OpenVEX's four statuses: not_affected, affected,
	// fixed, under_investigation.
	Status openvex.Status `json:"status"`

	// Justification is required when Status is not_affected: one of
	// OpenVEX's justification codes explaining why the vulnerability
	// doesn't apply. ImpactStatement is an alternative (or supplement) to
	// Justification, per the OpenVEX spec.
	Justification   openvex.Justification `json:"justification,omitempty"`
	ImpactStatement string                `json:"impactStatement,omitempty"`

	// ActionStatement is required when Status is affected: what the
	// manufacturer is doing to remediate or mitigate.
	ActionStatement string `json:"actionStatement,omitempty"`

	// FixedVersion is required when Status is fixed: the version where the
	// vulnerability was resolved.
	FixedVersion string `json:"fixedVersion,omitempty"`

	// Deadline is required when Status is under_investigation: the date by
	// which triage will conclude. Must be no more than
	// MaxUnderInvestigationDeadline out.
	Deadline *time.Time `json:"deadline,omitempty"`
}

// Validate checks that the statement satisfies the OpenVEX spec's
// per-status requirements (delegated to go-vex, so this package doesn't
// duplicate that logic), plus the two fields go-vex doesn't know about:
// FixedVersion for status fixed, and Deadline for status
// under_investigation.
func (s Statement) Validate() error {
	ov := openvex.Statement{
		Status:          s.Status,
		Justification:   s.Justification,
		ImpactStatement: s.ImpactStatement,
		ActionStatement: s.ActionStatement,
	}
	if err := ov.Validate(); err != nil {
		return fmt.Errorf("%s: %w", s.VulnerabilityID, err)
	}

	switch s.Status {
	case openvex.StatusFixed:
		if s.FixedVersion == "" {
			return fmt.Errorf("%s: fixedVersion is required when status is %q", s.VulnerabilityID, s.Status)
		}
	case openvex.StatusUnderInvestigation:
		if s.Deadline == nil {
			return fmt.Errorf("%s: deadline is required when status is %q", s.VulnerabilityID, s.Status)
		}
		if s.Deadline.After(time.Now().Add(MaxUnderInvestigationDeadline)) {
			return fmt.Errorf("%s: deadline %s is more than 60 days out (CRA-recommended maximum)", s.VulnerabilityID, s.Deadline.Format("2006-01-02"))
		}
	}
	return nil
}

// defaultStatement is used for findings with no matching triage Statement,
// so every known vulnerability is documented in the VEX output even before
// a human has triaged it, rather than silently dropped.
func defaultStatement(vulnerabilityID string, now time.Time) Statement {
	deadline := now.Add(MaxUnderInvestigationDeadline)
	return Statement{
		VulnerabilityID: vulnerabilityID,
		Status:          openvex.StatusUnderInvestigation,
		Deadline:        &deadline,
	}
}

// statusToImpactAnalysisState maps OpenVEX's Status vocabulary onto
// CycloneDX's ImpactAnalysisState vocabulary; the two specs use different
// terms for the same four triage outcomes.
var statusToImpactAnalysisState = map[openvex.Status]cyclonedx.ImpactAnalysisState{
	openvex.StatusNotAffected:        cyclonedx.IASNotAffected,
	openvex.StatusAffected:           cyclonedx.IASExploitable,
	openvex.StatusFixed:              cyclonedx.IASResolved,
	openvex.StatusUnderInvestigation: cyclonedx.IASInTriage,
}

// justificationToImpactAnalysisJustification maps OpenVEX's five
// not_affected justification codes onto CycloneDX's nine-value
// justification vocabulary. There's no 1:1 mapping between the two specs,
// so this picks the closest CycloneDX term for each OpenVEX code.
var justificationToImpactAnalysisJustification = map[openvex.Justification]cyclonedx.ImpactAnalysisJustification{
	openvex.ComponentNotPresent:                         cyclonedx.IAJCodeNotPresent,
	openvex.VulnerableCodeNotPresent:                    cyclonedx.IAJCodeNotPresent,
	openvex.VulnerableCodeNotInExecutePath:              cyclonedx.IAJCodeNotReachable,
	openvex.VulnerableCodeCannotBeControlledByAdversary: cyclonedx.IAJRequiresEnvironment,
	openvex.InlineMitigationsAlreadyExist:               cyclonedx.IAJProtectedByMitigatingControl,
}

// Metadata describes the product the VEX document is about, populating the
// CycloneDX BOM's metadata.component.
type Metadata struct {
	ProductName    string
	ProductVersion string
	ProductPURL    string
	Supplier       string
}

// GenerateDocument builds a CycloneDX VEX document (a CycloneDX BOM whose
// vulnerabilities carry an analysis block) from findings and their triage
// statements, keyed by vulnerability ID. Findings that share a vulnerability
// ID are merged into a single CycloneDX vulnerability entry with multiple
// "affects" targets, matching how CycloneDX VEX documents are normally
// structured (one entry per vulnerability, not per component). Findings
// with no matching entry in statements default to under_investigation with
// a 60-day deadline (see defaultStatement), so every known vulnerability is
// documented even before triage is complete.
func GenerateDocument(findings []vulnscan.Finding, statements map[string]Statement, meta Metadata) (*cyclonedx.BOM, error) {
	now := time.Now().UTC()

	bom := cyclonedx.NewBOM()
	bom.SerialNumber = fmt.Sprintf("urn:uuid:%s", uuid.NewString())
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: now.Format(time.RFC3339),
		Component: &cyclonedx.Component{
			Type:       cyclonedx.ComponentTypeApplication,
			BOMRef:     componentRef(meta.ProductName, meta.ProductVersion, meta.ProductPURL),
			Name:       meta.ProductName,
			Version:    meta.ProductVersion,
			PackageURL: meta.ProductPURL,
		},
	}
	if meta.Supplier != "" {
		bom.Metadata.Supplier = &cyclonedx.OrganizationalEntity{Name: meta.Supplier}
	}

	type group struct {
		finding vulnscan.Finding
		refs    []string
	}
	components := map[string]cyclonedx.Component{}
	groups := map[string]*group{}
	var order []string

	for _, f := range findings {
		ref := componentRef(f.PackageName, f.PackageVersion, f.PackagePURL)
		if _, ok := components[ref]; !ok {
			components[ref] = cyclonedx.Component{
				Type:       cyclonedx.ComponentTypeLibrary,
				BOMRef:     ref,
				Name:       f.PackageName,
				Version:    f.PackageVersion,
				PackageURL: f.PackagePURL,
			}
		}

		g, ok := groups[f.VulnerabilityID]
		if !ok {
			g = &group{finding: f}
			groups[f.VulnerabilityID] = g
			order = append(order, f.VulnerabilityID)
		}
		g.refs = append(g.refs, ref)
	}

	compList := make([]cyclonedx.Component, 0, len(components))
	for _, c := range components {
		compList = append(compList, c)
	}
	sort.Slice(compList, func(i, j int) bool { return compList[i].BOMRef < compList[j].BOMRef })
	bom.Components = &compList

	vulns := make([]cyclonedx.Vulnerability, 0, len(order))
	for _, id := range order {
		g := groups[id]

		stmt, ok := statements[id]
		if !ok {
			stmt = defaultStatement(id, now)
		}
		stmt.VulnerabilityID = id
		if err := stmt.Validate(); err != nil {
			return nil, fmt.Errorf("invalid VEX statement: %w", err)
		}

		v, err := toVulnerability(g.finding, stmt, g.refs, now)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	bom.Vulnerabilities = &vulns

	return bom, nil
}

// toVulnerability converts one finding (representative of a group sharing
// the same vulnerability ID) plus its triage statement into a CycloneDX
// Vulnerability entry.
func toVulnerability(f vulnscan.Finding, stmt Statement, refs []string, now time.Time) (cyclonedx.Vulnerability, error) {
	state, ok := statusToImpactAnalysisState[stmt.Status]
	if !ok {
		return cyclonedx.Vulnerability{}, fmt.Errorf("%s: unrecognized VEX status %q", f.VulnerabilityID, stmt.Status)
	}

	analysis := &cyclonedx.VulnerabilityAnalysis{
		State:       state,
		FirstIssued: now.Format(time.RFC3339),
		LastUpdated: now.Format(time.RFC3339),
	}
	switch stmt.Status {
	case openvex.StatusNotAffected:
		if stmt.Justification != "" {
			analysis.Justification = justificationToImpactAnalysisJustification[stmt.Justification]
		}
		analysis.Detail = stmt.ImpactStatement
	case openvex.StatusAffected:
		analysis.Detail = stmt.ActionStatement
	case openvex.StatusFixed:
		analysis.Detail = fmt.Sprintf("fixed in version %s", stmt.FixedVersion)
	case openvex.StatusUnderInvestigation:
		analysis.Detail = fmt.Sprintf("under investigation; triage deadline %s", stmt.Deadline.Format("2006-01-02"))
	}

	var ratings *[]cyclonedx.VulnerabilityRating
	if f.CVSSScore > 0 {
		score := f.CVSSScore
		ratings = &[]cyclonedx.VulnerabilityRating{{
			Score:    &score,
			Severity: severity(f.Severity),
			Method:   cyclonedx.ScoringMethodCVSSv31,
			Vector:   f.CVSSVector,
		}}
	}

	affects := make([]cyclonedx.Affects, 0, len(refs))
	for _, ref := range refs {
		affects = append(affects, cyclonedx.Affects{Ref: ref})
	}

	return cyclonedx.Vulnerability{
		BOMRef:   fmt.Sprintf("vuln-%s", f.VulnerabilityID),
		ID:       f.VulnerabilityID,
		Ratings:  ratings,
		Analysis: analysis,
		Affects:  &affects,
	}, nil
}

// componentRef derives a stable bom-ref for a component: the PURL when
// available (globally unique), falling back to name@version.
func componentRef(name, version, purl string) string {
	if purl != "" {
		return purl
	}
	return fmt.Sprintf("%s@%s", name, version)
}

// severity maps Grype/OSV severity strings (e.g. "Critical", "Negligible")
// onto CycloneDX's lowercase Severity vocabulary.
func severity(s string) cyclonedx.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return cyclonedx.SeverityCritical
	case "high":
		return cyclonedx.SeverityHigh
	case "medium":
		return cyclonedx.SeverityMedium
	case "low":
		return cyclonedx.SeverityLow
	case "negligible":
		return cyclonedx.SeverityNone
	default:
		return cyclonedx.SeverityUnknown
	}
}
