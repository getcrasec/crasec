// Package csafgen builds CSAF (Common Security Advisory Framework) 2.0
// advisories from vulnscan.Finding data and manufacturer-supplied
// document/product/publisher metadata.
//
// CSAF 2.0 is the OASIS-standardized, machine-readable advisory format
// ENISA recommends for CRA vulnerability disclosures, and it's what the
// EUVD (EU Vulnerability Database) ingests. Rather than hand-rolling the
// document structure and its own JSON-schema validator, this package builds
// on github.com/gocsaf/csaf/v3/csaf, a BSI-maintained library whose
// generated Go types mirror the OASIS spec field-for-field and whose
// ValidateCSAF embeds the exact schema published at
// https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json.
package csafgen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	csaf "github.com/gocsaf/csaf/v3/csaf"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/getcrasec/crasec/internal/vulnscan"
)

// Grype FixState values (see internal/vulnscan.Finding.FixState / Grype's
// grype/vulnerability.FixState), duplicated here as plain strings so this
// package doesn't need to import grype just to compare a tag.
const (
	fixStateFixed    = "fixed"
	fixStateNotFixed = "not-fixed"
	fixStateWontFix  = "wont-fix"
)

// Metadata is the document/product/publisher information a human (or CI
// pipeline) supplies to generate a CSAF advisory; everything vulnerability-
// specific comes from the findings themselves.
type Metadata struct {
	TrackingID      string // e.g. CRASEC-2026-0001; stable across revisions of the same advisory
	Title           string
	Category        string // free-form CSAF document category, e.g. "csaf_security_advisory"
	Lang            string // BCP 47, e.g. "en"
	Status          string // draft, final, or interim
	RevisionNumber  string // this revision's number, e.g. "1", "2"
	RevisionSummary string
	EngineVersion   string // crasec's own version, recorded in document.tracking.generator

	PublisherName      string
	PublisherNamespace string // URL identifying the publisher
	PublisherContact   string
	PublisherCategory  string // vendor, coordinator, discoverer, user, translator, other

	VendorName     string // product_tree vendor branch name; defaults to PublisherName
	ProductName    string
	ProductVersion string
	ProductPURL    string
	ProductCPE     string
}

// GenerateAdvisory builds a CSAF 2.0 Advisory from findings and meta. prev,
// when non-nil and carrying the same TrackingID, supplies the document's
// prior revision history and initial release date so re-running this
// command against an updated findings set appends a new revision instead of
// resetting the advisory's history.
func GenerateAdvisory(findings []vulnscan.Finding, meta Metadata, prev *csaf.Advisory) (*csaf.Advisory, error) {
	doc, err := buildDocument(meta, prev)
	if err != nil {
		return nil, err
	}

	tree, productID := buildProductTree(meta)

	vulns, err := buildVulnerabilities(findings, productID)
	if err != nil {
		return nil, err
	}

	return &csaf.Advisory{
		Document:        doc,
		ProductTree:     tree,
		Vulnerabilities: vulns,
	}, nil
}

// MarshalAndValidate serializes adv to indented JSON and validates it
// against the embedded official CSAF 2.0 JSON schema, returning an error
// that lists every schema violation instead of ever producing bytes for an
// invalid document.
func MarshalAndValidate(adv *csaf.Advisory) ([]byte, error) {
	data, err := json.MarshalIndent(adv, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling advisory: %w", err)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("re-parsing advisory for schema validation: %w", err)
	}

	violations, err := csaf.ValidateCSAF(doc)
	if err != nil {
		return nil, fmt.Errorf("validating against CSAF 2.0 schema: %w", err)
	}
	if len(violations) > 0 {
		return nil, fmt.Errorf("generated advisory failed CSAF 2.0 schema validation:\n  %s", strings.Join(violations, "\n  "))
	}

	return data, nil
}

// LoadPrevious reads a previously generated advisory at path, so
// GenerateAdvisory can carry forward its revision history. Returns (nil,
// nil) when path doesn't exist: a fresh advisory, not an error.
func LoadPrevious(path string) (*csaf.Advisory, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	adv, err := csaf.LoadAdvisory(path)
	if err != nil {
		return nil, fmt.Errorf("loading previous advisory %s: %w", path, err)
	}
	return adv, nil
}

func buildDocument(meta Metadata, prev *csaf.Advisory) (*csaf.Document, error) {
	if meta.TrackingID == "" {
		return nil, errors.New("tracking ID is required")
	}
	if meta.Title == "" {
		return nil, errors.New("title is required")
	}
	if meta.PublisherName == "" || meta.PublisherNamespace == "" {
		return nil, errors.New("publisher name and namespace (a URL identifying the publisher) are required")
	}

	status := csaf.TrackingStatus(meta.Status)
	switch status {
	case csaf.CSAFTrackingStatusDraft, csaf.CSAFTrackingStatusFinal, csaf.CSAFTrackingStatusInterim:
	default:
		return nil, fmt.Errorf("invalid status %q: must be draft, final, or interim", meta.Status)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	revNumber := csaf.RevisionNumber(meta.RevisionNumber)
	revision := &csaf.Revision{
		Date:    ptr(now),
		Number:  &revNumber,
		Summary: ptr(orDefault(meta.RevisionSummary, "Generated by crasec")),
	}

	initialRelease := now
	var history csaf.Revisions
	if prev != nil && prev.Document != nil && prev.Document.Tracking != nil {
		t := prev.Document.Tracking
		if t.ID != nil && string(*t.ID) == meta.TrackingID {
			if t.InitialReleaseDate != nil {
				initialRelease = *t.InitialReleaseDate
			}
			history = append(history, t.RevisionHistory...)
		}
	}
	history = append(history, revision)

	trackingID := csaf.TrackingID(meta.TrackingID)
	tracking := &csaf.Tracking{
		ID:                 &trackingID,
		Status:             &status,
		Version:            &revNumber,
		CurrentReleaseDate: ptr(now),
		InitialReleaseDate: ptr(initialRelease),
		RevisionHistory:    history,
		Generator: &csaf.Generator{
			Date:   ptr(now),
			Engine: &csaf.Engine{Name: ptr("crasec"), Version: strp(meta.EngineVersion)},
		},
	}

	pubCategory := csaf.Category(orDefault(meta.PublisherCategory, string(csaf.CSAFCategoryVendor)))
	publisher := &csaf.DocumentPublisher{
		Category:       &pubCategory,
		Name:           ptr(meta.PublisherName),
		Namespace:      ptr(meta.PublisherNamespace),
		ContactDetails: strp(meta.PublisherContact),
	}

	category := csaf.DocumentCategory(orDefault(meta.Category, "csaf_security_advisory"))
	lang := csaf.Lang(orDefault(meta.Lang, "en"))
	csafVersion := csaf.CSAFVersion20

	return &csaf.Document{
		Category:    &category,
		CSAFVersion: &csafVersion,
		Title:       ptr(meta.Title),
		Lang:        &lang,
		Publisher:   publisher,
		Tracking:    tracking,
	}, nil
}

// buildProductTree describes the single product a crasec advisory is about
// as vendor > product_name > product_version branches, with the leaf
// full_product_name carrying the CPE/PURL identification helper. It returns
// that leaf's ProductID so vulnerabilities can reference it.
func buildProductTree(meta Metadata) (*csaf.ProductTree, csaf.ProductID) {
	productID := csaf.ProductID(productRef(meta))

	label := meta.ProductName
	if meta.ProductVersion != "" {
		label = fmt.Sprintf("%s %s", meta.ProductName, meta.ProductVersion)
	}

	leaf := &csaf.FullProductName{
		Name:                        ptr(label),
		ProductID:                   &productID,
		ProductIdentificationHelper: buildIdentificationHelper(meta),
	}

	versionBranch := &csaf.Branch{
		Category: ptr(csaf.CSAFBranchCategoryProductVersion),
		Name:     ptr(orDefault(meta.ProductVersion, "unknown")),
		Product:  leaf,
	}
	nameBranch := &csaf.Branch{
		Category: ptr(csaf.CSAFBranchCategoryProductName),
		Name:     ptr(meta.ProductName),
		Branches: csaf.Branches{versionBranch},
	}
	vendorBranch := &csaf.Branch{
		Category: ptr(csaf.CSAFBranchCategoryVendor),
		Name:     ptr(orDefault(meta.VendorName, meta.PublisherName)),
		Branches: csaf.Branches{nameBranch},
	}

	return &csaf.ProductTree{Branches: csaf.Branches{vendorBranch}}, productID
}

func buildIdentificationHelper(meta Metadata) *csaf.ProductIdentificationHelper {
	if meta.ProductCPE == "" && meta.ProductPURL == "" {
		return nil
	}
	h := &csaf.ProductIdentificationHelper{}
	if meta.ProductCPE != "" {
		h.CPE = ptr(csaf.CPE(meta.ProductCPE))
	}
	if meta.ProductPURL != "" {
		h.PURL = ptr(csaf.PURL(meta.ProductPURL))
	}
	return h
}

// productRef derives a stable product_id: the PURL when available (globally
// unique), falling back to name@version or bare name.
func productRef(meta Metadata) string {
	if meta.ProductPURL != "" {
		return meta.ProductPURL
	}
	if meta.ProductVersion != "" {
		return fmt.Sprintf("%s@%s", meta.ProductName, meta.ProductVersion)
	}
	return meta.ProductName
}

// buildVulnerabilities converts findings into CSAF vulnerability entries,
// one per unique vulnerability ID (a finding's package/version informs the
// entry's notes and remediation, but every entry references the single
// product declared in the product tree (crasec advisories are scoped to
// one product per document, matching internal/vex's GenerateDocument).
func buildVulnerabilities(findings []vulnscan.Finding, productID csaf.ProductID) (csaf.Vulnerabilities, error) {
	seen := map[string]bool{}
	var order []string
	byID := map[string]vulnscan.Finding{}
	for _, f := range findings {
		if !seen[f.VulnerabilityID] {
			seen[f.VulnerabilityID] = true
			order = append(order, f.VulnerabilityID)
		}
		byID[f.VulnerabilityID] = f
	}

	vulns := make(csaf.Vulnerabilities, 0, len(order))
	for _, id := range order {
		vulns = append(vulns, toVulnerability(byID[id], productID))
	}
	return vulns, nil
}

func toVulnerability(f vulnscan.Finding, productID csaf.ProductID) *csaf.Vulnerability {
	v := &csaf.Vulnerability{
		Title:         ptr(fmt.Sprintf("%s in %s", f.VulnerabilityID, f.PackageName)),
		Notes:         buildNotes(f),
		ProductStatus: &csaf.ProductStatus{KnownAffected: &csaf.Products{&productID}},
	}

	// discovery_date and cwe aren't tracked by "crasec vuln correlate"
	// today (Grype's match data doesn't surface either), so both are left
	// unset; both are optional per the CSAF schema.

	if strings.HasPrefix(f.VulnerabilityID, "CVE-") {
		v.CVE = ptr(csaf.CVE(f.VulnerabilityID))
	} else {
		v.IDs = append(v.IDs, &csaf.VulnerabilityID{
			SystemName: ptr(vulnIDSystemName(f.VulnerabilityID)),
			Text:       ptr(f.VulnerabilityID),
		})
	}
	if f.EUVDID != "" {
		v.IDs = append(v.IDs, &csaf.VulnerabilityID{
			SystemName: ptr("ENISA EUVD"),
			Text:       ptr(f.EUVDID),
		})
	}

	if score := buildScore(f, productID); score != nil {
		v.Scores = csaf.Scores{score}
	}
	if rem := buildRemediation(f, productID); rem != nil {
		v.Remediations = csaf.Remediations{rem}
	}
	if f.ActivelyExploited {
		details := "Actively exploited in the wild"
		if f.KEVDateAdded != "" {
			details = fmt.Sprintf("%s (CISA KEV, added %s)", details, f.KEVDateAdded)
		}
		v.Threats = csaf.Threats{{
			Category:   ptr(csaf.CSAFThreatCategoryExploitStatus),
			Details:    ptr(details),
			ProductIds: &csaf.Products{&productID},
		}}
	}

	return v
}

func vulnIDSystemName(id string) string {
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return "GitHub Security Advisory"
	case strings.HasPrefix(id, "OSV-"):
		return "OSV"
	default:
		return "Other"
	}
}

func buildNotes(f vulnscan.Finding) csaf.Notes {
	desc := fmt.Sprintf("%s affects %s", f.VulnerabilityID, f.PackageName)
	if f.PackageVersion != "" {
		desc += "@" + f.PackageVersion
	}
	if f.Severity != "" {
		desc += fmt.Sprintf(" (severity: %s)", f.Severity)
	}

	return csaf.Notes{
		{NoteCategory: ptr(csaf.CSAFNoteCategoryDescription), Text: ptr(desc)},
		{NoteCategory: ptr(csaf.CSAFNoteCategorySummary), Text: ptr(fmt.Sprintf("%s in %s", f.VulnerabilityID, f.PackageName))},
	}
}

// buildScore emits a CVSS v3.x score only when the finding's vector is
// actually a "CVSS:3.0/..." or "CVSS:3.1/..." vector: CSAF's cvss_v3 object
// requires version/vectorString/baseScore/baseSeverity together, and a
// vector in another format (or no vector at all) can't satisfy the
// vectorString pattern, so it's better to omit the score than emit an
// invalid one.
func buildScore(f vulnscan.Finding, productID csaf.ProductID) *csaf.Score {
	if f.CVSSScore <= 0 || f.CVSSVector == "" {
		return nil
	}

	var version csaf.CVSSVersion3
	switch {
	case strings.HasPrefix(f.CVSSVector, "CVSS:3.1"):
		version = csaf.CVSSVersion31
	case strings.HasPrefix(f.CVSSVector, "CVSS:3.0"):
		version = csaf.CVSSVersion30
	default:
		return nil
	}

	score := f.CVSSScore
	severity := cvssSeverity(score)
	vector := csaf.CVSS3VectorString(f.CVSSVector)

	return &csaf.Score{
		Products: &csaf.Products{&productID},
		CVSS3: &csaf.CVSS3{
			Version:      &version,
			VectorString: &vector,
			BaseScore:    &score,
			BaseSeverity: &severity,
		},
	}
}

func cvssSeverity(score float64) csaf.CVSS3Severity {
	switch {
	case score >= 9.0:
		return csaf.CVSS3SeverityCritical
	case score >= 7.0:
		return csaf.CVSS3SeverityHigh
	case score >= 4.0:
		return csaf.CVSS3SeverityMedium
	case score > 0:
		return csaf.CVSS3SeverityLow
	default:
		return csaf.CVSS3SeverityNone
	}
}

func buildRemediation(f vulnscan.Finding, productID csaf.ProductID) *csaf.Remediation {
	var category csaf.RemediationCategory
	var details string

	switch f.FixState {
	case fixStateFixed:
		category = csaf.CSAFRemediationCategoryVendorFix
		if len(f.FixVersions) > 0 {
			details = fmt.Sprintf("Upgrade %s to version %s.", f.PackageName, strings.Join(f.FixVersions, " or "))
		} else {
			details = fmt.Sprintf("A fix is available for %s.", f.PackageName)
		}
	case fixStateWontFix:
		category = csaf.CSAFRemediationCategoryNoFixPlanned
		details = fmt.Sprintf("No fix is planned for %s in %s.", f.VulnerabilityID, f.PackageName)
	case fixStateNotFixed:
		category = csaf.CSAFRemediationCategoryNoneAvailable
		details = fmt.Sprintf("No fix is currently available for %s in %s.", f.VulnerabilityID, f.PackageName)
	default:
		return nil
	}

	return &csaf.Remediation{
		Category:   &category,
		Details:    ptr(details),
		ProductIds: &csaf.Products{&productID},
	}
}

func ptr[T any](v T) *T { return &v }

// strp is ptr for strings, except it returns nil for "" so optional
// CSAF fields are omitted rather than emitted empty.
func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
