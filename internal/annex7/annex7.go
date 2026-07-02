// Package annex7 models and persists the CRA Annex VII "technical
// documentation" file: the record every manufacturer must compile and keep
// for 10 years, and the file a market-surveillance authority (Italy's
// AGCM, Germany's BNetzA, etc.) will request first to check CRA conformity.
// It's edited through an interactive bubbletea wizard (see Wizard) rather
// than handed to callers as a one-shot generator, since most of its content
// — design rationale, SDLC description, conformity assessment — is
// judgment a human has to supply, not something derivable from scanning
// the product.
package annex7

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// TechnicalFile is the CRA Annex VII technical documentation for one
// product, covering all 10 mandatory sections.
type TechnicalFile struct {
	Product string `json:"product"` // scaffold key, e.g. "myapp"; stable across --edit sessions

	General           GeneralDescription    `json:"1_general_description"`
	Design            DesignAndDevelopment  `json:"2_design_and_development"`
	SecurityByDefault SecurityByDefault     `json:"3_security_by_default"`
	SDLC              SDLC                  `json:"4_sdlc"`
	Standards         ApplicableStandards   `json:"5_applicable_standards"`
	SBOM              SBOMReference         `json:"6_sbom_reference"`
	VulnHandling      VulnerabilityHandling `json:"7_vulnerability_handling_policy"`
	Conformity        ConformityAssessment  `json:"8_conformity_assessment"`
	DoCReference      EUDoCReference        `json:"9_eu_doc_reference"`
	DoCCopy           EUDoCCopy             `json:"10_eu_doc_copy"`
}

// GeneralDescription is section 1: what the product is.
type GeneralDescription struct {
	ProductName            string `json:"product_name"`
	ProductVersion         string `json:"product_version"`
	Purpose                string `json:"purpose"`
	IntendedUseEnvironment string `json:"intended_use_environment"`
}

// DesignAndDevelopment is section 2: design & development documentation.
type DesignAndDevelopment struct {
	ArchitectureDiagramPath string `json:"architecture_diagram_path"`
	ThreatModelReference    string `json:"threat_model_reference"`
	DesignRationale         string `json:"design_rationale"`
}

// SecurityByDefault is section 3: security-by-default configuration.
type SecurityByDefault struct {
	DefaultAuthSettings      string `json:"default_auth_settings"`
	NetworkExposure          string `json:"network_exposure"`
	AutomaticUpdateMechanism string `json:"automatic_update_mechanism"`
}

// SDLC is section 4: the secure development lifecycle description.
type SDLC struct {
	DevelopmentProcess   string `json:"development_process"`
	CodeReviewPolicy     string `json:"code_review_policy"`
	TestingApproach      string `json:"testing_approach"`
	DependencyManagement string `json:"dependency_management"`
}

// ApplicableStandards is section 5: which harmonised standards were
// applied, or a direct Annex I self-assessment if none were.
type ApplicableStandards struct {
	AssessedToAnnexIDirectly bool     `json:"assessed_to_annex_i_directly"`
	Standards                []string `json:"standards,omitempty"`
}

// SBOMReference is section 6: where the signed SBOM lives. Auto-populated
// from an existing sbom.cdx.json (and its .sig, if present) when scaffolding
// or editing, without clobbering values a human already filled in.
type SBOMReference struct {
	Path             string `json:"path"`
	SignaturePath    string `json:"signature_path,omitempty"`
	ComponentName    string `json:"component_name,omitempty"`
	ComponentVersion string `json:"component_version,omitempty"`
}

// VulnerabilityHandling is section 7: where the public disclosure policy
// lives.
type VulnerabilityHandling struct {
	PolicyURL string `json:"policy_url"`
}

// ProductClass is the CRA risk classification of the product, which
// determines whether self-assessment is sufficient or a notified body is
// required.
type ProductClass string

const (
	ClassDefault   ProductClass = "default"
	ClassImportant ProductClass = "important"
	ClassCritical  ProductClass = "critical"
)

// ConformityAssessment is section 8: how conformity was assessed.
// NotifiedBody* only apply (and are only required) when Class isn't
// ClassDefault.
type ConformityAssessment struct {
	Class                ProductClass `json:"product_class"`
	SelfAssessment       bool         `json:"self_assessment"`
	NotifiedBodyName     string       `json:"notified_body_name,omitempty"`
	NotifiedBodyID       string       `json:"notified_body_id,omitempty"`
	CertificateReference string       `json:"certificate_reference,omitempty"`
}

// EUDoCReference is section 9: a pointer to the Declaration of Conformity.
type EUDoCReference struct {
	Reference string `json:"reference"`
}

// EUDoCCopy is section 10: the DoC itself, embedded inline or linked —
// at least one of the two must be set.
type EUDoCCopy struct {
	EmbeddedText string `json:"embedded_text,omitempty"`
	LinkPath     string `json:"link_path,omitempty"`
}

// New returns a fresh TechnicalFile scaffold for product, with section 1's
// product name pre-seeded.
func New(product string) *TechnicalFile {
	doc := &TechnicalFile{Product: product}
	doc.General.ProductName = product
	return doc
}

// Load reads a previously saved TechnicalFile from path.
func Load(path string) (*TechnicalFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var doc TechnicalFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &doc, nil
}

// Exists reports whether a scaffold already exists at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Save writes doc to path as indented JSON, regardless of completion state
// — an in-progress technical file is still saved, so a wizard session can
// always be resumed with --edit.
func Save(doc *TechnicalFile, path string) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding technical file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ErrNotFound is returned by Load callers via errors.Is against the
// underlying os error; kept here so cmd/ doesn't need to import "os" just
// to check this.
var ErrNotFound = os.ErrNotExist

// IsNotFound reports whether err (from Load) is a missing-file error.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
