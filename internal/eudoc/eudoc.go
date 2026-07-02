// Package eudoc models and generates the EU Declaration of Conformity
// (DoC): the legal document, defined by CRA Annex V, in which a
// manufacturer formally declares their product meets the CRA's essential
// requirements. Without it a product cannot legally bear the CE marking or
// be placed on the EU market. Unlike internal/annex7 (a long-lived record
// edited over time through a wizard), the DoC is generated in one shot from
// inputs the manufacturer already has on hand — most of them, in fact,
// already recorded in the Annex VII technical file.
package eudoc

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/getcrasec/crasec/internal/annex7"
)

// DeclarationStatement is the fixed wording CRA Annex V requires verbatim.
const DeclarationStatement = "This declaration of conformity is issued under the sole responsibility of the manufacturer."

// Declaration is the EU Declaration of Conformity for one product,
// covering every field CRA Annex V requires.
type Declaration struct {
	Manufacturer Manufacturer `json:"manufacturer"`
	Product      Product      `json:"product"`

	// DeclarationStatement always equals the constant above; it's kept in
	// the struct (rather than hard-coded only in the template) so the JSON
	// this command writes is a complete, standalone record of what was
	// declared.
	DeclarationStatement string `json:"declaration_statement"`

	// ObjectOfDeclaration describes the product and its intended use —
	// what, precisely, this declaration is about.
	ObjectOfDeclaration string `json:"object_of_declaration"`

	Conformity          Conformity `json:"conformity"`
	AssessmentProcedure string     `json:"assessment_procedure"`
	Signatory           Signatory  `json:"signatory"`
}

// Manufacturer identifies who is declaring conformity. Address must be an
// EU-registered address (the manufacturer's own, or an EU-based authorized
// representative's) per Annex V — crasec doesn't validate that a given
// address is actually within the EU, since that's a legal determination,
// not a syntactic one.
type Manufacturer struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// Product identifies what's being declared conformant.
type Product struct {
	Name        string `json:"name"`
	ModelNumber string `json:"model_number,omitempty"`

	// BatchOrVersionIdentifier is Annex V's "type, batch or serial number"
	// language, applied to software: normally the product's version.
	BatchOrVersionIdentifier string `json:"batch_or_version_identifier"`
}

// Conformity is how conformity was demonstrated: applied standards (or a
// direct Annex I assessment), and — only for Important/Critical class
// products — the notified body that was involved.
type Conformity struct {
	AssessedToAnnexIDirectly bool     `json:"assessed_to_annex_i_directly"`
	Standards                []string `json:"standards,omitempty"`
	NotifiedBodyName         string   `json:"notified_body_name,omitempty"`
	NotifiedBodyNumber       string   `json:"notified_body_number,omitempty"`
}

// Signatory is who is signing this declaration on the manufacturer's
// behalf, and when/where. Signature itself is a physical/wet or
// electronic-signature field left blank in the rendered PDF for the named
// signatory to actually sign — crasec's own Sigstore signing (see "crasec
// doc sign") attests to the eu-doc.json/eu-doc.pdf files as artifacts, and
// is a separate thing from this signatory field.
type Signatory struct {
	Name     string `json:"name"`
	Function string `json:"function"` // job title / role, e.g. "Chief Technology Officer"
	Place    string `json:"place"`
	Date     string `json:"date"` // YYYY-MM-DD
}

// FromAnnex7 pre-populates a Declaration from an Annex VII technical file
// wherever their fields overlap, to minimize re-entry. Manufacturer
// identity and signatory details aren't tracked by Annex VII at all and
// must be supplied separately; callers typically overlay a few more fields
// (model number, notified body number, etc.) that Annex VII doesn't carry
// either.
func FromAnnex7(doc *annex7.TechnicalFile) Declaration {
	d := Declaration{
		DeclarationStatement: DeclarationStatement,
	}
	d.Product.Name = doc.General.ProductName
	d.Product.BatchOrVersionIdentifier = doc.General.ProductVersion
	d.ObjectOfDeclaration = composeObject(doc)

	d.Conformity.AssessedToAnnexIDirectly = doc.Standards.AssessedToAnnexIDirectly
	d.Conformity.Standards = doc.Standards.Standards
	if !doc.Conformity.SelfAssessment {
		d.Conformity.NotifiedBodyName = doc.Conformity.NotifiedBodyName
		d.Conformity.NotifiedBodyNumber = doc.Conformity.NotifiedBodyID
	}
	d.AssessmentProcedure = defaultAssessmentProcedure(doc.Conformity.Class, doc.Conformity.SelfAssessment)

	return d
}

// composeObject builds a default "object of declaration" description from
// Annex VII's general-description section (product/version/purpose/
// intended use environment) — the same information Annex V asks for, just
// under different field names.
func composeObject(doc *annex7.TechnicalFile) string {
	var b strings.Builder
	b.WriteString(doc.General.ProductName)
	if doc.General.ProductVersion != "" {
		fmt.Fprintf(&b, " version %s", doc.General.ProductVersion)
	}
	if doc.General.Purpose != "" {
		fmt.Fprintf(&b, " — %s", doc.General.Purpose)
	}
	if doc.General.IntendedUseEnvironment != "" {
		fmt.Fprintf(&b, " Intended use environment: %s.", doc.General.IntendedUseEnvironment)
	}
	return b.String()
}

// defaultAssessmentProcedure applies the mapping CRA Annex VIII draws
// between risk class and conformity assessment module: internal
// production control (Module A) for self-assessed Default-class products,
// third-party involvement (Module B+C or H) once a notified body is
// required. This is a starting point, not a legal determination — exactly
// which module applies for a given Important/Critical product depends on
// facts crasec doesn't have, so callers should confirm/override it via
// --assessment-procedure rather than treat this as authoritative.
func defaultAssessmentProcedure(class annex7.ProductClass, selfAssessed bool) string {
	if class == annex7.ClassDefault || selfAssessed {
		return "Module A — internal production control (CRA Annex VIII)"
	}
	return "Module B + C, or Module H, involving a notified body (CRA Annex VIII) — confirm the exact module with the notified body"
}

// Validate returns a description of every Annex V-required field that's
// still missing. A DoC is a legal declaration, not a draft like the Annex
// VII technical file, so "doc generate" refuses to emit one that fails
// this check rather than silently producing an incomplete declaration.
func (d Declaration) Validate() []string {
	var missing []string
	req := func(ok bool, field string) {
		if !ok {
			missing = append(missing, field)
		}
	}

	req(d.Manufacturer.Name != "", "manufacturer.name")
	req(d.Manufacturer.Address != "", "manufacturer.address")
	req(d.Product.Name != "", "product.name")
	req(d.Product.BatchOrVersionIdentifier != "", "product.batch_or_version_identifier")
	req(d.DeclarationStatement != "", "declaration_statement")
	req(d.ObjectOfDeclaration != "", "object_of_declaration")
	req(d.Conformity.AssessedToAnnexIDirectly || len(d.Conformity.Standards) > 0,
		"conformity.standards (or conformity.assessed_to_annex_i_directly)")
	if d.Conformity.NotifiedBodyName != "" || d.Conformity.NotifiedBodyNumber != "" {
		req(d.Conformity.NotifiedBodyName != "", "conformity.notified_body_name")
		req(d.Conformity.NotifiedBodyNumber != "", "conformity.notified_body_number")
	}
	req(d.AssessmentProcedure != "", "assessment_procedure")
	req(d.Signatory.Name != "", "signatory.name")
	req(d.Signatory.Function != "", "signatory.function")
	req(d.Signatory.Place != "", "signatory.place")
	req(d.Signatory.Date != "", "signatory.date")

	return missing
}

// Load reads a previously saved Declaration from path.
func Load(path string) (*Declaration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var d Declaration
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &d, nil
}

// Save writes d to path as indented JSON.
func Save(d Declaration, path string) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding EU Declaration of Conformity: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
