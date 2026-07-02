package eudoc

import (
	"path/filepath"
	"testing"

	"github.com/getcrasec/crasec/internal/annex7"
)

func TestFromAnnex7_MapsOverlappingFields(t *testing.T) {
	a7 := annex7.New("myapp")
	a7.General.ProductVersion = "2.3.1"
	a7.General.Purpose = "does secure things"
	a7.General.IntendedUseEnvironment = "cloud"
	a7.Standards.AssessedToAnnexIDirectly = false
	a7.Standards.Standards = []string{"IEC 62443-4-2"}
	a7.Conformity.Class = annex7.ClassDefault
	a7.Conformity.SelfAssessment = true

	d := FromAnnex7(a7)

	if d.Product.Name != "myapp" {
		t.Errorf("expected product name %q, got %q", "myapp", d.Product.Name)
	}
	if d.Product.BatchOrVersionIdentifier != "2.3.1" {
		t.Errorf("expected batch/version %q, got %q", "2.3.1", d.Product.BatchOrVersionIdentifier)
	}
	if d.DeclarationStatement != DeclarationStatement {
		t.Errorf("expected the fixed Annex V declaration statement, got %q", d.DeclarationStatement)
	}
	if d.ObjectOfDeclaration == "" {
		t.Error("expected a composed object of declaration")
	}
	if len(d.Conformity.Standards) != 1 || d.Conformity.Standards[0] != "IEC 62443-4-2" {
		t.Errorf("expected standards to carry over, got %v", d.Conformity.Standards)
	}
	if d.Conformity.NotifiedBodyName != "" {
		t.Error("expected no notified body for a self-assessed Default-class product")
	}
	if d.AssessmentProcedure == "" || d.AssessmentProcedure[:8] != "Module A" {
		t.Errorf("expected Module A for self-assessed Default class, got %q", d.AssessmentProcedure)
	}
}

func TestFromAnnex7_NotifiedBodyCarriesOverWhenNotSelfAssessed(t *testing.T) {
	a7 := annex7.New("myapp")
	a7.Conformity.Class = annex7.ClassImportant
	a7.Conformity.SelfAssessment = false
	a7.Conformity.NotifiedBodyName = "TÜV SÜD"
	a7.Conformity.NotifiedBodyID = "0123"

	d := FromAnnex7(a7)

	if d.Conformity.NotifiedBodyName != "TÜV SÜD" || d.Conformity.NotifiedBodyNumber != "0123" {
		t.Errorf("expected notified body to carry over, got name=%q number=%q", d.Conformity.NotifiedBodyName, d.Conformity.NotifiedBodyNumber)
	}
	if d.AssessmentProcedure[:8] == "Module A" {
		t.Errorf("expected a notified-body assessment procedure for Important class, got %q", d.AssessmentProcedure)
	}
}

func TestValidate_ReportsEachMissingField(t *testing.T) {
	var d Declaration
	missing := d.Validate()
	if len(missing) == 0 {
		t.Fatal("expected an empty Declaration to report missing fields")
	}

	want := []string{
		"manufacturer.name", "manufacturer.address",
		"product.name", "product.batch_or_version_identifier",
		"object_of_declaration",
		"assessment_procedure",
		"signatory.name", "signatory.function", "signatory.place", "signatory.date",
	}
	for _, w := range want {
		found := false
		for _, m := range missing {
			if m == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be reported missing; got %v", w, missing)
		}
	}

	// declaration_statement is missing here since it's zero-valued, but
	// FromAnnex7 always sets it — check it's specifically checked too.
	found := false
	for _, m := range missing {
		if m == "declaration_statement" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected declaration_statement to be reported missing on a zero Declaration; got %v", missing)
	}
}

func TestValidate_NotifiedBodyPartialIsFlagged(t *testing.T) {
	d := validDeclaration()
	d.Conformity.NotifiedBodyName = "TÜV SÜD"
	// NotifiedBodyNumber intentionally left blank.

	missing := d.Validate()
	found := false
	for _, m := range missing {
		if m == "conformity.notified_body_number" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a name-without-number notified body to be flagged incomplete; got %v", missing)
	}
}

func TestValidate_CompleteDeclarationHasNoMissingFields(t *testing.T) {
	d := validDeclaration()
	if missing := d.Validate(); len(missing) != 0 {
		t.Fatalf("expected no missing fields, got %v", missing)
	}
}

func TestSaveLoad_RoundTrips(t *testing.T) {
	d := validDeclaration()
	path := filepath.Join(t.TempDir(), "eu-doc.json")

	if err := Save(d, path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Manufacturer.Name != d.Manufacturer.Name || loaded.Product.Name != d.Product.Name {
		t.Fatalf("expected round-tripped declaration to match, got %+v", loaded)
	}
}

func validDeclaration() Declaration {
	return Declaration{
		Manufacturer:         Manufacturer{Name: "Acme Corp", Address: "1 Rue de la Paix, 75002 Paris, France"},
		Product:              Product{Name: "myapp", BatchOrVersionIdentifier: "1.0.0"},
		DeclarationStatement: DeclarationStatement,
		ObjectOfDeclaration:  "myapp version 1.0.0 — does things.",
		Conformity:           Conformity{AssessedToAnnexIDirectly: true},
		AssessmentProcedure:  "Module A — internal production control (CRA Annex VIII)",
		Signatory:            Signatory{Name: "Jane Doe", Function: "CTO", Place: "Paris", Date: "2026-07-02"},
	}
}
