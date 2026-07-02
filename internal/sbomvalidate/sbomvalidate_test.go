package sbomvalidate

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// fullyCompliantComponent satisfies all 10 BSI TR-03183-2 fields checked by
// Validate, so each test below can flip exactly one field back to missing.
func fullyCompliantComponent() cyclonedx.Component {
	return cyclonedx.Component{
		BOMRef:      "comp-a",
		Name:        "left-pad",
		Version:     "1.3.0",
		PackageURL:  "pkg:npm/left-pad@1.3.0",
		Description: "pads a string",
		Manufacturer: &cyclonedx.OrganizationalEntity{
			Name: "Acme Corp",
		},
		Supplier: &cyclonedx.OrganizationalEntity{
			Name: "Acme Corp",
		},
		Properties: &[]cyclonedx.Property{
			{Name: "bsi:component:filename", Value: "left-pad-1.3.0.tgz"},
		},
		ExternalReferences: &[]cyclonedx.ExternalReference{
			{
				Type: cyclonedx.ERTypeDistribution,
				URL:  "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
				Hashes: &[]cyclonedx.Hash{
					{Algorithm: cyclonedx.HashAlgoSHA512, Value: "deadbeef"},
				},
			},
		},
		Licenses: &cyclonedx.Licenses{
			{Expression: "MIT"},
		},
	}
}

// bomWithComponent wraps c as the sole component of a minimal BOM, with a
// dependency-graph entry so the "dependencies" field check passes.
func bomWithComponent(c cyclonedx.Component) *cyclonedx.BOM {
	return &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{c},
		Dependencies: &[]cyclonedx.Dependency{
			{Ref: c.BOMRef},
		},
	}
}

func TestValidate_FullyCompliantComponentScores100(t *testing.T) {
	bom := bomWithComponent(fullyCompliantComponent())
	result := Validate(bom)

	if result.TotalComponents != 1 {
		t.Fatalf("TotalComponents = %d, want 1", result.TotalComponents)
	}
	if result.Score != 100 {
		t.Errorf("Score = %.1f, want 100", result.Score)
	}
	if len(result.Components[0].Missing) != 0 {
		t.Errorf("Missing = %v, want none", result.Components[0].Missing)
	}
	for _, s := range result.FieldStats {
		if s.Pct != 100 {
			t.Errorf("field %q Pct = %.1f, want 100", s.ID, s.Pct)
		}
	}
}

func TestValidate_EachMissingFieldIsReported(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *cyclonedx.Component)
		fieldID string
	}{
		{"missing creator", func(c *cyclonedx.Component) { c.Manufacturer = nil }, "creator"},
		{"missing name", func(c *cyclonedx.Component) { c.Name = "" }, "name"},
		{"missing version", func(c *cyclonedx.Component) { c.Version = "" }, "version"},
		{"missing filename", func(c *cyclonedx.Component) { c.Properties = nil }, "filename"},
		{"missing hash-sha512", func(c *cyclonedx.Component) { c.ExternalReferences = nil }, "hash-sha512"},
		{"missing purl", func(c *cyclonedx.Component) { c.PackageURL = "" }, "purl"},
		{"missing dependencies", func(c *cyclonedx.Component) { c.BOMRef = "" }, "dependencies"},
		{"missing license", func(c *cyclonedx.Component) { c.Licenses = nil }, "license"},
		{"missing supplier", func(c *cyclonedx.Component) { c.Supplier = nil }, "supplier"},
		{"missing description", func(c *cyclonedx.Component) { c.Description = "" }, "description"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comp := fullyCompliantComponent()
			c.mutate(&comp)
			result := Validate(bomWithComponent(comp))

			missing := result.Components[0].Missing
			if len(missing) != 1 || missing[0].ID != c.fieldID {
				t.Fatalf("Missing = %v, want exactly [%s]", missing, c.fieldID)
			}
			if result.Score >= 100 {
				t.Errorf("Score = %.1f, want < 100 with %s missing", result.Score, c.fieldID)
			}
		})
	}
}

func TestValidate_InlineHashSatisfiesHashField(t *testing.T) {
	comp := fullyCompliantComponent()
	comp.ExternalReferences = nil
	comp.Hashes = &[]cyclonedx.Hash{
		{Algorithm: cyclonedx.HashAlgoSHA512, Value: "deadbeef"},
	}

	result := Validate(bomWithComponent(comp))
	if len(result.Components[0].Missing) != 0 {
		t.Errorf("Missing = %v, want none (inline hash should satisfy hash-sha512)", result.Components[0].Missing)
	}
}

func TestValidate_MetadataComponentIsScored(t *testing.T) {
	bom := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{Name: "root"},
		},
	}
	result := Validate(bom)
	if result.TotalComponents != 1 {
		t.Fatalf("TotalComponents = %d, want 1 (metadata.component should count)", result.TotalComponents)
	}
}

func TestValidate_EmptyBOMReportsZeroComponents(t *testing.T) {
	result := Validate(&cyclonedx.BOM{})
	if result.TotalComponents != 0 {
		t.Fatalf("TotalComponents = %d, want 0", result.TotalComponents)
	}
	if result.Score != 0 {
		t.Errorf("Score = %.1f, want 0 for an empty BOM (no division by zero)", result.Score)
	}
}

func TestValidate_AggregateScoreAcrossMixedComponents(t *testing.T) {
	good := fullyCompliantComponent()
	good.BOMRef = "good"
	bad := cyclonedx.Component{BOMRef: "bad", Name: "bad-component"} // only "name" passes

	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{good, bad},
		Dependencies: &[]cyclonedx.Dependency{
			{Ref: good.BOMRef},
			{Ref: bad.BOMRef},
		},
	}
	result := Validate(bom)

	if result.TotalComponents != 2 {
		t.Fatalf("TotalComponents = %d, want 2", result.TotalComponents)
	}
	// good passes all 10, bad passes only "name" and "dependencies" (has a
	// BOMRef present in the dependency graph) => 12/20 = 60%.
	wantScore := 60.0
	if result.Score != wantScore {
		t.Errorf("Score = %.1f, want %.1f", result.Score, wantScore)
	}
}
