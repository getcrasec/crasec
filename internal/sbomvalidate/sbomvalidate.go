// Package sbomvalidate scores a CycloneDX SBOM against the 10 mandatory
// per-component fields BSI TR-03183-2 v2.1.0 requires (§3.2.9, §5.2.2,
// §5.2.4, §6.1) — the authoritative technical guideline EU regulators point
// to for what a CRA-compliant SBOM actually contains. Each field also maps
// to CRA Annex I, Part II, §1(a).
package sbomvalidate

import (
	"sort"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// FieldRef identifies one BSI field check and the standards it satisfies.
type FieldRef struct {
	ID     string
	BSIRef string
	CRARef string
}

// fieldRule defines one BSI TR-03183-2 field check for a CycloneDX component.
type fieldRule struct {
	FieldRef
	check func(c *cyclonedx.Component, ctx *validationCtx) bool
}

type validationCtx struct {
	depSet map[string]bool // BOMRefs that appear in bom.Dependencies[].ref
}

// bsiFieldRules lists the 10 mandatory fields from BSI TR-03183-2 v2.1.0 §5.2.2 / §5.2.4.
var bsiFieldRules = []fieldRule{
	{
		FieldRef: FieldRef{ID: "creator", BSIRef: "BSI TR-03183-2 §5.2.2", CRARef: "CRA Annex I, Part II, §1(a)"},
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return orgPopulated(c.Manufacturer)
		},
	},
	{
		FieldRef: FieldRef{ID: "name", BSIRef: "BSI TR-03183-2 §5.2.2", CRARef: "CRA Annex I, Part II, §1(a)"},
		check:    func(c *cyclonedx.Component, _ *validationCtx) bool { return c.Name != "" },
	},
	{
		FieldRef: FieldRef{ID: "version", BSIRef: "BSI TR-03183-2 §5.2.2", CRARef: "CRA Annex I, Part II, §1(a)"},
		check:    func(c *cyclonedx.Component, _ *validationCtx) bool { return c.Version != "" },
	},
	{
		FieldRef: FieldRef{ID: "filename", BSIRef: "BSI TR-03183-2 §5.2.2", CRARef: "CRA Annex I, Part II, §1(a)"},
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return hasBSIProp(c, "bsi:component:filename")
		},
	},
	{
		FieldRef: FieldRef{ID: "hash-sha512", BSIRef: "BSI TR-03183-2 §5.2.2", CRARef: "CRA Annex I, Part II, §1(a)"},
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return hasDistSHA512(c) || hasInlineSHA512(c)
		},
	},
	{
		FieldRef: FieldRef{ID: "purl", BSIRef: "BSI TR-03183-2 §5.2.4", CRARef: "CRA Annex I, Part II, §1(a)"},
		check:    func(c *cyclonedx.Component, _ *validationCtx) bool { return c.PackageURL != "" },
	},
	{
		FieldRef: FieldRef{ID: "dependencies", BSIRef: "BSI TR-03183-2 §5.2.2", CRARef: "CRA Annex I, Part II, §1(a)"},
		check: func(c *cyclonedx.Component, ctx *validationCtx) bool {
			return c.BOMRef != "" && ctx.depSet[c.BOMRef]
		},
	},
	{
		FieldRef: FieldRef{ID: "license", BSIRef: "BSI TR-03183-2 §5.2.2 + §6.1", CRARef: "CRA Annex I, Part II, §1(a)"},
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return hasLicense(c)
		},
	},
	{
		FieldRef: FieldRef{ID: "supplier", BSIRef: "BSI TR-03183-2 §3.2.9", CRARef: "CRA Annex I, Part II, §1(a)"},
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return orgPopulated(c.Supplier)
		},
	},
	{
		FieldRef: FieldRef{ID: "description", BSIRef: "BSI TR-03183-2 §5.2.2 (best practice)", CRARef: "CRA Annex I, Part II, §1(a)"},
		check:    func(c *cyclonedx.Component, _ *validationCtx) bool { return c.Description != "" },
	},
}

// ComponentResult is one component's BSI field check outcome.
type ComponentResult struct {
	Label   string
	Missing []FieldRef
}

// FieldStat is one field's population rate across every scored component.
type FieldStat struct {
	FieldRef
	Passed int
	Pct    float64
}

// Result is the outcome of scoring an SBOM against BSI TR-03183-2.
type Result struct {
	TotalComponents int
	Components      []ComponentResult
	// FieldStats is sorted by Pct descending.
	FieldStats []FieldStat
	// Score is the aggregate percentage of all (component × field) checks
	// that passed.
	Score float64
}

// Validate scores every component (including the SBOM's own metadata
// component, if present) against all 10 BSI TR-03183-2 fields.
func Validate(bom *cyclonedx.BOM) Result {
	components := collectAllComponents(bom)
	ctx := buildValidationCtx(bom)

	results := make([]ComponentResult, 0, len(components))
	fieldPassed := make([]int, len(bsiFieldRules))

	for i := range components {
		c := &components[i]
		var missing []FieldRef
		for j, rule := range bsiFieldRules {
			if rule.check(c, ctx) {
				fieldPassed[j]++
			} else {
				missing = append(missing, rule.FieldRef)
			}
		}
		results = append(results, ComponentResult{Label: componentLabel(c), Missing: missing})
	}

	n := len(components)
	stats := make([]FieldStat, len(bsiFieldRules))
	for i, rule := range bsiFieldRules {
		pct := 0.0
		if n > 0 {
			pct = float64(fieldPassed[i]) / float64(n) * 100
		}
		stats[i] = FieldStat{FieldRef: rule.FieldRef, Passed: fieldPassed[i], Pct: pct}
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Pct > stats[j].Pct })

	totalPossible := n * len(bsiFieldRules)
	totalActual := 0
	for _, p := range fieldPassed {
		totalActual += p
	}
	score := 0.0
	if totalPossible > 0 {
		score = float64(totalActual) / float64(totalPossible) * 100
	}

	return Result{
		TotalComponents: n,
		Components:      results,
		FieldStats:      stats,
		Score:           score,
	}
}

func collectAllComponents(bom *cyclonedx.BOM) []cyclonedx.Component {
	var out []cyclonedx.Component
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		out = append(out, *bom.Metadata.Component)
	}
	if bom.Components != nil {
		out = append(out, *bom.Components...)
	}
	return out
}

func buildValidationCtx(bom *cyclonedx.BOM) *validationCtx {
	depSet := make(map[string]bool)
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			depSet[d.Ref] = true
		}
	}
	return &validationCtx{depSet: depSet}
}

func componentLabel(c *cyclonedx.Component) string {
	if c.PackageURL != "" {
		return c.PackageURL
	}
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}
