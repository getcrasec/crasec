package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
)

// fieldRule defines one BSI TR-03183-2 field check for a CycloneDX component.
type fieldRule struct {
	id     string
	bsiRef string
	craRef string
	check  func(c *cyclonedx.Component, ctx *validationCtx) bool
}

type validationCtx struct {
	depSet map[string]bool // BOMRefs that appear in bom.Dependencies[].ref
}

// bsiFieldRules lists the 10 mandatory fields from BSI TR-03183-2 v2.1.0 §5.2.2 / §5.2.4.
var bsiFieldRules = []fieldRule{
	{
		id: "creator", bsiRef: "BSI TR-03183-2 §5.2.2", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return orgPopulated(c.Manufacturer)
		},
	},
	{
		id: "name", bsiRef: "BSI TR-03183-2 §5.2.2", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool { return c.Name != "" },
	},
	{
		id: "version", bsiRef: "BSI TR-03183-2 §5.2.2", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool { return c.Version != "" },
	},
	{
		id: "filename", bsiRef: "BSI TR-03183-2 §5.2.2", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return hasBSIProp(c, "bsi:component:filename")
		},
	},
	{
		id: "hash-sha512", bsiRef: "BSI TR-03183-2 §5.2.2", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return hasDistSHA512(c) || hasInlineSHA512(c)
		},
	},
	{
		id: "purl", bsiRef: "BSI TR-03183-2 §5.2.4", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool { return c.PackageURL != "" },
	},
	{
		id: "dependencies", bsiRef: "BSI TR-03183-2 §5.2.2", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, ctx *validationCtx) bool {
			return c.BOMRef != "" && ctx.depSet[c.BOMRef]
		},
	},
	{
		id: "license", bsiRef: "BSI TR-03183-2 §5.2.2 + §6.1", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return hasLicense(c)
		},
	},
	{
		id: "supplier", bsiRef: "BSI TR-03183-2 §3.2.9", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool {
			return orgPopulated(c.Supplier)
		},
	},
	{
		id: "description", bsiRef: "BSI TR-03183-2 §5.2.2 (best practice)", craRef: "CRA Annex I, Part II, §1(a)",
		check: func(c *cyclonedx.Component, _ *validationCtx) bool { return c.Description != "" },
	},
}

var (
	validateStrict   bool
	validateMinScore float64
)

var sbomValidateCmd = &cobra.Command{
	Use:   "validate <sbom.cdx.json>",
	Short: "Validate a CycloneDX SBOM against BSI TR-03183-2 v2.1.0",
	Long: `Parse a CycloneDX SBOM and score each component against the 10 fields
required by BSI TR-03183-2 v2.1.0 (the authoritative technical guideline for
EU CRA SBOM compliance). The aggregate 0–100% score is the headline KPI.

Fields checked per component (BSI TR-03183-2 v2.1.0):
  creator       Manufacturer URL or contact (§5.2.2 / CRA Annex I Part II §1(a))
  name          Component name              (§5.2.2)
  version       Component version           (§5.2.2)
  filename      bsi:component:filename      (§5.2.2)
  hash-sha512   SHA-512 of deployable       (§5.2.2)
  purl          Package URL identifier      (§5.2.4)
  dependencies  Declared in dependency graph(§5.2.2)
  license       SPDX licence expression     (§5.2.2 + §6.1)
  supplier      Supplier name or contact    (§3.2.9)
  description   Human-readable description  (§5.2.2, best practice)`,
	Args: cobra.ExactArgs(1),
	RunE: runValidate,
}

func init() {
	sbomCmd.AddCommand(sbomValidateCmd)
	sbomValidateCmd.Flags().BoolVar(&validateStrict, "strict", false, "exit non-zero if any field is missing from any component")
	sbomValidateCmd.Flags().Float64Var(&validateMinScore, "min-score", 0, "exit non-zero if aggregate score is below this value (0–100)")
}

func runValidate(cmd *cobra.Command, args []string) error {
	path := args[0]
	out := cmd.OutOrStdout()

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var bom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(f, cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	components := collectAllComponents(&bom)
	if len(components) == 0 {
		fmt.Fprintln(out, "No components found in SBOM.")
		return nil
	}

	fmt.Fprintf(out, "Validating %s  ·  BSI TR-03183-2 v2.1.0  ·  %d components\n\n",
		path, len(components))

	ctx := buildValidationCtx(&bom)

	type compResult struct {
		label   string
		missing []string
	}

	results := make([]compResult, 0, len(components))
	fieldPassed := make([]int, len(bsiFieldRules))

	for i := range components {
		c := &components[i]
		var missing []string
		for j, rule := range bsiFieldRules {
			if rule.check(c, ctx) {
				fieldPassed[j]++
			} else {
				missing = append(missing, rule.id)
			}
		}
		results = append(results, compResult{label: componentLabel(c), missing: missing})
	}

	// Print per-component warnings, capped at 20 to keep output readable.
	const maxWarnComponents = 20
	shown, totalAffected := 0, 0
	for _, r := range results {
		if len(r.missing) == 0 {
			continue
		}
		totalAffected++
		if shown >= maxWarnComponents {
			continue
		}
		fmt.Fprintf(out, "WARN  [%s]\n", r.label)
		for _, fid := range r.missing {
			rule := ruleByID(fid)
			fmt.Fprintf(out, "        missing %-14s  %s / %s\n", fid, rule.bsiRef, rule.craRef)
		}
		shown++
	}
	if totalAffected > shown {
		fmt.Fprintf(out, "      ... %d more components with warnings omitted\n", totalAffected-shown)
	}
	if totalAffected > 0 {
		fmt.Fprintln(out)
	}

	// Per-field coverage table, sorted highest → lowest.
	type fieldStat struct {
		id     string
		passed int
		pct    float64
	}
	n := len(components)
	stats := make([]fieldStat, len(bsiFieldRules))
	for i, rule := range bsiFieldRules {
		pct := float64(fieldPassed[i]) / float64(n) * 100
		stats[i] = fieldStat{rule.id, fieldPassed[i], pct}
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].pct > stats[j].pct })

	fmt.Fprintln(out, "Per-field population:")
	for _, s := range stats {
		bar := coverageBar(s.pct, 20)
		fmt.Fprintf(out, "  %-14s  %s  %d/%d  (%.1f%%)\n", s.id, bar, s.passed, n, s.pct)
	}

	// Aggregate score
	totalPossible := n * len(bsiFieldRules)
	totalActual := 0
	for _, p := range fieldPassed {
		totalActual += p
	}
	score := float64(totalActual) / float64(totalPossible) * 100

	fmt.Fprintf(out, "\nBSI TR-03183-2 compliance score: %.1f%%\n", score)
	fmt.Fprintf(out, "(%d/%d fields populated, %d components × %d fields)\n\n",
		totalActual, totalPossible, n, len(bsiFieldRules))

	// Result + CI exit codes
	if validateStrict && totalAffected > 0 {
		fmt.Fprintln(out, "Result: FAIL  (--strict: all fields must be present in all components)")
		os.Exit(1)
	}
	if validateMinScore > 0 && score < validateMinScore {
		fmt.Fprintf(out, "Result: FAIL  (score %.1f%% < --min-score %.0f%%)\n", score, validateMinScore)
		os.Exit(1)
	}

	if totalAffected == 0 {
		fmt.Fprintln(out, "Result: PASS  (all 10 BSI fields present in all components)")
	} else {
		fmt.Fprintf(out, "Result: %.1f%%  (add --strict or --min-score N for CI gating)\n", score)
	}

	return nil
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

// orgPopulated returns true when the entity exists and carries at least a name,
// a URL, or a contact entry — enough to identify who made/supplied the component.
func orgPopulated(org *cyclonedx.OrganizationalEntity) bool {
	if org == nil {
		return false
	}
	if org.Name != "" {
		return true
	}
	if org.URL != nil {
		for _, u := range *org.URL {
			if u != "" {
				return true
			}
		}
	}
	if org.Contact != nil {
		for _, c := range *org.Contact {
			if c.Email != "" || c.Name != "" {
				return true
			}
		}
	}
	return false
}

func hasBSIProp(c *cyclonedx.Component, name string) bool {
	if c.Properties == nil {
		return false
	}
	for _, p := range *c.Properties {
		if p.Name == name && p.Value != "" {
			return true
		}
	}
	return false
}

// hasDistSHA512 checks the BSI-mandated path: externalReferences[type=distribution].hashes[alg=SHA-512].
func hasDistSHA512(c *cyclonedx.Component) bool {
	if c.ExternalReferences == nil {
		return false
	}
	for _, ref := range *c.ExternalReferences {
		if ref.Type == cyclonedx.ERTypeDistribution && ref.Hashes != nil {
			for _, h := range *ref.Hashes {
				if h.Algorithm == cyclonedx.HashAlgoSHA512 && h.Value != "" {
					return true
				}
			}
		}
	}
	return false
}

// hasInlineSHA512 checks component.hashes[alg=SHA-512] as an accepted fallback.
func hasInlineSHA512(c *cyclonedx.Component) bool {
	if c.Hashes == nil {
		return false
	}
	for _, h := range *c.Hashes {
		if h.Algorithm == cyclonedx.HashAlgoSHA512 && h.Value != "" {
			return true
		}
	}
	return false
}

func hasLicense(c *cyclonedx.Component) bool {
	if c.Licenses == nil {
		return false
	}
	for _, lc := range *c.Licenses {
		if lc.Expression != "" {
			return true
		}
		if lc.License != nil && (lc.License.ID != "" || lc.License.Name != "") {
			return true
		}
	}
	return false
}

func ruleByID(id string) fieldRule {
	for _, r := range bsiFieldRules {
		if r.id == id {
			return r
		}
	}
	return fieldRule{bsiRef: "BSI TR-03183-2", craRef: "CRA Annex I, Part II, §1(a)"}
}

func coverageBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}
