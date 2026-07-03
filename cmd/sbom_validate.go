package cmd

import (
	"fmt"
	"os"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/sbomvalidate"
)

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

	f, err := os.Open(path) // #nosec G304 -- path is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle; nothing to flush on close

	var bom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(f, cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	result := sbomvalidate.Validate(&bom)
	if result.TotalComponents == 0 {
		fmt.Fprintln(out, "No components found in SBOM.") //nolint:errcheck // best-effort status output
		return nil
	}

	fmt.Fprintf(out, "Validating %s  ·  BSI TR-03183-2 v2.1.0  ·  %d components\n\n", //nolint:errcheck // best-effort status output
		path, result.TotalComponents)

	// Print per-component warnings, capped at 20 to keep output readable.
	const maxWarnComponents = 20
	shown, totalAffected := 0, 0
	for _, r := range result.Components {
		if len(r.Missing) == 0 {
			continue
		}
		totalAffected++
		if shown >= maxWarnComponents {
			continue
		}
		fmt.Fprintf(out, "WARN  [%s]\n", r.Label) //nolint:errcheck // best-effort status output
		for _, field := range r.Missing {
			fmt.Fprintf(out, "        missing %-14s  %s / %s\n", field.ID, field.BSIRef, field.CRARef) //nolint:errcheck // best-effort status output
		}
		shown++
	}
	if totalAffected > shown {
		fmt.Fprintf(out, "      ... %d more components with warnings omitted\n", totalAffected-shown) //nolint:errcheck // best-effort status output
	}
	if totalAffected > 0 {
		fmt.Fprintln(out) //nolint:errcheck // best-effort status output
	}

	// Per-field coverage table, already sorted highest → lowest.
	fmt.Fprintln(out, "Per-field population:") //nolint:errcheck // best-effort status output
	for _, s := range result.FieldStats {
		bar := coverageBar(s.Pct, 20)
		fmt.Fprintf(out, "  %-14s  %s  %d/%d  (%.1f%%)\n", s.ID, bar, s.Passed, result.TotalComponents, s.Pct) //nolint:errcheck // best-effort status output
	}

	fmt.Fprintf(out, "\nBSI TR-03183-2 compliance score: %.1f%%\n", result.Score) //nolint:errcheck // best-effort status output
	fmt.Fprintf(out, "(%d/%d fields populated, %d components × %d fields)\n\n",   //nolint:errcheck // best-effort status output
		totalActual(result), result.TotalComponents*len(result.FieldStats), result.TotalComponents, len(result.FieldStats))

	// Result + CI exit codes
	if validateStrict && totalAffected > 0 {
		fmt.Fprintln(out, "Result: FAIL  (--strict: all fields must be present in all components)") //nolint:errcheck // best-effort status output
		os.Exit(1)
	}
	if validateMinScore > 0 && result.Score < validateMinScore {
		fmt.Fprintf(out, "Result: FAIL  (score %.1f%% < --min-score %.0f%%)\n", result.Score, validateMinScore) //nolint:errcheck // best-effort status output
		os.Exit(1)
	}

	if totalAffected == 0 {
		fmt.Fprintln(out, "Result: PASS  (all 10 BSI fields present in all components)") //nolint:errcheck // best-effort status output
	} else {
		fmt.Fprintf(out, "Result: %.1f%%  (add --strict or --min-score N for CI gating)\n", result.Score) //nolint:errcheck // best-effort status output
	}

	return nil
}

func totalActual(result sbomvalidate.Result) int {
	n := 0
	for _, s := range result.FieldStats {
		n += s.Passed
	}
	return n
}

func coverageBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}
