package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/vulnscan"
)

var (
	correlateSBOMPath string
	correlateOutput   string
	correlateUseOSV   bool
)

var vulnCorrelateCmd = &cobra.Command{
	Use:   "correlate",
	Short: "Correlate an SBOM against vulnerability databases with Grype and OSV-Scanner",
	Long: `Match the components in a CycloneDX SBOM against vulnerability data
(NVD, GHSA, distro advisories, and other sources aggregated into Grype's
vulnerability database, run as a Go library rather than an external process)
and report one finding per matched vulnerability/component pair.

By default this also runs osv-scanner (https://github.com/google/osv-scanner)
against the same SBOM and merges its results with Grype's, deduplicating by
vulnerability ID (following CVE/GHSA/OSV aliases). OSV.dev, which
osv-scanner queries, often covers Go modules, Python packages, Rust crates,
and distro advisories that Grype's NVD-based database misses; merged
findings carry data from whichever scanner is more reliable for that field
(OSV-Scanner for fix versions, Grype for CVSS), and every finding records
which scanner(s) reported it. osv-scanner must already be installed and on
PATH (go install github.com/google/osv-scanner/cmd/osv-scanner@latest); use
--osv-scanner=false to skip it.

Typical pipeline:
  crasec sbom generate --target ./path -o sbom.cdx.json
  crasec vuln correlate --sbom sbom.cdx.json

Findings are written as a JSON array to stdout (or --output); each finding
carries the vulnerability ID, affected component name/version, severity,
CVSS score, fix version (if available), and data source. This is the
structured input later consumed by VEX triage and the ENISA report
workflow.`,
	RunE: runVulnCorrelate,
}

func init() {
	vulnCmd.AddCommand(vulnCorrelateCmd)
	vulnCorrelateCmd.Flags().StringVar(&correlateSBOMPath, "sbom", "", "path to a CycloneDX SBOM to correlate")
	vulnCorrelateCmd.Flags().StringVarP(&correlateOutput, "output", "o", "", "write findings to this file instead of stdout")
	vulnCorrelateCmd.Flags().BoolVar(&correlateUseOSV, "osv-scanner", true, "also query OSV.dev via osv-scanner and merge results with Grype's (requires osv-scanner on PATH)")
	if err := vulnCorrelateCmd.MarkFlagRequired("sbom"); err != nil {
		panic(err)
	}
}

func runVulnCorrelate(cmd *cobra.Command, _ []string) error {
	grypeFindings, err := vulnscan.Correlate(cmd.Context(), correlateSBOMPath)
	if err != nil {
		return err
	}

	findings := grypeFindings
	if correlateUseOSV {
		osvFindings, err := vulnscan.RunOSVScanner(cmd.Context(), correlateSBOMPath)
		if err != nil {
			return fmt.Errorf("running osv-scanner (pass --osv-scanner=false to skip it): %w", err)
		}
		findings = vulnscan.MergeFindings(grypeFindings, osvFindings)
	}

	w, closeW, err := resolveCorrelateWriter(cmd)
	if err != nil {
		return err
	}
	defer closeW()

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("encoding findings: %w", err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "found %d vulnerability matches\n", len(findings))
	return nil
}

// resolveCorrelateWriter returns the io.Writer to use for findings output.
// When --output is set it opens (or creates) the named file; otherwise it
// returns cmd.OutOrStdout(). The caller must invoke the returned close func.
func resolveCorrelateWriter(cmd *cobra.Command) (io.Writer, func(), error) {
	if correlateOutput == "" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.Create(correlateOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file %s: %w", correlateOutput, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", correlateOutput, cerr)
		}
	}, nil
}
