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
)

var vulnCorrelateCmd = &cobra.Command{
	Use:   "correlate",
	Short: "Correlate an SBOM against vulnerability databases with Grype",
	Long: `Match the components in a CycloneDX SBOM against vulnerability data
(NVD, GHSA, distro advisories, and other sources aggregated into Grype's
vulnerability database, run as a Go library rather than an external process)
and report one finding per matched vulnerability/component pair.

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
	if err := vulnCorrelateCmd.MarkFlagRequired("sbom"); err != nil {
		panic(err)
	}
}

func runVulnCorrelate(cmd *cobra.Command, _ []string) error {
	findings, err := vulnscan.Correlate(cmd.Context(), correlateSBOMPath)
	if err != nil {
		return err
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
