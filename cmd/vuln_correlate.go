package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/euvd"
	"github.com/getcrasec/crasec/internal/kev"
	"github.com/getcrasec/crasec/internal/vulnscan"
)

var (
	correlateSBOMPath string
	correlateOutput   string
	correlateUseOSV   bool
	correlateUseKEV   bool
	correlateKEVCache string
	correlateUseEUVD  bool
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

Findings are also cross-referenced against CISA's Known Exploited
Vulnerabilities (KEV) catalog by CVE ID (following aliases). A KEV match
means the vulnerability is confirmed being exploited in the wild right now:
the finding is flagged actively exploited, its CRA relevance score is
forced above the Article 14 reporting threshold, and
article14ReportRequired is set — CRA Article 14 requires manufacturers to
report actively exploited vulnerabilities to ENISA within 24 hours. The KEV
catalog is downloaded from CISA and cached locally, refreshed once every 24
hours; use --kev=false to skip this check entirely.

Pass --enable-euvd to also cross-reference findings against ENISA's own EU
Vulnerability Database (EUVD) — the CRA's authoritative vulnerability
source and the database behind ENISA's Single Reporting Platform. Matches
attach EUVD's ID and CVSS assessment (euvdBaseScore etc.) alongside, not in
place of, the finding's existing CVSS data; when the two disagree on
severity by a full point or more, severityDisagreement is set so both
scores stay visible instead of one silently winning. EUVD's API is
currently in beta with no published stable spec, so this is opt-in and
off by default: a single failed request is treated as "EUVD is down" and
correlation proceeds without EUVD data rather than failing the run.

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
	vulnCorrelateCmd.Flags().BoolVar(&correlateUseKEV, "kev", true, "flag findings present in the CISA Known Exploited Vulnerabilities catalog (Article 14 trigger)")
	vulnCorrelateCmd.Flags().StringVar(&correlateKEVCache, "kev-cache", "", "path to cache the KEV catalog at (default: ~/.crasec/cache/kev.json)")
	vulnCorrelateCmd.Flags().BoolVar(&correlateUseEUVD, "enable-euvd", false, "cross-reference findings against ENISA's EU Vulnerability Database (beta API; off by default)")
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

	exploitedCount := 0
	if correlateUseKEV {
		catalog, err := loadKEVCatalog(cmd)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not load CISA KEV catalog (%v); findings will not be checked for active exploitation\n", err)
		} else {
			vulnscan.ApplyKEV(findings, catalog)
		}
	}
	for _, f := range findings {
		if f.ActivelyExploited {
			exploitedCount++
		}
	}

	disagreementCount := 0
	if correlateUseEUVD {
		if err := vulnscan.ApplyEUVD(cmd.Context(), findings, euvd.NewClient()); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: EUVD cross-reference unavailable (%v); continuing without it\n", err)
		}
		for _, f := range findings {
			if f.SeverityDisagreement {
				disagreementCount++
			}
		}
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
	if correlateUseKEV {
		fmt.Fprintf(cmd.ErrOrStderr(), "%d ACTIVELY EXPLOITED (CISA KEV) — Article 14 report required within 24h\n", exploitedCount)
	}
	if correlateUseEUVD && disagreementCount > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "%d finding(s) where EUVD and NVD/OSV disagree on severity by 1.0+ (see severityDisagreement)\n", disagreementCount)
	}
	return nil
}

// loadKEVCatalog resolves the cache path (--kev-cache, or the default
// ~/.crasec/cache/kev.json) and loads the CISA KEV catalog, downloading a
// fresh copy if the cache is missing or older than 24h.
func loadKEVCatalog(cmd *cobra.Command) (*kev.Catalog, error) {
	cachePath := correlateKEVCache
	if cachePath == "" {
		var err error
		cachePath, err = kev.DefaultCachePath()
		if err != nil {
			return nil, err
		}
	}
	return kev.Load(cmd.Context(), cachePath)
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
