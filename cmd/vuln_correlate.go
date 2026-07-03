package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/epss"
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
	correlateUseEPSS  bool
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
Vulnerabilities (KEV) catalog by CVE ID (following aliases), flagging
confirmed active exploitation, and against FIRST.org's EPSS API for a
30-day exploitation-probability score. Together with CVSS these feed the
CRA-relevance formula that is the reason this tool exists rather than a
generic scanner:

  CRA Score = CVSS Base Score × KEV Multiplier × EPSS Weight

  KEV Multiplier: 2.0 if actively exploited (in CISA KEV), else 1.0
  EPSS Weight:    1.5 if EPSS probability > 0.7, else 1.0

  > 14      CRA-CRITICAL  Article 14 trigger: report to ENISA within 24h
  7 - 14    MONITOR       track, no immediate reporting
  < 7       LOW           document in VEX, no action required

Findings are sorted by CRA score descending, both in the JSON output and in
the human-readable table printed to stderr (CRA-CRITICAL rows highlighted
in red when stderr is a terminal). Use --kev=false / --epss=false to skip
either input (the corresponding multiplier/weight then defaults to 1.0
rather than the finding being skipped). The KEV catalog is downloaded from
CISA and cached locally, refreshed once every 24 hours.

Pass --enable-euvd to also cross-reference findings against ENISA's own EU
Vulnerability Database (EUVD), the CRA's authoritative vulnerability
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
	vulnCorrelateCmd.Flags().BoolVar(&correlateUseEPSS, "epss", true, "fetch EPSS exploitation-probability scores from FIRST.org for CRA-relevance scoring")
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
		osvFindings, osvErr := vulnscan.RunOSVScanner(cmd.Context(), correlateSBOMPath)
		if osvErr != nil {
			return fmt.Errorf("running osv-scanner (pass --osv-scanner=false to skip it): %w", osvErr)
		}
		findings = vulnscan.MergeFindings(grypeFindings, osvFindings)
	}

	if correlateUseKEV {
		catalog, kevErr := loadKEVCatalog(cmd)
		if kevErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not load CISA KEV catalog (%v); findings will not be checked for active exploitation\n", kevErr) //nolint:errcheck // best-effort status output
		} else {
			vulnscan.ApplyKEV(findings, catalog)
		}
	}

	epssScores := map[string]float64{}
	if correlateUseEPSS {
		scores, epssErr := epss.NewClient().FetchScores(cmd.Context(), collectVulnerabilityIDs(findings))
		if epssErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: EPSS unavailable (%v); CRA scoring will use the default EPSS weight\n", epssErr) //nolint:errcheck // best-effort status output
		} else {
			epssScores = scores
		}
	}
	vulnscan.ApplyCRAScore(findings, epssScores)

	disagreementCount := 0
	if correlateUseEUVD {
		if euvdErr := vulnscan.ApplyEUVD(cmd.Context(), findings, euvd.NewClient()); euvdErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: EUVD cross-reference unavailable (%v); continuing without it\n", euvdErr) //nolint:errcheck // best-effort status output
		}
		for _, f := range findings {
			if f.SeverityDisagreement {
				disagreementCount++
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].CRARelevanceScore > findings[j].CRARelevanceScore
	})

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

	criticalCount := 0
	for _, f := range findings {
		if f.Article14ReportRequired {
			criticalCount++
		}
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "found %d vulnerability matches\n", len(findings))                         //nolint:errcheck // best-effort status output
	fmt.Fprintf(cmd.ErrOrStderr(), "%d CRA-CRITICAL: Article 14 report required within 24h\n", criticalCount) //nolint:errcheck // best-effort status output
	if correlateUseEUVD && disagreementCount > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "%d finding(s) where EUVD and NVD/OSV disagree on severity by 1.0+ (see severityDisagreement)\n", disagreementCount) //nolint:errcheck // best-effort status output
	}
	if len(findings) > 0 {
		printFindingsTable(cmd.ErrOrStderr(), findings)
	}
	return nil
}

// collectVulnerabilityIDs gathers every vulnerability ID and alias across
// findings, for a single batched EPSS lookup instead of one per finding.
func collectVulnerabilityIDs(findings []vulnscan.Finding) []string {
	ids := make([]string, 0, len(findings)*2)
	for _, f := range findings {
		ids = append(ids, f.VulnerabilityID)
		ids = append(ids, f.AliasIDs...)
	}
	return ids
}

const (
	ansiRed   = "\x1b[31m"
	ansiReset = "\x1b[0m"
)

// printFindingsTable renders findings (assumed already sorted by CRA score
// descending) as a human-readable table, with the category column
// highlighted in red for Article 14 triggers when w is a terminal. This is
// purely a presentation aid alongside the JSON output written elsewhere,
// which remains the structured contract for downstream tooling.
func printFindingsTable(w io.Writer, findings []vulnscan.Finding) {
	colorize := isTerminal(w)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VULNERABILITY\tPACKAGE\tCVSS\tKEV\tEPSS\tCRA SCORE\tCATEGORY") //nolint:errcheck // best-effort status output
	for _, f := range findings {
		kevMark := "-"
		if f.ActivelyExploited {
			kevMark = "YES"
		}

		category := f.CRACategory
		if f.Article14ReportRequired {
			category += " (ARTICLE 14)"
			if colorize {
				category = ansiRed + category + ansiReset
			}
		}

		fmt.Fprintf(tw, "%s\t%s@%s\t%.1f\t%s\t%.2f\t%.2f\t%s\n", //nolint:errcheck // best-effort status output
			f.VulnerabilityID, f.PackageName, f.PackageVersion,
			f.CVSSScore, kevMark, f.EPSSScore, f.CRARelevanceScore, category)
	}
	tw.Flush() //nolint:errcheck // best-effort; table has already been written to tw above
}

// isTerminal reports whether w is a character device (a terminal), so
// printFindingsTable only emits ANSI color codes when a human is likely to
// be looking at the output, not when stderr is redirected to a file/pipe.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
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
	f, err := os.Create(correlateOutput) // #nosec G304 -- correlateOutput is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file %s: %w", correlateOutput, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", correlateOutput, cerr)
		}
	}, nil
}
