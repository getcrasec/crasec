package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/sbomgen"
	"github.com/getcrasec/crasec/internal/vex"
	"github.com/getcrasec/crasec/internal/vextriage"
	"github.com/getcrasec/crasec/internal/vulnscan"
)

var (
	vexFindingsPath   string
	vexStatementsPath string
	vexFromFilePath   string
	vexSBOMPath       string
	vexDraftPath      string
	vexOutput         string
	vexProductName    string
	vexProductVersion string
	vexProductPURL    string
	vexSupplier       string
)

var vexGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a CycloneDX VEX document from findings and triage decisions",
	Long: `Build a VEX (Vulnerability Exploitability eXchange) document: the CRA's
mechanism for a manufacturer to state, per vulnerability, whether it is
actually exploitable in their product. Output is CycloneDX VEX JSON (a
CycloneDX BOM whose vulnerabilities carry an analysis block): what auditors
and market-surveillance authorities review when assessing a manufacturer's
vulnerability management process.

Input is the findings JSON produced by "crasec vuln correlate" (--findings).
Product metadata (name/version/purl) is read from --sbom's metadata.component
when given; --product-name/--product-version/--product-purl override it, and
--product-name is required if --sbom isn't given.

Triage decisions can come from three places (pick one):

  --from-file <decisions.yaml>   non-interactive, CI-friendly: a
                                  version-controlled YAML file of decisions,
                                  keyed by CVE. If any finding in --findings
                                  has no matching entry, the command prints
                                  the untriaged findings and exits non-zero
                                  instead of generating a document; a new
                                  CVE must get a human decision, checked into
                                  the decisions file, before the pipeline can
                                  proceed. Format:

                                    - cve: CVE-2024-XXXXX
                                      component: log4j-core@2.14.1   # informational
                                      status: not_affected
                                      justification: vulnerable_code_not_present
                                      notes: "why this doesn't apply"
                                    - cve: CVE-2023-YYYYY
                                      status: fixed
                                      fixed_version: "1.6.0"

  --statements <file>            non-interactive: a JSON array of pre-made
                                  decisions, keyed by vulnerability ID.
                                  Findings with no matching entry silently
                                  default to under_investigation; use
                                  --from-file instead if you want missing
                                  decisions to block the run.

  (neither given)                 interactive: an in-terminal triage session
                                  walks through each finding, asking for a
                                  status and the fields that status requires:

                                    not_affected          justification code + optional notes
                                    affected               action statement (required)
                                    fixed                  fixed version (required)
                                    under_investigation    deadline is auto-set 60 days out

                                  Progress is saved to --draft (default
                                  .crasec-vex-draft.json) after every
                                  confirmed finding, so a long session can be
                                  resumed by rerunning the same command;
                                  already-triaged findings won't be asked
                                  again. Press 'q' at any point to save and
                                  quit; rerun later to pick up where you left
                                  off. The VEX document is only written once
                                  every finding has a decision.

Typical pipeline:
  crasec sbom generate --target ./path
  crasec vuln correlate --sbom sbom.cdx.json
  crasec vex generate --sbom sbom.cdx.json --findings findings.json

CI pipeline:
  crasec vex generate --sbom sbom.cdx.json --findings findings.json \
    --from-file vex-decisions.yaml -o vex.cdx.json`,
	RunE: runVexGenerate,
}

func init() {
	vexCmd.AddCommand(vexGenerateCmd)
	vexGenerateCmd.Flags().StringVar(&vexFindingsPath, "findings", "", "path to findings JSON produced by \"crasec vuln correlate\"")
	vexGenerateCmd.Flags().StringVar(&vexSBOMPath, "sbom", "", "path to the CycloneDX SBOM the findings were correlated against (used for product metadata)")
	vexGenerateCmd.Flags().StringVar(&vexStatementsPath, "statements", "", "path to a JSON array of pre-made triage decisions (skips the interactive TUI)")
	vexGenerateCmd.Flags().StringVar(&vexFromFilePath, "from-file", "", "path to a version-controlled YAML decisions file; exits non-zero if any finding lacks a decision (CI pipelines)")
	vexGenerateCmd.Flags().StringVar(&vexDraftPath, "draft", "", "where interactive triage progress is saved/resumed (default: .crasec-vex-draft.json)")
	vexGenerateCmd.Flags().StringVarP(&vexOutput, "output", "o", "vex.cdx.json", "write the VEX document to this file (\"-\" for stdout)")
	vexGenerateCmd.Flags().StringVar(&vexProductName, "product-name", "", "name of the product this VEX document is about (default: --sbom's metadata.component.name)")
	vexGenerateCmd.Flags().StringVar(&vexProductVersion, "product-version", "", "version of the product this VEX document is about (default: --sbom's metadata.component.version)")
	vexGenerateCmd.Flags().StringVar(&vexProductPURL, "product-purl", "", "package URL identifying the product (default: --sbom's metadata.component.purl)")
	vexGenerateCmd.Flags().StringVar(&vexSupplier, "supplier", "", "name of the manufacturer/supplier issuing this VEX document (optional)")
	if err := vexGenerateCmd.MarkFlagRequired("findings"); err != nil {
		panic(err)
	}
}

func runVexGenerate(cmd *cobra.Command, _ []string) error {
	// Errors past this point are about input data (missing findings,
	// incomplete triage, invalid decisions), not CLI misuse, so a cobra
	// flag-usage dump would just be noise, especially in CI logs.
	cmd.SilenceUsage = true

	if vexFromFilePath != "" && vexStatementsPath != "" {
		return fmt.Errorf("--from-file and --statements are mutually exclusive; pick one")
	}

	findings, err := loadFindings(vexFindingsPath)
	if err != nil {
		return err
	}

	meta, err := resolveVexMetadata(cmd)
	if err != nil {
		return err
	}

	var statements map[string]vex.Statement
	switch {
	case vexFromFilePath != "":
		statements, err = loadBulkDecisions(cmd, vexFromFilePath, findings)
		if err != nil {
			return err
		}
	case vexStatementsPath != "":
		statements, err = loadVEXStatements(vexStatementsPath)
		if err != nil {
			return err
		}
	default:
		var completed bool
		statements, completed, err = vextriage.Run(findings, vexDraftPath)
		if err != nil {
			return fmt.Errorf("interactive triage: %w", err)
		}
		if !completed {
			draftPath := vexDraftPath
			if draftPath == "" {
				draftPath = vextriage.DefaultDraftPath
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "triage session ended early; progress saved to %s\nrerun this command to resume, or pass --statements %s to generate now with the remaining findings defaulted to under_investigation\n", draftPath, draftPath) //nolint:errcheck // best-effort status output
			return nil
		}
	}

	bom, err := vex.GenerateDocument(findings, statements, meta)
	if err != nil {
		return fmt.Errorf("generating VEX document: %w", err)
	}

	w, closeW, err := resolveVexWriter(cmd)
	if err != nil {
		return err
	}
	defer closeW()

	if err := sbomgen.WriteCycloneDX16(w, bom); err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "wrote VEX document with %d vulnerabilities\n", len(*bom.Vulnerabilities)) //nolint:errcheck // best-effort status output
	return nil
}

// resolveVexMetadata builds the VEX document's product metadata, reading
// defaults from --sbom's metadata.component (when given) and letting the
// --product-* flags override them. Returns an error if no product name is
// available from either source.
func resolveVexMetadata(cmd *cobra.Command) (vex.Metadata, error) {
	meta := vex.Metadata{
		ProductName:    vexProductName,
		ProductVersion: vexProductVersion,
		ProductPURL:    vexProductPURL,
		Supplier:       vexSupplier,
	}

	if vexSBOMPath != "" {
		component, err := loadSBOMComponent(vexSBOMPath)
		if err != nil {
			return vex.Metadata{}, err
		}
		if component != nil {
			if !cmd.Flags().Changed("product-name") {
				meta.ProductName = component.Name
			}
			if !cmd.Flags().Changed("product-version") {
				meta.ProductVersion = component.Version
			}
			if !cmd.Flags().Changed("product-purl") {
				meta.ProductPURL = component.PackageURL
			}
		}
	}

	if meta.ProductName == "" {
		return vex.Metadata{}, fmt.Errorf("no product name available: pass --product-name, or --sbom pointing at an SBOM with metadata.component.name set")
	}
	return meta, nil
}

// loadSBOMComponent reads a CycloneDX SBOM and returns its
// metadata.component, or nil if the SBOM has none.
func loadSBOMComponent(path string) (*cyclonedx.Component, error) {
	f, err := os.Open(path) // #nosec G304 -- path is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return nil, fmt.Errorf("opening SBOM %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle; nothing to flush on close

	var bom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(f, cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parsing SBOM %s: %w", path, err)
	}
	if bom.Metadata == nil {
		return nil, nil
	}
	return bom.Metadata.Component, nil
}

// loadFindings reads and decodes the findings JSON produced by
// "crasec vuln correlate".
func loadFindings(path string) ([]vulnscan.Finding, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return nil, fmt.Errorf("reading findings %s: %w", path, err)
	}
	var findings []vulnscan.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parsing findings %s: %w", path, err)
	}
	return findings, nil
}

// loadBulkDecisions loads a --from-file YAML decisions file and enforces
// the CI-pipeline gate: every finding must have a matching decision, or the
// command reports the gap and fails rather than silently generating an
// incomplete VEX document. Decisions whose recorded component no longer
// matches any current finding for that CVE are flagged as a non-fatal
// warning, since the component may have moved on since the decision was
// made.
func loadBulkDecisions(cmd *cobra.Command, path string, findings []vulnscan.Finding) (map[string]vex.Statement, error) {
	decisions, statements, err := vex.LoadDecisionsFile(path)
	if err != nil {
		return nil, err
	}

	if stale := vex.StaleDecisions(decisions, findings); len(stale) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d decision(s) in %s reference a component that no longer matches current findings (may be stale):\n", len(stale), path) //nolint:errcheck // best-effort status output
		for _, d := range stale {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s (recorded against %s)\n", d.CVE, d.Component) //nolint:errcheck // best-effort status output
		}
	}

	missing := untriagedFindings(findings, statements)
	if len(missing) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "%d finding(s) not covered by %s:\n", len(missing), path) //nolint:errcheck // best-effort status output
		printUntriagedTable(cmd.ErrOrStderr(), missing)
		return nil, fmt.Errorf("add a decision for each finding above to %s and rerun", path)
	}

	return statements, nil
}

// untriagedFindings returns one representative finding per vulnerability ID
// present in findings but absent from statements, sorted by CRA relevance
// score descending (most urgent first).
func untriagedFindings(findings []vulnscan.Finding, statements map[string]vex.Statement) []vulnscan.Finding {
	seen := map[string]bool{}
	var missing []vulnscan.Finding
	for _, f := range findings {
		if _, ok := statements[f.VulnerabilityID]; ok {
			continue
		}
		if seen[f.VulnerabilityID] {
			continue
		}
		seen[f.VulnerabilityID] = true
		missing = append(missing, f)
	}
	sort.SliceStable(missing, func(i, j int) bool {
		return missing[i].CRARelevanceScore > missing[j].CRARelevanceScore
	})
	return missing
}

func printUntriagedTable(w io.Writer, findings []vulnscan.Finding) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VULNERABILITY\tCOMPONENT\tCVSS\tCRA SCORE\tCATEGORY") //nolint:errcheck // best-effort status output
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s@%s\t%.1f\t%.2f\t%s\n", //nolint:errcheck // best-effort status output
			f.VulnerabilityID, f.PackageName, f.PackageVersion, f.CVSSScore, f.CRARelevanceScore, f.CRACategory)
	}
	tw.Flush() //nolint:errcheck // best-effort; table has already been written to tw above
}

// loadVEXStatements reads a JSON array of triage decisions and indexes them
// by vulnerability ID.
func loadVEXStatements(path string) (map[string]vex.Statement, error) {
	statements := map[string]vex.Statement{}
	data, err := os.ReadFile(path) // #nosec G304 -- path is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return nil, fmt.Errorf("reading VEX statements %s: %w", path, err)
	}
	var list []vex.Statement
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parsing VEX statements %s: %w", path, err)
	}
	for _, s := range list {
		if s.VulnerabilityID == "" {
			return nil, fmt.Errorf("VEX statement missing vulnerabilityId")
		}
		statements[s.VulnerabilityID] = s
	}
	return statements, nil
}

// resolveVexWriter returns the io.Writer to use for the VEX document.
// --output "-" writes to stdout; otherwise it opens (or creates) the named
// file. The caller must invoke the returned close func.
func resolveVexWriter(cmd *cobra.Command) (io.Writer, func(), error) {
	if vexOutput == "-" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.Create(vexOutput) // #nosec G304 -- vexOutput is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file %s: %w", vexOutput, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", vexOutput, cerr)
		}
	}, nil
}
