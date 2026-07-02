package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/vex"
	"github.com/getcrasec/crasec/internal/vulnscan"
)

var (
	vexFindingsPath   string
	vexStatementsPath string
	vexOutput         string
	vexProductName    string
	vexProductVersion string
	vexProductPURL    string
	vexSupplier       string
)

var vulnVexCmd = &cobra.Command{
	Use:   "vex",
	Short: "Generate a CycloneDX VEX document from findings and triage decisions",
	Long: `Build a VEX (Vulnerability Exploitability eXchange) document: the CRA's
mechanism for a manufacturer to state, per vulnerability, whether it is
actually exploitable in their product. Output is CycloneDX VEX JSON (a
CycloneDX BOM whose vulnerabilities carry an analysis block) — what auditors
and market-surveillance authorities review when assessing a manufacturer's
vulnerability management process.

Input is the findings JSON produced by "crasec vuln correlate" (--findings)
and, optionally, a JSON array of triage decisions (--statements) mapping
each finding's vulnerability ID to one of four statuses:

  not_affected          requires "justification" and/or "impactStatement"
  affected               requires "actionStatement" describing the remediation plan
  fixed                  requires "fixedVersion"
  under_investigation    requires "deadline" (max 60 days recommended)

Example --statements entry:

  {
    "vulnerabilityId": "CVE-2024-XXXXX",
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "impactStatement": "our code does not call the vulnerable JNDI lookup path"
  }

Findings with no matching entry in --statements default to
under_investigation with a 60-day deadline, so every known vulnerability is
documented even before a human has triaged it.`,
	RunE: runVulnVex,
}

func init() {
	vulnCmd.AddCommand(vulnVexCmd)
	vulnVexCmd.Flags().StringVar(&vexFindingsPath, "findings", "", "path to findings JSON produced by \"crasec vuln correlate\"")
	vulnVexCmd.Flags().StringVar(&vexStatementsPath, "statements", "", "path to a JSON array of triage decisions, keyed by vulnerability ID (default: all findings marked under_investigation)")
	vulnVexCmd.Flags().StringVarP(&vexOutput, "output", "o", "", "write the VEX document to this file instead of stdout")
	vulnVexCmd.Flags().StringVar(&vexProductName, "product-name", "", "name of the product this VEX document is about")
	vulnVexCmd.Flags().StringVar(&vexProductVersion, "product-version", "", "version of the product this VEX document is about")
	vulnVexCmd.Flags().StringVar(&vexProductPURL, "product-purl", "", "package URL identifying the product (optional)")
	vulnVexCmd.Flags().StringVar(&vexSupplier, "supplier", "", "name of the manufacturer/supplier issuing this VEX document (optional)")
	if err := vulnVexCmd.MarkFlagRequired("findings"); err != nil {
		panic(err)
	}
	if err := vulnVexCmd.MarkFlagRequired("product-name"); err != nil {
		panic(err)
	}
}

func runVulnVex(cmd *cobra.Command, _ []string) error {
	findings, err := loadFindings(vexFindingsPath)
	if err != nil {
		return err
	}

	statements, err := loadVEXStatements(vexStatementsPath)
	if err != nil {
		return err
	}

	meta := vex.Metadata{
		ProductName:    vexProductName,
		ProductVersion: vexProductVersion,
		ProductPURL:    vexProductPURL,
		Supplier:       vexSupplier,
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

	if err := writeCycloneDX16(w, bom); err != nil {
		return err
	}

	untriaged := 0
	for _, id := range vulnerabilityIDs(findings) {
		if _, ok := statements[id]; !ok {
			untriaged++
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote VEX document with %d vulnerabilities (%d defaulted to under_investigation)\n", len(*bom.Vulnerabilities), untriaged)
	return nil
}

// loadFindings reads and decodes the findings JSON produced by
// "crasec vuln correlate".
func loadFindings(path string) ([]vulnscan.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading findings %s: %w", path, err)
	}
	var findings []vulnscan.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parsing findings %s: %w", path, err)
	}
	return findings, nil
}

// loadVEXStatements reads a JSON array of triage decisions and indexes them
// by vulnerability ID. An empty path is not an error: it means no triage
// has been done yet, and every finding will default to under_investigation.
func loadVEXStatements(path string) (map[string]vex.Statement, error) {
	statements := map[string]vex.Statement{}
	if path == "" {
		return statements, nil
	}

	data, err := os.ReadFile(path)
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

// vulnerabilityIDs returns the distinct vulnerability IDs across findings.
func vulnerabilityIDs(findings []vulnscan.Finding) []string {
	seen := map[string]struct{}{}
	var ids []string
	for _, f := range findings {
		if _, ok := seen[f.VulnerabilityID]; ok {
			continue
		}
		seen[f.VulnerabilityID] = struct{}{}
		ids = append(ids, f.VulnerabilityID)
	}
	return ids
}

// resolveVexWriter returns the io.Writer to use for the VEX document.
// When --output is set it opens (or creates) the named file; otherwise it
// returns cmd.OutOrStdout(). The caller must invoke the returned close func.
func resolveVexWriter(cmd *cobra.Command) (io.Writer, func(), error) {
	if vexOutput == "" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.Create(vexOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file %s: %w", vexOutput, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", vexOutput, cerr)
		}
	}, nil
}
