package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/vex"
	"github.com/getcrasec/crasec/internal/vextriage"
	"github.com/getcrasec/crasec/internal/vulnscan"
)

var (
	vexFindingsPath   string
	vexStatementsPath string
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
CycloneDX BOM whose vulnerabilities carry an analysis block) — what auditors
and market-surveillance authorities review when assessing a manufacturer's
vulnerability management process.

Input is the findings JSON produced by "crasec vuln correlate" (--findings).
Product metadata (name/version/purl) is read from --sbom's metadata.component
when given; --product-name/--product-version/--product-purl override it, and
--product-name is required if --sbom isn't given.

Triage decisions can come from two places:

  --statements <file>   non-interactive: a JSON array of pre-made decisions,
                         keyed by vulnerability ID. No prompts.

  (omitted)              interactive: an in-terminal triage session walks
                         through each finding, asking for a status and the
                         fields that status requires:

                           not_affected          justification code + optional notes
                           affected               action statement (required)
                           fixed                  fixed version (required)
                           under_investigation    deadline is auto-set 60 days out

                         Progress is saved to --draft (default
                         .crasec-vex-draft.json) after every confirmed
                         finding, so a long session can be resumed by
                         rerunning the same command — already-triaged
                         findings won't be asked again. Press 'q' at any
                         point to save and quit; rerun later to pick up
                         where you left off. The VEX document is only
                         written once every finding has a decision.

Typical pipeline:
  crasec sbom generate --target ./path -o sbom.cdx.json
  crasec vuln correlate --sbom sbom.cdx.json -o findings.json
  crasec vex generate --sbom sbom.cdx.json --findings findings.json`,
	RunE: runVexGenerate,
}

func init() {
	vexCmd.AddCommand(vexGenerateCmd)
	vexGenerateCmd.Flags().StringVar(&vexFindingsPath, "findings", "", "path to findings JSON produced by \"crasec vuln correlate\"")
	vexGenerateCmd.Flags().StringVar(&vexSBOMPath, "sbom", "", "path to the CycloneDX SBOM the findings were correlated against (used for product metadata)")
	vexGenerateCmd.Flags().StringVar(&vexStatementsPath, "statements", "", "path to a JSON array of pre-made triage decisions (skips the interactive TUI)")
	vexGenerateCmd.Flags().StringVar(&vexDraftPath, "draft", "", "where interactive triage progress is saved/resumed (default: .crasec-vex-draft.json)")
	vexGenerateCmd.Flags().StringVarP(&vexOutput, "output", "o", "", "write the VEX document to this file instead of stdout")
	vexGenerateCmd.Flags().StringVar(&vexProductName, "product-name", "", "name of the product this VEX document is about (default: --sbom's metadata.component.name)")
	vexGenerateCmd.Flags().StringVar(&vexProductVersion, "product-version", "", "version of the product this VEX document is about (default: --sbom's metadata.component.version)")
	vexGenerateCmd.Flags().StringVar(&vexProductPURL, "product-purl", "", "package URL identifying the product (default: --sbom's metadata.component.purl)")
	vexGenerateCmd.Flags().StringVar(&vexSupplier, "supplier", "", "name of the manufacturer/supplier issuing this VEX document (optional)")
	if err := vexGenerateCmd.MarkFlagRequired("findings"); err != nil {
		panic(err)
	}
}

func runVexGenerate(cmd *cobra.Command, _ []string) error {
	findings, err := loadFindings(vexFindingsPath)
	if err != nil {
		return err
	}

	meta, err := resolveVexMetadata(cmd)
	if err != nil {
		return err
	}

	var statements map[string]vex.Statement
	if vexStatementsPath != "" {
		statements, err = loadVEXStatements(vexStatementsPath)
		if err != nil {
			return err
		}
	} else {
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
			fmt.Fprintf(cmd.ErrOrStderr(), "triage session ended early; progress saved to %s\nrerun this command to resume, or pass --statements %s to generate now with the remaining findings defaulted to under_investigation\n", draftPath, draftPath)
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

	if err := writeCycloneDX16(w, bom); err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "wrote VEX document with %d vulnerabilities\n", len(*bom.Vulnerabilities))
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
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM %s: %w", path, err)
	}
	defer f.Close()

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
// by vulnerability ID.
func loadVEXStatements(path string) (map[string]vex.Statement, error) {
	statements := map[string]vex.Statement{}
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
