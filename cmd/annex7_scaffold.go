package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/annex7"
)

var (
	annex7Product string
	annex7Output  string
	annex7SBOM    string
	annex7Edit    bool
)

var annex7ScaffoldCmd = &cobra.Command{
	Use:   "scaffold",
	Short: "Interactively build the CRA Annex VII technical documentation file",
	Long: `Walk through all 10 sections CRA Annex VII requires in a manufacturer's
technical documentation: the file a market-surveillance authority (Italy's
AGCM, Germany's BNetzA, etc.) requests first to check CRA conformity, and
which must be kept for 10 years:

  1. General description            6. SBOM reference
  2. Design & development docs      7. Vulnerability handling policy
  3. Security-by-default config     8. Conformity assessment result
  4. SDLC description               9. EU DoC reference
  5. Applicable standards          10. Copy of EU DoC

Every confirmed field is saved to --output immediately, so the file itself
is the draft: quitting at any point ('q' from the section overview, or
Ctrl+C) leaves exactly as much on disk as was confirmed, and rerunning with
--edit resumes from there, showing each already-answered field pre-filled.

Section 6 (SBOM reference) is auto-populated from --sbom (default:
./sbom.cdx.json, if present) the first time it's empty; it won't overwrite
values you've already filled in on a later --edit run.

  crasec sbom generate --target ./path -o sbom.cdx.json
  crasec annex7 scaffold --product myapp
  crasec annex7 scaffold --product myapp --edit   # resume later`,
	RunE: runAnnex7Scaffold,
}

func init() {
	annex7Cmd.AddCommand(annex7ScaffoldCmd)

	annex7ScaffoldCmd.Flags().StringVar(&annex7Product, "product", "", "product identifier, e.g. myapp (required)")
	annex7ScaffoldCmd.Flags().StringVarP(&annex7Output, "output", "o", "", "path to the technical file (default: annex7-<product>.json)")
	annex7ScaffoldCmd.Flags().StringVar(&annex7SBOM, "sbom", "sbom.cdx.json", "path to the signed SBOM, used to auto-populate section 6")
	annex7ScaffoldCmd.Flags().BoolVar(&annex7Edit, "edit", false, "resume/modify an existing technical file instead of scaffolding a new one")

	if err := annex7ScaffoldCmd.MarkFlagRequired("product"); err != nil {
		panic(err)
	}
}

func runAnnex7Scaffold(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	output := annex7Output
	if output == "" {
		output = fmt.Sprintf("annex7-%s.json", annex7Product)
	}

	exists := annex7.Exists(output)
	switch {
	case exists && !annex7Edit:
		return fmt.Errorf("%s already exists; pass --edit to resume/modify it", output)
	case !exists && annex7Edit:
		return fmt.Errorf("%s doesn't exist yet; run without --edit first to scaffold it", output)
	}

	var doc *annex7.TechnicalFile
	if exists {
		var err error
		doc, err = annex7.Load(output)
		if err != nil {
			return err
		}
		if cmd.Flags().Changed("product") {
			doc.Product = annex7Product
			doc.General.ProductName = annex7Product
		}
	} else {
		doc = annex7.New(annex7Product)
	}

	if err := autoPopulateSBOMReference(cmd, doc); err != nil {
		return err
	}

	final, err := annex7.Run(doc, output)
	if err != nil {
		return err
	}

	done, total := annex7.Completion(final)
	fmt.Fprintf(cmd.ErrOrStderr(), "saved %s (%d/%d sections complete)\n", output, done, total)
	return nil
}

// autoPopulateSBOMReference fills section 6 from an SBOM the first time
// it's empty; it never overwrites a value already present (manually
// entered, or populated by an earlier run), matching --edit's general
// "don't clobber what's already there" behavior. If --sbom was explicitly
// passed and doesn't exist, that's reported as an error; the default path
// silently missing is not (the SBOM may not have been generated yet).
func autoPopulateSBOMReference(cmd *cobra.Command, doc *annex7.TechnicalFile) error {
	if doc.SBOM.Path != "" {
		return nil
	}

	if _, err := os.Stat(annex7SBOM); err != nil {
		if cmd.Flags().Changed("sbom") {
			return fmt.Errorf("--sbom %s: %w", annex7SBOM, err)
		}
		return nil
	}

	component, err := loadSBOMComponent(annex7SBOM)
	if err != nil {
		return err
	}

	doc.SBOM.Path = annex7SBOM
	if _, err := os.Stat(annex7SBOM + ".sig"); err == nil {
		doc.SBOM.SignaturePath = annex7SBOM + ".sig"
	}
	if component != nil {
		doc.SBOM.ComponentName = component.Name
		doc.SBOM.ComponentVersion = component.Version
	}
	return nil
}
