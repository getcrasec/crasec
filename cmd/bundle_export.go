package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/bundle"
	"github.com/getcrasec/crasec/internal/config"
)

var (
	bundleProduct string
	bundleOutput  string

	bundleSBOM, bundleSBOMSig         string
	bundleVEX, bundleVEXSig           string
	bundleCSAF, bundleCSAFSig         string
	bundleAnnex7JSON, bundleAnnex7PDF string
	bundleEUDocJSON, bundleEUDocPDF   string
	bundleEUDocPDFSig                 string
)

var bundleExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Assemble the auditor-ready CRA evidence package (ZIP)",
	Long: `Bundle every CRA compliance artifact crasec can generate for a product
into a single ZIP an auditor or market-surveillance authority can be handed
directly: SBOM, VEX, CSAF security advisory, Annex VII technical
documentation, and EU Declaration of Conformity, each with its Sigstore
signature where one applies, plus manifest.json (SHA-256 and generation
timestamp for every file, and which CRA requirement it satisfies) and a
plain-language README.txt.

This command only assembles artifacts that already exist on disk; it
doesn't generate them. Every artifact is required: if any is missing,
crasec lists exactly which ones and the command to generate each, and
exits without writing a partial bundle.

By default every artifact is looked up at the same filename its own
generate command defaults to; --sbom/--vex/--csaf/--annex7-json/... let you
point at different paths if you used non-default output locations.

  crasec sbom generate --target . -o sbom.cdx.json && crasec sbom sign sbom.cdx.json
  crasec vuln correlate --sbom sbom.cdx.json -o findings.json
  crasec vex generate --sbom sbom.cdx.json --findings findings.json -o vex.cdx.json && crasec vex sign vex.cdx.json
  crasec csaf generate --findings findings.json --tracking-id ... -o advisory.json && crasec csaf sign advisory.json
  crasec annex7 scaffold --product myapp
  crasec annex7 export --input annex7-myapp.json -o annex7.pdf
  crasec doc generate --product myapp --annex7 annex7-myapp.json ... --sign
  crasec bundle export --product myapp -o evidence-bundle.zip`,
	RunE: runBundleExport,
}

func init() {
	bundleCmd.AddCommand(bundleExportCmd)

	defaults := bundle.DefaultOptions("")

	bundleExportCmd.Flags().StringVar(&bundleProduct, "product", "", "product identifier, recorded in manifest.json and README.txt (default: .crasec.yaml's product.name, from \"crasec init\")")
	bundleExportCmd.Flags().StringVarP(&bundleOutput, "output", "o", defaults.Output, "path for the resulting ZIP")

	bundleExportCmd.Flags().StringVar(&bundleSBOM, "sbom", defaults.SBOM, "path to the signed SBOM")
	bundleExportCmd.Flags().StringVar(&bundleSBOMSig, "sbom-sig", defaults.SBOMSig, "path to the SBOM's Sigstore signature")
	bundleExportCmd.Flags().StringVar(&bundleVEX, "vex", defaults.VEX, "path to the signed VEX document")
	bundleExportCmd.Flags().StringVar(&bundleVEXSig, "vex-sig", defaults.VEXSig, "path to the VEX document's Sigstore signature")
	bundleExportCmd.Flags().StringVar(&bundleCSAF, "csaf", defaults.CSAF, "path to the signed CSAF advisory")
	bundleExportCmd.Flags().StringVar(&bundleCSAFSig, "csaf-sig", defaults.CSAFSig, "path to the CSAF advisory's Sigstore signature")
	bundleExportCmd.Flags().StringVar(&bundleAnnex7JSON, "annex7-json", defaults.Annex7JSON, "path to the Annex VII technical file (JSON)")
	bundleExportCmd.Flags().StringVar(&bundleAnnex7PDF, "annex7-pdf", defaults.Annex7PDF, "path to the Annex VII technical file (PDF)")
	bundleExportCmd.Flags().StringVar(&bundleEUDocJSON, "eudoc-json", defaults.EUDocJSON, "path to the EU Declaration of Conformity (JSON)")
	bundleExportCmd.Flags().StringVar(&bundleEUDocPDF, "eudoc-pdf", defaults.EUDocPDF, "path to the EU Declaration of Conformity (PDF)")
	bundleExportCmd.Flags().StringVar(&bundleEUDocPDFSig, "eudoc-pdf-sig", defaults.EUDocPDFSig, "path to the EU DoC PDF's Sigstore signature")

	if err := bundleExportCmd.MarkFlagRequired("product"); err != nil {
		panic(err)
	}
	bundleExportCmd.PreRunE = applyConfigDefaults(map[string]func(*config.Config) string{
		"product": func(c *config.Config) string { return c.Product.Name },
	})
}

func runBundleExport(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	opts := bundle.Options{
		Product: bundleProduct,
		Output:  bundleOutput,

		SBOM: bundleSBOM, SBOMSig: bundleSBOMSig,
		VEX: bundleVEX, VEXSig: bundleVEXSig,
		CSAF: bundleCSAF, CSAFSig: bundleCSAFSig,
		Annex7JSON: bundleAnnex7JSON, Annex7PDF: bundleAnnex7PDF,
		EUDocJSON: bundleEUDocJSON, EUDocPDF: bundleEUDocPDF, EUDocPDFSig: bundleEUDocPDFSig,

		EngineVersion: version,
	}

	artifacts := opts.Artifacts()
	if missing := bundle.MissingArtifacts(artifacts); len(missing) > 0 {
		printMissingArtifacts(cmd.ErrOrStderr(), missing)
		return fmt.Errorf("%d required artifact(s) missing; generate them and re-run \"crasec bundle export\"", len(missing))
	}

	manifest, err := bundle.Export(opts)
	if err != nil {
		return err
	}

	// Best-effort status output to stderr; a write failure here doesn't
	// affect the command's actual result.
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s (%d files)\n", bundleOutput, len(manifest.Files)) //nolint:errcheck
	for _, f := range manifest.Files {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %-24s sha256:%s\n", f.Name, f.SHA256[:12]+"...") //nolint:errcheck
	}
	return nil
}

// printMissingArtifacts writes a best-effort status report; a write failure
// here doesn't change the fact that artifacts are missing, which the caller
// reports separately as the actual command error.
func printMissingArtifacts(w io.Writer, missing []bundle.Artifact) {
	fmt.Fprintf(w, "%d required artifact(s) not found:\n\n", len(missing)) //nolint:errcheck
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE\tEXPECTED AT\tGENERATE WITH") //nolint:errcheck
	for _, m := range missing {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.BundleName, m.SourcePath, m.Hint) //nolint:errcheck
	}
	tw.Flush()      //nolint:errcheck
	fmt.Fprintln(w) //nolint:errcheck
}
