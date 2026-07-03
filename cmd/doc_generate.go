package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/annex7"
	"github.com/getcrasec/crasec/internal/artifactsign"
	"github.com/getcrasec/crasec/internal/config"
	"github.com/getcrasec/crasec/internal/doc"
	"github.com/getcrasec/crasec/internal/eudoc"
	"github.com/getcrasec/crasec/internal/eudocexport"
	"github.com/getcrasec/crasec/internal/pdfexport"
)

var (
	docProduct    string
	docAnnex7     string
	docOutput     string
	docPDF        string
	docNoPDF      bool
	docChromePath string
	docSign       bool
	docLanguages  string

	docManufacturerName    string
	docManufacturerAddress string
	docModelNumber         string
	docBatchVersion        string
	docObject              string
	docStandards           string
	docAssessedDirectly    bool
	docNotifiedBodyName    string
	docNotifiedBodyNumber  string
	docAssessmentProcedure string

	docSignatoryName     string
	docSignatoryFunction string
	docSignatoryPlace    string
	docSignatoryDate     string
)

var docGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate the EU Declaration of Conformity (CRA Annex V)",
	Long: `Build the EU Declaration of Conformity: the legal document in which the
manufacturer formally declares their product meets the CRA's essential
requirements. Required for every in-scope product: without it, a product
cannot legally bear the CE marking or be placed on the EU market.

Fields shared with the Annex VII technical file (product name/version,
purpose, applicable standards, conformity assessment class/notified body)
are auto-populated from --annex7; manufacturer identity and signatory
details aren't tracked there and must be supplied via flags. Any --<field>
flag explicitly passed overrides the auto-populated value.

This is a legal declaration, not a draft: generation fails, and nothing is
written, if any Annex V-required field is still missing after
auto-population and flag overrides, unlike "annex7 scaffold", which is
allowed to stay incomplete between wizard sessions.

CRA Annex V requires the declaration to be available in the language(s) of
every member state a product is sold into. --languages (default "en")
takes a comma-separated list of ISO 639-1 codes (e.g. en,it,de,fr) or "all"
for every EU language crasec currently has an embedded translation for;
each is rendered as its own line in the PDF's declaration statement. An
explicitly-named language with no embedded translation yet is a hard
error; "all" degrades gracefully instead and reports what's missing.

Output is eu-doc.json (machine-readable) and eu-doc.pdf (via headless
Chrome; see "crasec annex7 export" for the same --chrome-path/$CHROME_PATH
detection and error behavior; --no-pdf skips it if no browser is
available). Pass --sign to also Sigstore-sign both files immediately
(equivalent to running "crasec doc sign" on each afterward).

  crasec annex7 scaffold --product myapp
  crasec doc generate --product myapp --annex7 annex7-myapp.json \
    --manufacturer-name "Acme Corp" --manufacturer-address "1 Rue de la Paix, 75002 Paris, France" \
    --signatory-name "Jane Doe" --signatory-function "CTO" --signatory-place Paris \
    --languages en,it,de,fr`,
	RunE: runDocGenerate,
}

func init() {
	docCmd.AddCommand(docGenerateCmd)

	docGenerateCmd.Flags().StringVar(&docProduct, "product", "", "product identifier, e.g. myapp (default: .crasec.yaml's product.name, from \"crasec init\")")
	docGenerateCmd.Flags().StringVar(&docAnnex7, "annex7", "", "path to the Annex VII technical file (default: annex7-<product>.json)")
	docGenerateCmd.Flags().StringVarP(&docOutput, "output", "o", "eu-doc.json", "path for the machine-readable declaration")
	docGenerateCmd.Flags().StringVar(&docPDF, "pdf", "eu-doc.pdf", "path for the human-readable PDF")
	docGenerateCmd.Flags().BoolVar(&docNoPDF, "no-pdf", false, "skip PDF conversion (JSON only); use if no Chrome/Chromium is available")
	docGenerateCmd.Flags().StringVar(&docChromePath, "chrome-path", "", "path to a Chrome/Chromium executable (default: $CHROME_PATH, then auto-detected)")
	docGenerateCmd.Flags().BoolVar(&docSign, "sign", false, "Sigstore-sign both outputs immediately after writing them")
	docGenerateCmd.Flags().StringVar(&docLanguages, "languages", "en", "comma-separated EU language codes (ISO 639-1) for the declaration statement, or \"all\"")

	docGenerateCmd.Flags().StringVar(&docManufacturerName, "manufacturer-name", "", "manufacturer name (default: .crasec.yaml's manufacturer.name, from \"crasec init\")")
	docGenerateCmd.Flags().StringVar(&docManufacturerAddress, "manufacturer-address", "", "manufacturer's EU-registered address (default: .crasec.yaml's manufacturer.address, from \"crasec init\")")
	docGenerateCmd.Flags().StringVar(&docModelNumber, "model-number", "", "product model number, if applicable")
	docGenerateCmd.Flags().StringVar(&docBatchVersion, "batch-version", "", "batch/version identifier (default: --annex7's product version)")
	docGenerateCmd.Flags().StringVar(&docObject, "object", "", "object of declaration (default: composed from --annex7's product description)")
	docGenerateCmd.Flags().StringVar(&docStandards, "standards", "", "comma-separated standards/specs applied (default: --annex7's applicable standards)")
	docGenerateCmd.Flags().BoolVar(&docAssessedDirectly, "assessed-directly", false, "essential requirements of Annex I assessed directly, no harmonised standards (default: --annex7's setting)")
	docGenerateCmd.Flags().StringVar(&docNotifiedBodyName, "notified-body-name", "", "notified body name (Important/Critical class only; default: --annex7's)")
	docGenerateCmd.Flags().StringVar(&docNotifiedBodyNumber, "notified-body-number", "", "notified body number (Important/Critical class only; default: --annex7's)")
	docGenerateCmd.Flags().StringVar(&docAssessmentProcedure, "assessment-procedure", "", "conformity assessment module applied (default: derived from --annex7's risk class)")

	docGenerateCmd.Flags().StringVar(&docSignatoryName, "signatory-name", "", "name of the person signing on the manufacturer's behalf (required)")
	docGenerateCmd.Flags().StringVar(&docSignatoryFunction, "signatory-function", "", "signatory's job title/function (required)")
	docGenerateCmd.Flags().StringVar(&docSignatoryPlace, "signatory-place", "", "place of signing (required)")
	docGenerateCmd.Flags().StringVar(&docSignatoryDate, "signatory-date", "", "date of signing, YYYY-MM-DD (default: today)")

	for _, f := range []string{"product", "manufacturer-name", "manufacturer-address", "signatory-name", "signatory-function", "signatory-place"} {
		if err := docGenerateCmd.MarkFlagRequired(f); err != nil {
			panic(err)
		}
	}
	docGenerateCmd.PreRunE = applyConfigDefaults(map[string]func(*config.Config) string{
		"product":              func(c *config.Config) string { return c.Product.Name },
		"manufacturer-name":    func(c *config.Config) string { return c.Manufacturer.Name },
		"manufacturer-address": func(c *config.Config) string { return c.Manufacturer.Address },
	})
}

func runDocGenerate(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	annex7Path := docAnnex7
	if annex7Path == "" {
		annex7Path = fmt.Sprintf("annex7-%s.json", docProduct)
	}

	var declaration eudoc.Declaration
	var annex7ProductLabel string
	if _, err := os.Stat(annex7Path); err == nil {
		a7, loadErr := annex7.Load(annex7Path)
		if loadErr != nil {
			return loadErr
		}
		declaration = eudoc.FromAnnex7(a7)
		annex7ProductLabel = a7.Product
	} else if cmd.Flags().Changed("annex7") {
		return fmt.Errorf("--annex7 %s: %w", annex7Path, err)
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s not found; generating without Annex VII auto-population\n", annex7Path) //nolint:errcheck // best-effort status output
	}

	applyDocOverrides(cmd, &declaration)

	if err := applyLanguages(cmd, &declaration); err != nil {
		return err
	}

	if missing := declaration.Validate(); len(missing) > 0 {
		return fmt.Errorf("EU Declaration of Conformity is missing required field(s): %s", strings.Join(missing, ", "))
	}

	if err := eudoc.Save(declaration, docOutput); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", docOutput) //nolint:errcheck // best-effort status output

	if !docNoPDF {
		if err := generateDocPDF(cmd, declaration, annex7ProductLabel); err != nil {
			return err
		}
	}

	if docSign {
		return signDocOutputs(cmd)
	}

	outputs := docOutput
	if !docNoPDF {
		outputs = docOutput + `" and "` + docPDF
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "run \"crasec doc sign %s\" (or pass --sign next time) to Sigstore-sign the output(s)\n", outputs) //nolint:errcheck // best-effort status output
	return nil
}

func generateDocPDF(cmd *cobra.Command, declaration eudoc.Declaration, annex7ProductLabel string) error {
	html, err := eudocexport.RenderHTML(declaration, annex7ProductLabel)
	if err != nil {
		return err
	}
	chromePath, err := pdfexport.DetectChrome(pdfexport.ChromePathEnvOverride(docChromePath))
	if err != nil {
		return err
	}
	pdfBytes, err := pdfexport.RenderPDF(cmd.Context(), html, chromePath, eudocexport.Label)
	if err != nil {
		return err
	}
	if err := os.WriteFile(docPDF, pdfBytes, 0o644); err != nil { // #nosec G306 -- report is a shareable compliance document, not secret
		return fmt.Errorf("writing %s: %w", docPDF, err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", docPDF) //nolint:errcheck // best-effort status output
	return nil
}

// applyDocOverrides layers manufacturer/signatory identity (never
// Annex-VII-sourced) and any explicitly-passed --<field> flags on top of
// the Annex VII auto-population, following the same
// "cmd.Flags().Changed(...) wins" convention "crasec vex generate" and
// "crasec csaf generate" already use.
func applyDocOverrides(cmd *cobra.Command, d *eudoc.Declaration) {
	d.Manufacturer.Name = docManufacturerName
	d.Manufacturer.Address = docManufacturerAddress

	if cmd.Flags().Changed("model-number") {
		d.Product.ModelNumber = docModelNumber
	}
	if cmd.Flags().Changed("batch-version") {
		d.Product.BatchOrVersionIdentifier = docBatchVersion
	}
	if cmd.Flags().Changed("object") {
		d.ObjectOfDeclaration = docObject
	}
	if cmd.Flags().Changed("assessed-directly") {
		d.Conformity.AssessedToAnnexIDirectly = docAssessedDirectly
	}
	if cmd.Flags().Changed("standards") {
		d.Conformity.Standards = splitCommaList(docStandards)
	}
	if cmd.Flags().Changed("notified-body-name") {
		d.Conformity.NotifiedBodyName = docNotifiedBodyName
	}
	if cmd.Flags().Changed("notified-body-number") {
		d.Conformity.NotifiedBodyNumber = docNotifiedBodyNumber
	}
	if cmd.Flags().Changed("assessment-procedure") {
		d.AssessmentProcedure = docAssessmentProcedure
	}

	d.Signatory.Name = docSignatoryName
	d.Signatory.Function = docSignatoryFunction
	d.Signatory.Place = docSignatoryPlace
	d.Signatory.Date = docSignatoryDate
	if d.Signatory.Date == "" {
		d.Signatory.Date = time.Now().Format("2006-01-02")
	}
}

// applyLanguages resolves --languages into Declaration.Statements. Unlike
// the rest of applyDocOverrides, an explicitly-named language that isn't
// available is a hard error: silently dropping a language someone asked
// for by name would be worse than failing loudly on a legal document.
// "all" degrades gracefully instead, since it inherently means "whatever's
// currently embedded"; see internal/doc, which is filled in incrementally.
func applyLanguages(cmd *cobra.Command, d *eudoc.Declaration) error {
	raw := strings.TrimSpace(docLanguages)
	if raw == "" {
		raw = "en"
	}

	var codes []string
	if strings.EqualFold(raw, "all") {
		codes = doc.AvailableLanguages()
		if missing := doc.MissingLanguages(); len(missing) > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: %d of the EU's 24 official languages don't have an embedded translation yet and are omitted: %s\n", //nolint:errcheck // best-effort status output
				len(missing), strings.Join(missing, ", "))
		}
	} else {
		codes = splitCommaList(raw)
	}
	if len(codes) == 0 {
		return fmt.Errorf(`--languages must list at least one EU language code, or "all"`)
	}

	statements := make([]eudoc.Statement, 0, len(codes))
	for _, code := range codes {
		text, err := doc.Statement(code)
		if err != nil {
			return fmt.Errorf("--languages: %w", err)
		}
		statements = append(statements, eudoc.Statement{Language: strings.ToLower(strings.TrimSpace(code)), Text: text})
	}
	d.Statements = statements
	return nil
}

func splitCommaList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func signDocOutputs(cmd *cobra.Command) error {
	paths := []string{docOutput}
	if !docNoPDF {
		paths = append(paths, docPDF)
	}
	for _, path := range paths {
		sigPath, err := artifactsign.SignFile(cmd.Context(), path)
		if err != nil {
			return fmt.Errorf("signing %s: %w", path, err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "signed %s -> %s\n", path, sigPath) //nolint:errcheck // best-effort status output
	}
	return nil
}
