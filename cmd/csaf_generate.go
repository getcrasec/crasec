package cmd

import (
	"fmt"
	"io"
	"os"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/csafgen"
)

var (
	csafFindingsPath string
	csafSBOMPath     string
	csafOutput       string

	csafTrackingID      string
	csafTitle           string
	csafCategory        string
	csafLang            string
	csafStatus          string
	csafRevision        string
	csafRevisionSummary string

	csafPublisherName      string
	csafPublisherNamespace string
	csafPublisherContact   string
	csafPublisherCategory  string

	csafVendor         string
	csafProductName    string
	csafProductVersion string
	csafProductPURL    string
	csafProductCPE     string
)

var csafGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a CSAF 2.0 advisory from correlated findings",
	Long: `Build a CSAF (Common Security Advisory Framework) 2.0 document: the
machine-readable advisory format ENISA recommends for CRA vulnerability
disclosures, and what feeds the EUVD (EU Vulnerability Database). Output is
plain CSAF 2.0 JSON with three top-level sections — document (title,
tracking ID, status, revision history, publisher), product_tree (the
affected product's full_product_name/CPE and vendor/product/version
branches), and vulnerabilities (CVE, CVSS v3.x scores, notes, remediations)
— validated against the official OASIS CSAF 2.0 JSON schema
(https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json) before
anything is written.

Input is the findings JSON produced by "crasec vuln correlate" (--findings).
Product metadata (name/version/purl/cpe) is read from --sbom's
metadata.component when given; --product-* flags override it, and
--product-name is required if --sbom isn't given.

Re-running this command against the same --output path and --tracking-id
appends a new revision to document.tracking.revision_history (and bumps
current_release_date) rather than resetting it — pass --revision with an
incremented number and a --revision-summary describing what changed.

Typical pipeline:
  crasec sbom generate --target ./path -o sbom.cdx.json
  crasec vuln correlate --sbom sbom.cdx.json -o findings.json
  crasec csaf generate --sbom sbom.cdx.json --findings findings.json \
    --tracking-id CRASEC-2026-0001 --title "Security advisory for MyApp" \
    --publisher-name "Acme Corp" --publisher-namespace https://acme.example \
    -o advisory.json
  crasec csaf sign advisory.json`,
	RunE: runCSAFGenerate,
}

func init() {
	csafCmd.AddCommand(csafGenerateCmd)

	csafGenerateCmd.Flags().StringVar(&csafFindingsPath, "findings", "", "path to findings JSON produced by \"crasec vuln correlate\"")
	csafGenerateCmd.Flags().StringVar(&csafSBOMPath, "sbom", "", "path to the CycloneDX SBOM the findings were correlated against (used for product metadata)")
	csafGenerateCmd.Flags().StringVarP(&csafOutput, "output", "o", "advisory.json", "write the CSAF document to this file (\"-\" for stdout)")

	csafGenerateCmd.Flags().StringVar(&csafTrackingID, "tracking-id", "", "unique, stable document tracking ID, e.g. CRASEC-2026-0001 (required)")
	csafGenerateCmd.Flags().StringVar(&csafTitle, "title", "", "document title (required)")
	csafGenerateCmd.Flags().StringVar(&csafCategory, "category", "csaf_security_advisory", "CSAF document category")
	csafGenerateCmd.Flags().StringVar(&csafLang, "lang", "en", "document language (BCP 47)")
	csafGenerateCmd.Flags().StringVar(&csafStatus, "status", "draft", "document status: draft, final, or interim")
	csafGenerateCmd.Flags().StringVar(&csafRevision, "revision", "1", "this revision's number; bump it on every re-generation")
	csafGenerateCmd.Flags().StringVar(&csafRevisionSummary, "revision-summary", "", "what changed in this revision (default: \"Initial version\" or \"Updated vulnerability data\")")

	csafGenerateCmd.Flags().StringVar(&csafPublisherName, "publisher-name", "", "manufacturer/publisher name (required)")
	csafGenerateCmd.Flags().StringVar(&csafPublisherNamespace, "publisher-namespace", "", "URL identifying the publisher, e.g. https://example.com (required)")
	csafGenerateCmd.Flags().StringVar(&csafPublisherContact, "publisher-contact", "", "publisher contact details (email, URL, etc.)")
	csafGenerateCmd.Flags().StringVar(&csafPublisherCategory, "publisher-category", "vendor", "publisher category: vendor, coordinator, discoverer, user, translator, or other")

	csafGenerateCmd.Flags().StringVar(&csafVendor, "vendor", "", "product_tree vendor branch name (default: --publisher-name)")
	csafGenerateCmd.Flags().StringVar(&csafProductName, "product-name", "", "name of the product this advisory is about (default: --sbom's metadata.component.name)")
	csafGenerateCmd.Flags().StringVar(&csafProductVersion, "product-version", "", "version of the product this advisory is about (default: --sbom's metadata.component.version)")
	csafGenerateCmd.Flags().StringVar(&csafProductPURL, "product-purl", "", "package URL identifying the product (default: --sbom's metadata.component.purl)")
	csafGenerateCmd.Flags().StringVar(&csafProductCPE, "product-cpe", "", "CPE identifying the product (default: --sbom's metadata.component.cpe)")

	for _, f := range []string{"findings", "tracking-id", "title", "publisher-name", "publisher-namespace"} {
		if err := csafGenerateCmd.MarkFlagRequired(f); err != nil {
			panic(err)
		}
	}
}

func runCSAFGenerate(cmd *cobra.Command, _ []string) error {
	// Errors past this point are about input data (missing product info,
	// findings that don't parse, a document that fails schema validation),
	// not CLI misuse, so a cobra flag-usage dump would just be noise.
	cmd.SilenceUsage = true

	findings, err := loadFindings(csafFindingsPath)
	if err != nil {
		return err
	}

	meta, err := resolveCSAFMetadata(cmd)
	if err != nil {
		return err
	}

	var prev *gocsaf.Advisory
	if csafOutput != "-" {
		if prev, err = csafgen.LoadPrevious(csafOutput); err != nil {
			return err
		}
	}

	adv, err := csafgen.GenerateAdvisory(findings, meta, prev)
	if err != nil {
		return fmt.Errorf("generating CSAF advisory: %w", err)
	}

	data, err := csafgen.MarshalAndValidate(adv)
	if err != nil {
		return err
	}

	w, closeW, err := resolveCSAFWriter()
	if err != nil {
		return err
	}
	defer closeW()

	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing CSAF advisory: %w", err)
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("writing CSAF advisory: %w", err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "wrote CSAF advisory with %d vulnerabilities\n", len(adv.Vulnerabilities))
	return nil
}

// resolveCSAFMetadata builds a csafgen.Metadata from flags, reading product
// defaults from --sbom's metadata.component (when given) and letting the
// --product-* flags override them, same pattern as "crasec vex generate".
func resolveCSAFMetadata(cmd *cobra.Command) (csafgen.Metadata, error) {
	meta := csafgen.Metadata{
		TrackingID:      csafTrackingID,
		Title:           csafTitle,
		Category:        csafCategory,
		Lang:            csafLang,
		Status:          csafStatus,
		RevisionNumber:  csafRevision,
		RevisionSummary: csafRevisionSummary,
		EngineVersion:   version,

		PublisherName:      csafPublisherName,
		PublisherNamespace: csafPublisherNamespace,
		PublisherContact:   csafPublisherContact,
		PublisherCategory:  csafPublisherCategory,

		VendorName:     csafVendor,
		ProductName:    csafProductName,
		ProductVersion: csafProductVersion,
		ProductPURL:    csafProductPURL,
		ProductCPE:     csafProductCPE,
	}

	if csafSBOMPath != "" {
		component, err := loadSBOMComponent(csafSBOMPath)
		if err != nil {
			return csafgen.Metadata{}, err
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
			if !cmd.Flags().Changed("product-cpe") {
				meta.ProductCPE = component.CPE
			}
		}
	}

	if meta.ProductName == "" {
		return csafgen.Metadata{}, fmt.Errorf("no product name available: pass --product-name, or --sbom pointing at an SBOM with metadata.component.name set")
	}
	return meta, nil
}

// resolveCSAFWriter returns the io.Writer to use for the CSAF document.
// --output "-" writes to stdout; otherwise it creates (or truncates) the
// named file. The caller must invoke the returned close func.
func resolveCSAFWriter() (io.Writer, func(), error) {
	if csafOutput == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(csafOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file %s: %w", csafOutput, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", csafOutput, cerr)
		}
	}, nil
}
