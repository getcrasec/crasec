package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/annex7"
	"github.com/getcrasec/crasec/internal/annex7export"
	"github.com/getcrasec/crasec/internal/pdfexport"
)

var (
	annex7ExportInput      string
	annex7ExportOutput     string
	annex7ExportFormat     string
	annex7ExportChromePath string
)

var annex7ExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the Annex VII technical file as a human-readable PDF or HTML report",
	Long: `Render a technical file produced by "crasec annex7 scaffold" into a
document an auditor, the board, or a compliance officer can actually read
and sign. The JSON is for a SaaS vault to store and index, not for a human.

--format pdf (the default) converts the report to PDF using headless
Chrome/Chromium via chromedp; a browser must be installed on the system (in
Docker/CI, add "chromium" to the base image). If none is found, crasec
reports that clearly rather than failing deep inside the conversion.
--chrome-path (or $CHROME_PATH) points it at a specific install.

--format html skips the Chrome dependency entirely and writes the same
styled report as standalone HTML, useful for previewing the layout, or
when no browser is available.

Incomplete sections (missing required fields) are highlighted in amber in
both formats, so it's obvious at a glance whether the file is audit-ready.

The source JSON is always copied alongside the export (same path as
--output with its extension replaced by .json). That's the file the SaaS
vault stores; the PDF/HTML is for people.

  crasec annex7 scaffold --product myapp
  crasec annex7 export --input annex7-myapp.json --format pdf -o annex7.pdf`,
	RunE: runAnnex7Export,
}

func init() {
	annex7Cmd.AddCommand(annex7ExportCmd)

	annex7ExportCmd.Flags().StringVar(&annex7ExportInput, "input", "", "path to the technical file JSON produced by \"crasec annex7 scaffold\" (required)")
	annex7ExportCmd.Flags().StringVarP(&annex7ExportOutput, "output", "o", "annex7.pdf", "output path for the report")
	annex7ExportCmd.Flags().StringVar(&annex7ExportFormat, "format", "pdf", "output format: pdf or html")
	annex7ExportCmd.Flags().StringVar(&annex7ExportChromePath, "chrome-path", "", "path to a Chrome/Chromium executable (default: $CHROME_PATH, then auto-detected)")

	if err := annex7ExportCmd.MarkFlagRequired("input"); err != nil {
		panic(err)
	}
}

func runAnnex7Export(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	format := strings.ToLower(annex7ExportFormat)
	if format != "pdf" && format != "html" {
		return fmt.Errorf("invalid --format %q: must be pdf or html", annex7ExportFormat)
	}

	doc, err := annex7.Load(annex7ExportInput)
	if err != nil {
		return err
	}

	html, err := annex7export.RenderHTML(doc)
	if err != nil {
		return err
	}

	var reportBytes []byte
	switch format {
	case "html":
		reportBytes = html
	case "pdf":
		chromePath, err := pdfexport.DetectChrome(pdfexport.ChromePathEnvOverride(annex7ExportChromePath))
		if err != nil {
			return err
		}
		reportBytes, err = pdfexport.RenderPDF(cmd.Context(), html, chromePath, annex7export.Label)
		if err != nil {
			return err
		}
	}

	if err := os.WriteFile(annex7ExportOutput, reportBytes, 0o644); err != nil { // #nosec G306 -- report is a shareable compliance document, not secret
		return fmt.Errorf("writing %s: %w", annex7ExportOutput, err)
	}

	// The JSON is what the SaaS vault stores and indexes; keep it right
	// next to the human-facing report.
	jsonPath := strings.TrimSuffix(annex7ExportOutput, filepath.Ext(annex7ExportOutput)) + ".json"
	if err := annex7.Save(doc, jsonPath); err != nil {
		return err
	}

	// Best-effort status output to stderr; a write failure here doesn't
	// affect the command's actual result.
	done, total := annex7.Completion(doc)
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s and %s (%d/%d sections complete)\n", annex7ExportOutput, jsonPath, done, total) //nolint:errcheck
	if done < total {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d section(s) incomplete, highlighted in amber in the report\n", total-done) //nolint:errcheck
	}
	return nil
}
