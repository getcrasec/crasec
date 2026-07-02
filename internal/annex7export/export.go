// Package annex7export renders a CRA Annex VII technical file
// (internal/annex7.TechnicalFile) into human-facing output: an HTML report
// and, via headless Chrome (chromedp), a PDF an auditor or board member can
// actually read and sign — as opposed to the JSON the wizard writes, which
// is meant for a SaaS vault to store and index, not for a person to open.
package annex7export

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/getcrasec/crasec/internal/annex7"
)

//go:embed templates/annex7.html
var templateFS embed.FS

var reportTemplate = template.Must(template.ParseFS(templateFS, "templates/annex7.html"))

// templateData is what templates/annex7.html renders.
type templateData struct {
	Product         string
	GeneratedAt     string
	Done, Total     int
	PercentComplete int
	Sections        []annex7.RenderedSection
}

// RenderHTML renders doc into the standalone Annex VII report: CSS is
// inline and there are no external resource references, so the same bytes
// work as a report on their own and as chromedp's PDF conversion input.
func RenderHTML(doc *annex7.TechnicalFile) ([]byte, error) {
	done, total := annex7.Completion(doc)
	percent := 0
	if total > 0 {
		percent = done * 100 / total
	}

	data := templateData{
		Product:         doc.Product,
		GeneratedAt:     time.Now().UTC().Format("2006-01-02 15:04 MST"),
		Done:            done,
		Total:           total,
		PercentComplete: percent,
		Sections:        annex7.Render(doc),
	}

	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("rendering annex7 report HTML: %w", err)
	}
	return buf.Bytes(), nil
}

// footerTemplate is Chrome's print footer (see PrintToPDFParams.FooterTemplate);
// it's rendered by Chrome itself outside the page's own DOM, hence the
// separate small HTML snippet with Chrome's special pageNumber/totalPages
// classes rather than anything from templates/annex7.html.
const footerTemplate = `<div style="font-size:8px; width:100%; text-align:center; color:#8a94a3; -webkit-print-color-adjust:exact;">crasec &middot; CRA Annex VII Technical Documentation &middot; Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>`

// RenderPDF converts html into a PDF using headless Chrome/Chromium at
// chromePath (see DetectChrome). The conversion is given a bounded timeout
// so a broken browser install hangs the command instead of the caller.
func RenderPDF(ctx context.Context, html []byte, chromePath string) ([]byte, error) {
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	defer cancelTimeout()

	opts := append(append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...),
		chromedp.ExecPath(chromePath),
	)
	if isRoot() {
		// Chrome refuses to run sandboxed as root, which is the normal
		// state of affairs in an unprivileged CI/Docker container — add
		// --no-sandbox only in that case rather than unconditionally
		// weakening the sandbox on a developer's own machine.
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()

	taskCtx, cancelTask := chromedp.NewContext(allocCtx)
	defer cancelTask()

	// Navigate to a real file:// URL rather than injecting the HTML via a
	// data: URL or SetDocumentContent: PrintToPDF needs a fully loaded
	// page, and a multi-section report can exceed practical data: URL
	// length limits.
	tmp, err := os.CreateTemp("", "annex7-*.html")
	if err != nil {
		return nil, fmt.Errorf("creating temporary HTML file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(html); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing temporary HTML file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing temporary HTML file: %w", err)
	}

	var pdfData []byte
	err = chromedp.Run(taskCtx,
		chromedp.Navigate("file://"+tmp.Name()),
		chromedp.ActionFunc(func(ctx context.Context) error {
			data, _, err := page.PrintToPDF().
				WithPrintBackground(true).
				WithDisplayHeaderFooter(true).
				WithHeaderTemplate("<span></span>").
				WithFooterTemplate(footerTemplate).
				WithMarginTop(0.4).
				WithMarginBottom(0.5).
				WithMarginLeft(0.4).
				WithMarginRight(0.4).
				Do(ctx)
			if err != nil {
				return err
			}
			pdfData = data
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("converting Annex VII report to PDF via headless Chrome (%s): %w", chromePath, err)
	}
	return pdfData, nil
}

func isRoot() bool {
	return runtime.GOOS != "windows" && os.Geteuid() == 0
}

// chromeAbsolutePaths are well-known install locations chromedp itself
// checks first on platforms where PATH lookups alone are unreliable
// (notably macOS, where Chrome.app isn't normally on PATH at all).
func chromeAbsolutePaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "windows":
		paths := []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		}
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			paths = append(paths,
				filepath.Join(local, `Google\Chrome\Application\chrome.exe`),
				filepath.Join(local, `Chromium\Application\chrome.exe`),
			)
		}
		return paths
	default:
		return nil
	}
}

// chromePathNames are the binary names checked via $PATH, in priority
// order — Docker/CI images conventionally install one of these.
var chromePathNames = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"chrome",
}

// DetectChrome finds a Chrome/Chromium executable for RenderPDF to drive.
// override (--chrome-path, or the CHROME_PATH environment variable) always
// wins when set. Detection failure returns an actionable error explaining
// how to install a browser or point crasec at one, rather than letting
// chromedp fail deep inside PDF conversion with an opaque exec error — its
// own fallback is to blindly attempt to exec "google-chrome".
func DetectChrome(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("--chrome-path %s: %w", override, err)
		}
		return override, nil
	}

	for _, path := range chromeAbsolutePaths() {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	for _, name := range chromePathNames {
		if found, err := exec.LookPath(name); err == nil {
			return found, nil
		}
	}

	return "", fmt.Errorf(`no Chrome/Chromium installation found for PDF export.

Install one of:
  macOS:        brew install --cask google-chrome
  Debian/Ubuntu: apt-get install chromium
  Docker/CI:     add "chromium" (or "google-chrome-stable") to the base image

Or point crasec at an existing install with --chrome-path /path/to/chrome
(or the CHROME_PATH environment variable). Use --format html to skip PDF
conversion entirely and just get the styled HTML report`)
}
