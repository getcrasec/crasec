// Package pdfexport converts a standalone HTML report (inline CSS, no
// external resource references) into a PDF via headless Chrome/Chromium
// (chromedp), and locates a Chrome/Chromium executable to drive. It's
// artifact-agnostic — internal/annex7export and internal/eudocexport both
// build their own HTML and hand it here rather than each reimplementing
// the chromedp/Chrome-detection plumbing.
package pdfexport

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// footerTemplate returns Chrome's print footer (see
// PrintToPDFParams.FooterTemplate); it's rendered by Chrome itself outside
// the page's own DOM, using Chrome's special pageNumber/totalPages classes
// rather than anything from the caller's own HTML template. label
// identifies which artifact this PDF is (e.g. "CRA Annex VII Technical
// Documentation", "EU Declaration of Conformity").
func footerTemplate(label string) string {
	return fmt.Sprintf(`<div style="font-size:8px; width:100%%; text-align:center; color:#8a94a3; -webkit-print-color-adjust:exact;">crasec &middot; %s &middot; Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>`, label)
}

// RenderPDF converts html into a PDF using headless Chrome/Chromium at
// chromePath (see DetectChrome), with a footer branded with label. The
// conversion is given a bounded timeout so a broken browser install hangs
// the command instead of the caller.
func RenderPDF(ctx context.Context, html []byte, chromePath, label string) ([]byte, error) {
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
	tmp, err := os.CreateTemp("", "crasec-pdf-*.html")
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
				WithFooterTemplate(footerTemplate(label)).
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
		return nil, fmt.Errorf("converting %s to PDF via headless Chrome (%s): %w", label, chromePath, err)
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

// ChromePathEnvOverride resolves the --chrome-path flag value, falling back
// to $CHROME_PATH — the same override precedence every crasec PDF-exporting
// command uses.
func ChromePathEnvOverride(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("CHROME_PATH")
}
