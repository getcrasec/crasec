// Package eudocexport renders an EU Declaration of Conformity
// (internal/eudoc.Declaration) into a human-facing HTML report, ready for
// PDF conversion via internal/pdfexport — the same split
// internal/annex7/internal/annex7export uses.
package eudocexport

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"time"

	"github.com/getcrasec/crasec/internal/eudoc"
)

//go:embed templates/eudoc.html
var templateFS embed.FS

var reportTemplate = template.Must(template.ParseFS(templateFS, "templates/eudoc.html"))

// templateData is what templates/eudoc.html renders.
type templateData struct {
	D             eudoc.Declaration
	GeneratedAt   string
	Annex7Product string // empty if this Declaration wasn't derived from an Annex VII file
}

// RenderHTML renders d into the standalone EU Declaration of Conformity
// report: CSS is inline and there are no external resource references, so
// the same bytes work as a report on their own and as internal/pdfexport's
// PDF conversion input. annex7Product, if non-empty, is credited in the
// report's footer as the source of the auto-populated fields.
func RenderHTML(d eudoc.Declaration, annex7Product string) ([]byte, error) {
	data := templateData{
		D:             d,
		GeneratedAt:   time.Now().UTC().Format("2006-01-02 15:04 MST"),
		Annex7Product: annex7Product,
	}

	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("rendering EU DoC report HTML: %w", err)
	}
	return buf.Bytes(), nil
}

// Label identifies this report for internal/pdfexport's PDF page footer.
const Label = "EU Declaration of Conformity"
