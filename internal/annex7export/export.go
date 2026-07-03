// Package annex7export renders a CRA Annex VII technical file
// (internal/annex7.TechnicalFile) into a human-facing HTML report, as
// opposed to the JSON the wizard writes, which is meant for a SaaS vault to
// store and index, not for a person to open. PDF conversion of that HTML is
// handled by internal/pdfexport, shared with internal/eudocexport.
package annex7export

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"time"

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
// work as a report on their own and as internal/pdfexport's PDF conversion
// input.
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

// Label identifies this report for internal/pdfexport's PDF page footer.
const Label = "CRA Annex VII Technical Documentation"
