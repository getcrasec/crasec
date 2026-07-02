package annex7

import "strings"

// RenderedField is one section field prepared for a human-facing export
// (PDF/HTML) rather than the wizard.
type RenderedField struct {
	Label string
	Value string
	Empty bool
}

// RenderedSection is one of Annex VII's 10 sections, prepared for a
// human-facing export.
type RenderedSection struct {
	Number   int
	Title    string
	Complete bool
	Fields   []RenderedField
}

// Render returns doc's 10 sections in a form suitable for annex7export (or
// any other human-facing renderer), reusing the exact field labels and
// completion rules the wizard uses so the PDF/HTML export and the
// interactive wizard can never drift apart.
func Render(doc *TechnicalFile) []RenderedSection {
	out := make([]RenderedSection, len(sections))
	for i, s := range sections {
		rs := RenderedSection{
			Number:   s.number,
			Title:    s.title,
			Complete: SectionComplete(doc, i),
			Fields:   make([]RenderedField, len(s.fields)),
		}
		for j, f := range s.fields {
			val := f.get(doc)
			rs.Fields[j] = RenderedField{
				Label: f.label,
				Value: val,
				Empty: strings.TrimSpace(val) == "",
			}
		}
		out[i] = rs
	}
	return out
}
