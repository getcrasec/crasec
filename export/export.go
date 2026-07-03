// Package export embeds the standalone HTML report templates
// internal/annex7export and internal/eudocexport render into PDF via
// internal/pdfexport. It exists because go:embed patterns can't reach
// outside the directory tree of the file that declares them, so once the
// templates moved to this shared top-level export/templates (alongside
// export/logo, the brand assets those templates inline), each package
// embedding them locally was no longer possible.
package export

import "embed"

// Templates holds every report template; callers parse the specific file
// they need with html/template.ParseFS.
//
//go:embed templates/annex7.html templates/eudoc.html
var Templates embed.FS
