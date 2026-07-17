# Crasec Logo System

Mirrors `crasec-web/public/crasec-logo-kit/svg/` — that's the source of
truth; these files are copies kept in sync for the PDF export templates
(`export/templates/annex7.html`, `export/templates/eudoc.html`), which embed
their own inline copy of `crasec-logo-pdf-header.svg` rather than loading it
at runtime (see "Embed in PDF HTML template" below).

## Files

| File | Size | Use |
|---|---|---|
| `crasec-logo-primary.svg` | 148×33 | Default — all light backgrounds |
| `crasec-logo-reversed.svg` | 148×33 | On dark backgrounds |
| `crasec-logo-mono.svg` | 148×33 | Greyscale / single-ink printing |
| `crasec-logo-pdf-header.svg` | 145×33 | PDF document headers (chromedp) |
| `crasec-mark.svg` | 48×48 | Favicon, document stamps, icon-only |

## The mark

A rounded squircle in brand blue (#0066CC) with a light-blue (#7CB0EA)
diagonal corner cut. Soft radius, no gradients, no effects. Scales from
16px favicon to full page.

## Embed in PDF HTML template (chromedp)

Always inline the SVG — never use an `<img>` tag or external file reference.
chromedp does not reliably resolve external paths inside Go embed contexts.

```html
<!-- Paste at top of doc-header div in annex7.html and eudoc.html -->
<div class="doc-logo">
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 442 100" width="145" height="33">
    <path d="M28,4 H68 L96,32 V84 A12,12 0 0 1 84,96 H16 A12,12 0 0 1 4,84 V16 A12,12 0 0 1 16,4 Z" fill="#0066CC"/>
    <path d="M68,4 L96,32 L68,32 Z" fill="#7CB0EA"/>
    <path d="M153.573 76.11...Z" fill="#0E1220"/> <!-- wordmark; copy the full path data from crasec-logo-pdf-header.svg -->
  </svg>
</div>
```

## Colours

| Token | Hex | Role |
|---|---|---|
| Brand blue | `#0066CC` | Mark fill |
| Light blue | `#7CB0EA` | Mark corner-cut accent |
| Ink | `#0E1220` | Wordmark (light bg), mark fill (mono) |
| White | `#FFFFFF` | Mark + wordmark on dark backgrounds |

## Rules

- Never stretch or distort the aspect ratio
- Never place the primary (blue) variant on a coloured background other than dark — use the reversed (white) variant instead
- Never render below 48px wide total — use `crasec-mark.svg` below that threshold
- Do not add a tagline or descriptor text to the logo — the mark and wordmark are complete as-is
