# Crasec Logo System

## Files

| File | Size | Use |
|---|---|---|
| `crasec-logo-primary.svg` | 148×38 | Default — all light backgrounds |
| `crasec-logo-reversed.svg` | 148×38 | On dark backgrounds |
| `crasec-logo-mono.svg` | 148×38 | Greyscale / single-ink printing |
| `crasec-logo-pdf-header.svg` | 120×32 | PDF document headers (chromedp) |
| `crasec-mark.svg` | 48×48 | Favicon, document stamps, icon-only |

## The mark

Solid emerald square (#1D9E75) cut by a single white diagonal slash.
No radius. No gradients. No effects. Scales from 16px favicon to full page.

## Embed in PDF HTML template (chromedp)

Always inline the SVG — never use an `<img>` tag or external file reference.
chromedp does not reliably resolve external paths inside Go embed contexts.

```html
<!-- Paste at top of doc-header div in annex7.html and eu-doc.html -->
<div class="doc-logo">
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 32" width="120" height="32">
    <rect x="0" y="0" width="32" height="32" fill="#1D9E75"/>
    <line x1="0" y1="32" x2="32" y2="0" stroke="#FFFFFF" stroke-width="4.5" stroke-linecap="square"/>
    <text x="42" y="24"
      font-family="Inter,system-ui,sans-serif"
      font-size="22" font-weight="700" letter-spacing="-0.8"
      fill="#141412">crasec</text>
  </svg>
</div>
```

## Colours

| Token | Hex | Role |
|---|---|---|
| Brand emerald | `#1D9E75` | Mark fill |
| Near-black | `#141412` | Wordmark (light bg), mark fill (mono) |
| White | `#FFFFFF` | Slash on mark, wordmark on dark |

## Rules

- Never add border-radius to the mark — the sharp corner is intentional
- Never stretch or distort the aspect ratio
- Never place on a coloured background other than dark (`#0F0F0E` or similar) — use the reversed variant instead
- Never render below 48px wide total — use `crasec-mark.svg` below that threshold
- Do not add a tagline or descriptor text to the logo — the mark and wordmark are complete as-is
