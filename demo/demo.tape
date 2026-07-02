# demo.tape — the README's terminal demo GIF.
#
# Records the real crasec CLI running against demo/fixtures/vulnerable-node-app
# (a package.json/package-lock.json pinned to express 4.17.1 / lodash 4.17.15
# / minimist 0.0.8 — versions with real, published CVEs) and produces a real,
# valid evidence-bundle.zip on camera.
#
# What's recorded live: init, sbom generate, vuln correlate, bundle export,
# and unzipping the result — all offline/deterministic, no network- or
# browser-dependent step in the recording itself.
#
# What's pre-baked (see prepare.sh): the SBOM's Sigstore signature, the VEX
# document, the CSAF advisory, the Annex VII technical file, and the EU
# Declaration of Conformity, plus every one of *their* Sigstore signatures.
# Annex VII is a guided wizard meant to take real thought, not be typed
# through in 90 seconds; every signature needs its own interactive Sigstore
# browser login, and four of those in one GIF (plus whatever lag vhs's
# screen capture has around a step that shells out to open a real browser)
# makes for a slog to record and an unreliable one to reproduce. Run
# demo/prepare.sh once, interactively, before recording; nothing in the
# final ZIP is fabricated, just prepared ahead of time instead of on screen.
#
# One consequence: the live "sbom generate" step below writes a *fresh*
# sbom.cdx.json (new timestamp/serial each run), but the sbom.cdx.json.sig
# bundled alongside it was signed over prepare.sh's earlier run. "crasec
# bundle export" only checks that required files exist, not that signatures
# still match their artifact's current bytes, so this doesn't block
# recording — it just means this demo doesn't double as proof the bundled
# SBOM's signature verifies; "crasec sbom verify" against a freshly-recorded
# file isn't part of this recording.
#
# Before any of this: build crasec from this branch and put it on PATH —
# both prepare.sh and this tape invoke the "crasec" command directly, and a
# stale globally-installed crasec would silently record the wrong version.
#   go build -o /tmp/crasec-demo/crasec .   # from the repo root
#   export PATH="/tmp/crasec-demo:$PATH"
#   crasec version                          # sanity check
#
# Install vhs: go install github.com/charmbracelet/vhs@latest
# Record (from the demo/ directory, so the relative paths below resolve):
#   cd demo && ./prepare.sh && vhs demo.tape

Output demo.gif

Require crasec
Require unzip

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 720
Set Padding 20
Set Theme "GitHub Dark"
Set TypingSpeed 90ms
Set PlaybackSpeed 1.0

Hide
Type "rm -rf .work && mkdir -p .work/vulnerable-node-app && cd .work/vulnerable-node-app" Enter
Type "cp ../../fixtures/vulnerable-node-app/package.json ../../fixtures/vulnerable-node-app/package-lock.json ." Enter
Type "cp ../../.seed/sbom.cdx.json.sig ." Enter
Type "cp ../../.seed/vex.cdx.json ../../.seed/vex.cdx.json.sig ." Enter
Type "cp ../../.seed/advisory.json ../../.seed/advisory.json.sig ." Enter
Type "cp ../../.seed/annex7.json ../../.seed/annex7.pdf ." Enter
Type "cp ../../.seed/eu-doc.json ../../.seed/eu-doc.pdf ../../.seed/eu-doc.pdf.sig ." Enter
Type "clear" Enter
Show

# --- crasec init -----------------------------------------------------------
# Wait+Screen (not the default Wait, which only checks the cursor's current
# line) — the wizard's label text isn't necessarily on the last line.
Type "crasec init"
Enter
Wait+Screen@5s /Product name/
Enter
Wait+Screen@2s /Product version/
Enter
Wait+Screen@2s /Manufacturer name/
Type "Acme Corp"
Enter
Wait+Screen@2s /Manufacturer address/
Type "1 Rue de la Paix, 75002 Paris, France"
Enter
Wait+Screen@2s /Scan target/
Enter
Wait+Screen@2s /Review/
Enter
Sleep 800ms

# --- crasec sbom generate ---------------------------------------------------
Type "crasec sbom generate -o sbom.cdx.json"
Enter
Wait@30s
Sleep 500ms

# --- crasec vuln correlate ---------------------------------------------------
# --osv-scanner=false: keeps recording to a single dependency (crasec
# itself) and matches the finding set demo/fixtures/.../vex-decisions.yaml
# (used by prepare.sh) was built from.
#
# Plain Wait (default Line scope, waits for the shell prompt to reappear)
# rather than Wait+Screen /regex/ — the latter has repeatedly stalled on
# this setup for any command with real backend work behind it (Sigstore
# signing, KEV-catalog fetch), even once standalone runs confirmed the
# underlying command itself completes quickly. Plain Wait already proved
# reliable for "sbom generate" above, so it's used consistently below too.
Type "crasec vuln correlate --sbom sbom.cdx.json --osv-scanner=false -o findings.json"
Enter
Wait@30s
Sleep 2s

# --- crasec bundle export ---------------------------------------------------
Type "crasec bundle export"
Enter
Wait@15s
Sleep 500ms

Type "unzip -l evidence-bundle.zip"
Enter
Sleep 3s
