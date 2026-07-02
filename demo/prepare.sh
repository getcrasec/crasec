#!/usr/bin/env bash
# One-time setup for demo.tape: produces the compliance artifacts that
# can't be generated live on camera in a 90-second recording — the Annex
# VII technical file (a guided wizard meant to take real thought, not be
# typed through in a GIF) and every Sigstore signature (keyless signing
# opens a real browser OIDC login; it can't run unattended in a recorded
# terminal). Everything demo.tape *does* run live (init, sbom generate,
# vuln correlate, bundle export) runs unmodified against what this script
# produces — nothing in the final ZIP is fabricated, just prepared ahead
# of time instead of on screen.
#
# Run this once, interactively, before recording:
#   demo/prepare.sh
#
# It will pause and open a browser for Sigstore login four times (once per
# artifact signed) unless GITHUB_ACTIONS is set, in which case Sigstore
# uses the workflow's ambient OIDC token instead.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
FIXTURE="fixtures/vulnerable-node-app"
SEED="$(pwd)/.seed"
CRASEC="${CRASEC_BIN:-crasec}"

rm -rf "$SEED"
mkdir -p "$SEED"
cp "$FIXTURE"/package.json "$FIXTURE"/package-lock.json "$SEED"/
cd "$SEED"

"$CRASEC" init --non-interactive \
  --product vulnerable-node-app \
  --manufacturer-name "Acme Corp" \
  --manufacturer-address "1 Rue de la Paix, 75002 Paris, France"

"$CRASEC" sbom generate -o sbom.cdx.json
"$CRASEC" sbom sign sbom.cdx.json

# --osv-scanner=false: keeps the demo to a single dependency (crasec
# itself). vex-decisions.yaml below was built from this same grype-only
# finding set — if you drop this flag, regenerate that file too, since
# osv-scanner surfaces additional CVEs it won't have decisions for.
"$CRASEC" vuln correlate --sbom sbom.cdx.json --osv-scanner=false -o findings.json

"$CRASEC" vex generate --sbom sbom.cdx.json --findings findings.json \
  --from-file "../$FIXTURE/vex-decisions.yaml" -o vex.cdx.json
"$CRASEC" vex sign vex.cdx.json

"$CRASEC" csaf generate --sbom sbom.cdx.json --findings findings.json \
  --tracking-id CRASEC-2026-0001 \
  --title "Security advisory for vulnerable-node-app" \
  --publisher-name "Acme Corp" \
  --publisher-namespace "https://acme.example" \
  -o advisory.json
"$CRASEC" csaf sign advisory.json

echo
echo "Now run the Annex VII wizard interactively (it's meant to be filled"
echo "in by a human, not scripted) and export it:"
echo
echo "  cd $SEED"
echo "  crasec annex7 scaffold --product vulnerable-node-app"
echo "  crasec annex7 export --input annex7-vulnerable-node-app.json -o annex7.pdf"
echo
echo "Then generate and sign the EU Declaration of Conformity:"
echo
echo "  crasec doc generate --product vulnerable-node-app \\"
echo "    --manufacturer-name \"Acme Corp\" \\"
echo "    --manufacturer-address \"1 Rue de la Paix, 75002 Paris, France\" \\"
echo "    --signatory-name \"Jane Doe\" --signatory-function \"CTO\" --signatory-place Paris \\"
echo "    --sign"
echo
echo "Once eu-doc.json/eu-doc.pdf/eu-doc.pdf.sig exist alongside annex7.json/annex7.pdf"
echo "in $SEED, demo.tape is ready to record: crasec bundle export will find"
echo "every required artifact and produce a real evidence-bundle.zip on camera."
