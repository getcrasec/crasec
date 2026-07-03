// Package bundle assembles the auditor-ready CRA evidence package: a
// single ZIP containing every compliance artifact crasec can generate
// (SBOM, VEX, CSAF advisory, Annex VII technical file, EU Declaration of
// Conformity) plus a manifest.json an auditor can use to verify nothing
// was tampered with after generation, and a README.txt explaining what
// each file is in plain language.
//
// This package only assembles artifacts that already exist on disk; it
// doesn't generate them. That's deliberate: each artifact has its own
// generation command (with its own required inputs, like findings data or
// a manufacturer's signatory details) that "bundle export" has no business
// re-implementing.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// Artifact is one file the evidence bundle expects to find on disk.
type Artifact struct {
	// BundleName is the name this file is given inside the ZIP (and in
	// manifest.json), not necessarily the same as SourcePath's basename,
	// since crasec's own generate commands don't all default to the
	// bundle's canonical names (e.g. "crasec csaf generate" defaults to
	// advisory.json, but the bundle calls it csaf-advisory.json).
	BundleName string
	SourcePath string
	// Satisfies is the CRA requirement this artifact evidences, recorded
	// in manifest.json and explained in README.txt.
	Satisfies string
	// Hint is the command that produces this artifact, shown when it's
	// missing.
	Hint string
}

// Options configures where "bundle export" looks for each artifact and
// where it writes the resulting ZIP.
type Options struct {
	Product string

	SBOM, SBOMSig                    string
	VEX, VEXSig                      string
	CSAF, CSAFSig                    string
	Annex7JSON, Annex7PDF            string
	EUDocJSON, EUDocPDF, EUDocPDFSig string

	Output string // path to the resulting ZIP

	// EngineVersion is crasec's own version, recorded in the README.
	EngineVersion string
}

// DefaultOptions returns Options with every artifact path set to the
// default filename its own generate command uses, so "bundle export
// --product X" works out of the box for anyone who ran every prior step
// with default flags.
func DefaultOptions(product string) Options {
	return Options{
		Product: product,

		SBOM:    "sbom.cdx.json",
		SBOMSig: "sbom.cdx.json.sig",

		VEX:    "vex.cdx.json",
		VEXSig: "vex.cdx.json.sig",

		CSAF:    "advisory.json",
		CSAFSig: "advisory.json.sig",

		Annex7JSON: "annex7.json",
		Annex7PDF:  "annex7.pdf",

		EUDocJSON:   "eu-doc.json",
		EUDocPDF:    "eu-doc.pdf",
		EUDocPDFSig: "eu-doc.pdf.sig",

		Output: "evidence-bundle.zip",
	}
}

// Artifacts returns the fixed, ordered list of files the evidence bundle
// requires, resolved against o's configured paths.
func (o Options) Artifacts() []Artifact {
	product := o.Product

	return []Artifact{
		{
			BundleName: "sbom.cdx.json", SourcePath: o.SBOM,
			Satisfies: "CRA Annex I, Part II, §1 — Software Bill of Materials",
			Hint:      fmt.Sprintf("crasec sbom generate --target <path> -o %s", o.SBOM),
		},
		{
			BundleName: "sbom.cdx.json.sig", SourcePath: o.SBOMSig,
			Satisfies: "Integrity signature for sbom.cdx.json",
			Hint:      fmt.Sprintf("crasec sbom sign %s", o.SBOM),
		},
		{
			BundleName: "vex.cdx.json", SourcePath: o.VEX,
			Satisfies: "CRA Annex I, Part II, §2 — Vulnerability handling (exploitability assessment)",
			Hint:      fmt.Sprintf("crasec vex generate --sbom %s --findings findings.json -o %s", o.SBOM, o.VEX),
		},
		{
			BundleName: "vex.cdx.json.sig", SourcePath: o.VEXSig,
			Satisfies: "Integrity signature for vex.cdx.json",
			Hint:      fmt.Sprintf("crasec vex sign %s", o.VEX),
		},
		{
			BundleName: "csaf-advisory.json", SourcePath: o.CSAF,
			Satisfies: "CRA Article 14 — Vulnerability reporting / public disclosure (ENISA-recommended CSAF format)",
			Hint:      fmt.Sprintf("crasec csaf generate --findings findings.json --tracking-id <id> --title <title> --publisher-name <name> --publisher-namespace <url> -o %s", o.CSAF),
		},
		{
			BundleName: "csaf-advisory.json.sig", SourcePath: o.CSAFSig,
			Satisfies: "Integrity signature for csaf-advisory.json",
			Hint:      fmt.Sprintf("crasec csaf sign %s", o.CSAF),
		},
		{
			BundleName: "annex7.json", SourcePath: o.Annex7JSON,
			Satisfies: "CRA Annex VII — Technical documentation (machine-readable)",
			Hint:      fmt.Sprintf("crasec annex7 scaffold --product %s && crasec annex7 export --input annex7-%s.json -o %s", product, product, o.Annex7PDF),
		},
		{
			BundleName: "annex7.pdf", SourcePath: o.Annex7PDF,
			Satisfies: "CRA Annex VII — Technical documentation (human-readable)",
			Hint:      fmt.Sprintf("crasec annex7 export --input annex7-%s.json -o %s", product, o.Annex7PDF),
		},
		{
			BundleName: "eu-doc.json", SourcePath: o.EUDocJSON,
			Satisfies: "CRA Annex V — EU Declaration of Conformity (machine-readable)",
			Hint:      fmt.Sprintf("crasec doc generate --product %s --annex7 annex7-%s.json ... -o %s", product, product, o.EUDocJSON),
		},
		{
			BundleName: "eu-doc.pdf", SourcePath: o.EUDocPDF,
			Satisfies: "CRA Annex V — EU Declaration of Conformity (signed copy for CE marking)",
			Hint:      fmt.Sprintf("crasec doc generate --product %s --annex7 annex7-%s.json ... --pdf %s", product, product, o.EUDocPDF),
		},
		{
			BundleName: "eu-doc.pdf.sig", SourcePath: o.EUDocPDFSig,
			Satisfies: "Integrity signature for eu-doc.pdf",
			Hint:      fmt.Sprintf("crasec doc sign %s", o.EUDocPDF),
		},
	}
}

// MissingArtifacts checks every artifact in artifacts for existence on
// disk, returning the ones that aren't there. "bundle export" refuses to
// produce a ZIP silently missing evidence, so this is checked up front.
func MissingArtifacts(artifacts []Artifact) []Artifact {
	var missing []Artifact
	for _, a := range artifacts {
		if _, err := os.Stat(a.SourcePath); err != nil {
			missing = append(missing, a)
		}
	}
	return missing
}

// hashFile reads path and returns its contents alongside their SHA-256
// hex digest and last-modified time (used as the manifest's generated_at:
// simple, robust across every artifact's file format (JSON, PDF, and
// Sigstore bundle alike), unlike trying to extract a timestamp from each
// format's own internal structure).
func hashFile(path string) (data []byte, sha256Hex string, modTime time.Time, err error) {
	data, err = os.ReadFile(path) // #nosec G304 -- path is caller-supplied (ultimately a CLI flag), not attacker-controlled remote input
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("reading %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("stat %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), info.ModTime().UTC(), nil
}
