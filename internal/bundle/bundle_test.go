package bundle

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAll creates every artifact DefaultOptions expects, in dir, with
// distinct content so hashes are easy to tell apart in assertions.
func writeAll(t *testing.T, dir string) Options {
	t.Helper()
	opts := DefaultOptions("myapp")
	opts.Output = filepath.Join(dir, "evidence-bundle.zip")

	set := map[string]*string{
		opts.SBOM: &opts.SBOM, opts.SBOMSig: &opts.SBOMSig,
		opts.VEX: &opts.VEX, opts.VEXSig: &opts.VEXSig,
		opts.CSAF: &opts.CSAF, opts.CSAFSig: &opts.CSAFSig,
		opts.Annex7JSON: &opts.Annex7JSON, opts.Annex7PDF: &opts.Annex7PDF,
		opts.EUDocJSON: &opts.EUDocJSON, opts.EUDocPDF: &opts.EUDocPDF, opts.EUDocPDFSig: &opts.EUDocPDFSig,
	}

	// Rewrite each field to live under dir, and create the file with
	// content unique to its own (original, relative) name.
	rewrite := func(rel *string) {
		content := "content of " + *rel
		abs := filepath.Join(dir, *rel)
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		*rel = abs
	}
	for rel := range set {
		rewrite(set[rel])
	}

	return opts
}

func TestMissingArtifacts_AllMissingOnEmptyDir(t *testing.T) {
	opts := DefaultOptions("myapp")
	opts.Output = filepath.Join(t.TempDir(), "bundle.zip")
	// Point every source path somewhere that doesn't exist.
	dir := t.TempDir()
	opts.SBOM = filepath.Join(dir, opts.SBOM)
	opts.SBOMSig = filepath.Join(dir, opts.SBOMSig)
	opts.VEX = filepath.Join(dir, opts.VEX)
	opts.VEXSig = filepath.Join(dir, opts.VEXSig)
	opts.CSAF = filepath.Join(dir, opts.CSAF)
	opts.CSAFSig = filepath.Join(dir, opts.CSAFSig)
	opts.Annex7JSON = filepath.Join(dir, opts.Annex7JSON)
	opts.Annex7PDF = filepath.Join(dir, opts.Annex7PDF)
	opts.EUDocJSON = filepath.Join(dir, opts.EUDocJSON)
	opts.EUDocPDF = filepath.Join(dir, opts.EUDocPDF)
	opts.EUDocPDFSig = filepath.Join(dir, opts.EUDocPDFSig)

	missing := MissingArtifacts(opts.Artifacts())
	if len(missing) != 11 {
		t.Fatalf("expected all 11 artifacts missing, got %d: %v", len(missing), missing)
	}
	for _, m := range missing {
		if m.Hint == "" {
			t.Errorf("expected a non-empty hint for missing artifact %s", m.BundleName)
		}
	}
}

func TestExport_FailsCleanlyWhenArtifactsAreMissing(t *testing.T) {
	dir := t.TempDir()
	opts := DefaultOptions("myapp")
	opts.Output = filepath.Join(dir, "evidence-bundle.zip")
	opts.SBOM = filepath.Join(dir, "sbom.cdx.json") // doesn't exist

	if _, err := Export(opts); err == nil {
		t.Fatal("expected Export to fail when artifacts are missing")
	}
	if _, err := os.Stat(opts.Output); err == nil {
		t.Fatal("expected no ZIP to be written when artifacts are missing")
	}
}

func TestExport_ProducesValidZipWithAllEntries(t *testing.T) {
	dir := t.TempDir()
	opts := writeAll(t, dir)

	manifest, err := Export(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 11 {
		t.Fatalf("expected 11 manifest entries, got %d", len(manifest.Files))
	}

	zr, err := zip.OpenReader(opts.Output)
	if err != nil {
		t.Fatalf("opening bundle as zip: %v", err)
	}
	defer zr.Close()

	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}

	wantNames := []string{
		"sbom.cdx.json", "sbom.cdx.json.sig",
		"vex.cdx.json", "vex.cdx.json.sig",
		"csaf-advisory.json", "csaf-advisory.json.sig",
		"annex7.json", "annex7.pdf",
		"eu-doc.json", "eu-doc.pdf", "eu-doc.pdf.sig",
		"manifest.json", "README.txt",
	}
	for _, w := range wantNames {
		if !names[w] {
			t.Errorf("expected bundle to contain %q, entries: %v", w, names)
		}
	}
	if len(zr.File) != len(wantNames) {
		t.Errorf("expected exactly %d entries, got %d: %v", len(wantNames), len(zr.File), names)
	}
}

func TestExport_ManifestSHA256MatchesActualZipContent(t *testing.T) {
	dir := t.TempDir()
	opts := writeAll(t, dir)

	manifest, err := Export(opts)
	if err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(opts.Output)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		byName[f.Name] = f
	}

	for _, entry := range manifest.Files {
		zf, ok := byName[entry.Name]
		if !ok {
			t.Fatalf("manifest references %q, not present in zip", entry.Name)
		}
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		buf := make([]byte, 4096)
		for {
			n, rerr := rc.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		rc.Close()

		got := hex.EncodeToString(h.Sum(nil))
		if got != entry.SHA256 {
			t.Errorf("%s: manifest sha256 %s doesn't match actual zip content sha256 %s", entry.Name, entry.SHA256, got)
		}
	}
}

func TestExport_ManifestJSONInsideZipMatchesReturnedManifest(t *testing.T) {
	dir := t.TempDir()
	opts := writeAll(t, dir)

	manifest, err := Export(opts)
	if err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(opts.Output)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()

		var fromZip Manifest
		if err := json.NewDecoder(rc).Decode(&fromZip); err != nil {
			t.Fatal(err)
		}
		if fromZip.Product != manifest.Product || len(fromZip.Files) != len(manifest.Files) {
			t.Fatalf("manifest.json inside the zip doesn't match Export's returned manifest: %+v vs %+v", fromZip, manifest)
		}
		return
	}
	t.Fatal("manifest.json not found in zip")
}

func TestExport_ReadmeExplainsEveryBundledFile(t *testing.T) {
	dir := t.TempDir()
	opts := writeAll(t, dir)

	if _, err := Export(opts); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(opts.Output)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "README.txt" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		buf := make([]byte, 0, 8192)
		tmp := make([]byte, 4096)
		for {
			n, rerr := rc.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if rerr != nil {
				break
			}
		}
		content := string(buf)
		for _, mention := range []string{"sbom.cdx.json", "vex.cdx.json", "csaf-advisory.json", "annex7.json", "eu-doc.json", "manifest.json"} {
			if !strings.Contains(content, mention) {
				t.Errorf("expected README.txt to mention %q", mention)
			}
		}
		return
	}
	t.Fatal("README.txt not found in zip")
}
