package bundle

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ManifestEntry is one file's integrity record in manifest.json.
type ManifestEntry struct {
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	GeneratedAt string `json:"generated_at"`
	Satisfies   string `json:"satisfies"`
}

// Manifest is manifest.json: the auditor's single entry point to verify
// nothing in the bundle was tampered with after generation.
type Manifest struct {
	Product         string          `json:"product"`
	BundleCreatedAt string          `json:"bundle_created_at"`
	Files           []ManifestEntry `json:"files"`
}

// Export assembles the evidence bundle at opts.Output. Every artifact in
// opts.Artifacts() must already exist on disk (see MissingArtifacts);
// callers should check that first to produce a clear pre-flight error
// rather than have Export fail partway through reading files.
func Export(opts Options) (_ *Manifest, err error) {
	artifacts := opts.Artifacts()
	if missing := MissingArtifacts(artifacts); len(missing) > 0 {
		return nil, fmt.Errorf("%d required artifact(s) missing; see the list above", len(missing))
	}

	now := time.Now().UTC()
	manifest := &Manifest{
		Product:         opts.Product,
		BundleCreatedAt: now.Format(time.RFC3339),
	}

	type loaded struct {
		artifact Artifact
		data     []byte
	}
	files := make([]loaded, 0, len(artifacts))

	for _, a := range artifacts {
		data, sum, modTime, hashErr := hashFile(a.SourcePath)
		if hashErr != nil {
			return nil, hashErr
		}
		files = append(files, loaded{artifact: a, data: data})
		manifest.Files = append(manifest.Files, ManifestEntry{
			Name:        a.BundleName,
			SHA256:      sum,
			GeneratedAt: modTime.Format(time.RFC3339),
			Satisfies:   a.Satisfies,
		})
	}

	manifestJSON, jsonErr := json.MarshalIndent(manifest, "", "  ")
	if jsonErr != nil {
		return nil, fmt.Errorf("encoding manifest.json: %w", jsonErr)
	}

	readme := renderReadme(opts, manifest, now)

	zf, createErr := os.Create(opts.Output)
	if createErr != nil {
		return nil, fmt.Errorf("creating %s: %w", opts.Output, createErr)
	}
	defer func() {
		if closeErr := zf.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing %s: %w", opts.Output, closeErr)
		}
		if err != nil {
			// Don't leave a partial/corrupt ZIP behind for a later "bundle
			// export" run to trip over. Best-effort: we're already
			// returning an error, so a failed cleanup isn't actionable.
			_ = os.Remove(opts.Output) //nolint:errcheck
		}
	}()

	zw := zip.NewWriter(zf)

	for _, f := range files {
		if err = writeZipEntry(zw, f.artifact.BundleName, now, f.data); err != nil {
			return nil, err
		}
	}
	if err = writeZipEntry(zw, "manifest.json", now, manifestJSON); err != nil {
		return nil, err
	}
	if err = writeZipEntry(zw, "README.txt", now, []byte(readme)); err != nil {
		return nil, err
	}
	if err = zw.Close(); err != nil {
		return nil, fmt.Errorf("finalizing %s: %w", opts.Output, err)
	}

	return manifest, nil
}

// writeZipEntry writes one file into zw with a fixed modification time:
// zip entries default to the time they're written, which would make two
// bundles produced seconds apart byte-for-byte different even when their
// contents are identical; pinning it to the bundle's own creation instant
// keeps that from being a spurious diff.
func writeZipEntry(zw *zip.Writer, name string, modTime time.Time, data []byte) error {
	hdr := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: modTime,
	}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return fmt.Errorf("adding %s to bundle: %w", name, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing %s to bundle: %w", name, err)
	}
	return nil
}
