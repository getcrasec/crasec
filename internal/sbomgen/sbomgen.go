// Package sbomgen builds a CycloneDX (or SPDX) SBOM for a scan target:
// a filesystem directory, a container image, or a remote git repository.
//
// Directory scans run syft unconditionally, then overlay cdxgen when it's
// on PATH and the directory has a build manifest cdxgen understands
// (package-lock.json, pom.xml, Cargo.lock, ...): cdxgen's build-time
// dependency resolution is richer than syft's filesystem heuristics for
// those ecosystems, so its components win on PURL collisions and syft
// fills in whatever cdxgen didn't cover. Container images are syft-only:
// there's no build manifest to hand cdxgen.
package sbomgen

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
)

// Options configures Generate.
type Options struct {
	// ProductName, when set, becomes the SBOM's root component name;
	// see normalizeMetadataComponent. Typically .crasec.yaml's
	// product.name.
	ProductName string

	// StatusWriter receives progress messages (cdxgen invocation, merge
	// results, degraded-mode warnings). Defaults to io.Discard if nil.
	StatusWriter io.Writer
}

func (o Options) statusWriter() io.Writer {
	if o.StatusWriter == nil {
		return io.Discard
	}
	return o.StatusWriter
}

// Generate builds a CycloneDX BOM for target, routing to the right
// scanner(s) based on target type.
func Generate(ctx context.Context, target string, opts Options) (*cyclonedx.BOM, error) {
	if IsContainerTarget(target) {
		return syftScan(ctx, target)
	}
	return directoryScan(ctx, target, opts)
}

// directoryScan runs syft unconditionally, then overlays cdxgen when it is
// available and the directory contains a recognised build manifest.
func directoryScan(ctx context.Context, dir string, opts Options) (*cyclonedx.BOM, error) {
	syftBOM, err := syftScan(ctx, dir)
	if err != nil {
		return nil, err
	}

	if !cdxgenAvailable() || !hasCdxgenManifest(dir) {
		normalizeMetadataComponent(syftBOM, dir, opts.ProductName)
		return syftBOM, nil
	}

	cdxBOM, err := cdxgenScan(ctx, dir, opts.statusWriter())
	if err != nil {
		// cdxgen failure is non-fatal; degrade gracefully.
		fmt.Fprintf(opts.statusWriter(), "warning: cdxgen failed (%v), using syft results only\n", err) //nolint:errcheck // best-effort status output
		normalizeMetadataComponent(syftBOM, dir, opts.ProductName)
		return syftBOM, nil
	}

	merged := mergeBOMs(cdxBOM, syftBOM)
	normalizeMetadataComponent(merged, dir, opts.ProductName)
	fmt.Fprintf(opts.statusWriter(), "merged cdxgen + syft: %d components\n", componentCount(merged)) //nolint:errcheck // best-effort status output
	return merged, nil
}

// normalizeMetadataComponent replaces a scan's root component identity when
// syft or cdxgen couldn't infer a meaningful one, most commonly a directory
// scan target of "." coming back as component name "." (type "file"), which
// then propagates verbatim into every downstream artifact (VEX/CSAF product
// metadata, Annex VII's SBOM reference) that reads it from the SBOM. Prefers
// the product name from .crasec.yaml; falls back to the scan directory's
// basename.
func normalizeMetadataComponent(bom *cyclonedx.BOM, dir, productName string) {
	if bom.Metadata == nil {
		bom.Metadata = &cyclonedx.Metadata{}
	}
	if bom.Metadata.Component == nil {
		bom.Metadata.Component = &cyclonedx.Component{}
	}
	c := bom.Metadata.Component
	if c.Name == "" || c.Name == "." {
		if productName != "" {
			c.Name = productName
		} else if abs, err := filepath.Abs(dir); err == nil {
			c.Name = filepath.Base(abs)
		}
	}
	if c.Type == "" || c.Type == cyclonedx.ComponentTypeFile {
		c.Type = cyclonedx.ComponentTypeApplication
	}
}

// syftScan runs syft against target and returns a CycloneDX BOM.
func syftScan(ctx context.Context, target string) (*cyclonedx.BOM, error) {
	src, err := syft.GetSource(ctx, target, syft.DefaultGetSourceConfig())
	if err != nil {
		return nil, fmt.Errorf("resolving source %q: %w", target, err)
	}
	defer src.Close() //nolint:errcheck // read-only handle; nothing to flush on close

	s, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("syft scan: %w", err)
	}

	return cyclonedxhelpers.ToFormatModel(*s), nil
}

// IsContainerTarget reports whether target is an explicit image reference
// that syft should pull and unpack rather than treat as a filesystem path.
func IsContainerTarget(target string) bool {
	for _, prefix := range []string{"docker:", "registry:", "oci:", "podman:"} {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

func componentCount(bom *cyclonedx.BOM) int {
	if bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}
