package sbomgen

import (
	"context"
	"fmt"
	"io"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/spdxjson"
)

// WriteSPDX30 scans target with syft and writes an SPDX 3.0 JSON SBOM to w.
// cdxgen isn't used here: it produces CycloneDX, not SPDX.
func WriteSPDX30(ctx context.Context, w io.Writer, target string) error {
	src, err := syft.GetSource(ctx, target, syft.DefaultGetSourceConfig())
	if err != nil {
		return fmt.Errorf("resolving source %q: %w", target, err)
	}
	defer src.Close() //nolint:errcheck // read-only handle; nothing to flush on close

	s, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return fmt.Errorf("generating SBOM: %w", err)
	}

	cfg := spdxjson.DefaultEncoderConfig()
	cfg.Version = "3.0"
	enc, err := spdxjson.NewFormatEncoderWithConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating SPDX 3.0 encoder: %w", err)
	}
	return enc.Encode(w, *s)
}
