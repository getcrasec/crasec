package sbomgen

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/getcrasec/crasec/internal/ociattest"
)

// cyclonedxPredicateType is the in-toto predicate type for a CycloneDX SBOM,
// per https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md.
const cyclonedxPredicateType = "https://cyclonedx.org/bom"

// ContainerImageRef strips crasec's "docker:"/"registry:" target prefixes to
// recover the underlying registry-hosted image reference. "oci:"/"podman:"
// targets point at local-only storage with no guaranteed registry location,
// so they report ok=false and the caller skips the OCI referrer push.
func ContainerImageRef(target string) (string, bool) {
	for _, prefix := range []string{"docker:", "registry:"} {
		if strings.HasPrefix(target, prefix) {
			return strings.TrimPrefix(target, prefix), true
		}
	}
	return "", false
}

// AttestSBOM signs bom as an in-toto attestation over imageRef and pushes it
// to the registry as an OCI 1.1 referrer, so the SBOM travels with the image
// through any OCI-compatible registry without a separate delivery mechanism.
func AttestSBOM(ctx context.Context, imageRef string, bom *cyclonedx.BOM, statusWriter io.Writer) error {
	var buf bytes.Buffer
	enc := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return fmt.Errorf("encoding SBOM predicate: %w", err)
	}

	fmt.Fprintf(statusWriter, "signing and pushing in-toto attestation to %s...\n", imageRef)
	if err := ociattest.AttestAndPush(ctx, imageRef, cyclonedxPredicateType, buf.Bytes()); err != nil {
		return err
	}
	fmt.Fprintf(statusWriter, "attestation pushed as OCI referrer of %s\n", imageRef)
	return nil
}
