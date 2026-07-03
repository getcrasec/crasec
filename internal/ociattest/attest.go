// Package ociattest signs in-toto attestations over container images and
// publishes them as OCI 1.1 referrers, so any OCI-aware tool (or another
// registry copy) can discover them without a separate delivery channel.
//
// This is the shared attestation primitive for every crasec artifact type
// that is scoped to a container image (SBOM, VEX, CSAF, EU DoC); per-command
// code should call AttestAndPush rather than duplicating the OCI plumbing.
package ociattest

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/getcrasec/crasec/internal/artifactsign"
)

// statementType identifies an in-toto v1 Statement.
// See https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md.
const statementType = "https://in-toto.io/Statement/v1"

// bundleMediaType is both the OCI layer media type and (via config media
// type fallback, per the OCI 1.1 image spec) the manifest's artifactType:
// the referrer holds a full Sigstore bundle (DSSE-signed statement, signing
// certificate, and Rekor transparency log entry), not a bare signature, so
// it is independently verifiable once fetched from the registry.
const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// predicateTypeAnnotation lets registry UIs and OCI clients show what kind
// of predicate an attestation layer carries without parsing its contents.
const predicateTypeAnnotation = "in-toto.io/predicate-type"

// statement is an in-toto v1 Statement: a signed claim binding a predicate
// (e.g. an SBOM) to one or more subjects (e.g. a container image digest).
type statement struct {
	Type          string          `json:"_type"`
	Subject       []subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// AttestAndPush wraps predicate in a signed in-toto attestation over the
// image at imageRef (a registry-hosted reference such as "myimage:tag" or
// "ghcr.io/org/myimage@sha256:...") and pushes it to the registry as an OCI
// 1.1 referrer of the image's manifest. predicateType identifies the
// predicate's schema, e.g. "https://cyclonedx.org/bom" for a CycloneDX SBOM.
func AttestAndPush(ctx context.Context, imageRef, predicateType string, predicate json.RawMessage) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("parsing image reference %q: %w", imageRef, err)
	}

	keychain := remote.WithAuthFromKeychain(authn.DefaultKeychain)

	desc, err := remote.Get(ref, remote.WithContext(ctx), keychain)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", imageRef, err)
	}

	stmt := statement{
		Type:          statementType,
		PredicateType: predicateType,
		Predicate:     predicate,
		Subject: []subject{{
			Name:   ref.Context().Name(),
			Digest: map[string]string{"sha256": desc.Digest.Hex},
		}},
	}
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		return fmt.Errorf("marshaling in-toto statement: %w", err)
	}

	b, err := artifactsign.SignStatement(ctx, stmtJSON)
	if err != nil {
		return fmt.Errorf("signing in-toto statement: %w", err)
	}
	bundleJSON, err := b.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshaling signature bundle: %w", err)
	}

	layer := static.NewLayer(bundleJSON, types.MediaType(bundleMediaType))
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
		Annotations: map[string]string{
			predicateTypeAnnotation: predicateType,
		},
	})
	if err != nil {
		return fmt.Errorf("building attestation manifest: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(bundleMediaType))
	img = mutate.Subject(img, desc.Descriptor).(v1.Image)

	// Tag mirrors the classic "sha256-<digest>.att" cosign convention so the
	// pushed manifest is human-discoverable even against registries that
	// don't yet support the OCI 1.1 Referrers API (remote.Write registers it
	// as a referrer of subjectDesc either way, via the API or a fallback tag).
	attTag := ref.Context().Tag(fmt.Sprintf("sha256-%s.att", desc.Digest.Hex))
	if err := remote.Write(attTag, img, remote.WithContext(ctx), keychain); err != nil {
		return fmt.Errorf("pushing attestation to %s: %w", imageRef, err)
	}

	return nil
}
