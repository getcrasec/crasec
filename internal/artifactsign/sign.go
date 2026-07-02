// Package artifactsign implements Sigstore keyless signing and verification
// for crasec's compliance artifacts (SBOM, VEX, CSAF, EU DoC). It is the
// single place that talks to Fulcio and Rekor; per-artifact commands should
// call SignFile / VerifyFile rather than reimplementing the flow.
package artifactsign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// defaultOIDCIssuer/defaultOIDCClientID are Sigstore's public-good
	// interactive OIDC endpoint, used when no CI identity is available.
	defaultOIDCIssuer   = "https://oauth2.sigstore.dev/auth"
	defaultOIDCClientID = "sigstore"

	fulcioTimeout = 30 * time.Second
	rekorTimeout  = 90 * time.Second
)

// Identity pins verification to a specific keyless signer. Any zero-valued
// field is left unconstrained.
type Identity struct {
	SAN         string
	SANRegex    string
	Issuer      string
	IssuerRegex string
}

// SignFile signs the file at path and writes the resulting Sigstore bundle
// to path+".sig", returning the bundle's path.
func SignFile(ctx context.Context, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	b, err := Sign(ctx, data)
	if err != nil {
		return "", err
	}

	sigBytes, err := b.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshaling signature bundle: %w", err)
	}

	sigPath := path + ".sig"
	if err := os.WriteFile(sigPath, sigBytes, 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", sigPath, err)
	}
	return sigPath, nil
}

// Sign produces a Sigstore bundle over data using keyless signing: it
// authenticates to Fulcio with an OIDC identity (a GitHub Actions workflow
// token when running in CI, otherwise an interactive browser login), signs
// with a fresh ephemeral keypair, and records the signature in Rekor's
// transparency log.
func Sign(ctx context.Context, data []byte) (*bundle.Bundle, error) {
	idToken, err := identityToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtaining OIDC identity: %w", err)
	}

	tufClient, err := tuf.New(tuf.DefaultOptions().WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("initializing TUF client: %w", err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetching Sigstore trusted root: %w", err)
	}

	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetching Sigstore signing config: %w", err)
	}

	fulcioService, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, time.Now())
	if err != nil {
		return nil, fmt.Errorf("selecting Fulcio service: %w", err)
	}

	rekorServices, err := root.SelectServices(signingConfig.RekorLogURLs(),
		signingConfig.RekorLogURLsConfig(), sign.RekorAPIVersions, time.Now())
	if err != nil {
		return nil, fmt.Errorf("selecting Rekor service: %w", err)
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}

	opts := sign.BundleOptions{
		Context:     ctx,
		TrustedRoot: trustedRoot,
		CertificateProvider: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioService.URL,
			Timeout: fulcioTimeout,
			Retries: 1,
		}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{
			IDToken: idToken,
		},
	}
	for _, svc := range rekorServices {
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{
			BaseURL: svc.URL,
			Timeout: rekorTimeout,
			Retries: 1,
			Version: svc.MajorAPIVersion,
		}))
	}

	pb, err := sign.Bundle(&sign.PlainData{Data: data}, keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("signing artifact: %w", err)
	}

	b, err := bundle.NewBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("building signature bundle: %w", err)
	}
	return b, nil
}

// VerifyFile verifies the Sigstore bundle at sigPath against the artifact at
// artifactPath: the signature must match the artifact's digest, the signing
// certificate must chain to Fulcio's trusted root, and the signature must be
// recorded in Rekor's transparency log. When identity is non-nil, the
// certificate's SAN/issuer must also match it; a nil identity accepts any
// keyless signer.
func VerifyFile(ctx context.Context, artifactPath, sigPath string, identity *Identity) (*verify.VerificationResult, error) {
	b, err := bundle.LoadJSONFromPath(sigPath)
	if err != nil {
		return nil, fmt.Errorf("loading signature bundle %s: %w", sigPath, err)
	}

	tufClient, err := tuf.New(tuf.DefaultOptions().WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("initializing TUF client: %w", err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetching Sigstore trusted root: %w", err)
	}

	sev, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("building verifier: %w", err)
	}

	artifact, err := os.Open(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", artifactPath, err)
	}
	defer artifact.Close()

	var identityPolicy verify.PolicyOption
	if identity != nil {
		certID, err := verify.NewShortCertificateIdentity(identity.Issuer, identity.IssuerRegex, identity.SAN, identity.SANRegex)
		if err != nil {
			return nil, fmt.Errorf("building certificate identity policy: %w", err)
		}
		identityPolicy = verify.WithCertificateIdentity(certID)
	} else {
		identityPolicy = verify.WithoutIdentitiesUnsafe()
	}

	res, err := sev.Verify(b, verify.NewPolicy(verify.WithArtifact(artifact), identityPolicy))
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return res, nil
}

// identityToken returns an OIDC identity token to present to Fulcio: a
// GitHub Actions workflow token when running in a workflow, otherwise an
// interactive browser login against Sigstore's public OIDC endpoint.
func identityToken(ctx context.Context) (string, error) {
	tok, err := githubActionsIdentityToken(ctx)
	if err != nil {
		return "", err
	}
	if tok != "" {
		return tok, nil
	}
	return interactiveIdentityToken()
}

// githubActionsIdentityToken fetches an OIDC token scoped to "sigstore" from
// GitHub Actions' OIDC provider. It returns ("", nil) when the workflow
// environment variables are absent, so the caller falls back to the
// interactive flow.
func githubActionsIdentityToken(ctx context.Context) (string, error) {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return "", nil
	}

	u, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("parsing ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", "sigstore")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+reqToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting GitHub Actions OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub Actions OIDC token request failed: %s", resp.Status)
	}

	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decoding GitHub Actions OIDC token response: %w", err)
	}
	if body.Value == "" {
		return "", errors.New("GitHub Actions OIDC token response missing value")
	}
	return body.Value, nil
}

func interactiveIdentityToken() (string, error) {
	fmt.Fprintln(os.Stderr, "no CI OIDC token detected; opening browser for Sigstore identity login...")
	tok, err := oauthflow.OIDConnect(defaultOIDCIssuer, defaultOIDCClientID, "", "", &oauthflow.InteractiveIDTokenGetter{})
	if err != nil {
		return "", fmt.Errorf("interactive OIDC login: %w", err)
	}
	return tok.RawString, nil
}
