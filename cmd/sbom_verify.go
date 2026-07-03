package cmd

import (
	"fmt"

	"github.com/getcrasec/crasec/internal/artifactsign"
	"github.com/spf13/cobra"
)

var (
	verifyCertIdentity        string
	verifyCertIdentityRegex   string
	verifyCertOIDCIssuer      string
	verifyCertOIDCIssuerRegex string
)

var sbomVerifyCmd = &cobra.Command{
	Use:   "verify <sbom.cdx.json> <sbom.cdx.json.sig>",
	Short: "Verify a Sigstore signature over an SBOM",
	Long: `Verify a Sigstore bundle produced by "crasec sbom sign": checks the
signature against the artifact's digest, validates the signing certificate
against Fulcio's trusted root, and confirms the signature is recorded in
Rekor's transparency log.

By default any keyless identity is accepted; pass --certificate-identity /
--certificate-oidc-issuer (or their -regex variants) to pin verification to a
specific signer, e.g. a GitHub Actions workflow.`,
	Args: cobra.ExactArgs(2),
	RunE: runSbomVerify,
}

func init() {
	sbomCmd.AddCommand(sbomVerifyCmd)
	sbomVerifyCmd.Flags().StringVar(&verifyCertIdentity, "certificate-identity", "", "require the signing certificate SAN to equal this value")
	sbomVerifyCmd.Flags().StringVar(&verifyCertIdentityRegex, "certificate-identity-regex", "", "require the signing certificate SAN to match this regex")
	sbomVerifyCmd.Flags().StringVar(&verifyCertOIDCIssuer, "certificate-oidc-issuer", "", "require the signing certificate's OIDC issuer to equal this value")
	sbomVerifyCmd.Flags().StringVar(&verifyCertOIDCIssuerRegex, "certificate-oidc-issuer-regex", "", "require the signing certificate's OIDC issuer to match this regex")
}

func runSbomVerify(cmd *cobra.Command, args []string) error {
	artifactPath, sigPath := args[0], args[1]
	out := cmd.OutOrStdout()

	var identity *artifactsign.Identity
	if verifyCertIdentity != "" || verifyCertIdentityRegex != "" || verifyCertOIDCIssuer != "" || verifyCertOIDCIssuerRegex != "" {
		identity = &artifactsign.Identity{
			SAN:         verifyCertIdentity,
			SANRegex:    verifyCertIdentityRegex,
			Issuer:      verifyCertOIDCIssuer,
			IssuerRegex: verifyCertOIDCIssuerRegex,
		}
	} else {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: no --certificate-identity/--certificate-oidc-issuer given; accepting any keyless signer") //nolint:errcheck // best-effort status output
	}

	res, err := artifactsign.VerifyFile(cmd.Context(), artifactPath, sigPath, identity)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Result: PASS  (%s)\n", sigPath) //nolint:errcheck // best-effort status output
	if res.Signature != nil && res.Signature.Certificate != nil {
		fmt.Fprintf(out, "  signer:  %s\n", res.Signature.Certificate.SubjectAlternativeName) //nolint:errcheck // best-effort status output
		fmt.Fprintf(out, "  issuer:  %s\n", res.Signature.Certificate.CertificateIssuer)      //nolint:errcheck // best-effort status output
	}
	for _, ts := range res.VerifiedTimestamps {
		fmt.Fprintf(out, "  %s:  %s (%s)\n", ts.Type, ts.Timestamp.Format("2006-01-02T15:04:05Z07:00"), ts.URI) //nolint:errcheck // best-effort status output
	}
	return nil
}
