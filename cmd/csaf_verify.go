package cmd

import (
	"fmt"

	"github.com/getcrasec/crasec/internal/artifactsign"
	"github.com/spf13/cobra"
)

var (
	csafVerifyCertIdentity        string
	csafVerifyCertIdentityRegex   string
	csafVerifyCertOIDCIssuer      string
	csafVerifyCertOIDCIssuerRegex string
)

var csafVerifyCmd = &cobra.Command{
	Use:   "verify <advisory.json> <advisory.json.sig>",
	Short: "Verify a Sigstore signature over a CSAF advisory",
	Long: `Verify a Sigstore bundle produced by "crasec csaf sign": checks the
signature against the artifact's digest, validates the signing certificate
against Fulcio's trusted root, and confirms the signature is recorded in
Rekor's transparency log.

By default any keyless identity is accepted; pass --certificate-identity /
--certificate-oidc-issuer (or their -regex variants) to pin verification to a
specific signer, e.g. a GitHub Actions workflow.`,
	Args: cobra.ExactArgs(2),
	RunE: runCSAFVerify,
}

func init() {
	csafCmd.AddCommand(csafVerifyCmd)
	csafVerifyCmd.Flags().StringVar(&csafVerifyCertIdentity, "certificate-identity", "", "require the signing certificate SAN to equal this value")
	csafVerifyCmd.Flags().StringVar(&csafVerifyCertIdentityRegex, "certificate-identity-regex", "", "require the signing certificate SAN to match this regex")
	csafVerifyCmd.Flags().StringVar(&csafVerifyCertOIDCIssuer, "certificate-oidc-issuer", "", "require the signing certificate's OIDC issuer to equal this value")
	csafVerifyCmd.Flags().StringVar(&csafVerifyCertOIDCIssuerRegex, "certificate-oidc-issuer-regex", "", "require the signing certificate's OIDC issuer to match this regex")
}

func runCSAFVerify(cmd *cobra.Command, args []string) error {
	artifactPath, sigPath := args[0], args[1]
	out := cmd.OutOrStdout()

	var identity *artifactsign.Identity
	if csafVerifyCertIdentity != "" || csafVerifyCertIdentityRegex != "" || csafVerifyCertOIDCIssuer != "" || csafVerifyCertOIDCIssuerRegex != "" {
		identity = &artifactsign.Identity{
			SAN:         csafVerifyCertIdentity,
			SANRegex:    csafVerifyCertIdentityRegex,
			Issuer:      csafVerifyCertOIDCIssuer,
			IssuerRegex: csafVerifyCertOIDCIssuerRegex,
		}
	} else {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: no --certificate-identity/--certificate-oidc-issuer given; accepting any keyless signer")
	}

	res, err := artifactsign.VerifyFile(cmd.Context(), artifactPath, sigPath, identity)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Result: PASS  (%s)\n", sigPath)
	if res.Signature != nil && res.Signature.Certificate != nil {
		fmt.Fprintf(out, "  signer:  %s\n", res.Signature.Certificate.SubjectAlternativeName)
		fmt.Fprintf(out, "  issuer:  %s\n", res.Signature.Certificate.CertificateIssuer)
	}
	for _, ts := range res.VerifiedTimestamps {
		fmt.Fprintf(out, "  %s:  %s (%s)\n", ts.Type, ts.Timestamp.Format("2006-01-02T15:04:05Z07:00"), ts.URI)
	}
	return nil
}
