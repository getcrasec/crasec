package cmd

import (
	"fmt"

	"github.com/getcrasec/crasec/internal/artifactsign"
	"github.com/spf13/cobra"
)

var docSignCmd = &cobra.Command{
	Use:   "sign <file>",
	Short: "Sign an EU Declaration of Conformity file with Sigstore keyless signing",
	Long: `Sign a file using Sigstore's keyless signing flow.

Identity is established via OIDC: a GitHub Actions workflow token when
running in CI, or an interactive browser login otherwise. Fulcio issues a
short-lived certificate for that identity, the file is signed with a fresh
ephemeral key, and the signature is recorded in Rekor's public transparency
log. The resulting bundle is written to <file>.sig.

Run this against both eu-doc.json and eu-doc.pdf (or pass --sign to
"crasec doc generate" to do both automatically).`,
	Args: cobra.ExactArgs(1),
	RunE: runDocSign,
}

func init() {
	docCmd.AddCommand(docSignCmd)
}

func runDocSign(cmd *cobra.Command, args []string) error {
	path := args[0]
	sigPath, err := artifactsign.SignFile(cmd.Context(), path)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "signed %s -> %s\n", path, sigPath) //nolint:errcheck // best-effort status output
	return nil
}
