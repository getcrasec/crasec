package cmd

import (
	"fmt"

	"github.com/getcrasec/crasec/internal/artifactsign"
	"github.com/spf13/cobra"
)

var vexSignCmd = &cobra.Command{
	Use:   "sign <vex.cdx.json>",
	Short: "Sign a VEX document with Sigstore keyless signing",
	Long: `Sign a file using Sigstore's keyless signing flow.

Identity is established via OIDC: a GitHub Actions workflow token when
running in CI, or an interactive browser login otherwise. Fulcio issues a
short-lived certificate for that identity, the file is signed with a fresh
ephemeral key, and the signature is recorded in Rekor's public transparency
log. The resulting bundle is written to <file>.sig.`,
	Args: cobra.ExactArgs(1),
	RunE: runVexSign,
}

func init() {
	vexCmd.AddCommand(vexSignCmd)
}

func runVexSign(cmd *cobra.Command, args []string) error {
	path := args[0]
	sigPath, err := artifactsign.SignFile(cmd.Context(), path)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "signed %s -> %s\n", path, sigPath)
	return nil
}
