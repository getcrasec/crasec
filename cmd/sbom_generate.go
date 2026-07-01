package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/spf13/cobra"
)

var generateTarget string

var sbomGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate an SBOM for a target",
	Long: `Generate a Software Bill of Materials (SBOM) and write it to stdout as JSON.

Supported target formats:
  ./path                       filesystem directory or file
  docker:myimage:tag           container image via local Docker daemon
  https://github.com/org/repo  remote git repository (cloned then scanned)`,
	RunE: runGenerate,
}

func init() {
	sbomCmd.AddCommand(sbomGenerateCmd)
	sbomGenerateCmd.Flags().StringVar(&generateTarget, "target", "", "scan target: ./path, docker:image:tag, or https://github.com/org/repo")
	if err := sbomGenerateCmd.MarkFlagRequired("target"); err != nil {
		panic(err)
	}
}

func runGenerate(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	target := generateTarget

	if isRemoteGitURL(target) {
		tmpDir, cleanup, err := cloneRepo(ctx, target)
		if err != nil {
			return err
		}
		defer cleanup()
		target = tmpDir
	}

	src, err := syft.GetSource(ctx, target, syft.DefaultGetSourceConfig())
	if err != nil {
		return fmt.Errorf("resolving source %q: %w", generateTarget, err)
	}
	defer src.Close()

	s, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return fmt.Errorf("generating SBOM: %w", err)
	}

	enc := syftjson.NewFormatEncoder()
	if err := enc.Encode(cmd.OutOrStdout(), *s); err != nil {
		return fmt.Errorf("encoding SBOM: %w", err)
	}

	return nil
}

func isRemoteGitURL(target string) bool {
	return strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://")
}

func cloneRepo(ctx context.Context, repoURL string) (dir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "crasec-clone-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}

	cleanup = func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to remove temp dir %s: %v\n", tmpDir, removeErr)
		}
	}

	fmt.Fprintf(os.Stderr, "cloning %s...\n", repoURL)
	c := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, tmpDir)
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone %s: %w", repoURL, err)
	}

	return tmpDir, cleanup, nil
}
