package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/config"
	"github.com/getcrasec/crasec/internal/sbomgen"
)

const (
	formatCycloneDX = "cyclonedx"
	formatSPDX      = "spdx"
)

var (
	generateTarget string
	generateFormat string
	generateOutput string
)

var sbomGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate an SBOM for a target",
	Long: `Generate a Software Bill of Materials (SBOM) and write it to stdout or a file.

Primary format  : CycloneDX 1.6 JSON  (BSI TR-03183-2 / CRA compliant, default)
Alternate format: SPDX 3.0 JSON       (US SSDF compatible, --format spdx)

Scan strategy:
  Directory / git repo  cdxgen + syft when a build manifest is found and
                        cdxgen is on PATH; syft-only otherwise. Results are
                        merged: cdxgen is preferred per-package (richer
                        build-time metadata); syft covers the rest.
  Container image       syft only.
  --format spdx         syft only (cdxgen produces CycloneDX, not SPDX).

CycloneDX output is validated against the embedded 1.6 JSON schema before
being written; the command exits non-zero if validation fails.

Container images (--target docker:... or registry:...): after the SBOM is
written, it is also signed as an in-toto attestation (Sigstore keyless
signing, same identity flow as "sbom sign") and pushed to the registry as an
OCI 1.1 referrer of the image, so any OCI-aware tool can discover it without
a separate delivery channel.

Supported target formats:
  ./path                       filesystem directory or file
  docker:myimage:tag           container image via local Docker daemon
  https://github.com/org/repo  remote git repository (cloned, then scanned)`,
	RunE: runGenerate,
}

func init() {
	sbomCmd.AddCommand(sbomGenerateCmd)
	sbomGenerateCmd.Flags().StringVar(&generateTarget, "target", "", "scan target: ./path, docker:image:tag, or https://github.com/org/repo (default: .crasec.yaml's scan.target, from \"crasec init\")")
	sbomGenerateCmd.Flags().StringVar(&generateFormat, "format", formatCycloneDX, `output format: "cyclonedx" (default) or "spdx"`)
	sbomGenerateCmd.Flags().StringVarP(&generateOutput, "output", "o", "sbom.cdx.json", "write SBOM to this file (\"-\" for stdout)")
	if err := sbomGenerateCmd.MarkFlagRequired("target"); err != nil {
		panic(err)
	}
	sbomGenerateCmd.PreRunE = applyConfigDefaults(map[string]func(*config.Config) string{
		"target": func(c *config.Config) string { return c.Scan.Target },
	})
}

func runGenerate(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	target := generateTarget

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var productName string
	if cfg != nil {
		productName = cfg.Product.Name
	}

	if sbomgen.IsRemoteGitURL(target) {
		tmpDir, cleanup, cloneErr := sbomgen.CloneRepo(ctx, target, cmd.ErrOrStderr())
		if cloneErr != nil {
			return cloneErr
		}
		defer cleanup()
		target = tmpDir
	}

	w, closeW, err := resolveWriter(cmd)
	if err != nil {
		return err
	}
	defer closeW()

	// SPDX path: syft only (cdxgen produces CycloneDX, not SPDX).
	if generateFormat == formatSPDX {
		return sbomgen.WriteSPDX30(ctx, w, target)
	}

	bom, err := sbomgen.Generate(ctx, target, sbomgen.Options{
		ProductName:  productName,
		StatusWriter: cmd.ErrOrStderr(),
	})
	if err != nil {
		return err
	}
	if err := sbomgen.WriteCycloneDX16(w, bom); err != nil {
		return err
	}

	if sbomgen.IsContainerTarget(target) {
		if imageRef, ok := sbomgen.ContainerImageRef(target); ok {
			if err := sbomgen.AttestSBOM(ctx, imageRef, bom, cmd.ErrOrStderr()); err != nil {
				return fmt.Errorf("attesting SBOM to %s: %w", imageRef, err)
			}
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: skipping attestation push for %s (not a registry-hosted image reference)\n", target) //nolint:errcheck // best-effort status output
		}
	}
	return nil
}

// resolveWriter returns the io.Writer to use for SBOM output.
// --output "-" writes to stdout; otherwise it opens (or creates) the named
// file. The caller must invoke the returned close func.
func resolveWriter(cmd *cobra.Command) (io.Writer, func(), error) {
	if generateOutput == "-" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.Create(generateOutput) // #nosec G304 -- generateOutput is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file %s: %w", generateOutput, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: closing %s: %v\n", generateOutput, cerr) //nolint:errcheck // best-effort status output
		}
	}, nil
}
