package cmd

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/spdxjson"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/spf13/cobra"
)

//go:embed schema/bom-1.6.schema.json
var cdx16SchemaBytes []byte

//go:embed schema/spdx.schema.json
var spdxSchemaBytes []byte

//go:embed schema/jsf-0.82.schema.json
var jsfSchemaBytes []byte

const (
	formatCycloneDX = "cyclonedx"
	formatSPDX      = "spdx"

	// $id values declared inside the downloaded schema files.
	cdx16SchemaID = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	spdxSchemaID  = "http://cyclonedx.org/schema/spdx.schema.json"
	jsfSchemaID   = "http://cyclonedx.org/schema/jsf-0.82.schema.json"
)

// cdxgenManifests are filenames whose presence in a directory means cdxgen
// can produce richer build-time dependency data than syft's filesystem scan.
var cdxgenManifests = []string{
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", // npm / Node.js
	"pom.xml",                                            // Maven
	"build.gradle", "build.gradle.kts",                  // Gradle
	"Cargo.lock",                                         // Rust / Cargo
	"requirements.txt", "pyproject.toml", "Pipfile.lock", // Python
	"Gemfile.lock",    // Ruby
	"packages.config", // .NET
}

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

Supported target formats:
  ./path                       filesystem directory or file
  docker:myimage:tag           container image via local Docker daemon
  https://github.com/org/repo  remote git repository (cloned, then scanned)`,
	RunE: runGenerate,
}

func init() {
	sbomCmd.AddCommand(sbomGenerateCmd)
	sbomGenerateCmd.Flags().StringVar(&generateTarget, "target", "", "scan target: ./path, docker:image:tag, or https://github.com/org/repo")
	sbomGenerateCmd.Flags().StringVar(&generateFormat, "format", formatCycloneDX, `output format: "cyclonedx" (default) or "spdx"`)
	sbomGenerateCmd.Flags().StringVarP(&generateOutput, "output", "o", "", "write SBOM to this file instead of stdout")
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

	w, closeW, err := resolveWriter(cmd)
	if err != nil {
		return err
	}
	defer closeW()

	// SPDX path: syft only (cdxgen produces CycloneDX, not SPDX).
	if generateFormat == formatSPDX {
		return writeSPDX30(ctx, w, target)
	}

	bom, err := buildCycloneDXBOM(ctx, target)
	if err != nil {
		return err
	}
	return writeCycloneDX16(w, bom)
}

// resolveWriter returns the io.Writer to use for SBOM output.
// When --output is set it opens (or creates) the named file; otherwise it
// returns cmd.OutOrStdout(). The caller must invoke the returned close func.
func resolveWriter(cmd *cobra.Command) (io.Writer, func(), error) {
	if generateOutput == "" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.Create(generateOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file %s: %w", generateOutput, err)
	}
	return f, func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", generateOutput, cerr)
		}
	}, nil
}

// buildCycloneDXBOM routes to the right scanner(s) based on target type.
func buildCycloneDXBOM(ctx context.Context, target string) (*cyclonedx.BOM, error) {
	if isContainerTarget(target) {
		return syftScan(ctx, target)
	}
	return directoryScan(ctx, target)
}

// directoryScan runs syft unconditionally, then overlays cdxgen when it is
// available and the directory contains a recognised build manifest.
func directoryScan(ctx context.Context, dir string) (*cyclonedx.BOM, error) {
	syftBOM, err := syftScan(ctx, dir)
	if err != nil {
		return nil, err
	}

	if !cdxgenAvailable() || !hasCdxgenManifest(dir) {
		return syftBOM, nil
	}

	cdxBOM, err := cdxgenScan(ctx, dir)
	if err != nil {
		// cdxgen failure is non-fatal; degrade gracefully.
		fmt.Fprintf(os.Stderr, "warning: cdxgen failed (%v), using syft results only\n", err)
		return syftBOM, nil
	}

	merged := mergeBOMs(cdxBOM, syftBOM)
	fmt.Fprintf(os.Stderr, "merged cdxgen + syft: %d components\n", componentCount(merged))
	return merged, nil
}

// syftScan runs syft against target and returns a CycloneDX BOM.
func syftScan(ctx context.Context, target string) (*cyclonedx.BOM, error) {
	src, err := syft.GetSource(ctx, target, syft.DefaultGetSourceConfig())
	if err != nil {
		return nil, fmt.Errorf("resolving source %q: %w", target, err)
	}
	defer src.Close()

	s, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("syft scan: %w", err)
	}

	return cyclonedxhelpers.ToFormatModel(*s), nil
}

// cdxgenScan invokes the cdxgen CLI, writes output to a temp file, parses it,
// and returns the BOM. Callers must verify cdxgen is on PATH before calling.
func cdxgenScan(ctx context.Context, dir string) (*cyclonedx.BOM, error) {
	tmp, err := os.CreateTemp("", "crasec-cdxgen-*.json")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	fmt.Fprintf(os.Stderr, "running cdxgen on %s...\n", dir)
	c := exec.CommandContext(ctx, "cdxgen", "--output", tmp.Name(), dir)
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("cdxgen exited: %w", err)
	}

	f, err := os.Open(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("reading cdxgen output: %w", err)
	}
	defer f.Close()

	var bom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(f, cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parsing cdxgen output: %w", err)
	}
	return &bom, nil
}

// mergeBOMs merges cdxgen and syft BOMs, deduplicating by PURL.
// cdxgen components are preferred when both sources report the same package.
// Syft components with no matching PURL in cdxgen are appended.
func mergeBOMs(cdxgenBOM, syftBOM *cyclonedx.BOM) *cyclonedx.BOM {
	merged := *cdxgenBOM

	// Index every cdxgen PURL for O(1) dedup checks.
	cdxgenPURLs := make(map[string]struct{})
	if cdxgenBOM.Components != nil {
		for _, c := range *cdxgenBOM.Components {
			if c.PackageURL != "" {
				cdxgenPURLs[c.PackageURL] = struct{}{}
			}
		}
	}

	// Start with all cdxgen components (richer build-time metadata).
	components := make([]cyclonedx.Component, 0)
	if cdxgenBOM.Components != nil {
		components = append(components, *cdxgenBOM.Components...)
	}

	// Append syft-only components: no PURL match in cdxgen.
	if syftBOM.Components != nil {
		for _, c := range *syftBOM.Components {
			if _, found := cdxgenPURLs[c.PackageURL]; c.PackageURL == "" || !found {
				components = append(components, c)
			}
		}
	}

	merged.Components = &components
	return &merged
}

func writeCycloneDX16(w io.Writer, bom *cyclonedx.BOM) error {
	var buf bytes.Buffer
	enc := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return fmt.Errorf("encoding CycloneDX 1.6 BOM: %w", err)
	}

	if err := validateCycloneDX16(buf.Bytes()); err != nil {
		return err
	}

	_, err := w.Write(buf.Bytes())
	return err
}

func writeSPDX30(ctx context.Context, w io.Writer, target string) error {
	src, err := syft.GetSource(ctx, target, syft.DefaultGetSourceConfig())
	if err != nil {
		return fmt.Errorf("resolving source %q: %w", target, err)
	}
	defer src.Close()

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

func validateCycloneDX16(data []byte) error {
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(cdx16SchemaID, bytes.NewReader(cdx16SchemaBytes)); err != nil {
		return fmt.Errorf("loading CycloneDX 1.6 schema: %w", err)
	}
	if err := compiler.AddResource(spdxSchemaID, bytes.NewReader(spdxSchemaBytes)); err != nil {
		return fmt.Errorf("loading SPDX license schema: %w", err)
	}
	if err := compiler.AddResource(jsfSchemaID, bytes.NewReader(jsfSchemaBytes)); err != nil {
		return fmt.Errorf("loading JSF 0.82 schema: %w", err)
	}

	sch, err := compiler.Compile(cdx16SchemaID)
	if err != nil {
		return fmt.Errorf("compiling CycloneDX 1.6 schema: %w", err)
	}

	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing BOM JSON: %w", err)
	}

	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("CycloneDX 1.6 schema validation failed: %w", err)
	}
	return nil
}

// hasCdxgenManifest reports whether dir contains a build manifest that
// cdxgen handles more accurately than syft's filesystem heuristics.
func hasCdxgenManifest(dir string) bool {
	for _, name := range cdxgenManifests {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

func cdxgenAvailable() bool {
	_, err := exec.LookPath("cdxgen")
	return err == nil
}

// isContainerTarget reports whether target is an explicit image reference
// that syft should pull and unpack rather than treat as a filesystem path.
func isContainerTarget(target string) bool {
	for _, prefix := range []string{"docker:", "registry:", "oci:", "podman:"} {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

func componentCount(bom *cyclonedx.BOM) int {
	if bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
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
