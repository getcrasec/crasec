package sbomgen

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// cdxgenManifests are filenames whose presence in a directory means cdxgen
// can produce richer build-time dependency data than syft's filesystem scan.
var cdxgenManifests = []string{
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", // npm / Node.js
	"pom.xml",                          // Maven
	"build.gradle", "build.gradle.kts", // Gradle
	"Cargo.lock",                                         // Rust / Cargo
	"requirements.txt", "pyproject.toml", "Pipfile.lock", // Python
	"Gemfile.lock",    // Ruby
	"packages.config", // .NET
}

// cdxgenScan invokes the cdxgen CLI, writes output to a temp file, parses it,
// and returns the BOM. Callers must verify cdxgen is on PATH before calling.
func cdxgenScan(ctx context.Context, dir string, statusWriter io.Writer) (*cyclonedx.BOM, error) {
	tmp, err := os.CreateTemp("", "crasec-cdxgen-*.json")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // best-effort temp file cleanup
	tmp.Close()                 //nolint:errcheck // no writes since CreateTemp; nothing to flush

	fmt.Fprintf(statusWriter, "running cdxgen on %s...\n", dir)          //nolint:errcheck // best-effort status output
	c := exec.CommandContext(ctx, "cdxgen", "--output", tmp.Name(), dir) // #nosec G204 -- dir is a user-supplied CLI argument, not attacker-controlled remote input
	c.Stderr = statusWriter
	if runErr := c.Run(); runErr != nil {
		return nil, fmt.Errorf("cdxgen exited: %w", runErr)
	}

	f, err := os.Open(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("reading cdxgen output: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only handle; nothing to flush on close

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
