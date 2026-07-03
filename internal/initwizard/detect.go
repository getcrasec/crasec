package initwizard

import (
	"os"
	"path/filepath"
)

// ecosystemManifest pairs a language ecosystem with the manifest file that
// signals it's present in a directory.
type ecosystemManifest struct {
	Ecosystem string
	Manifest  string
}

// manifestChecks is deliberately just these five: the ecosystems crasec's
// scan tooling (syft/cdxgen) already knows how to build a meaningfully
// better SBOM for, not an exhaustive list of every possible manifest.
var manifestChecks = []ecosystemManifest{
	{"go", "go.mod"},
	{"node", "package.json"},
	{"java", "pom.xml"},
	{"rust", "Cargo.toml"},
	{"python", "requirements.txt"},
}

// KnownEcosystems is the full pick list offered when detection is
// ambiguous or empty: manifestChecks' ecosystems plus "other" for
// anything crasec doesn't specifically recognize yet.
var KnownEcosystems = []string{"go", "node", "java", "rust", "python", "other"}

// DetectEcosystems scans dir for the manifest files in manifestChecks,
// returning every ecosystem found (a monorepo can legitimately match more
// than one).
func DetectEcosystems(dir string) []ecosystemManifest {
	var found []ecosystemManifest
	for _, c := range manifestChecks {
		if _, err := os.Stat(filepath.Join(dir, c.Manifest)); err == nil {
			found = append(found, c)
		}
	}
	return found
}
