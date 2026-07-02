package sbomgen

import (
	"os"
	"path/filepath"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func TestIsContainerTarget(t *testing.T) {
	cases := map[string]bool{
		"docker:myimage:tag":     true,
		"registry:myimage:tag":   true,
		"oci:myimage":            true,
		"podman:myimage":         true,
		".":                      false,
		"./path/to/repo":         false,
		"https://github.com/a/b": false,
	}
	for target, want := range cases {
		if got := IsContainerTarget(target); got != want {
			t.Errorf("IsContainerTarget(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestIsRemoteGitURL(t *testing.T) {
	cases := map[string]bool{
		"https://github.com/org/repo": true,
		"http://example.com/repo.git": true,
		".":                           false,
		"docker:myimage:tag":          false,
	}
	for target, want := range cases {
		if got := IsRemoteGitURL(target); got != want {
			t.Errorf("IsRemoteGitURL(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestContainerImageRef(t *testing.T) {
	cases := []struct {
		target  string
		wantRef string
		wantOK  bool
	}{
		{"docker:myimage:tag", "myimage:tag", true},
		{"registry:example.com/myimage:tag", "example.com/myimage:tag", true},
		{"oci:myimage", "", false},
		{"podman:myimage", "", false},
	}
	for _, c := range cases {
		ref, ok := ContainerImageRef(c.target)
		if ref != c.wantRef || ok != c.wantOK {
			t.Errorf("ContainerImageRef(%q) = (%q, %v), want (%q, %v)", c.target, ref, ok, c.wantRef, c.wantOK)
		}
	}
}

func TestHasCdxgenManifest(t *testing.T) {
	dir := t.TempDir()
	if hasCdxgenManifest(dir) {
		t.Fatal("empty directory should not report a cdxgen manifest")
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !hasCdxgenManifest(dir) {
		t.Fatal("directory with package-lock.json should report a cdxgen manifest")
	}
}

func TestNormalizeMetadataComponent(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Base(dir)

	cases := []struct {
		name        string
		bom         *cyclonedx.BOM
		productName string
		wantName    string
		wantType    cyclonedx.ComponentType
	}{
		{
			name:        "dot name with product name set",
			bom:         &cyclonedx.BOM{Metadata: &cyclonedx.Metadata{Component: &cyclonedx.Component{Name: ".", Type: cyclonedx.ComponentTypeFile}}},
			productName: "myapp",
			wantName:    "myapp",
			wantType:    cyclonedx.ComponentTypeApplication,
		},
		{
			name:        "dot name with no product name falls back to directory basename",
			bom:         &cyclonedx.BOM{Metadata: &cyclonedx.Metadata{Component: &cyclonedx.Component{Name: ".", Type: cyclonedx.ComponentTypeFile}}},
			productName: "",
			wantName:    base,
			wantType:    cyclonedx.ComponentTypeApplication,
		},
		{
			name:        "meaningful name is left untouched",
			bom:         &cyclonedx.BOM{Metadata: &cyclonedx.Metadata{Component: &cyclonedx.Component{Name: "express", Type: cyclonedx.ComponentTypeApplication}}},
			productName: "myapp",
			wantName:    "express",
			wantType:    cyclonedx.ComponentTypeApplication,
		},
		{
			name:        "nil metadata is filled in",
			bom:         &cyclonedx.BOM{},
			productName: "myapp",
			wantName:    "myapp",
			wantType:    cyclonedx.ComponentTypeApplication,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			normalizeMetadataComponent(c.bom, dir, c.productName)
			got := c.bom.Metadata.Component
			if got.Name != c.wantName {
				t.Errorf("Name = %q, want %q", got.Name, c.wantName)
			}
			if got.Type != c.wantType {
				t.Errorf("Type = %q, want %q", got.Type, c.wantType)
			}
		})
	}
}

func TestMergeBOMs(t *testing.T) {
	cdxgenBOM := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{Name: "express", PackageURL: "pkg:npm/express@4.17.1"},
		},
	}
	syftBOM := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{Name: "express", PackageURL: "pkg:npm/express@4.17.1"}, // duplicate PURL, should be dropped
			{Name: "lodash", PackageURL: "pkg:npm/lodash@4.17.15"},  // syft-only, should be kept
		},
	}

	merged := mergeBOMs(cdxgenBOM, syftBOM)
	if merged.Components == nil || len(*merged.Components) != 2 {
		t.Fatalf("expected 2 merged components (1 cdxgen + 1 syft-only), got %d", componentCount(merged))
	}

	purls := map[string]bool{}
	for _, c := range *merged.Components {
		purls[c.PackageURL] = true
	}
	for _, want := range []string{"pkg:npm/express@4.17.1", "pkg:npm/lodash@4.17.15"} {
		if !purls[want] {
			t.Errorf("merged BOM missing expected component %q", want)
		}
	}
}
