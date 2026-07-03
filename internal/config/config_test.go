package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestSaveLoad_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)

	c := &Config{
		Product:      Product{Name: "myapp", Version: "1.0.0"},
		Manufacturer: Manufacturer{Name: "Acme Corp", Address: "Paris, France"},
		Ecosystem:    "go",
		Scan:         Scan{Target: "."},
	}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatal(err)
	}

	var loaded Config
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Product.Name != "myapp" || loaded.Manufacturer.Address != "Paris, France" {
		t.Fatalf("expected round-tripped config to match, got %+v", loaded)
	}
}

func TestLoad_NoConfigReturnsNilNil(t *testing.T) {
	dir := t.TempDir()
	restore := chdir(t, dir)
	defer restore()

	// No HOME fallback should exist either in a throwaway temp HOME.
	t.Setenv("HOME", t.TempDir())

	c, err := Load()
	if err != nil {
		t.Fatalf("expected no error when no config exists, got %v", err)
	}
	if c != nil {
		t.Fatalf("expected nil config when none exists, got %+v", c)
	}
}

func TestLoad_ReadsProjectConfig(t *testing.T) {
	dir := t.TempDir()
	restore := chdir(t, dir)
	defer restore()

	c := &Config{Product: Product{Name: "myapp"}}
	if err := c.Save(FileName); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Product.Name != "myapp" {
		t.Fatalf("expected to load the project config, got %+v", loaded)
	}
}

func TestLoad_CorruptFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	restore := chdir(t, dir)
	defer restore()

	if err := os.WriteFile(FileName, []byte("not: valid: yaml: at: all: ["), 0o644); err != nil { // #nosec G306 -- test fixture, not sensitive
		t.Fatal(err)
	}

	if _, err := Load(); err == nil {
		t.Fatal("expected an error for a corrupt config file, not a silent nil")
	}
}

func TestApplyDefault_SetsUnchangedFlagAndSatisfiesRequired(t *testing.T) {
	cmd := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
	var target string
	cmd.Flags().StringVar(&target, "target", "", "")
	if err := cmd.MarkFlagRequired("target"); err != nil {
		t.Fatal(err)
	}

	if err := ApplyDefault(cmd, "target", "."); err != nil {
		t.Fatal(err)
	}
	if target != "." {
		t.Fatalf("expected target to be set to %q, got %q", ".", target)
	}
	if err := cmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("expected ApplyDefault to satisfy the required-flag check, got %v", err)
	}
}

func TestApplyDefault_DoesNotOverrideExplicitFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	var target string
	cmd.Flags().StringVar(&target, "target", "", "")
	if err := cmd.Flags().Set("target", "./explicit"); err != nil {
		t.Fatal(err)
	}

	if err := ApplyDefault(cmd, "target", "./from-config"); err != nil {
		t.Fatal(err)
	}
	if target != "./explicit" {
		t.Fatalf("expected explicit flag value to survive, got %q", target)
	}
}

func TestApplyDefault_EmptyValueIsNoop(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	var target string
	cmd.Flags().StringVar(&target, "target", "default-val", "")

	if err := ApplyDefault(cmd, "target", ""); err != nil {
		t.Fatal(err)
	}
	if target != "default-val" {
		t.Fatalf("expected untouched default to survive, got %q", target)
	}
}

func chdir(t *testing.T, dir string) func() {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return func() { _ = os.Chdir(orig) } //nolint:errcheck // best-effort restore of test working directory
}
