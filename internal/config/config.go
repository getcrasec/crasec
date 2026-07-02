// Package config reads and writes .crasec.yaml: the project-level settings
// file "crasec init" produces, so that a project set up once doesn't need
// --target/--product/--manufacturer-* repeated on every later command.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// FileName is the config file "crasec init" writes to the project root.
const FileName = ".crasec.yaml"

// Config is the project-level settings collected by "crasec init".
type Config struct {
	Product      Product      `yaml:"product"`
	Manufacturer Manufacturer `yaml:"manufacturer"`
	// Ecosystem is the detected/confirmed primary language ecosystem
	// (go, node, python, java, rust, other) — informational today, but
	// gives downstream commands a hook to specialize behavior later
	// without re-running detection.
	Ecosystem string `yaml:"ecosystem,omitempty"`
	Scan      Scan   `yaml:"scan"`
}

// Product identifies what's being built.
type Product struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version,omitempty"`
}

// Manufacturer is the identity CRA Annex V's EU Declaration of Conformity
// requires: a name and an EU-registered address.
type Manufacturer struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

// Scan is where "crasec sbom generate" should look by default.
type Scan struct {
	Target string `yaml:"target"`
}

// Load reads .crasec.yaml from the current directory, falling back to
// ~/.crasec/config.yaml — the same two locations root.go's own viper setup
// searches, and the "project first, personal default second" order every
// other crasec command that reads project state already uses. A missing
// file is not an error: (nil, nil) means "no config yet", distinct from a
// config file that exists but fails to parse.
func Load() (*Config, error) {
	path, err := findConfigPath()
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}

func findConfigPath() (string, error) {
	if _, err := os.Stat(FileName); err == nil {
		return FileName, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil //nolint:nilerr // no resolvable home dir just means "no personal default"; not a hard error
	}
	homePath := filepath.Join(home, ".crasec", "config.yaml")
	if _, err := os.Stat(homePath); err == nil {
		return homePath, nil
	}
	return "", nil
}

// Save writes c to path as YAML.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ApplyDefault sets cmd's flagName to val when the flag wasn't explicitly
// passed on the command line and val is non-empty. This has to happen via
// Flags().Set — a flag's variable holding a non-empty default isn't enough
// to satisfy cobra's MarkFlagRequired, which checks Flags().Changed —
// which is also what Set() marks true. Called from a command's PreRunE
// (which runs before cobra validates required flags), this lets a flag
// stay declared required for anyone who hasn't run "crasec init" yet,
// while being silently satisfied by .crasec.yaml for anyone who has.
func ApplyDefault(cmd *cobra.Command, flagName, val string) error {
	if val == "" || cmd.Flags().Changed(flagName) {
		return nil
	}
	return cmd.Flags().Set(flagName, val)
}
