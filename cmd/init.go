package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/config"
	"github.com/getcrasec/crasec/internal/initwizard"
)

var (
	initProduct             string
	initProductVersion      string
	initManufacturerName    string
	initManufacturerAddress string
	initEcosystem           string
	initTarget              string
	initNonInteractive      bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Guided first-run setup: detect your project and write .crasec.yaml",
	Long: `The first command to run in a new project. Detects your project's
ecosystem (go.mod, package.json, pom.xml, Cargo.toml, requirements.txt),
walks through product and manufacturer identity (the manufacturer name and
EU-registered address are required later for the EU Declaration of
Conformity), and writes .crasec.yaml to the project root.

Every crasec command that would otherwise need --target, --product,
--manufacturer-name, or --manufacturer-address reads its default from
.crasec.yaml once it exists, so a project set up once needs far fewer
flags on every later run.

Re-running "crasec init" in a project that already has .crasec.yaml
resumes with its current values pre-filled, for updating settings rather
than starting over.

--non-interactive skips the wizard entirely (for CI/scripted setup); it
requires --product, --manufacturer-name, and --manufacturer-address (or a
prior .crasec.yaml already carrying them).`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().BoolVar(&initNonInteractive, "non-interactive", false, "write .crasec.yaml directly from flags instead of running the wizard")
	initCmd.Flags().StringVar(&initProduct, "product", "", "product name (non-interactive mode)")
	initCmd.Flags().StringVar(&initProductVersion, "product-version", "", "product version (non-interactive mode)")
	initCmd.Flags().StringVar(&initManufacturerName, "manufacturer-name", "", "manufacturer name (non-interactive mode)")
	initCmd.Flags().StringVar(&initManufacturerAddress, "manufacturer-address", "", "manufacturer's EU-registered address (non-interactive mode)")
	initCmd.Flags().StringVar(&initEcosystem, "ecosystem", "", "primary ecosystem: go, node, java, rust, python, or other (non-interactive mode; default: auto-detected)")
	initCmd.Flags().StringVar(&initTarget, "target", "", `scan target for "sbom generate" (non-interactive mode; default: ".")`)
}

func runInit(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting current directory: %w", err)
	}

	existing, err := config.Load()
	if err != nil {
		return err
	}

	var cfg *config.Config
	if initNonInteractive {
		cfg, err = nonInteractiveConfig(cwd, existing)
		if err != nil {
			return err
		}
	} else {
		var completed bool
		cfg, completed, err = initwizard.Run(cwd, existing)
		if err != nil {
			return err
		}
		if !completed {
			fmt.Fprintln(cmd.ErrOrStderr(), "init cancelled; .crasec.yaml was not written")
			return nil
		}
	}

	if err := cfg.Save(config.FileName); err != nil {
		return err
	}

	printNextSteps(cmd.OutOrStdout(), cfg)
	return nil
}

// nonInteractiveConfig builds a Config from --non-interactive's flags,
// layered over any existing .crasec.yaml (so re-running with just one
// changed flag doesn't blank out the rest) and auto-detection for
// ecosystem/target when those specific flags are omitted.
func nonInteractiveConfig(cwd string, existing *config.Config) (*config.Config, error) {
	cfg := &config.Config{}
	if existing != nil {
		cfg = existing
	}

	if initProduct != "" {
		cfg.Product.Name = initProduct
	}
	if initProductVersion != "" {
		cfg.Product.Version = initProductVersion
	}
	if initManufacturerName != "" {
		cfg.Manufacturer.Name = initManufacturerName
	}
	if initManufacturerAddress != "" {
		cfg.Manufacturer.Address = initManufacturerAddress
	}
	if initEcosystem != "" {
		cfg.Ecosystem = initEcosystem
	}
	if initTarget != "" {
		cfg.Scan.Target = initTarget
	}
	if cfg.Scan.Target == "" {
		cfg.Scan.Target = "."
	}
	if cfg.Ecosystem == "" {
		if detected := initwizard.DetectEcosystems(cwd); len(detected) == 1 {
			cfg.Ecosystem = detected[0].Ecosystem
		}
	}

	var missing []string
	if cfg.Product.Name == "" {
		missing = append(missing, "--product")
	}
	if cfg.Manufacturer.Name == "" {
		missing = append(missing, "--manufacturer-name")
	}
	if cfg.Manufacturer.Address == "" {
		missing = append(missing, "--manufacturer-address")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("--non-interactive requires %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

func printNextSteps(w io.Writer, cfg *config.Config) {
	fmt.Fprintf(w, "\nWrote %s for %q\n\n", config.FileName, cfg.Product.Name)
	fmt.Fprintln(w, "What's next:")
	fmt.Fprintln(w, "  → Run:  crasec sbom generate")
	fmt.Fprintln(w, "  → Then: crasec vuln correlate --sbom sbom.cdx.json")
	fmt.Fprintln(w, "  → Then: crasec vex generate --sbom sbom.cdx.json --findings findings.json")
	fmt.Fprintln(w, "  → Then: crasec bundle export")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Each of those now reads its defaults from %s — no flags needed to get started.\n", config.FileName)
}
