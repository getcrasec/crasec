package cmd

import (
	"bytes"
	"fmt"
	"os"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/spf13/cobra"
)

var csafValidateCmd = &cobra.Command{
	Use:   "validate <advisory.json>",
	Short: "Validate a CSAF document against the official CSAF 2.0 JSON schema",
	Long: `Parse a CSAF document and validate it against the exact schema published
at https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json (embedded,
so this works offline). Useful for checking an advisory.json that was hand
edited or produced by something other than "crasec csaf generate", or for a
CI gate on a checked-in advisory.`,
	Args: cobra.ExactArgs(1),
	RunE: runCSAFValidate,
}

func init() {
	csafCmd.AddCommand(csafValidateCmd)
}

func runCSAFValidate(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true
	path := args[0]

	data, err := os.ReadFile(path) // #nosec G304 -- path is a user-supplied CLI argument, not attacker-controlled remote input
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parsing %s as JSON: %w", path, err)
	}

	violations, err := gocsaf.ValidateCSAF(doc)
	if err != nil {
		return fmt.Errorf("validating %s against CSAF 2.0 schema: %w", path, err)
	}

	out := cmd.OutOrStdout()
	if len(violations) == 0 {
		fmt.Fprintf(out, "Result: PASS  (%s conforms to CSAF 2.0)\n", path) //nolint:errcheck // best-effort status output
		return nil
	}

	fmt.Fprintf(out, "Result: FAIL  (%d schema violation(s) in %s)\n", len(violations), path) //nolint:errcheck // best-effort status output
	for _, v := range violations {
		fmt.Fprintf(out, "  %s\n", v) //nolint:errcheck // best-effort status output
	}
	os.Exit(1)
	return nil
}
