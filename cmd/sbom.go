package cmd

import "github.com/spf13/cobra"

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Software Bill of Materials commands",
}

func init() {
	rootCmd.AddCommand(sbomCmd)
}
