package cmd

import "github.com/spf13/cobra"

var csafCmd = &cobra.Command{
	Use:   "csaf",
	Short: "CSAF (Common Security Advisory Framework) commands",
}

func init() {
	rootCmd.AddCommand(csafCmd)
}
