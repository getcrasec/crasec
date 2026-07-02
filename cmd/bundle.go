package cmd

import "github.com/spf13/cobra"

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Evidence bundle commands",
}

func init() {
	rootCmd.AddCommand(bundleCmd)
}
