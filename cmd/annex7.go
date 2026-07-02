package cmd

import "github.com/spf13/cobra"

var annex7Cmd = &cobra.Command{
	Use:   "annex7",
	Short: "CRA Annex VII technical documentation commands",
}

func init() {
	rootCmd.AddCommand(annex7Cmd)
}
