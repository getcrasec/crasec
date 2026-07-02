package cmd

import "github.com/spf13/cobra"

var docCmd = &cobra.Command{
	Use:   "doc",
	Short: "EU Declaration of Conformity commands",
}

func init() {
	rootCmd.AddCommand(docCmd)
}
