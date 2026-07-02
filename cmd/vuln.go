package cmd

import "github.com/spf13/cobra"

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Vulnerability scanning commands",
}

func init() {
	rootCmd.AddCommand(vulnCmd)
}
