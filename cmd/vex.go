package cmd

import "github.com/spf13/cobra"

var vexCmd = &cobra.Command{
	Use:   "vex",
	Short: "VEX (Vulnerability Exploitability eXchange) commands",
}

func init() {
	rootCmd.AddCommand(vexCmd)
}
