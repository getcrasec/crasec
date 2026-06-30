package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Set at build time via:
//
//	go build -ldflags "-X github.com/getcrasec/crasec/cmd.version=1.0.0 \
//	                   -X github.com/getcrasec/crasec/cmd.commit=<git-sha> \
//	                   -X github.com/getcrasec/crasec/cmd.date=<iso-date>"
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("crasec %s (commit: %s, built: %s)\n", version, commit, date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
