package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "crasec",
	Short: "EU Cyber Resilience Act compliance evidence, generated from your repo",
	Long: `crasec turns a repository into the signed evidence package the EU Cyber
Resilience Act requires: an SBOM, a vulnerability correlation report scored
for CRA relevance, a VEX exploitability statement, a CSAF security advisory,
Annex VII technical documentation, and an EU Declaration of Conformity,
bundled into a single ZIP an auditor or market-surveillance authority can be
handed directly.

Start with:
  crasec init`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .crasec.yaml in project root or ~/.crasec/config.yaml)")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Search order: project root (.crasec.yaml), then ~/.crasec/config.yaml
		viper.AddConfigPath(".")
		viper.AddConfigPath(home + "/.crasec")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".crasec")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
