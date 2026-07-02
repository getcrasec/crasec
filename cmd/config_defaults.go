package cmd

import (
	"github.com/spf13/cobra"

	"github.com/getcrasec/crasec/internal/config"
)

// applyConfigDefaults returns a PreRunE that fills in any of the given
// flags left unset from .crasec.yaml (written by "crasec init") — set as
// a command's PreRunE, this runs before cobra validates required flags, so
// a flag can stay declared required for anyone who hasn't run
// "crasec init" yet while being silently satisfied by the project config
// for anyone who has.
func applyConfigDefaults(binds map[string]func(*config.Config) string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg == nil {
			return nil
		}
		for flagName, get := range binds {
			if err := config.ApplyDefault(cmd, flagName, get(cfg)); err != nil {
				return err
			}
		}
		return nil
	}
}
