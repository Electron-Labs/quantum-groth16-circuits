package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "quantum-gnark-circuits",
	Short: "CLI for ineracting with quantum circuits",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var OutputDir string

func init() {
	RootCmd.PersistentFlags().StringVar(&OutputDir, "out", "artifacts", "Output directory for storing artifacts")

	RootCmd.CompletionOptions.DisableDefaultCmd = true
}
