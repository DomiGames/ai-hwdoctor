package cmd

import (
	"ai-hwdoctor/tui"

	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch terminal UI",
	Long:  "Launch interactive terminal interface",
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.StartTUI(apiKey, verbose)
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
