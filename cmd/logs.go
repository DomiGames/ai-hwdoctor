package cmd

import (
	"ai-hwdoctor/monitor"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	follow    bool
	lines     int
	logFilter string
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Display system hardware logs",
	Long:  "Display recent hardware-related system logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		printLogo()
		
		if follow {
			fmt.Println("\nTailing hardware logs (Ctrl+C to exit)...")
			return monitor.TailLogs(lines, logFilter)
		}
		
		fmt.Printf("\nRecent hardware logs (last %d lines):\n\n", lines)
		logs, err := monitor.GetRecentLogs(lines, logFilter)
		if err != nil {
			return fmt.Errorf("log retrieval failed: %w", err)
		}

		for _, log := range logs {
			fmt.Println(log)
		}

		return nil
	},
}

func init() {
	logsCmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow logs in real-time")
	logsCmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of log lines to display")
	logsCmd.Flags().StringVar(&logFilter, "filter", "", "Filter logs by keyword")
	rootCmd.AddCommand(logsCmd)
}
