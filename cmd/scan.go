package cmd

import (
	"ai-hwdoctor/monitor"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	showFull bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan connected hardware devices",
	Long:  "Perform hardware device scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		printLogo()
		fmt.Println("\nScanning hardware devices...")
		
		devices, err := monitor.ScanDevices(showFull)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		if len(devices) == 0 {
			fmt.Println("No devices found.")
			return nil
		}

		fmt.Printf("\nFound %d device(s):\n\n", len(devices))
		for i, device := range devices {
			fmt.Printf("%d. %s\n", i+1, device)
			if verbose {
				fmt.Printf("   Path: %s\n", device.Path)
				fmt.Printf("   Type: %s\n", device.Type)
				fmt.Printf("   Status: %s\n", device.Status)
				fmt.Println()
			}
		}

		if !showFull {
			fmt.Println("\nNote: Showing user-relevant devices only. Use '--full' for all.")
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVarP(&showFull, "full", "f", false, "Show all system devices")
	rootCmd.AddCommand(scanCmd)
}
