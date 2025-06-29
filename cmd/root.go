package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	apiKey  string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "doctor",
	Short: "AI-HWDoctor - Hardware monitoring and troubleshooting tool",
	Long: `AI-HWDoctor is a cross-platform CLI and TUI tool for real-time hardware monitoring,
log analysis, and AI-powered troubleshooting. It monitors USB device connections,
parses system logs, and provides intelligent diagnostics.`,
	Version: version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "OpenAI API key for enhanced diagnostics")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	
	// Set environment variable if available
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		apiKey = key
	}
}

func printLogo() {
	logo := `
┌─────────────────────────────────────────┐
│          AI-HWDoctor v` + version + `            │
│   Hardware Monitoring & Diagnostics     │
└─────────────────────────────────────────┘`
	fmt.Println(logo)
}
