
# AI-HWDoctor

A cross-platform CLI and TUI tool for real-time hardware monitoring, log analysis, and AI-powered troubleshooting.

## Features

- 🔍 **Real-time Hardware Monitoring**: Detect USB insertions, device connections, and hardware changes
     - 📋 **System Log Analysis**: Parse and tail logs from `dmesg` and system sources
     - 🤖 **AI-Powered Diagnostics**: Get intelligent troubleshooting suggestions (offline + OpenAI)
     - 💻 **Cross-Platform**: Works on Linux, macOS, and Windows
     - 🎯 **Interactive TUI**: Beautiful terminal interface with real-time updates
     - ⚡ **CLI Commands**: Quick scanning and log analysis from command line

     ## Installation

     ### From Source

     ```
     git clone <repository-url>
     cd ai-hwdoctor
     go build -o doctor .
     ```

     ### Usage

     #### CLI Commands

     ```bash
     # Scan connected devices
     ./doctor scan

     # View recent hardware logs
     ./doctor logs

     # Follow logs in real-time
     ./doctor logs --follow

     # Filter logs by keyword
     ./doctor logs --filter="usb"

     # Launch interactive TUI
     ./doctor tui
     ```

     #### TUI Interface

     Launch the interactive terminal UI for real-time monitoring:

     ```bash
     ./doctor tui
     ```

     **TUI Controls:**
     - `Tab/Shift+Tab`: Switch between tabs
     - `↑↓ or j/k`: Navigate items
     - `Enter`: Analyze selected device/logs
     - `R`: Refresh data
     - `1/2/3/4`: Jump to specific tabs (Devices/Logs/AI/Fix Progress)
     - `F`: Apply AI-suggested fix (opens a new terminal window to execute commands)
     - `Y/N`: Confirm or cancel fix application
     - `Q`: Quit

     #### AI Integration

     For enhanced AI diagnostics, set your OpenAI API key:

     ```bash
     export OPENAI_API_KEY="your-api-key"
     ./doctor tui
     ```

     Or pass it directly:

     ```bash
     ./doctor tui --api-key="your-api-key"
     ```

     ## Architecture

     ```
     ai-hwdoctor/
     ├── cmd/           # CLI commands (Cobra)
     │   ├── root.go    # Root command and global flags
     │   ├── scan.go    # Device scanning command
     │   ├── logs.go    # Log viewing command
     │   └── tui.go     # TUI launcher command
     ├── tui/           # Terminal UI (bubbletea + lipgloss)
     │   └── app.go     # Main TUI application
     ├── monitor/       # Hardware detection and log parsing
     │   ├── devices.go # Device scanning logic
     │   ├── logs.go    # Log parsing and tailing
     │   └── watcher.go # Real-time event monitoring
     ├── ai/            # AI integration
     │   └── llm.go     # Offline and online LLM handlers
     └── main.go        # Entry point
     ```

     ## Platform Support

     ### Linux
     - USB device detection via `/sys/bus/usb/devices` and `/proc/bus/usb/devices`
     - PCI device scanning via `/sys/bus/pci/devices`
     - Block device monitoring via `/sys/block`
     - System log parsing via `dmesg`

     ### macOS
     - Device detection via `system_profiler` and `ioreg`
     - Log analysis via unified logging system
     - Hardware event monitoring

     ### Windows
     - Device detection via WMI queries
     - Event log integration
     - Hardware change notifications

     ## AI Features

     ### Offline Diagnostics
     - Rule-based analysis for common hardware issues
     - Pattern matching for USB, disk, network, audio, and graphics problems
     - No external dependencies required

     ### Online Diagnostics (OpenAI)
     - Advanced AI analysis using GPT models
     - Contextual troubleshooting based on device info and logs
     - Confidence scoring and severity assessment

     ## Development

     ### Prerequisites
     - Go 1.21 or later
     - Linux, macOS, or Windows

     ### Building

     ```bash
     go mod tidy
     go build -o doctor .
     ```

     ### Testing

     ```bash
     go test ./...
     ```

     ## Contributing

     1. Fork the repository
     2. Create a feature branch
     3. Make your changes
     4. Add tests if applicable
     5. Submit a pull request

     ## License

     MIT License - see LICENSE file for details.

     ## Troubleshooting

     ### Permissions
     On Linux, some device information may require root access:

     ```bash
     sudo ./doctor scan
     ```

     ### Dependencies
     Make sure you have the required system tools:
     - Linux: `dmesg`, `lspci`, `lsusb`
     - macOS: `system_profiler`, `log`
     - Windows: PowerShell access

     ### Common Issues

     1. **No devices detected**: Check if running with sufficient permissions
     2. **Logs not available**: Verify system log access permissions
     3. **AI not working**: Check API key configuration and network connectivity

