package tui

import (
    "fmt"
    "os/exec"
    "runtime"
    "strings"
    "time"

    "ai-hwdoctor/ai"
    "ai-hwdoctor/communication"
    "ai-hwdoctor/monitor"

    "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
)

const (
    tabDevices = 0
    tabLogs    = 1
    tabAI      = 2
    tabFix     = 3
    visibleDevices = 10
    visibleLogs = 20
)

// Model represents the state of the TUI application.
type Model struct {
    activeTab               int
    devices                 []monitor.Device
    logs                    []monitor.LogEntry
    events                  []monitor.HardwareEvent
    watcher                 *monitor.Watcher
    llmProvider             ai.LLMProvider
    diagnostics             []*ai.DiagnosticResult
    commManager             *communication.CommunicationManager
    width                   int
    height                  int
    selectedDevice          int
    selectedLog             int
    logScroll               int
    deviceScroll            int
    lastUpdate              time.Time
    fixInProgress           bool
    fixOutput               []string
    currentFix              *ai.DiagnosticResult
    confirmation            bool
    communicationPair       []monitor.Device
    driverInstallInProgress bool
    driverInstallOutput     []string
    tabStyle                lipgloss.Style
    activeTabStyle          lipgloss.Style
    contentStyle            lipgloss.Style
    deviceStyle             lipgloss.Style
    logStyle                lipgloss.Style
    headerStyle             lipgloss.Style
    badgeStyle              lipgloss.Style
}

// Custom message types for Bubble Tea updates
type tickMsg time.Time
type devicesMsg []monitor.Device
type logsMsg []monitor.LogEntry
type eventMsg monitor.HardwareEvent
type diagnosticMsg *ai.DiagnosticResult
type fixUpdateMsg struct {
    output string
}
type fixCompleteMsg struct {
    err error
}
type communicationResultMsg string

// StartTUI initializes and runs the TUI application.
func StartTUI(apiKey string, verbose bool) error {
    llmProvider := ai.NewLLMProvider(apiKey)
    commManager := communication.NewCommunicationManager()
    watcher, err := monitor.NewWatcher()
    if err != nil {
        return fmt.Errorf("watcher failed: %w", err)
    }

    m := Model{
        llmProvider:   llmProvider,
        watcher:       watcher,
        commManager:   commManager,
        devices:       []monitor.Device{},
        logs:          []monitor.LogEntry{},
        events:        []monitor.HardwareEvent{},
        diagnostics:   []*ai.DiagnosticResult{},
        lastUpdate:    time.Now(),
        fixOutput:     []string{},
        driverInstallOutput: []string{},
    }

    m.setupStyles()

    if err := watcher.Start(); err != nil {
        return fmt.Errorf("watcher start failed: %w", err)
    }

    p := tea.NewProgram(m, tea.WithAltScreen())
    _, err = p.Run()
    
    watcher.Stop()
    return err
}

// setupStyles initializes the lipgloss styles for the TUI components.
func (m *Model) setupStyles() {
    m.tabStyle = lipgloss.NewStyle().Padding(0, 2).Background(lipgloss.Color("240")).Foreground(lipgloss.Color("15"))
    m.activeTabStyle = lipgloss.NewStyle().Padding(0, 2).Background(lipgloss.Color("4")).Foreground(lipgloss.Color("15")).Bold(true)
    m.contentStyle = lipgloss.NewStyle().Padding(1, 2).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("4"))
    m.deviceStyle = lipgloss.NewStyle().Padding(0, 1).Margin(0, 0, 1, 0)
    m.logStyle = lipgloss.NewStyle().Padding(0, 1)
    m.headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("4")).Padding(1, 2)
    m.badgeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("4")).Padding(0, 1).Bold(true)
}

// Init sets up initial commands for the TUI.
func (m Model) Init() tea.Cmd {
    return tea.Batch(
        tick(),
        m.fetchDevices(),
        m.fetchLogs(),
        m.listenForEvents(),
    )
}

// Update handles all user interactions and message updates.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    var cmds []tea.Cmd

    switch msg := msg.(type) {
    case tea.WindowSizeMsg:
        m.width = msg.Width
        m.height = msg.Height

    case tea.KeyMsg:
        switch msg.String() {
        case "ctrl+c", "q":
            return m, tea.Quit
        case "tab":
            m.activeTab = (m.activeTab + 1) % 4
        case "shift+tab":
            m.activeTab = (m.activeTab - 1 + 4) % 4
        case "1":
            m.activeTab = tabDevices
        case "2":
            m.activeTab = tabLogs
        case "3":
            m.activeTab = tabAI
        case "4":
            m.activeTab = tabFix
        case "r":
            cmds = append(cmds, m.fetchDevices(), m.fetchLogs())
        case "up", "k":
            m.handleUpKey()
        case "down", "j":
            m.handleDownKey()
        case "pageup":
            m.handlePageUp()
        case "pagedown":
            m.handlePageDown()
        case "enter":
            if cmd := m.handleEnter(); cmd != nil {
                cmds = append(cmds, cmd)
            }
        case "f":
            if m.activeTab == tabAI && len(m.diagnostics) > 0 {
                m.confirmation = true
            }
        case "y":
            if m.confirmation {
                m.confirmation = false
                m.activeTab = tabFix
                if strings.Contains(strings.ToLower(m.diagnostics[0].Solution), "driver") {
                    m.driverInstallInProgress = true
                    m.driverInstallOutput = []string{"Starting driver installation..."}
                    cmds = append(cmds, m.applyFix(m.diagnostics[0]))
                } else {
                    m.fixInProgress = true
                    m.fixOutput = []string{"Starting fix application..."}
                    m.currentFix = m.diagnostics[0]
                    cmds = append(cmds, m.applyFix(m.diagnostics[0]))
                }
            }
        case "n":
            if m.confirmation {
                m.confirmation = false
            }
        case "c":
            if m.activeTab == tabDevices {
                if len(m.communicationPair) < 2 {
                    device := m.devices[m.selectedDevice]
                    m.communicationPair = append(m.communicationPair, device)
                    if len(m.communicationPair) == 2 {
                        cmds = append(cmds, m.establishCommunication())
                    }
                }
            }
        }

    case tickMsg:
        m.lastUpdate = time.Time(msg)
        cmds = append(cmds, tick())

    case devicesMsg:
        m.devices = []monitor.Device(msg)

    case logsMsg:
        m.logs = []monitor.LogEntry(msg)

    case eventMsg:
        event := monitor.HardwareEvent(msg)
        m.events = append([]monitor.HardwareEvent{event}, m.events...)
        if len(m.events) > 50 {
            m.events = m.events[:50]
        }
        cmds = append(cmds, m.listenForEvents())

    case diagnosticMsg:
        diagnostic := (*ai.DiagnosticResult)(msg)
        m.diagnostics = append([]*ai.DiagnosticResult{diagnostic}, m.diagnostics...)
        if len(m.diagnostics) > 10 {
            m.diagnostics = m.diagnostics[:10]
        }

    case fixUpdateMsg:
        m.fixOutput = []string{msg.output}
        m.fixInProgress = false
        return m, nil

    case fixCompleteMsg:
        if m.driverInstallInProgress {
            m.driverInstallInProgress = false
            if msg.err != nil {
                m.driverInstallOutput = append(m.driverInstallOutput, "Driver installation failed")
            } else {
                m.driverInstallOutput = append(m.driverInstallOutput, "Driver installation completed")
            }
        } else {
            m.fixInProgress = false
            if msg.err != nil {
                m.fixOutput = append(m.fixOutput, "Fix application failed")
            } else {
                m.fixOutput = append(m.fixOutput, "Fix application completed")
            }
        }

    case communicationResultMsg:
        m.events = append([]monitor.HardwareEvent{{
            Type:      monitor.LogUpdate,
            Message:   string(msg),
            Timestamp: time.Now(),
        }}, m.events...)
        m.communicationPair = nil
    }

    return m, tea.Batch(cmds...)
}

// View renders the current state of the TUI.
func (m Model) View() string {
    if m.width == 0 {
        return "Loading..."
    }

    header := m.renderHeader()
    tabs := m.renderTabs()
    content := m.renderContent()
    footer := m.renderFooter()

    return lipgloss.JoinVertical(lipgloss.Left, header, tabs, content, footer)
}

// renderHeader displays the title and status information.
func (m Model) renderHeader() string {
    title := "AI-HWDoctor - Hardware Diagnostics"
    status := fmt.Sprintf("Last Update: %s", m.lastUpdate.Format("15:04:05"))
    if m.llmProvider.IsAvailable() {
        status += " | AI: Online"
    } else {
        status += " | AI: Offline"
    }

    header := lipgloss.JoinHorizontal(
        lipgloss.Left,
        m.headerStyle.Render(title),
        lipgloss.NewStyle().Align(lipgloss.Right).Width(m.width-len(title)-4).Render(status),
    )

    return header
}

// renderTabs displays the tab navigation bar.
func (m Model) renderTabs() string {
    var tabs []string
    tabNames := []string{"1. Devices", "2. Logs", "3. AI", "4. Fix Progress"}
    for i, name := range tabNames {
        if i == m.activeTab {
            tabs = append(tabs, m.activeTabStyle.Render(name))
        } else {
            tabs = append(tabs, m.tabStyle.Render(name))
        }
    }
    return lipgloss.JoinHorizontal(lipgloss.Left, tabs...)
}

// renderContent displays the content based on the active tab.
func (m Model) renderContent() string {
    switch m.activeTab {
    case tabDevices:
        return m.renderDevicesTab()
    case tabLogs:
        return m.renderLogsTab()
    case tabAI:
        return m.renderAITab()
    case tabFix:
        return m.renderFixTab()
    default:
        return m.contentStyle.Render("Unknown tab")
    }
}

// renderDevicesTab shows the list of connected devices.
func (m Model) renderDevicesTab() string {
    if len(m.devices) == 0 {
        return m.contentStyle.Width(m.width - 4).Height(m.height - 8).Render("No devices. Press 'r'")
    }

    var content strings.Builder
    content.WriteString("Connected Devices:\n\n")
    
    start := m.deviceScroll
    end := min(start+visibleDevices, len(m.devices))
    
    for i := start; i < end; i++ {
        device := m.devices[i]
        style := m.deviceStyle
        if i == m.selectedDevice {
            style = style.Background(lipgloss.Color("4")).Foreground(lipgloss.Color("15"))
        }

        status := "OK"
        if device.Status != "connected" {
            status = "ERR"
        }

        deviceLine := fmt.Sprintf("%s %s", status, device.Name)
        content.WriteString(style.Render(deviceLine) + "\n")
        
        if i == m.selectedDevice {
            details := fmt.Sprintf("   Type: %s\n   Description: %s\n   ID: %s\n   Path: %s",
                device.Type, device.Description, device.ID, device.Path)
            content.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(details) + "\n")
        }
    }
    
    content.WriteString(fmt.Sprintf("\nShowing %d-%d of %d", start+1, end, len(m.devices)))
    return m.contentStyle.Width(m.width - 4).Height(m.height - 8).Render(content.String())
}

// renderLogsTab displays system logs.
func (m Model) renderLogsTab() string {
    if len(m.logs) == 0 {
        return m.contentStyle.Width(m.width - 4).Height(m.height - 8).Render("No logs. Press 'r'")
    }

    var content strings.Builder
    content.WriteString("System Logs:\n\n")
    
    start := m.logScroll
    end := min(start+visibleLogs, len(m.logs))
    
    for i := start; i < end; i++ {
        log := m.logs[i]
        style := m.logStyle
        if i == m.selectedLog {
            style = style.Background(lipgloss.Color("4")).Foreground(lipgloss.Color("15"))
        }

        levelColor := lipgloss.Color("15")
        switch log.Level {
        case "ERROR", "CRIT":
            levelColor = lipgloss.Color("1")
        case "WARN":
            levelColor = lipgloss.Color("3")
        case "INFO":
            levelColor = lipgloss.Color("2")
        case "DEBUG":
            levelColor = lipgloss.Color("6")
        }

        timestamp := log.Timestamp.Format("15:04:05")
        logLine := fmt.Sprintf("[%s] %s: %s", 
            lipgloss.NewStyle().Foreground(levelColor).Render(log.Level),
            log.Source, 
            log.Message)

        content.WriteString(style.Render(fmt.Sprintf("%s %s", timestamp, logLine)) + "\n")
    }
    
    content.WriteString(fmt.Sprintf("\nShowing %d-%d of %d", start+1, end, len(m.logs)))
    return m.contentStyle.Width(m.width - 4).Height(m.height - 8).Render(content.String())
}

// renderAITab shows AI diagnostic results.
func (m Model) renderAITab() string {
    var content strings.Builder
    content.WriteString("AI Diagnostics:\n\n")

    if !m.llmProvider.IsAvailable() {
        content.WriteString("AI unavailable. Set OPENAI_API_KEY.\n")
    }

    if len(m.diagnostics) == 0 {
        content.WriteString("No diagnostics. Select device and press Enter.")
    } else {
        diagnostic := m.diagnostics[0]

        severityColor := lipgloss.Color("2")
        switch diagnostic.Severity {
        case "Critical":
            severityColor = lipgloss.Color("1")
        case "High":
            severityColor = lipgloss.Color("3")
        case "Medium":
            severityColor = lipgloss.Color("6")
        case "Low":
            severityColor = lipgloss.Color("2")
        }

        header := fmt.Sprintf("%s [%s] - Confidence: %.0f%%",
            diagnostic.Issue,
            lipgloss.NewStyle().Foreground(severityColor).Render(diagnostic.Severity),
            diagnostic.Confidence*100)

        content.WriteString(lipgloss.NewStyle().Bold(true).Render(header) + "\n")
        
        if diagnostic.Device != "" {
            content.WriteString("For device: " + diagnostic.Device + "\n")
        }
        
        content.WriteString("\n" + diagnostic.Solution + "\n")

        if len(diagnostic.Commands) > 0 {
            content.WriteString("\nSuggested Commands:\n")
            for _, cmd := range diagnostic.Commands {
                prefix := "$"
                if cmd.RunAsRoot {
                    prefix = "#"
                }
                content.WriteString(fmt.Sprintf("  %s %s\n", prefix, cmd.Cmd))
            }
        }

        content.WriteString("\nAnalyzed at " + diagnostic.Timestamp.Format("2006-01-02 15:04:05") + "\n")
    }

    if m.confirmation {
        content.WriteString("\nApply this fix? (y/n)\n")
        content.WriteString("Commands to execute:\n")
        for _, cmd := range m.diagnostics[0].Commands {
            prefix := "$"
            if cmd.RunAsRoot {
                prefix = "#"
            }
            content.WriteString(fmt.Sprintf("  %s %s\n", prefix, cmd.Cmd))
        }
    }
    
    if m.fixInProgress || m.driverInstallInProgress {
        content.WriteString("\nFix in progress. Switch to Fix Progress tab.")
    }

    return m.contentStyle.Width(m.width - 4).Height(m.height - 8).Render(content.String())
}

// renderFixTab displays the progress of fix operations.
func (m Model) renderFixTab() string {
    var content strings.Builder
    content.WriteString("Fix Progress:\n\n")

    if m.fixInProgress {
        content.WriteString("Applying fix...\n")
    } else if m.driverInstallInProgress {
        content.WriteString("Installing drivers...\n")
    } else if len(m.fixOutput) == 0 && len(m.driverInstallOutput) == 0 {
        content.WriteString("No active fix operations")
        return m.contentStyle.Width(m.width - 4).Height(m.height - 8).Render(content.String())
    }

    if len(m.fixOutput) > 0 {
        content.WriteString("Fix Output:\n")
        for _, line := range m.fixOutput {
            content.WriteString(line + "\n")
        }
    }

    if len(m.driverInstallOutput) > 0 {
        content.WriteString("\nDriver Installation Output:\n")
        for _, line := range m.driverInstallOutput {
            content.WriteString(line + "\n")
        }
    }

    return m.contentStyle.Width(m.width - 4).Height(m.height - 8).Render(content.String())
}

// renderFooter shows help text and the "Built with Bolt.new" badge.
func (m Model) renderFooter() string {
    help := "Tab: Switch | ↑↓: Navigate | Enter: Analyze | R: Refresh"
    if m.activeTab == tabAI && len(m.diagnostics) > 0 {
        help += " | F: Apply Fix"
    }
    if m.activeTab == tabDevices {
        help += " | C: Connect Devices"
    }
    help += " | Q: Quit"

    badge := m.badgeStyle.Render("[Built with Bolt.new -> https://bolt.new/]")
    return lipgloss.JoinHorizontal(
        lipgloss.Left,
        lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Padding(0, 2).Render(help),
        lipgloss.NewStyle().Align(lipgloss.Right).Width(m.width-lipgloss.Width(help)-4).Render(badge),
    )
}

// handleUpKey moves the selection up in the active tab.
func (m *Model) handleUpKey() {
    switch m.activeTab {
    case tabDevices:
        if m.selectedDevice > 0 {
            m.selectedDevice--
            if m.selectedDevice < m.deviceScroll {
                m.deviceScroll = m.selectedDevice
            }
        }
    case tabLogs:
        if m.selectedLog > 0 {
            m.selectedLog--
            if m.selectedLog < m.logScroll {
                m.logScroll = m.selectedLog
            }
        }
    }
}

// handleDownKey moves the selection down in the active tab.
func (m *Model) handleDownKey() {
    switch m.activeTab {
    case tabDevices:
        if m.selectedDevice < len(m.devices)-1 {
            m.selectedDevice++
            if m.selectedDevice >= m.deviceScroll+visibleDevices {
                m.deviceScroll = m.selectedDevice - visibleDevices + 1
            }
        }
    case tabLogs:
        if m.selectedLog < len(m.logs)-1 {
            m.selectedLog++
            if m.selectedLog >= m.logScroll+visibleLogs {
                m.logScroll = m.selectedLog - visibleLogs + 1
            }
        }
    }
}

// handlePageUp scrolls up by one page in the active tab.
func (m *Model) handlePageUp() {
    switch m.activeTab {
    case tabDevices:
        m.deviceScroll -= visibleDevices
        if m.deviceScroll < 0 {
            m.deviceScroll = 0
        }
    case tabLogs:
        m.logScroll -= visibleLogs
        if m.logScroll < 0 {
            m.logScroll = 0
        }
    }
}

// handlePageDown scrolls down by one page in the active tab.
func (m *Model) handlePageDown() {
    switch m.activeTab {
    case tabDevices:
        m.deviceScroll += visibleDevices
        maxScroll := len(m.devices) - visibleDevices
        if m.deviceScroll > maxScroll {
            m.deviceScroll = maxScroll
        }
    case tabLogs:
        m.logScroll += visibleLogs
        maxScroll := len(m.logs) - visibleLogs
        if m.logScroll > maxScroll {
            m.logScroll = maxScroll
        }
    }
}

// handleEnter triggers actions based on the active tab.
func (m *Model) handleEnter() tea.Cmd {
    switch m.activeTab {
    case tabDevices:
        if m.selectedDevice < len(m.devices) {
            return m.diagnoseDevice(m.devices[m.selectedDevice])
        }
    case tabLogs:
        return m.analyzeLogs()
    }
    return nil
}

// tick schedules periodic updates every 2 seconds.
func tick() tea.Cmd {
    return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
        return tickMsg(t)
    })
}

// fetchDevices retrieves the list of connected devices.
func (m Model) fetchDevices() tea.Cmd {
    return func() tea.Msg {
        devices, _ := monitor.ScanDevices(false)
        return devicesMsg(devices)
    }
}

// fetchLogs retrieves recent system logs.
func (m Model) fetchLogs() tea.Cmd {
    return func() tea.Msg {
        logs, _ := monitor.GetRecentLogs(50, "")
        return logsMsg(logs)
    }
}

// listenForEvents listens for hardware events from the watcher.
func (m Model) listenForEvents() tea.Cmd {
    return func() tea.Msg {
        select {
        case event := <-m.watcher.Events():
            return eventMsg(event)
        case <-time.After(100 * time.Millisecond):
            return nil
        }
    }
}

// diagnoseDevice initiates AI diagnostics for a selected device.
func (m Model) diagnoseDevice(device monitor.Device) tea.Cmd {
    return func() tea.Msg {
        diagnostic, err := ai.DiagnoseDevice(device, m.logs, m.llmProvider)
        if err != nil {
            return nil
        }
        diagnostic.Device = device.Name
        return diagnosticMsg(diagnostic)
    }
}

// analyzeLogs initiates AI analysis of system logs.
func (m Model) analyzeLogs() tea.Cmd {
    return func() tea.Msg {
        diagnostic, err := ai.AnalyzeLogs(m.logs, m.llmProvider)
        if err != nil {
            return nil
        }
        return diagnosticMsg(diagnostic)
    }
}

// buildCommandString constructs a command string from a list of commands.
func buildCommandString(commands []ai.Command) string {
    var cmdParts []string
    for _, cmd := range commands {
        if cmd.RunAsRoot {
            cmdParts = append(cmdParts, "sudo "+cmd.Cmd)
        } else {
            cmdParts = append(cmdParts, cmd.Cmd)
        }
    }
    return strings.Join(cmdParts, " && ")
}

// openTerminalAndRun executes commands in a new terminal window.
func openTerminalAndRun(cmdString string) error {
    switch runtime.GOOS {
    case "linux":
        return openLinuxTerminal(cmdString)
    case "darwin":
        return openMacTerminal(cmdString)
    case "windows":
        return openWindowsTerminal(cmdString)
    default:
        return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
    }
}

// openLinuxTerminal opens a terminal on Linux to run commands.
func openLinuxTerminal(cmdString string) error {
    terminals := []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xterm"}
    for _, term := range terminals {
        if _, err := exec.LookPath(term); err == nil {
            cmd := exec.Command(term, "-e", "bash", "-c", cmdString+"; exec bash")
            return cmd.Start()
        }
    }
    return fmt.Errorf("no terminal emulator found")
}

// openMacTerminal opens a terminal on macOS to run commands.
func openMacTerminal(cmdString string) error {
    script := fmt.Sprintf(`tell application "Terminal" to do script "%s"`, strings.ReplaceAll(cmdString, `"`, `\"`))
    cmd := exec.Command("osascript", "-e", script)
    return cmd.Start()
}

// openWindowsTerminal opens a terminal on Windows to run commands.
func openWindowsTerminal(cmdString string) error {
    cmd := exec.Command("cmd", "/c", "start", "cmd", "/k", cmdString)
    return cmd.Start()
}

// applyFix applies a diagnostic fix by executing commands in a terminal.
func (m Model) applyFix(diagnostic *ai.DiagnosticResult) tea.Cmd {
    return func() tea.Msg {
        if len(diagnostic.Commands) == 0 {
            return fixUpdateMsg{output: "No commands to execute."}
        }
        cmdString := buildCommandString(diagnostic.Commands)
        err := openTerminalAndRun(cmdString)
        if err != nil {
            return fixUpdateMsg{output: "Error: " + err.Error()}
        }
        return fixUpdateMsg{output: "Fix commands are being executed in a new terminal window."}
    }
}

// sendUpdate sends a message to update the TUI state.
func (m Model) sendUpdate(msg tea.Msg) tea.Cmd {
    return func() tea.Msg {
        return msg
    }
}

// establishCommunication sets up communication between two devices.
func (m Model) establishCommunication() tea.Cmd {
    return func() tea.Msg {
        if len(m.communicationPair) != 2 {
            return communicationResultMsg("Need 2 devices")
        }
        
        result, err := m.commManager.EstablishCommunication(
            m.communicationPair[0],
            m.communicationPair[1],
        )
        
        if err != nil {
            return communicationResultMsg(fmt.Sprintf("Failed: %v", err))
        }
        return communicationResultMsg(result)
    }
}

// max returns the maximum of two integers.
func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// min returns the minimum of two integers.
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
