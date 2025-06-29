package monitor

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type LogEntry struct {
	Timestamp time.Time
	Level     string
	Source    string
	Message   string
	Raw       string
}

func (l LogEntry) String() string {
	timestamp := l.Timestamp.Format("15:04:05")
	level := l.Level
	if level == "" {
		level = "INFO"
	}
	
	levelColor := ""
	switch level {
	case "ERROR", "CRIT":
		levelColor = "\033[31m" // Red
	case "WARN":
		levelColor = "\033[33m" // Yellow
	case "INFO":
		levelColor = "\033[32m" // Green
	case "DEBUG":
		levelColor = "\033[36m" // Cyan
	}
	reset := "\033[0m"
	
	return fmt.Sprintf("%s [%s%s%s] %s: %s", 
		timestamp, levelColor, level, reset, l.Source, l.Message)
}

// Determines if a log is hardware-related
func isHardwareLog(source, message string) bool {
	// Skip common non-hardware services
	skipServices := []string{
		"sudo",
		"fontconfig",
		"snapd",
		"gvfsd",
		"pipewire",
		"wireplumber",
		"gnome-shell",
		"org.gnome",
		"gdm-",
		"thunar",
		"systemd",
		"dbus",
		"xdg",
	}
	
	for _, service := range skipServices {
		if strings.Contains(source, service) {
			return false
		}
	}

	// Focus on hardware-related sources
	hwKeywords := []string{
		"usb",
		"pci",
		"drm",
		"tpm",
		"modem",
		"bluetooth",
		"wifi",
		"ethernet",
		"network",
		"audio",
		"graphics",
		"storage",
		"disk",
		"memory",
		"cpu",
		"gpu",
		"sensor",
		"battery",
		"acpi",
		"kernel",
		"driver",
		"firmware",
		"udev",
		"input",
	}
	
	combined := strings.ToLower(source + " " + message)
	for _, kw := range hwKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	
	return false
}

func GetRecentLogs(lines int, filter string) ([]LogEntry, error) {
	switch runtime.GOOS {
	case "linux":
		return getLinuxLogs(lines, filter, false)
	case "darwin":
		return getMacOSLogs(lines, filter, false)
	case "windows":
		return getWindowsLogs(lines, filter, false)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func TailLogs(lines int, filter string) error {
	switch runtime.GOOS {
	case "linux":
		_, err := getLinuxLogs(lines, filter, true)
		return err
	case "darwin":
		_, err := getMacOSLogs(lines, filter, true)
		return err
	case "windows":
		_, err := getWindowsLogs(lines, filter, true)
		return err
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func getLinuxLogs(lines int, filter string, follow bool) ([]LogEntry, error) {
	// Try journalctl first
	journalLogs, journalErr := tryJournalctl(lines, filter)
	if journalErr == nil && len(journalLogs) > 0 {
		return journalLogs, nil
	}

	// Then try dmesg
	dmesgLogs, dmesgErr := tryDmesg(lines, filter, follow)
	if dmesgErr == nil && len(dmesgLogs) > 0 {
		return dmesgLogs, nil
	}

	// Finally try syslog as fallback
	syslogLogs, syslogErr := trySyslog(lines, filter)
	if syslogErr == nil && len(syslogLogs) > 0 {
		return syslogLogs, nil
	}

	// If all methods failed, return the most meaningful error
	if journalErr != nil {
		return nil, fmt.Errorf("journalctl failed: %v", journalErr)
	}
	if dmesgErr != nil {
		return nil, fmt.Errorf("dmesg failed: %v", dmesgErr)
	}
	return nil, fmt.Errorf("syslog failed: %v", syslogErr)
}

func tryJournalctl(lines int, filter string) ([]LogEntry, error) {
	args := []string{"-b", "-q", "-o", "short-iso", "--no-pager", "-n", fmt.Sprintf("%d", lines)}
	if filter != "" {
		args = append(args, "-g", filter)
	}
	
	cmd := exec.Command("journalctl", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("journalctl failed: %w", err)
	}
	
	return parseJournalctlOutput(string(output))
}

func parseJournalctlOutput(output string) ([]LogEntry, error) {
	var logs []LogEntry
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Parse ISO 8601 format: 2023-10-15T12:34:56+02:00 HOSTNAME SOURCE[PID]: MESSAGE
		parts := strings.SplitN(line, " ", 4)
		if len(parts) < 4 {
			continue
		}
		
		// Parse timestamp (ISO 8601 format)
		timestamp, err := time.Parse(time.RFC3339, parts[0])
		if err != nil {
			// Try without timezone offset
			timestamp, err = time.Parse("2006-01-02T15:04:05", parts[0])
			if err != nil {
				continue
			}
		}
		
		// Extract source and message
		source := parts[2]
		message := parts[3]
		
		// Clean up source (remove PID)
		if idx := strings.Index(source, "["); idx != -1 {
			source = source[:idx]
		}
		
		// Skip non-hardware logs
		if !isHardwareLog(source, message) {
			continue
		}
		
		// Detect log level
		level := "INFO"
		messageLower := strings.ToLower(message)
		switch {
		case strings.Contains(messageLower, "err") || 
		     strings.Contains(messageLower, "fail") || 
		     strings.Contains(messageLower, "crit"):
			level = "ERROR"
		case strings.Contains(messageLower, "warn"):
			level = "WARN"
		case strings.Contains(messageLower, "debug"):
			level = "DEBUG"
		}
		
		logs = append(logs, LogEntry{
			Timestamp: timestamp,
			Level:     level,
			Source:    source,
			Message:   message,
			Raw:       line,
		})
	}
	
	return logs, nil
}

func tryDmesg(lines int, filter string, follow bool) ([]LogEntry, error) {
	args := []string{"--human", "--decode", "--time-format", "ctime"}
	if follow {
		args = append(args, "--follow")
	}
	if lines > 0 && !follow {
		args = append(args, fmt.Sprintf("--lines=%d", lines))
	}
	
	cmd := exec.Command("dmesg", args...)
	
	if follow {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("stdout pipe: %w", err)
		}
		
		if err := cmd.Start(); err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				return nil, errors.New("permission denied. Try running with sudo?")
			}
			return nil, fmt.Errorf("start dmesg: %w", err)
		}
		
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if filter != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(filter)) {
				continue
			}
			
			entry := parseDmesgLogLine(line)
			fmt.Println(entry.String())
		}
		
		if err := cmd.Wait(); err != nil {
			return nil, fmt.Errorf("dmesg wait: %w", err)
		}
		
		return nil, nil
	}
	
	output, err := cmd.Output()
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return nil, errors.New("permission denied. Try running with sudo?")
		}
		return nil, fmt.Errorf("run dmesg: %w", err)
	}
	
	return parseDmesgOutput(string(output), filter)
}

func parseDmesgOutput(output, filter string) ([]LogEntry, error) {
	var logs []LogEntry
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		if filter != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(filter)) {
			continue
		}
		
		// Skip non-hardware logs
		if !isHardwareLog("kernel", line) {
			continue
		}
		
		entry := parseDmesgLogLine(line)
		logs = append(logs, entry)
	}
	
	return logs, nil
}

func parseDmesgLogLine(line string) LogEntry {
	entry := LogEntry{
		Raw:       line,
		Timestamp: time.Now(),
		Level:     "INFO",
		Source:    "kernel",
		Message:   line,
	}
	
	// Parse timestamp format: [Mon Jan 2 15:04:05 2006]
	if strings.HasPrefix(line, "[") {
		endBracket := strings.Index(line, "]")
		if endBracket > 0 {
			timestampStr := line[1:endBracket]
			entry.Message = strings.TrimSpace(line[endBracket+1:])
			
			// Try to parse timestamp
			if t, err := time.Parse("Mon Jan 2 15:04:05 2006", timestampStr); err == nil {
				entry.Timestamp = t
			}
		}
	}
	
	// Detect log level
	messageLower := strings.ToLower(entry.Message)
	switch {
	case strings.Contains(messageLower, "error") || 
	     strings.Contains(messageLower, "failed") || 
	     strings.Contains(messageLower, "crit"):
		entry.Level = "ERROR"
	case strings.Contains(messageLower, "warning") || 
	     strings.Contains(messageLower, "warn"):
		entry.Level = "WARN"
	case strings.Contains(messageLower, "debug"):
		entry.Level = "DEBUG"
	}
	
	return entry
}

func trySyslog(lines int, filter string) ([]LogEntry, error) {
	const syslogPath = "/var/log/syslog"
	
	file, err := os.Open(syslogPath)
	if err != nil {
		return nil, fmt.Errorf("open syslog: %w", err)
	}
	defer file.Close()
	
	var logs []LogEntry
	scanner := bufio.NewScanner(file)
	lineCount := 0
	
	// Syslog regex: Mmm dd hh:mm:ss hostname source: message
	syslogRegex := regexp.MustCompile(`^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) (\S+): (.*)$`)
	
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++
		
		// Skip if we have enough lines
		if lines > 0 && lineCount > lines {
			break
		}
		
		if filter != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(filter)) {
			continue
		}
		
		// Parse syslog line
		matches := syslogRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			// Skip unparsable lines
			continue
		}
		
		// Parse timestamp (assume current year)
		timestampStr := matches[1] + " " + strconv.Itoa(time.Now().Year())
		timestamp, err := time.Parse("Jan 2 15:04:05 2006", timestampStr)
		if err != nil {
			timestamp = time.Now()
		}
		
		host := matches[2]
		source := matches[3]
		message := matches[4]
		
		// Skip non-hardware logs
		if !isHardwareLog(source, message) {
			continue
		}
		
		// Detect log level
		level := "INFO"
		messageLower := strings.ToLower(message)
		switch {
		case strings.Contains(messageLower, "err") || 
		     strings.Contains(messageLower, "fail") || 
		     strings.Contains(messageLower, "crit"):
			level = "ERROR"
		case strings.Contains(messageLower, "warn"):
			level = "WARN"
		case strings.Contains(messageLower, "debug"):
			level = "DEBUG"
		}
		
		logs = append(logs, LogEntry{
			Timestamp: timestamp,
			Level:     level,
			Source:    fmt.Sprintf("%s/%s", host, source),
			Message:   message,
			Raw:       line,
		})
	}
	
	if err := scanner.Err(); err != nil {
		return logs, fmt.Errorf("scan syslog: %w", err)
	}
	
	return logs, nil
}

func getMacOSLogs(lines int, filter string, follow bool) ([]LogEntry, error) {
	// Use 'log' command on macOS
	args := []string{"show", "--predicate", "category CONTAINS 'hardware' OR category CONTAINS 'usb'", "--style", "compact"}
	if lines > 0 {
		args = append(args, "--last", fmt.Sprintf("%dm", lines))
	}
	if follow {
		args = append(args, "--stream")
	}
	
	cmd := exec.Command("log", args...)
	
	if follow {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("stdout pipe: %w", err)
		}
		
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("start log: %w", err)
		}
		
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if filter != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(filter)) {
				continue
			}
			
			entry := parseMacOSLogLine(line)
			fmt.Println(entry.String())
		}
		
		if err := cmd.Wait(); err != nil {
			return nil, fmt.Errorf("log wait: %w", err)
		}
		
		return nil, nil
	}
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run log: %w", err)
	}
	
	return parseMacOSOutput(string(output), filter)
}

func parseMacOSOutput(output, filter string) ([]LogEntry, error) {
	var logs []LogEntry
	lines := strings.Split(output, "\n")
	
	// macOS log format: Timestamp Process[PID]: Message
	logRegex := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (\S+)\[(\d+)\]: (.*)$`)
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		if filter != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(filter)) {
			continue
		}
		
		matches := logRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			logs = append(logs, parseMacOSLogLine(line))
			continue
		}
		
		timestamp, _ := time.Parse("2006-01-02 15:04:05.000", matches[1])
		process := matches[2]
		pid := matches[3]
		message := matches[4]
		
		// Skip non-hardware logs
		if !isHardwareLog(process, message) {
			continue
		}
		
		logs = append(logs, LogEntry{
			Timestamp: timestamp,
			Level:     "INFO",
			Source:    fmt.Sprintf("%s[%s]", process, pid),
			Message:   message,
			Raw:       line,
		})
	}
	
	return logs, nil
}

func parseMacOSLogLine(line string) LogEntry {
	return LogEntry{
		Raw:       line,
		Timestamp: time.Now(),
		Level:     "INFO",
		Source:    "system",
		Message:   line,
	}
}

func getWindowsLogs(lines int, filter string, follow bool) ([]LogEntry, error) {
	// Placeholder for Windows Event Log integration
	entry := LogEntry{
		Raw:       "Windows log parsing not yet implemented",
		Timestamp: time.Now(),
		Level:     "INFO",
		Source:    "system",
		Message:   "Windows log parsing not yet implemented",
	}
	
	if follow {
		fmt.Println(entry.String())
		// Keep running until interrupted
		select {}
	}
	
	return []LogEntry{entry}, nil
}
