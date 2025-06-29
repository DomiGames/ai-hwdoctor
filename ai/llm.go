package ai

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	
	"ai-hwdoctor/monitor"
)

type LLMProvider interface {
	Query(prompt string) (string, error)
	IsAvailable() bool
}

type OpenAIProvider struct {
	apiKey string
	client *http.Client
}

type OfflineLLMProvider struct{}

type DiagnosticResult struct {
	Issue       string
	Severity    string
	Solution    string
	Commands    []Command
	Confidence  float64
	Timestamp   time.Time
	Device      string
}

type Command struct {
	Description string
	Cmd         string
	RunAsRoot   bool
}

type DriverManager interface {
	InstallDriver(command string) (string, error)
	DownloadAndInstall(url string) (string, error)
}

type WindowsDriverManager struct{}
type LinuxDriverManager struct{}
type MacDriverManager struct{}

func (dm *WindowsDriverManager) InstallDriver(command string) (string, error) {
	cmd := exec.Command("powershell", "-Command", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (dm *LinuxDriverManager) InstallDriver(command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (dm *MacDriverManager) InstallDriver(command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (dm *WindowsDriverManager) DownloadAndInstall(url string) (string, error) {
	return downloadAndExecute(url, []string{"/S", "/quiet"})
}

func (dm *LinuxDriverManager) DownloadAndInstall(url string) (string, error) {
	return downloadAndExecute(url, []string{})
}

func (dm *MacDriverManager) DownloadAndInstall(url string) (string, error) {
	return downloadAndInstallMac(url)
}

func downloadAndExecute(url string, installArgs []string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	ext := filepath.Ext(url)
	if ext == "" {
		ext = ".bin"
	}
	file, err := os.CreateTemp("", "driver-*"+ext)
	if err != nil {
		return "", fmt.Errorf("temp file creation failed: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", fmt.Errorf("file save failed: %w", err)
	}
	file.Close()

	if runtime.GOOS != "windows" {
		os.Chmod(file.Name(), 0755)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(file.Name(), installArgs...)
	} else {
		cmd = exec.Command(file.Name())
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("installation failed: %w", err)
	}
	
	return fmt.Sprintf("Driver installed\n%s", string(output)), nil
}

func downloadAndInstallMac(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	file, err := os.CreateTemp("", "driver-*.pkg")
	if err != nil {
		return "", fmt.Errorf("temp file creation failed: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", fmt.Errorf("file save failed: %w", err)
	}
	file.Close()

	cmd := exec.Command("sudo", "installer", "-pkg", file.Name(), "-target", "/")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("installation failed: %w", err)
	}
	
	return fmt.Sprintf("Driver installed\n%s", string(output)), nil
}

func getDriverManager() DriverManager {
	switch runtime.GOOS {
	case "windows":
		return &WindowsDriverManager{}
	case "linux":
		return &LinuxDriverManager{}
	case "darwin":
		return &MacDriverManager{}
	default:
		return &LinuxDriverManager{}
	}
}

func NewLLMProvider(apiKey string) LLMProvider {
	if apiKey != "" {
		return &OpenAIProvider{
			apiKey: apiKey,
			client: &http.Client{Timeout: 30 * time.Second},
		}
	}
	return &OfflineLLMProvider{}
}

func (o *OpenAIProvider) IsAvailable() bool {
	return o.apiKey != ""
}

func (o *OpenAIProvider) Query(prompt string) (string, error) {
	requestBody := map[string]interface{}{
		"model": "gpt-3.5-turbo",
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are an expert hardware technician and system administrator. Provide concise, actionable diagnostics and solutions for hardware issues including driver installation commands when appropriate.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":  500,
		"temperature": 0.7,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("request marshal failed: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(string(jsonData)))
	if err != nil {
		return "", fmt.Errorf("request creation failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error: %d", resp.StatusCode)
	}

	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("response decode failed: %w", err)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no API response")
	}

	return response.Choices[0].Message.Content, nil
}

func (o *OfflineLLMProvider) IsAvailable() bool {
	return true
}

func (o *OfflineLLMProvider) Query(prompt string) (string, error) {
	return queryOfflineLLM(prompt), nil
}

func queryOfflineLLM(prompt string) string {
	promptLower := strings.ToLower(prompt)
	
	switch {
	case strings.Contains(promptLower, "usb") && strings.Contains(promptLower, "not recognized"):
		return `{
  "issue": "USB Device Not Recognized",
  "severity": "High",
  "solution": "USB device recognition failure",
  "commands": [
    {
      "description": "Install USB drivers",
      "cmd": "sudo apt update && sudo apt install linux-generic",
      "run_as_root": true
    },
    {
      "description": "Check USB info",
      "cmd": "lsusb",
      "run_as_root": false
    }
  ],
  "confidence": 0.85
}`

	case strings.Contains(promptLower, "disk") && (strings.Contains(promptLower, "error") || strings.Contains(promptLower, "fail")):
		return `{
  "issue": "Disk Error",
  "severity": "Critical",
  "solution": "Disk failure detected",
  "commands": [
    {
      "description": "Check disk health",
      "cmd": "sudo smartctl -a /dev/sdX",
      "run_as_root": true
    }
  ],
  "confidence": 0.9
}`

	case strings.Contains(promptLower, "network") || strings.Contains(promptLower, "wifi"):
		return `{
  "issue": "Network Issues",
  "severity": "Medium",
  "solution": "Network connectivity problems",
  "commands": [
    {
      "description": "Install network drivers",
      "cmd": "sudo apt install --reinstall network-manager",
      "run_as_root": true
    }
  ],
  "confidence": 0.75
}`

	case strings.Contains(promptLower, "audio") || strings.Contains(promptLower, "sound"):
		return `{
  "issue": "Audio Issues",
  "severity": "Medium",
  "solution": "Audio output problems",
  "commands": [
    {
      "description": "Install audio drivers",
      "cmd": "sudo apt install alsa-base pulseaudio",
      "run_as_root": true
    }
  ],
  "confidence": 0.7
}`

	case strings.Contains(promptLower, "graphics") || strings.Contains(promptLower, "gpu"):
		return `{
  "issue": "GPU Issues",
  "severity": "High",
  "solution": "Graphics problems",
  "commands": [
    {
      "description": "Install GPU drivers",
      "cmd": "sudo ubuntu-drivers autoinstall",
      "run_as_root": true
    }
  ],
  "confidence": 0.8
}`

	default:
		return `{
  "issue": "General Hardware Issue",
  "severity": "Medium",
  "solution": "Unspecified hardware problem",
  "commands": [
    {
      "description": "System update",
      "cmd": "sudo apt update && sudo apt upgrade -y",
      "run_as_root": true
    }
  ],
  "confidence": 0.6
}`
	}
}

func DiagnoseDevice(device monitor.Device, logs []monitor.LogEntry, provider LLMProvider) (*DiagnosticResult, error) {
	prompt := fmt.Sprintf(`# Hardware Diagnostic Request

## Device Information:
- Name: %s
- Type: %s
- Status: %s
- ID: %s
- Path: %s
- Vendor ID: %s
- Product ID: %s

## Recent System Events:`, 
		device.Name, device.Type, device.Status, device.ID, device.Path, 
		device.VendorID, device.ProductID)

	logCount := 0
	for i := len(logs) - 1; i >= 0; i-- {
		log := logs[i]
		if logCount >= 10 {
			break
		}
		if strings.Contains(strings.ToLower(log.Message), strings.ToLower(device.Name)) ||
		   strings.Contains(strings.ToLower(log.Message), strings.ToLower(device.Type)) ||
		   strings.Contains(strings.ToLower(log.Message), strings.ToLower(device.ID)) {
			prompt += fmt.Sprintf("\n- [%s] %s: %s", log.Level, log.Source, log.Message)
			logCount++
		}
	}

	if logCount == 0 {
		prompt += "\n- No recent related log entries"
	}

	prompt += `

## Required Analysis:
1. Identify hardware/driver issues
2. Assess severity
3. Provide troubleshooting steps
4. List commands for diagnosis/fixes
5. Include driver installation if needed
6. Confidence percentage

## Response Format:
{
  "issue": "Problem description",
  "severity": "Critical|High|Medium|Low",
  "solution": "Solution steps",
  "commands": [
    {
      "description": "Command purpose",
      "cmd": "actual-command",
      "run_as_root": true|false
    }
  ],
  "confidence": 0.85
}`

	response, err := provider.Query(prompt)
	if err != nil {
		return nil, fmt.Errorf("AI diagnosis failed: %w", err)
	}

	result, err := parseDiagnosticResponse(response)
	if err != nil {
		return fallbackDiagnosticResponse(response, device.Name), nil
	}
	
	result.Timestamp = time.Now()
	result.Device = device.Name
	return result, nil
}

func parseDiagnosticResponse(response string) (*DiagnosticResult, error) {
	startIdx := strings.Index(response, "{")
	endIdx := strings.LastIndex(response, "}")
	if startIdx == -1 || endIdx == -1 {
		return nil, fmt.Errorf("no JSON found")
	}

	jsonStr := response[startIdx : endIdx+1]
	
	var result DiagnosticResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("JSON parse failed: %w", err)
	}
	
	if result.Issue == "" || result.Solution == "" {
		return nil, fmt.Errorf("invalid response format")
	}
	
	return &result, nil
}

func fallbackDiagnosticResponse(response, deviceName string) *DiagnosticResult {
	severity := "Medium"
	confidence := 0.7
	commands := extractCommands(response)
	
	if strings.Contains(response, "Critical") {
		severity = "Critical"
		confidence = 0.9
	} else if strings.Contains(response, "High") {
		severity = "High"
		confidence = 0.8
	} else if strings.Contains(response, "Low") {
		severity = "Low"
		confidence = 0.6
	}
	
	issue := fmt.Sprintf("%s Issue", deviceName)
	if lines := strings.Split(response, "\n"); len(lines) > 0 {
		issue = strings.TrimSpace(lines[0])
	}

	return &DiagnosticResult{
		Issue:      issue,
		Severity:   severity,
		Solution:   response,
		Commands:   commands,
		Confidence: confidence,
		Timestamp:  time.Now(),
		Device:     deviceName,
	}
}

func extractCommands(response string) []Command {
	var commands []Command
	lines := strings.Split(response, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "sudo ") || 
		   strings.HasPrefix(line, "systemctl ") ||
		   strings.HasPrefix(line, "dmesg ") ||
		   strings.HasPrefix(line, "lspci ") ||
		   strings.HasPrefix(line, "lsusb ") ||
		   strings.HasPrefix(line, "ip ") ||
		   strings.HasPrefix(line, "iwlist ") ||
		   strings.HasPrefix(line, "journalctl ") ||
		   strings.Contains(strings.ToLower(line), "install") {
			runAsRoot := strings.HasPrefix(line, "sudo ")
			cmdStr := strings.TrimPrefix(line, "sudo ")
			desc := "System command"
			if strings.Contains(strings.ToLower(line), "install") {
				desc = "Driver installation"
			}
			commands = append(commands, Command{
				Description: desc,
				Cmd:         cmdStr,
				RunAsRoot:   runAsRoot,
			})
		}
	}
	
	return commands
}

func extractURL(text string) string {
	start := strings.Index(text, "http://")
	if start == -1 {
		start = strings.Index(text, "https://")
	}
	if start == -1 {
		return ""
	}
	
	end := strings.IndexAny(text[start:], " \n\t")
	if end == -1 {
		return text[start:]
	}
	return text[start:start+end]
}

func ExecuteSolution(commands []Command) (string, error) {
	var output strings.Builder
	driverManager := getDriverManager()

	for _, cmd := range commands {
		output.WriteString(fmt.Sprintf("Running: %s\n", cmd.Description))
		
		if strings.Contains(strings.ToLower(cmd.Description), "download") {
			url := extractURL(cmd.Cmd)
			if url == "" {
				url = extractURL(cmd.Description)
			}
			
			if url != "" {
				result, err := driverManager.DownloadAndInstall(url)
				output.WriteString(result + "\n")
				if err != nil {
					output.WriteString(fmt.Sprintf("Error: %v\n", err))
					return output.String(), fmt.Errorf("driver download failed: %s", cmd.Cmd)
				}
				continue
			}
		}
		
		if strings.Contains(strings.ToLower(cmd.Description), "driver") {
			result, err := driverManager.InstallDriver(cmd.Cmd)
			output.WriteString(result + "\n")
			if err != nil {
				output.WriteString(fmt.Sprintf("Error: %v\n", err))
				return output.String(), fmt.Errorf("driver installation failed: %s", cmd.Cmd)
			}
			continue
		}
		
		var execCmd *exec.Cmd
		if cmd.RunAsRoot {
			execCmd = exec.Command("sudo", "sh", "-c", cmd.Cmd)
		} else {
			execCmd = exec.Command("sh", "-c", cmd.Cmd)
		}
		
		cmdOutput, err := execCmd.CombinedOutput()
		output.WriteString(string(cmdOutput))
		output.WriteString("\n")
		
		if err != nil {
			output.WriteString(fmt.Sprintf("Error: %v\n", err))
			return output.String(), fmt.Errorf("command failed: %s", cmd.Cmd)
		}
	}
	
	return output.String(), nil
}

// Helper function to run interactive commands
func runInteractiveCommand(cmd *exec.Cmd) error {
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func ExecuteSolutionWithUpdates(commands []Command, updateChan chan<- string) error {
	defer close(updateChan)
	driverManager := getDriverManager()

	for _, cmd := range commands {
		updateChan <- fmt.Sprintf("Running: %s", cmd.Description)
		
		if strings.Contains(strings.ToLower(cmd.Description), "download") {
			url := extractURL(cmd.Cmd)
			if url == "" {
				url = extractURL(cmd.Description)
			}
			
			if url != "" {
				result, err := driverManager.DownloadAndInstall(url)
				updateChan <- result
				if err != nil {
					updateChan <- fmt.Sprintf("Error: %v", err)
					return fmt.Errorf("driver download failed: %s", cmd.Cmd)
				}
				continue
			}
		}
		
		if strings.Contains(strings.ToLower(cmd.Description), "driver") {
			result, err := driverManager.InstallDriver(cmd.Cmd)
			updateChan <- result
			if err != nil {
				updateChan <- fmt.Sprintf("Error: %v", err)
				return fmt.Errorf("driver installation failed: %s", cmd.Cmd)
			}
			continue
		}
		
		var execCmd *exec.Cmd
		if cmd.RunAsRoot {
			execCmd = exec.Command("sudo", "sh", "-c", cmd.Cmd)
		} else {
			execCmd = exec.Command("sh", "-c", cmd.Cmd)
		}
		
		// Handle sudo commands differently
		if cmd.RunAsRoot {
			updateChan <- "Switching to terminal for sudo authentication..."
			err := runInteractiveCommand(execCmd)
			if err != nil {
				updateChan <- fmt.Sprintf("Error: %v", err)
				return fmt.Errorf("command failed: %s", cmd.Cmd)
			}
			updateChan <- "Command completed successfully"
		} else {
			stdout, err := execCmd.StdoutPipe()
			if err != nil {
				updateChan <- fmt.Sprintf("Error: %v", err)
				return fmt.Errorf("command setup failed: %s", cmd.Cmd)
			}
			
			stderr, err := execCmd.StderrPipe()
			if err != nil {
				updateChan <- fmt.Sprintf("Error: %v", err)
				return fmt.Errorf("command setup failed: %s", cmd.Cmd)
			}
			
			if err := execCmd.Start(); err != nil {
				updateChan <- fmt.Sprintf("Error: %v", err)
				return fmt.Errorf("command start failed: %s", cmd.Cmd)
			}
			
			multiReader := io.MultiReader(stdout, stderr)
			scanner := bufio.NewScanner(multiReader)
			
			for scanner.Scan() {
				updateChan <- scanner.Text()
			}
			
			if err := execCmd.Wait(); err != nil {
				updateChan <- fmt.Sprintf("Error: %v", err)
				return fmt.Errorf("command failed: %s", cmd.Cmd)
			}
		}
	}
	
	return nil
}

func AnalyzeLogs(logs []monitor.LogEntry, provider LLMProvider) (*DiagnosticResult, error) {
	if len(logs) == 0 {
		return &DiagnosticResult{
			Issue:      "No Logs",
			Severity:   "Low",
			Solution:   "No hardware logs found",
			Confidence: 0.5,
			Timestamp:  time.Now(),
		}, nil
	}

	prompt := "Analyze hardware logs:\n\n"
	
	logCount := 0
	for i := len(logs) - 1; i >= 0 && logCount < 10; i-- {
		log := logs[i]
		prompt += fmt.Sprintf("[%s] %s: %s\n", log.Level, log.Source, log.Message)
		logCount++
	}

	prompt += `Provide:
1. Hardware/driver issues
2. Severity
3. Recommended actions
4. Driver installation if needed`

	response, err := provider.Query(prompt)
	if err != nil {
		return nil, fmt.Errorf("log analysis failed: %w", err)
	}

	result := &DiagnosticResult{
		Issue:      "Log Analysis",
		Severity:   "Medium",
		Solution:   response,
		Commands:   extractCommands(response),
		Confidence: 0.7,
		Timestamp:  time.Now(),
	}

	return result, nil
}

func GenerateCommunicationSolution(deviceA, deviceB monitor.Device, logs []monitor.LogEntry, provider LLMProvider) (*DiagnosticResult, error) {
	prompt := fmt.Sprintf(`# Device Communication Request

## Devices:
1. %s (%s) - %s
2. %s (%s) - %s

## Environment:
- OS: %s
- Kernel: %s

## Recent Errors:`,
		deviceA.Name, deviceA.Type, deviceA.ID,
		deviceB.Name, deviceB.Type, deviceB.ID,
		runtime.GOOS, getKernelVersion())
	
	logCount := 0
	for i := len(logs) - 1; i >= 0; i-- {
		if logCount >= 10 {
			break
		}
		if strings.Contains(strings.ToLower(logs[i].Message), strings.ToLower(deviceA.Name)) ||
		   strings.Contains(strings.ToLower(logs[i].Message), strings.ToLower(deviceB.Name)) ||
		   strings.Contains(strings.ToLower(logs[i].Message), "communication") ||
		   strings.Contains(strings.ToLower(logs[i].Message), "connect") {
			prompt += fmt.Sprintf("\n- [%s] %s: %s", logs[i].Level, logs[i].Source, logs[i].Message)
			logCount++
		}
	}

	prompt += `
Required:
1. Step-by-step solution
2. Terminal commands
3. Root commands marked
4. Driver installation if needed
5. Confidence percentage`

	response, err := provider.Query(prompt)
	if err != nil {
		return nil, fmt.Errorf("communication solution failed: %w", err)
	}

	result, err := parseDiagnosticResponse(response)
	if err != nil {
		return fallbackDiagnosticResponse(response, "Device Communication"), nil
	}
	
	result.Timestamp = time.Now()
	result.Device = fmt.Sprintf("%s and %s", deviceA.Name, deviceB.Name)
	return result, nil
}

func getKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	output, _ := cmd.Output()
	return strings.TrimSpace(string(output))
}
