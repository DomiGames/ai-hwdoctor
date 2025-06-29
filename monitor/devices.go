package monitor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Device struct {
	ID          string
	Name        string
	Type        string
	Status      string
	Path        string
	VendorID    string
	ProductID   string
	Description string
	LastSeen    time.Time
}

func (d Device) String() string {
	status := "✅"
	if d.Status != "connected" {
		status = "❌"
	}
	return fmt.Sprintf("%s %s (%s) - %s", status, d.Name, d.Type, d.Description)
}

func ScanDevices(showFull bool) ([]Device, error) {
	switch runtime.GOOS {
	case "linux":
		return scanLinuxDevices(showFull)
	case "darwin":
		return scanMacOSDevices()
	case "windows":
		return scanWindowsDevices()
	default:
		return []Device{}, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func scanLinuxDevices(showFull bool) ([]Device, error) {
	var devices []Device

	// Get USB devices via lsusb
	usbDevices, err := scanViaLSUSB()
	if err == nil {
		devices = append(devices, usbDevices...)
	}

	// Get PCI devices
	pciDevices, err := scanPCIDevices(showFull)
	if err == nil {
		devices = append(devices, pciDevices...)
	}

	// Get block devices
	blockDevices, err := scanBlockDevices()
	if err == nil {
		devices = append(devices, blockDevices...)
	}

	return devices, nil
}

func scanViaLSUSB() ([]Device, error) {
	cmd := exec.Command("lsusb")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("lsusb command failed: %w", err)
	}

	var devices []Device
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Parse lsusb output format:
		// Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		
		// Find the ID part
		var id string
		var nameParts []string
		for i, part := range parts {
			// Look for the "ID" marker
			if part == "ID" && i < len(parts)-1 {
				id = parts[i+1]
				nameParts = parts[i+2:]
				break
			}
		}
		
		if id == "" {
			continue
		}
		
		// Clean up ID (remove trailing colon if present)
		id = strings.TrimSuffix(id, ":")
		
		// Split into vendor and product
		idParts := strings.Split(id, ":")
		if len(idParts) != 2 {
			continue
		}
		
		vendor := idParts[0]
		product := idParts[1]
		name := strings.Join(nameParts, " ")
		
		devices = append(devices, Device{
			ID:          id,
			Name:        name,
			Type:        "USB",
			Status:      "connected",
			VendorID:    vendor,
			ProductID:   product,
			Description: name,
			LastSeen:    time.Now(),
		})
	}
	
	return devices, nil
}

func scanPCIDevices(showFull bool) ([]Device, error) {
	cmd := exec.Command("lspci")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("lspci command failed: %w", err)
	}

	var devices []Device
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Parse lspci output format:
		// 00:00.0 Host bridge: Advanced Micro Devices, Inc. [AMD] Device 14d8
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		
		slot := parts[0]
		description := parts[1]
		
		// Extract device class
		deviceClass := "Unknown"
		if strings.Contains(description, ":") {
			classParts := strings.SplitN(description, ":", 2)
			deviceClass = strings.TrimSpace(classParts[0])
			description = strings.TrimSpace(classParts[1])
		}
		
		// Filter out less relevant devices
		if !showFull && isSystemDevice(deviceClass) {
			continue
		}
		
		// Simplify description
		simplified := simplifyDescription(description)
		
		devices = append(devices, Device{
			ID:          slot,
			Name:        simplified,
			Type:        "PCI",
			Status:      "connected",
			Description: fmt.Sprintf("%s (%s)", simplified, deviceClass),
			LastSeen:    time.Now(),
		})
	}
	
	return devices, nil
}

// Check if a device is a system-level component
func isSystemDevice(class string) bool {
	systemClasses := []string{
		"Host bridge",
		"PCI bridge",
		"ISA bridge",
		"RAM memory",
		"Processor",
		"System peripheral",
		"Encryption controller",
		"Signal processing controller",
		"SMBus",
		"Host bridge",
		"IOMMU",
	}
	
	for _, sysClass := range systemClasses {
		if strings.Contains(class, sysClass) {
			return true
		}
	}
	return false
}

// Simplify complex device descriptions
func simplifyDescription(desc string) string {
	// Remove revision information
	if idx := strings.Index(desc, "(rev"); idx != -1 {
		desc = strings.TrimSpace(desc[:idx])
	}
	
	// Remove duplicate manufacturer names
	manufacturers := []string{
		"Advanced Micro Devices, Inc. [AMD]",
		"Intel Corporation",
		"NVIDIA Corporation",
		"Realtek Semiconductor Co., Ltd.",
		"Advanced Micro Devices, Inc. [AMD/ATI]",
	}
	
	for _, m := range manufacturers {
		desc = strings.Replace(desc, m, "", 1)
	}
	
	return strings.TrimSpace(desc)
}

func scanBlockDevices() ([]Device, error) {
	var devices []Device
	blockPath := "/sys/block"
	
	entries, err := os.ReadDir(blockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read block devices: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		name := entry.Name()
		devicePath := filepath.Join(blockPath, name)
		
		// Skip virtual devices
		if strings.HasPrefix(name, "loop") || 
		   strings.HasPrefix(name, "ram") ||
		   strings.HasPrefix(name, "zram") {
			continue
		}
		
		device := Device{
			ID:       name,
			Name:     fmt.Sprintf("/dev/%s", name),
			Type:     "Block",
			Status:   "connected",
			Path:     devicePath,
			LastSeen: time.Now(),
		}
		
		// Determine device type
		if isRemovable(devicePath) {
			device.Type = "Removable Storage"
		} else {
			device.Type = "Fixed Disk"
		}
		
		// Get model name
		model := readSysFile(devicePath, "device/model")
		if model == "" {
			model = readSysFile(devicePath, "device/vendor")
		}
		
		// Get size information
		size := ""
		if sizeBytes, err := os.ReadFile(filepath.Join(devicePath, "size")); err == nil {
			if sectors := strings.TrimSpace(string(sizeBytes)); sectors != "" {
				sectorCount, err := strconv.ParseInt(sectors, 10, 64)
				if err == nil {
					sizeGB := (sectorCount * 512) / (1024 * 1024 * 1024)
					if sizeGB > 0 {
						size = fmt.Sprintf("%dGB", sizeGB)
					}
				}
			}
		}
		
		if model != "" && size != "" {
			device.Description = fmt.Sprintf("%s %s", model, size)
		} else if model != "" {
			device.Description = model
		} else {
			device.Description = device.Type
		}
		
		devices = append(devices, device)
	}
	
	return devices, nil
}

func isRemovable(devicePath string) bool {
	removable := readSysFile(devicePath, "removable")
	return removable == "1"
}

func readSysFile(path, filename string) string {
	filePath := filepath.Join(path, filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

func scanMacOSDevices() ([]Device, error) {
	// Placeholder for macOS
	return []Device{}, nil
}

func scanWindowsDevices() ([]Device, error) {
	// Placeholder for Windows
	return []Device{}, nil
}
