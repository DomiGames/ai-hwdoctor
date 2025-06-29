package communication

import (
	"ai-hwdoctor/monitor"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CommunicationManager struct{}

func NewCommunicationManager() *CommunicationManager {
	return &CommunicationManager{}
}

func (cm *CommunicationManager) EstablishCommunication(deviceA, deviceB monitor.Device) (string, error) {
	protocol := detectCommunicationProtocol(deviceA, deviceB)
	
	switch protocol {
	case "usb":
		return setupUSBCommunication(deviceA, deviceB)
	case "network":
		return setupNetworkCommunication(deviceA, deviceB)
	case "bluetooth":
		return setupBluetoothCommunication(deviceA, deviceB)
	case "serial":
		return setupSerialCommunication(deviceA, deviceB)
	default:
		return "", fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func detectCommunicationProtocol(deviceA, deviceB monitor.Device) string {
	switch {
	case deviceA.Type == "USB" && deviceB.Type == "USB":
		return "usb"
	case strings.Contains(strings.ToLower(deviceA.Description), "network") || 
	     strings.Contains(strings.ToLower(deviceB.Description), "network"):
		return "network"
	case strings.Contains(strings.ToLower(deviceA.Description), "bluetooth") || 
	     strings.Contains(strings.ToLower(deviceB.Description), "bluetooth"):
		return "bluetooth"
	case strings.Contains(strings.ToLower(deviceA.Description), "serial") || 
	     strings.Contains(strings.ToLower(deviceB.Description), "serial"):
		return "serial"
	default:
		return "usb"
	}
}

func setupUSBCommunication(deviceA, deviceB monitor.Device) (string, error) {
	if err := ensureDeviceAccess(deviceA); err != nil {
		return "", err
	}
	if err := ensureDeviceAccess(deviceB); err != nil {
		return "", err
	}

	bridgeCmd := fmt.Sprintf("sudo usbip bind -b %s && sudo usbip bind -b %s", 
		filepath.Base(deviceA.Path), filepath.Base(deviceB.Path))
	
	if _, err := runCommand("sh", "-c", bridgeCmd); err != nil {
		return "", fmt.Errorf("USB bridge failed: %w", err)
	}
	
	return fmt.Sprintf("USB bridge established between %s and %s", 
		deviceA.Name, deviceB.Name), nil
}

func setupNetworkCommunication(deviceA, deviceB monitor.Device) (string, error) {
	ifaceA := filepath.Base(deviceA.Path)
	ifaceB := filepath.Base(deviceB.Path)
	
	bridgeCmd := fmt.Sprintf("sudo ip link add name br0 type bridge && "+
		"sudo ip link set %s master br0 && "+
		"sudo ip link set %s master br0 && "+
		"sudo ip link set br0 up", ifaceA, ifaceB)
	
	if _, err := runCommand("sh", "-c", bridgeCmd); err != nil {
		return "", fmt.Errorf("network bridge failed: %w", err)
	}
	
	return fmt.Sprintf("Network bridge between %s and %s", 
		deviceA.Name, deviceB.Name), nil
}

func setupBluetoothCommunication(deviceA, deviceB monitor.Device) (string, error) {
	if _, err := runCommand("sudo", "systemctl", "start", "bluetooth"); err != nil {
		return "", fmt.Errorf("Bluetooth start failed: %w", err)
	}

	macA := extractBluetoothMAC(deviceA)
	macB := extractBluetoothMAC(deviceB)
	if macA == "" || macB == "" {
		return "", fmt.Errorf("MAC addresses missing")
	}

	pairCmd := fmt.Sprintf("echo -e 'pair %s\npair %s\nquit' | bluetoothctl", macA, macB)
	if _, err := runCommand("sh", "-c", pairCmd); err != nil {
		return "", fmt.Errorf("pairing failed: %w", err)
	}
	
	return fmt.Sprintf("Bluetooth pairing initiated between %s and %s", 
		deviceA.Name, deviceB.Name), nil
}

func setupSerialCommunication(deviceA, deviceB monitor.Device) (string, error) {
	portA := deviceA.Path
	portB := deviceB.Path
	
	sttyCmd := fmt.Sprintf("stty -F %s 9600 cs8 -cstopb -parenb && stty -F %s 9600 cs8 -cstopb -parenb", 
		portA, portB)
	if _, err := runCommand("sh", "-c", sttyCmd); err != nil {
		return "", fmt.Errorf("serial config failed: %w", err)
	}
	
	socatCmd := fmt.Sprintf("socat %s,raw,echo=0 %s,raw,echo=0", portA, portB)
	go runCommand("sh", "-c", socatCmd)
	
	return fmt.Sprintf("Serial communication between %s and %s", 
		deviceA.Name, deviceB.Name), nil
}

func ensureDeviceAccess(device monitor.Device) error {
	if device.VendorID != "" && device.ProductID != "" {
		rule := fmt.Sprintf(`SUBSYSTEM=="usb", ATTR{idVendor}=="%s", ATTR{idProduct}=="%s", MODE="0666"`, 
			device.VendorID, device.ProductID)
		
		ruleFile := fmt.Sprintf("/etc/udev/rules.d/99-%s-%s.rules", 
			filepath.Base(device.Path), device.VendorID)
		
		if err := os.WriteFile(ruleFile, []byte(rule), 0644); err != nil {
			return err
		}
		
		if _, err := runCommand("sudo", "udevadm", "control", "--reload-rules"); err != nil {
			return err
		}
		if _, err := runCommand("sudo", "udevadm", "trigger"); err != nil {
			return err
		}
	}
	return nil
}

func extractBluetoothMAC(device monitor.Device) string {
	parts := strings.Split(device.ID, ":")
	if len(parts) > 2 {
		return parts[0]
	}
	return ""
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
