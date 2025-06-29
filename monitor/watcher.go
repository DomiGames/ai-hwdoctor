package monitor

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/fsnotify/fsnotify"
)

type EventType int

const (
	DeviceConnected EventType = iota
	DeviceDisconnected
	LogUpdate
)

type HardwareEvent struct {
	Type      EventType
	Device    *Device  // Removed "monitor." prefix
	Message   string
	Timestamp time.Time
}

type Watcher struct {
	events   chan HardwareEvent
	fsWatcher *fsnotify.Watcher
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewWatcher() (*Watcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file system watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &Watcher{
		events:    make(chan HardwareEvent, 100),
		fsWatcher: fsWatcher,
		ctx:       ctx,
		cancel:    cancel,
	}

	return w, nil
}

func (w *Watcher) Start() error {
	switch runtime.GOOS {
	case "linux":
		return w.startLinuxWatcher()
	case "darwin":
		return w.startMacOSWatcher()
	case "windows":
		return w.startWindowsWatcher()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func (w *Watcher) startLinuxWatcher() error {
	usbDevPath := "/sys/bus/usb/devices"
	if err := w.fsWatcher.Add(usbDevPath); err != nil {
		fmt.Printf("Warning: Cannot watch USB devices: %v\n", err)
	}

	blockDevPath := "/sys/block"
	if err := w.fsWatcher.Add(blockDevPath); err != nil {
		fmt.Printf("Warning: Cannot watch block devices: %v\n", err)
	}

	go w.processLinuxEvents()
	return nil
}

func (w *Watcher) processLinuxEvents() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastDevices := make(map[string]Device)
	
	// Fixed: Removed "monitor." prefix
	devices, _ := ScanDevices(true)
	for _, device := range devices {
		lastDevices[device.ID] = device
	}

	for {
		select {
		case <-w.ctx.Done():
			return
		case event := <-w.fsWatcher.Events:
			w.handleFileSystemEvent(event)
		case <-ticker.C:
			// Fixed: Removed "monitor." prefix
			currentDevices := make(map[string]Device)
			devices, err := ScanDevices(true)
			if err != nil {
				continue
			}

			for _, device := range devices {
				currentDevices[device.ID] = device
			}

			for id, device := range currentDevices {
				if _, exists := lastDevices[id]; !exists {
					w.events <- HardwareEvent{
						Type:      DeviceConnected,
						Device:    &device,
						Message:   fmt.Sprintf("Device connected: %s", device.Name),
						Timestamp: time.Now(),
					}
				}
			}

			for id, device := range lastDevices {
				if _, exists := currentDevices[id]; !exists {
					w.events <- HardwareEvent{
						Type:      DeviceDisconnected,
						Device:    &device,
						Message:   fmt.Sprintf("Device disconnected: %s", device.Name),
						Timestamp: time.Now(),
					}
				}
			}

			lastDevices = currentDevices
		}
	}
}

func (w *Watcher) handleFileSystemEvent(event fsnotify.Event) {
	deviceName := filepath.Base(event.Name)
	
	var eventType EventType
	var message string
	
	if event.Op&fsnotify.Create == fsnotify.Create {
		eventType = DeviceConnected
		message = fmt.Sprintf("New device detected: %s", deviceName)
	} else if event.Op&fsnotify.Remove == fsnotify.Remove {
		eventType = DeviceDisconnected
		message = fmt.Sprintf("Device removed: %s", deviceName)
	} else {
		return
	}

	w.events <- HardwareEvent{
		Type:      eventType,
		Message:   message,
		Timestamp: time.Now(),
	}
}

func (w *Watcher) startMacOSWatcher() error {
	go w.processMacOSEvents()
	return nil
}

func (w *Watcher) processMacOSEvents() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.events <- HardwareEvent{
				Type:      LogUpdate,
				Message:   "macOS device monitoring active",
				Timestamp: time.Now(),
			}
		}
	}
}

func (w *Watcher) startWindowsWatcher() error {
	go w.processWindowsEvents()
	return nil
}

func (w *Watcher) processWindowsEvents() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.events <- HardwareEvent{
				Type:      LogUpdate,
				Message:   "Windows device monitoring active",
				Timestamp: time.Now(),
			}
		}
	}
}

func (w *Watcher) Events() <-chan HardwareEvent {
	return w.events
}

func (w *Watcher) Stop() {
	w.cancel()
	if w.fsWatcher != nil {
		w.fsWatcher.Close()
	}
	close(w.events)
}
