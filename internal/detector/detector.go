package detector

import "github.com/hxuu/ataree/internal/ebpf"

// Detector consumes RawEvents and may emit an Alert.
// Keep it minimal so new detectors are easy to write.
type Detector interface {
	Name() string
	OnEvent(ev ebpf.RawEvent) (*Alert, error)
}

// Alert represents a single finding from a detector.
type Alert struct {
	Detector string
	Event    ebpf.RawEvent
	Message  string
}
