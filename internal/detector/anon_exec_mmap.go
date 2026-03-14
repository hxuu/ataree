package detector

import "github.com/hxuu/ataree/internal/ebpf"

// AnonExecMmap flags creation of anonymous executable memory.
type AnonExecMmap struct{}

func NewAnonExecMmap() *AnonExecMmap { return &AnonExecMmap{} }

func (AnonExecMmap) Name() string { return "anon-exec-mmap" }

func (AnonExecMmap) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType == ebpf.EventAnonExecMmap {
		return &Alert{Detector: "anon-exec-mmap", Event: ev, Message: "anonymous executable mapping"}, nil
	}
	return nil, nil
}
