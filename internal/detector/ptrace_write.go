package detector

import "github.com/hxuu/ataree/internal/ebpf"

// PtraceWrite alerts immediately on ptrace memory writes.
// Mirrors Tracee TRC-103 style: POKETEXT/POKEDATA is rare outside debugging.
type PtraceWrite struct{}

func NewPtraceWrite() *PtraceWrite { return &PtraceWrite{} }

func (PtraceWrite) Name() string { return "ptrace-write" }

func (PtraceWrite) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType == ebpf.EventPtraceWrite {
		return &Alert{Detector: "ptrace-write", Event: ev, Message: "ptrace write (POKETEXT/POKEDATA)"}, nil
	}
	return nil, nil
}
