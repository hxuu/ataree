package detector

import "github.com/hxuu/ataree/internal/ebpf"

// PtraceSetregs flags register hijack attempts.
type PtraceSetregs struct{}

func NewPtraceSetregs() *PtraceSetregs { return &PtraceSetregs{} }

func (PtraceSetregs) Name() string { return "ptrace-setregs" }

func (PtraceSetregs) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType == ebpf.EventPtraceSetregs {
		return &Alert{Detector: "ptrace-setregs", Event: ev, Message: "ptrace SETREGS modifies target context"}, nil
	}
	return nil, nil
}
