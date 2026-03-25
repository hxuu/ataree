package detector

import (
	"time"

	"github.com/hxuu/ataree/internal/ebpf"
)

// PtraceMprotect flags a process that does ptrace write/setregs followed by mprotect(PROT_EXEC) shortly after.
type PtraceMprotect struct {
	lastPtrace map[uint32]int64 // pid -> timestamp (ns)
}

func NewPtraceMprotect() *PtraceMprotect {
	return &PtraceMprotect{lastPtrace: make(map[uint32]int64)}
}

func (d *PtraceMprotect) Name() string { return "ptrace->mprotect" }

func (d *PtraceMprotect) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	switch ev.EventType {
	case ebpf.EventPtraceWrite, ebpf.EventPtraceSetregs:
		d.lastPtrace[ev.PID] = int64(ev.TimestampNS)
	case ebpf.EventMprotectExec:
		if ts, ok := d.lastPtrace[ev.PID]; ok && int64(ev.TimestampNS)-ts < int64(5*time.Second) {
			return &Alert{
				Detector: d.Name(),
				Event:    ev,
				Message:  "ptrace activity followed by mprotect(PROT_EXEC)",
			}, nil
		}
	}
	return nil, nil
}
