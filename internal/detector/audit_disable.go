package detector

import (
	"fmt"

	"github.com/hxuu/ataree/internal/ebpf"
)

type AuditDisable struct{}

func NewAuditDisable() *AuditDisable { return &AuditDisable{} }
func (AuditDisable) Name() string    { return "audit-disable" }

func (AuditDisable) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType != ebpf.EventExecveCmd {
		return nil, nil
	}
	if baseName(cstr(ev.Filename[:])) != "auditctl" {
		return nil, nil
	}
	argv1 := argv1String(ev)
	if argv1 == "-D" {
		return &Alert{
			Detector: "audit-disable",
			Event:    ev,
			Message:  fmt.Sprintf("auditctl %q (pid=%d)", argv1, ev.PID),
		}, nil
	}

	if argv1 != "-e" {
		return nil, nil
	}

	if argv2String(ev) == "0" {
		return &Alert{
			Detector: "audit-disable",
			Event:    ev,
			Message:  fmt.Sprintf("auditctl -e 0 (pid=%d)", ev.PID),
		}, nil
	}

	return nil, nil
}
