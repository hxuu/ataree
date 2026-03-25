package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

var legitimateSyslogWriters = map[string]bool{
	"rsyslogd": true,
	"syslogd":  true,
	"journald": true,
	"auditd":   true,
	"systemd":  true,
	"logger":   true,
}

type SyslogSpoof struct{}

func NewSyslogSpoof() *SyslogSpoof { return &SyslogSpoof{} }
func (SyslogSpoof) Name() string   { return "syslog-spoof" }

func (SyslogSpoof) OnEvent(e ebpf.RawEvent) (*Alert, error) {
	if e.EventType != ebpf.EventSensitiveWrite {
		return nil, nil
	}
	path := cstr(e.Filename[:])
	if !strings.HasPrefix(path, "/dev/log") {
		return nil, nil
	}
	comm := strings.ToLower(cstr(e.Comm[:]))
	if legitimateSyslogWriters[comm] {
		return nil, nil
	}
	return &Alert{
		Detector: "syslog-spoof",
		Event:    e,
		Message:  fmt.Sprintf("unexpected process writing to /dev/log: comm=%s pid=%d", comm, e.PID),
	}, nil
}
