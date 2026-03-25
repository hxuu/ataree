package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

var securityToolComms = map[string]bool{
	"falco": true, "auditd": true, "osqueryd": true, "sshd": true,
	"clamd": true, "snort": true, "suricata": true, "wazuh-agent": true,
	"filebeat": true, "fluentd": true, "rsyslogd": true, "syslogd": true,
	"systemd": true,
}

type KillTool struct{}

func NewKillTool() *KillTool  { return &KillTool{} }
func (KillTool) Name() string { return "kill-tool" }

func (KillTool) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType != ebpf.EventKillSignal {
		return nil, nil
	}
	target := strings.ToLower(commFromPID(ev.TargetPID))
	if !securityToolComms[target] {
		return nil, nil
	}
	return &Alert{
		Detector: "kill-tool",
		Event:    ev,
		Message:  fmt.Sprintf("signal %d → %q (pid=%d) by %q (pid=%d)", ev.Arg1, target, ev.TargetPID, cstr(ev.Comm[:]), ev.PID),
	}, nil
}
