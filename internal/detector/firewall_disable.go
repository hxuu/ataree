package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

var firewallComms = map[string]bool{
	"iptables": true, "ip6tables": true, "nft": true,
	"ufw": true, "firewall-cmd": true,
}

var firewallFlushArgs = []string{
	"-F", "--flush", "flush", "disable", "stop", "-X", "--delete-chain",
}

type FirewallDisable struct{}

func NewFirewallDisable() *FirewallDisable { return &FirewallDisable{} }
func (FirewallDisable) Name() string       { return "firewall-disable" }

func (FirewallDisable) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType != ebpf.EventExecveCmd {
		return nil, nil
	}
	if !firewallComms[baseName(cstr(ev.Filename[:]))] {
		return nil, nil
	}

	argv1 := argv1String(ev)
	for _, flag := range firewallFlushArgs {
		if strings.EqualFold(argv1, flag) {
			return &Alert{
				Detector: "firewall-disable",
				Event:    ev,
				Message:  fmt.Sprintf("firewall flush/disable: %s %s (pid=%d)", baseName(cstr(ev.Filename[:])), argv1, ev.PID),
			}, nil
		}
	}
	return nil, nil
}
