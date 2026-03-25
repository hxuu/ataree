package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

var sensitiveConfigPaths = map[string]bool{
	"/etc/hosts": true, "/etc/resolv.conf": true,
}

var logSinkPorts = []string{
	"514", "6514", "5044", "9200", "8200", "5601",
}

type IndicatorBlocking struct{}

func NewIndicatorBlocking() *IndicatorBlocking { return &IndicatorBlocking{} }
func (IndicatorBlocking) Name() string         { return "indicator-blocking" }

func (IndicatorBlocking) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	switch ev.EventType {

	case ebpf.EventSensitiveWrite:
		if !sensitiveConfigPaths[ev.FilenameString()] || ev.Arg1&0x3 == 0 {
			return nil, nil
		}
		return &Alert{Detector: "indicator-blocking", Event: ev,
			Message: fmt.Sprintf("sensitive config write-opened: %q by %q (pid=%d)", ev.FilenameString(), ev.CommString(), ev.PID)}, nil

	case ebpf.EventExecveCmd:
		base := baseName(ev.FilenameString())
		if base != "iptables" && base != "ip6tables" && base != "nft" && base != "iptables-legacy" {
			return nil, nil
		}
		args := cmdlineArgs(ev.PID)
		if !containsAny(args, []string{"DROP", "REJECT", "drop", "reject"}) {
			return nil, nil
		}
		for _, port := range logSinkPorts {
			if strings.Contains(args, port) {
				return &Alert{Detector: "indicator-blocking", Event: ev,
					Message: fmt.Sprintf("firewall blocking log-sink port %s (pid=%d)", port, ev.PID)}, nil
			}
		}
	}
	return nil, nil
}
