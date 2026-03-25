package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

var historyPathSuffixes = []string{
	"_history",
	".bash_logout",
	"HISTFILE",
}

type HistoryTamper struct{}

func NewHistoryTamper() *HistoryTamper { return &HistoryTamper{} }
func (HistoryTamper) Name() string     { return "history-tamper" }

func (HistoryTamper) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	switch ev.EventType {

	case ebpf.EventUnlinkPath:
		path := cstr(ev.Filename[:])
		for _, suf := range historyPathSuffixes {
			if strings.HasSuffix(path, suf) || strings.Contains(path, suf) {
				return &Alert{Detector: "history-tamper", Event: ev,
					Message: fmt.Sprintf("history file deleted: %s (pid=%d)", path, ev.PID)}, nil
			}
		}

	case ebpf.EventSensitiveWrite:
		if ev.Arg1&0x200 == 0 {
			return nil, nil
		}
		path := cstr(ev.Filename[:])
		for _, suf := range historyPathSuffixes {
			if strings.HasSuffix(path, suf) || strings.Contains(path, suf) {
				return &Alert{Detector: "history-tamper", Event: ev,
					Message: fmt.Sprintf("history file truncated via O_TRUNC: %s (pid=%d)", path, ev.PID)}, nil
			}
		}

	case ebpf.EventExecveCmd:
		if baseName(cstr(ev.Filename[:])) != "truncate" {
			return nil, nil
		}
		args := cmdlineArgs(ev.PID)
		for _, suf := range historyPathSuffixes {
			if strings.Contains(args, suf) {
				return &Alert{Detector: "history-tamper", Event: ev,
					Message: fmt.Sprintf("truncate(1) on history file (pid=%d): %s", ev.PID, strings.TrimSpace(args))}, nil
			}
		}
	}
	return nil, nil
}
