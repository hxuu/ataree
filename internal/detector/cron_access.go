package detector

import (
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

type CronAccess struct{}

func NewCronAccess() *CronAccess { return &CronAccess{} }

func (CronAccess) Name() string { return "cron-access" }
func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

func (CronAccess) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	name := cString(ev.Filename[:])

	if strings.HasPrefix(name, "/etc/cron") ||
		strings.HasPrefix(name, "/var/spool/cron") ||
		strings.HasPrefix(name, "/etc/cron.d/") ||
		strings.HasPrefix(name, "/etc/cron.daily/") ||
		strings.HasPrefix(name, "/etc/cron.hourly/") ||
		strings.HasPrefix(name, "/etc/cron.weekly/") ||
		strings.HasPrefix(name, "/etc/cron.monthly/") ||
		strings.HasSuffix(name, ".timer") {
		return &Alert{
			Detector: "cron-access",
			Event:    ev,
			Message:  "scheduled task accessed",
		}, nil
	}

	return nil, nil
}
