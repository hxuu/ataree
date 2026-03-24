package detector

import (
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

type CronPersistence struct{}

func NewCronPersistence() *CronPersistence {
	return &CronPersistence{}
}

func (CronPersistence) Name() string {
	return "cron-persistence"
}

func (CronPersistence) OnEvent(ev ebpf.RawEvent) (*Alert, error) {

	filename := cString(ev.Filename[:])
	comm := cString(ev.Comm[:])

	// cron paths
	if !(strings.HasPrefix(filename, "/etc/crontab") ||
		strings.HasPrefix(filename, "/etc/cron") ||
		strings.HasPrefix(filename, "/var/spool/cron")) {
		return nil, nil
	}

	// open flags
	flags := ev.Arg1

	const (
		O_WRONLY = 1
		O_RDWR   = 2
		O_CREAT  = 64
		O_TRUNC  = 512
	)

	writeOperation := flags&O_WRONLY != 0 ||
		flags&O_RDWR != 0 ||
		flags&O_CREAT != 0 ||
		flags&O_TRUNC != 0

	if !writeOperation {
		return nil, nil
	}

	// ignore legitimate schedulers
	if comm == "cron" || comm == "crond" || comm == "systemd" || comm == "anacron" {
		return nil, nil
	}

	return &Alert{
		Detector: "cron-persistence",
		Event:    ev,
		Message:  "process modified or created cron scheduled task",
	}, nil
}
