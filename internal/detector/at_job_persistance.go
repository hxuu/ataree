package detector

import (
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

type AtJobPersistence struct{}

func NewAtJobPersistence() *AtJobPersistence {
	return &AtJobPersistence{}
}

func (AtJobPersistence) Name() string {
	return "at-job-persistence"
}

func (AtJobPersistence) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	// Only process AT file modification events
	if ev.EventType != ebpf.EventAtFileMod {
		return nil, nil
	}

	filename := cString(ev.Filename[:])
	comm := cString(ev.Comm[:])

	// AT scheduler job locations
	if !(strings.HasPrefix(filename, "/var/spool/at/") ||
		strings.HasPrefix(filename, "/var/spool/cron/atjobs/") ||
		strings.HasPrefix(filename, "/var/spool/cron/atspool/")) {
		return nil, nil
	}

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

	// Only ignore the daemon, NOT the 'at' command!
	if comm == "atd" || comm == "atrun" || comm == "systemd" {
		return nil, nil
	}

	return &Alert{
		Detector: "at-job-persistence",
		Event:    ev,
		Message:  "process created or modified an AT scheduled job",
	}, nil
}
