package detector

import (
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

// SystemdTimerPersistence detects creation or modification of systemd timer units

type SystemdTimerPersistence struct{}

func NewSystemdTimerPersistence() *SystemdTimerPersistence {
	return &SystemdTimerPersistence{}
}

func (SystemdTimerPersistence) Name() string {
	return "systemd-timer-persistence"
}

func (SystemdTimerPersistence) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	// Only process file modification events
	if ev.EventType != ebpf.EventCronFileMod {
		return nil, nil
	}

	filename := cString(ev.Filename[:])
	comm := cString(ev.Comm[:])

	// Systemd timer unit locations
	// System-wide: /etc/systemd/system/*.timer, /usr/lib/systemd/system/*.timer
	// User-specific: ~/.config/systemd/user/*.timer
	if !(strings.HasSuffix(filename, ".timer") &&
		(strings.HasPrefix(filename, "/etc/systemd/system/") ||
			strings.HasPrefix(filename, "/usr/lib/systemd/system/") ||
			strings.HasPrefix(filename, "/lib/systemd/system/") ||
			strings.Contains(filename, "/.config/systemd/user/"))) {
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

	// Ignore legitimate systemd processes
	if comm == "systemd" || comm == "systemctl" {
		return nil, nil
	}

	return &Alert{
		Detector: "systemd-timer-persistence",
		Event:    ev,
		Message:  "process created or modified systemd timer unit",
	}, nil
}
