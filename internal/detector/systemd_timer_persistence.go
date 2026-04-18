package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

// SystemdTimerPersistence detects likely creation, modification,
// or enabling of systemd timer units.
type SystemdTimerPersistence struct{}

func NewSystemdTimerPersistence() *SystemdTimerPersistence {
	return &SystemdTimerPersistence{}
}

func (SystemdTimerPersistence) Name() string {
	return "systemd-timer-persistence"
}

func isSystemdTimerPath(filename string) bool {
	if !strings.HasSuffix(filename, ".timer") {
		return false
	}

	return strings.HasPrefix(filename, "/etc/systemd/system/") ||
		strings.HasPrefix(filename, "/usr/lib/systemd/system/") ||
		strings.HasPrefix(filename, "/lib/systemd/system/") ||
		strings.Contains(filename, "/.config/systemd/user/")
}

func isTimerEnablePath(filename string) bool {
	return strings.Contains(filename, "timers.target.wants/")
}

func (SystemdTimerPersistence) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	// For now, timer-related file activity is still emitted from eBPF
	// as generic file modification events.
	if ev.EventType != ebpf.EventCronFileMod {
		return nil, nil
	}
	

	filename := cString(ev.Filename[:])
	comm := cString(ev.Comm[:])
	flags := ev.Arg1

	// Ignore obvious system noise
	if strings.HasPrefix(comm, "systemd") || comm == "systemctl" {
		return nil, nil
	}

	// Detect persistence activation via symlink creation in timers.target.wants
	if isTimerEnablePath(filename) {
		return &Alert{
			Detector: "systemd-timer-persistence",
			Event:    ev,
			Message: fmt.Sprintf(
				"process %q likely enabled a systemd timer via %q (MITRE ATT&CK T1053.006 - Scheduled Task/Job: Systemd Timers)",
				comm, filename,
			),
		}, nil
	}

	// Only handle actual timer unit files from here
	if !isSystemdTimerPath(filename) {
		return nil, nil
	}

	const (
		O_WRONLY = 1
		O_RDWR   = 2
		O_CREAT  = 64
		O_EXCL   = 128
		O_TRUNC  = 512
		O_APPEND = 1024
	)

	isWriteOpen := flags&O_WRONLY != 0 || flags&O_RDWR != 0
	isCreate := flags&O_CREAT != 0
	isExclusiveCreate := flags&O_EXCL != 0
	isTruncate := flags&O_TRUNC != 0
	isAppend := flags&O_APPEND != 0

	// Ignore pure read access
	if !(isWriteOpen || isCreate || isTruncate || isAppend) {
		return nil, nil
	}

	action := "modified"
	if isCreate || isExclusiveCreate {
		action = "created"
	} else if isTruncate {
		action = "overwrote"
	} else if isAppend {
		action = "appended to"
	}

	return &Alert{
		Detector: "systemd-timer-persistence",
		Event:    ev,
		Message: fmt.Sprintf(
			"process %q likely %s systemd timer unit %q",
			comm, action, filename,
		),
	}, nil
}