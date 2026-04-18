package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

type SudoersAbuse struct{}

func NewSudoersAbuse() *SudoersAbuse { return &SudoersAbuse{} }

func (SudoersAbuse) Name() string { return "sudoers-abuse" }

func (SudoersAbuse) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType != ebpf.EventCronFileMod {
		return nil, nil
	}

	filename := cString(ev.Filename[:])
	comm := cString(ev.Comm[:])
	flags := ev.Arg1

	if !strings.HasPrefix(filename, "/etc/sudoers") {
		return nil, nil
	}

	switch comm {
	case "sudo", "visudo", "dpkg", "dpkg-preconfigu":
		return nil, nil
	}

	// Detect real write intent
	const (
		O_WRONLY = 1
		O_RDWR   = 2
		O_CREAT  = 64
		O_TRUNC  = 512
	)

	write := flags&O_WRONLY != 0 ||
		flags&O_RDWR != 0 ||
		flags&O_CREAT != 0 ||
		flags&O_TRUNC != 0

	// ONLY alert if actual write intent
	if !write {
		return nil, nil
	}

	// Only suspicious processes
	switch comm {
	case "sh", "bash", "nano", "vim", "tee":
		return &Alert{
			Detector: "sudoers-abuse",
			Event:    ev,
			Message: fmt.Sprintf(
				"process %q modified sudoers configuration %q (MITRE ATT&CK T1548.003)",
				comm, filename,
			),
		}, nil
	}

	return nil, nil
}
