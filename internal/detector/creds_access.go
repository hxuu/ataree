package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

type CredentialAccess struct{}

func NewCredentialAccess() *CredentialAccess { return &CredentialAccess{} }

func (CredentialAccess) Name() string { return "credential-access" }

func (CredentialAccess) OnEvent(ev ebpf.RawEvent) (*Alert, error) {

	if ev.EventType != ebpf.EventCronFileMod {
		return nil, nil
	}

	filename := cString(ev.Filename[:])
	comm := cString(ev.Comm[:])
	flags := ev.Arg1

	if !(strings.HasPrefix(filename, "/etc/shadow") ||
		strings.HasPrefix(filename, "/etc/passwd")) {
		return nil, nil
	}

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

	if !write {
		return nil, nil
	}

	switch comm {
	case "useradd", "usermod", "userdel",
		"passwd", "chpasswd", "newusers",
		"vipw", "pwconv", "pwunconv":
		return nil, nil
	}

	return &Alert{
		Detector: "credential-access",
		Event:    ev,
		Message: fmt.Sprintf(
			"process %q modified %q (possible account manipulation - T1003)",
			comm, filename,
		),
	}, nil
}