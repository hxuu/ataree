package detector

import (
	"fmt"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

var pkgManagerComms = map[string]bool{
	"apt": true, "apt-get": true, "dpkg": true, "rpm": true,
	"yum": true, "dnf": true, "zypper": true, "pacman": true,
}

var downgradeFlags = []string{
	"--allow-downgrades",
	"--oldpackage",
	"downgrade",
	"--force-old-files",
}

type PkgDowngrade struct{}

func NewPkgDowngrade() *PkgDowngrade { return &PkgDowngrade{} }
func (PkgDowngrade) Name() string    { return "pkg-downgrade" }

func (PkgDowngrade) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	if ev.EventType != ebpf.EventExecveCmd {
		return nil, nil
	}
	if !pkgManagerComms[baseName(cstr(ev.Filename[:]))] {
		return nil, nil
	}

	argv1 := strings.ToLower(argv1String(ev))
	for _, flag := range downgradeFlags {
		f := strings.ToLower(flag)
		if strings.HasPrefix(argv1, f) || strings.HasPrefix(f, argv1) {
			return &Alert{
				Detector: "pkg-downgrade",
				Event:    ev,
				Message:  fmt.Sprintf("downgrade flag %q via %s (pid=%d)", argv1String(ev), baseName(cstr(ev.Filename[:])), ev.PID),
			}, nil
		}
	}
	return nil, nil
}
