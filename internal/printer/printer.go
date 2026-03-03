package printer

import (
	"bytes"
	"fmt"

	"github.com/hxuu/ataree/internal/ebpf"
)

type Printer interface {
	Print(event ebpf.Event)
}

type Stdout struct{}

func (Stdout) Print(event ebpf.Event) {
	fmt.Printf("pid=%d command=%s\n", event.Pid, cString(event.Command[:]))
}

func cString(buf []byte) string {
	idx := bytes.IndexByte(buf, 0)
	if idx == -1 {
		return string(buf)
	}
	return string(buf[:idx])
}
