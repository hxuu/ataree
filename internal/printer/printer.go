package printer

import (
	"bytes"
	"fmt"

	"github.com/hxuu/ataree/internal/detector"
	"github.com/hxuu/ataree/internal/ebpf"
)

type Printer interface {
	Print(event ebpf.RawEvent)
	PrintAlert(alert detector.Alert)
}

type Stdout struct{}

func (Stdout) Print(event ebpf.RawEvent) {
	fmt.Printf("pid=%d comm=%s filename=%s event=%d arg1=%#x arg2=%#x\n",
		event.PID,
		cString(event.Comm[:]),
		cString(event.Filename[:]),
		event.EventType,
		event.Arg1,
		event.Arg2,
	)
}

func (Stdout) PrintAlert(a detector.Alert) {
	fmt.Printf("[ALERT] detector=%s pid=%d event=%d msg=%s\n",
		a.Detector,
		a.Event.PID,
		a.Event.EventType,
		a.Message,
	)
}

func cString(buf []byte) string {
	before, _, ok := bytes.Cut(buf, []byte{0})
	if !ok {
		return string(buf)
	}
	return string(before)
}
