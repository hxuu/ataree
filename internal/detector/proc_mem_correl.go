package detector

import "github.com/hxuu/ataree/internal/ebpf"

// ProcMemCorrel correlates /proc/<pid>/maps then /proc/<pid>/mem from same actor within a window.
type ProcMemCorrel struct {
	lastMaps map[uint32]uint64 // actor PID -> timestamp ns of maps open
}

func NewProcMemCorrel() *ProcMemCorrel {
	return &ProcMemCorrel{lastMaps: make(map[uint32]uint64)}
}

func (d *ProcMemCorrel) Name() string { return "proc-maps-mem" }

func (d *ProcMemCorrel) OnEvent(ev ebpf.RawEvent) (*Alert, error) {
	const windowNS = uint64(5 * 1e9) // 5s

	switch ev.EventType {
	case ebpf.EventProcMapsOpen:
		d.lastMaps[ev.PID] = ev.TimestampNS
	case ebpf.EventProcMemOpen:
		if ts, ok := d.lastMaps[ev.PID]; ok && ev.TimestampNS >= ts && ev.TimestampNS-ts <= windowNS {
			return &Alert{
				Detector: d.Name(),
				Event:    ev,
				Message:  "actor read maps then opened /proc/<pid>/mem",
			}, nil
		}
	}
	return nil, nil
}
