package ebpf

type EventType uint8

const (
	EventPtraceWrite    EventType = 1
	EventPtraceSetregs  EventType = 2
	EventProcMemOpen    EventType = 3
	EventProcMapsOpen   EventType = 4
	EventSoLoad         EventType = 5
	EventAnonExecMmap   EventType = 6
	EventMprotectExec   EventType = 7
	EventKillSignal     EventType = 8
	EventUnlinkPath     EventType = 9
	EventExecveCmd      EventType = 10
	EventSensitiveWrite EventType = 11
)

type RawEvent struct {
	TimestampNS uint64
	PID         uint32
	PPID        uint32
	TargetPID   uint32
	EventType   EventType
	_           [3]byte
	Comm        [16]byte
	Filename    [128]byte
	Arg1        uint64
	Arg2        uint64
}

func (e RawEvent) FilenameString() string {
	for i, c := range e.Filename {
		if c == 0 {
			return string(e.Filename[:i])
		}
	}
	return string(e.Filename[:])
}

func (e RawEvent) CommString() string {
	for i, c := range e.Comm {
		if c == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}
