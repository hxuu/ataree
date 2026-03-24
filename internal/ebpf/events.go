package ebpf

// Mirror of events.h for Go side.
type EventType uint8

const (
    EventPtraceWrite    EventType = 1
    EventPtraceSetregs  EventType = 2
    EventProcMemOpen    EventType = 3
    EventProcMapsOpen   EventType = 4
    EventSoLoad         EventType = 5
    EventAnonExecMmap   EventType = 6
    EventMprotectExec   EventType = 7
    EventAtFileMod      EventType = 9
    EventCronFileMod    EventType = 8
)

// RawEvent is emitted from BPF ring buffer.
type RawEvent struct {
    TimestampNS uint64
    PID         uint32
    PPID        uint32
    TargetPID   uint32
    EventType   EventType
    _           [3]byte // padding to align
    Comm        [16]byte
    Filename    [128]byte
    Arg1        uint64
    Arg2        uint64
}

