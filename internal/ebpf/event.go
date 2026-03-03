package ebpf

type Event struct {
	Pid     uint32
	Command [128]byte
}
