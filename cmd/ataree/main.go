package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/hxuu/ataree/bpf"
)

type event struct {
	Pid     uint32
	Command [128]byte
}

func main() {
	fmt.Println("runtimed starting...")

	var objs bpf.MinimaltraceObjects
	if err := bpf.LoadMinimaltraceObjects(&objs, nil); err != nil {
		fmt.Printf("error loading eBPF objects: %v\n", err)
		return
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.DetectExecve, nil)
	if err != nil {
		fmt.Printf("error attaching tracepoint: %v\n", err)
		return
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Printf("error creating ring buffer reader: %v\n", err)
		return
	}
	defer rd.Close()

	fmt.Println("eBPF objects loaded and attached successfully")
	fmt.Println("listening for execve events (Ctrl+C to stop)")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	go func() {
		<-stop
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("received signal, shutting down")
				return
			}
			fmt.Printf("error reading ring buffer: %v\n", err)
			continue
		}

		var evt event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			fmt.Printf("error parsing event: %v\n", err)
			continue
		}

		fmt.Printf("pid=%d command=%s\n", evt.Pid, cString(evt.Command[:]))
	}
}

func cString(buf []byte) string {
	idx := bytes.IndexByte(buf, 0)
	if idx == -1 {
		return string(buf)
	}
	return string(buf[:idx])
}
