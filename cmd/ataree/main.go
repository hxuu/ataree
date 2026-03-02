package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hxuu/ataree/bpf"
	"github.com/cilium/ebpf/link" // <--- Add this
)

func main() {
	fmt.Println("runtimed starting...")

	// 1. Load the eBPF objects
	var objs bpf.MinimaltraceObjects
	if err := bpf.LoadMinimaltraceObjects(&objs, nil); err != nil {
		fmt.Printf("error loading eBPF objects: %v\n", err)
		return
	}
	defer objs.Close()

	// 2. ATTACH the program to the Tracepoint (The missing piece!)
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.DetectExecve, nil)
	if err != nil {
		fmt.Printf("error attaching tracepoint: %v\n", err)
		return
	}
	defer tp.Close()

	fmt.Println("eBPF objects loaded and ATTACHED successfully!")
	fmt.Println("Press Ctrl+C to exit and see logs in /sys/kernel/tracing/trace_pipe")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
