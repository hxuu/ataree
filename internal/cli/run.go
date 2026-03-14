package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hxuu/ataree/internal/ebpf"
	"github.com/hxuu/ataree/internal/detector"
	"github.com/hxuu/ataree/internal/pipeline"
	"github.com/hxuu/ataree/internal/printer"
)

func Run() error {
	fmt.Println("runtimed starting...")

	program, err := ebpf.LoadAndAttach()
	if err != nil {
		return fmt.Errorf("error loading eBPF objects: %w", err)
	}
	defer func() { _ = program.Close() }()

	fmt.Println("eBPF objects loaded and attached successfully")
	fmt.Println("listening for execve events (Ctrl+C to stop)")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	go func() {
		<-stop
		_ = program.Close()
	}()

	dets := []detector.Detector{
		detector.NewPtraceWrite(),
		detector.NewPtraceSetregs(),
		detector.NewPtraceMprotect(),
		detector.NewProcMemCorrel(),
		detector.NewAnonExecMmap(),
	}

	return pipeline.Run(program, printer.Stdout{}, dets)
}
