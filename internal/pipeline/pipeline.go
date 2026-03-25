package pipeline

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/hxuu/ataree/internal/detector"
	"github.com/hxuu/ataree/internal/ebpf"
	"github.com/hxuu/ataree/internal/printer"
)

func Run(program *ebpf.Program, out printer.Printer, dets []detector.Detector) error {
	if program == nil || program.Reader == nil {
		return fmt.Errorf("program not initialized")
	}
	if out == nil {
		return fmt.Errorf("printer not initialized")
	}

	for {
		record, err := program.Reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("received signal, shutting down")
				return nil
			}
			fmt.Printf("error reading ring buffer: %v\n", err)
			continue
		}

		var evt ebpf.RawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			fmt.Printf("error parsing event: %v\n", err)
			continue
		}

		// Run every detector. Only print the raw event when at least one (filtering printed output)
		for _, det := range dets {
			alert, err := det.OnEvent(evt)
			if err != nil {
				fmt.Printf("detector %s error: %v\n", det.Name(), err)
				continue
			}
			if alert != nil {
				out.Print(evt)
				out.PrintAlert(*alert)
			}
		}
	}
}
