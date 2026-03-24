package ebpf

import (
	"errors"
	"fmt"
	"sync"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	bpf "github.com/hxuu/ataree/ebpf"
	
)

type Program struct {
	objs      bpf.AtareeObjects
	links     []link.Link
	Reader    *ringbuf.Reader
	closeOnce sync.Once
	closeErr  error
}

func LoadAndAttach() (*Program, error) {
	var objs bpf.AtareeObjects
	if err := bpf.LoadAtareeObjects(&objs, nil); err != nil {
		return nil, err
	}

	tracepoints := []struct {
		cat, name string
		prog      *cilium.Program
	}{
		{"syscalls", "sys_enter_ptrace",   objs.OnPtrace},
		{"syscalls", "sys_enter_openat",   objs.OnOpenat},
		{"syscalls", "sys_enter_mmap",     objs.OnMmap},
		{"syscalls", "sys_enter_mprotect", objs.OnMprotect},
		{"sched",    "sched_process_fork", objs.HandleFork},
		{"sched",    "sched_process_exit", objs.HandleExit},
	}

	var links []link.Link
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.cat, tp.name, tp.prog, nil)
		if err != nil {
			for _, l := range links { l.Close() }
			objs.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.cat, tp.name, err)
		}
		links = append(links, l)
	}

	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		for _, l := range links { l.Close() }
		objs.Close()
		return nil, err
	}

	return &Program{
		objs:   objs,
		links:  links,
		Reader: rd,
	}, nil
}

func (p *Program) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		var errs []error
		if p.Reader != nil {
			errs = append(errs, p.Reader.Close())
		}
		for _, l := range p.links {
			errs = append(errs, l.Close())
		}
		errs = append(errs, p.objs.Close())
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}
