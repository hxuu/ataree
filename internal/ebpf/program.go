package ebpf

import (
	"errors"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/hxuu/ataree/bpf"
)

type Program struct {
	Objs      bpf.MinimaltraceObjects
	TP        link.Link
	Reader    *ringbuf.Reader
	closeOnce sync.Once
	closeErr  error
}

func LoadAndAttach() (*Program, error) {
	var objs bpf.MinimaltraceObjects
	if err := bpf.LoadMinimaltraceObjects(&objs, nil); err != nil {
		return nil, err
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.DetectExecve, nil)
	if err != nil {
		_ = objs.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = tp.Close()
		_ = objs.Close()
		return nil, err
	}

	return &Program{
		Objs:   objs,
		TP:     tp,
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
		if p.TP != nil {
			errs = append(errs, p.TP.Close())
		}
		errs = append(errs, p.Objs.Close())
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}
