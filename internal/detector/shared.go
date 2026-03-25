package detector

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/hxuu/ataree/internal/ebpf"
)

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func argv1String(e ebpf.RawEvent) string {
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[0:8], e.Arg1)
	binary.LittleEndian.PutUint64(buf[8:16], e.Arg2)
	return cstr(buf[:])
}

func argv2String(e ebpf.RawEvent) string {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], e.TargetPID)
	return cstr(buf[:])
}

func baseName(p string) string {
	idx := strings.LastIndexByte(p, '/')
	if idx < 0 {
		return p
	}
	return p[idx+1:]
}

func cmdlineArgs(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(data), "\x00", " ")
}

func commFromPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
