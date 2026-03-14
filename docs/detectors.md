Detectors
=========

Overview
--------
Ataree decodes ring buffer events emitted by the eBPF program (`ebpf/ataree.bpf.c`) and runs a small set of Go detectors. Each detector is a plain struct implementing `Detector` (see `internal/detector/detector.go`) with `Name()` and `OnEvent(RawEvent)`.

Current Detectors
-----------------
- ptrace-write: alerts on PTRACE_POKETEXT/POKEDATA (`EventPtraceWrite`).
- ptrace-setregs: alerts on PTRACE_SETREGS (`EventPtraceSetregs`).
- ptrace->mprotect: alerts when ptrace write/setregs is followed by mprotect(PROT_EXEC) within 5s for the same PID.
- proc-maps-mem: alerts when an actor opens `/proc/<pid>/maps` then `/proc/<pid>/mem` within 5s.
- anon-exec-mmap: alerts on anonymous executable mappings (`MAP_ANONYMOUS | PROT_EXEC`).

Event Fields (RawEvent)
-----------------------
- TimestampNS, PID, PPID, TargetPID
- EventType (1..7; see `ebpf/events.h`)
- Comm (task name), Filename (only set on openat path)
- Arg1, Arg2 (hook-specific; ptrace: req/addr, mprotect: prot/addr, mmap: prot/addr)

Adding a Detector
-----------------
1. Create a file under `internal/detector/` and implement `Detector`.
2. Return `nil` when no alert, or an `Alert` with a short message.
3. Register it explicitly in `internal/cli/run.go` by appending to the `dets` slice.

Testing
-------
- Build and run PoCs under `poc_malware/` while ataree is running; alerts appear as `[ALERT] detector=...` on stdout.

Notes
-----
- Keep detector logic simple and fast; per-event memory/state should be bounded (maps keyed by PID).
- Use short windows (seconds) for correlations to avoid unbounded state.
