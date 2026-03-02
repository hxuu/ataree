//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COMMAND_LEN 128

struct event {
    __u32 pid;
    char command[COMMAND_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// This struct maps to the 'print fmt' you found
struct trace_event_raw_sys_enter_execve {
    unsigned long long unused; // The first 8 bytes are reserved for common fields
    int __syscall_nr;          // The syscall number
    const char *filename;      // This is the 0x... address you saw!
    const char *const *argv;   // Address of arguments array
    const char *const *envp;   // Address of environment array
};

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    struct event evt = {};
    long err;

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    err = bpf_probe_read_user_str(&evt.command, sizeof(evt.command), ctx->filename);
    if (err < 0) {
        return 0;
    }

    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);

    return 0;
}

char __license[] SEC("license") = "GPL";
