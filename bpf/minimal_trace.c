//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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
    char bin_path[128];

    /* * DECODING STEP:
     * We take the hex address (ctx->filename) and copy the string
     * located there into our 'bin_path' buffer.
     */
    long err = bpf_probe_read_user_str(&bin_path, sizeof(bin_path), ctx->filename);

    if (err > 0) {
        bpf_printk("Decoded filename: %s", bin_path);
    } else {
        bpf_printk("Failed to decode filename at address %p", ctx->filename);
    }

    return 0;
}

char __license[] SEC("license") = "GPL";
