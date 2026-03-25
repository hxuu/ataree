//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

struct proc_info {
    __u32 ppid;
};

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

typedef int pid_t;

struct trace_event_raw_sched_process_fork {
    struct trace_entry ent;
    __u32 __data_loc_parent_comm;
    pid_t parent_pid;
    __u32 __data_loc_child_comm;
    pid_t child_pid;
    char __data[0];
};

struct trace_event_raw_sched_process_template {
    struct trace_entry ent;
    char __data[8];
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];
    char __data[0];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct proc_info);
} process_tree SEC(".maps");

static __always_inline void fill_common(struct ataree_event *e, __u8 event_type, __u32 target)
{
    __u32 pid = bpf_get_current_pid_tgid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->target_pid = target;
    e->event_type = event_type;

    struct proc_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    e->ppid = pi ? pi->ppid : 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void submit_common(__u8 event_type, __u32 target, struct trace_event_raw_sys_enter *ctx)
{
    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, event_type, target);
    e->arg1 = ctx->args[2];
    e->arg2 = ctx->args[0];
    bpf_ringbuf_submit(e, 0);
}

static __always_inline int parse_proc_kind_local(const char *fn, int len, __u32 *pid_out, __u8 *kind)
{
    if (!fn || len < 12)
        return 0;
    if (fn[0] != '/' || fn[1] != 'p' || fn[2] != 'r' || fn[3] != 'o' || fn[4] != 'c' || fn[5] != '/')
        return 0;

    __u32 pid = 0;
    int slash = -1;

#pragma unroll
    for (int j = 0; j < 10; j++) {
        int i = 6 + j;
        if (i >= len)
            return 0;

        char c = fn[i];
        if (c >= '0' && c <= '9') {
            pid = pid * 10 + (c - '0');
            continue;
        }

        if (c != '/')
            return 0;

        slash = i;
        break;
    }

    if (slash < 0)
        return 0;

    if (slash + 4 < len && fn[slash + 1] == 'm' && fn[slash + 2] == 'a' && fn[slash + 3] == 'p' && fn[slash + 4] == 's') {
        *pid_out = pid;
        *kind = EVENT_PROC_MAPS_OPEN;
        return 1;
    }
    if (slash + 3 < len && fn[slash + 1] == 'm' && fn[slash + 2] == 'e' && fn[slash + 3] == 'm') {
        *pid_out = pid;
        *kind = EVENT_PROC_MEM_OPEN;
        return 1;
    }

    return 0;
}

static __always_inline int emit_path_event(const char *pathname, __u8 event_type)
{
    char fn[128];
    int len = bpf_probe_read_user_str(fn, sizeof(fn), pathname);
    if (len <= 0)
        return 0;

    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, event_type, 0);
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 child = ctx->child_pid;
    struct proc_info info = {.ppid = ctx->parent_pid};

    bpf_map_update_elem(&process_tree, &child, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&process_tree, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int on_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u64 req = ctx->args[0];

    if (req == 4 || req == 5) {
        submit_common(EVENT_PTRACE_WRITE, (__u32)ctx->args[1], ctx);
    } else if (req == 13) {
        submit_common(EVENT_PTRACE_SETREGS, (__u32)ctx->args[1], ctx);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    __u64 flags = ctx->args[2];
    char fn[128] = {};
    int len = bpf_probe_read_user_str(fn, sizeof(fn), filename);
    if (len <= 0)
        return 0;

    __u32 target = 0;
    __u8 kind = 0;
    if (parse_proc_kind_local(fn, len, &target, &kind)) {
        struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;

        __builtin_memset(e, 0, sizeof(*e));
        fill_common(e, kind, target);
        bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
        e->arg1 = flags;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    if (!((flags & 0x1) || (flags & 0x2)))
        return 0;

    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_SENSITIVE_WRITE, 0);
    e->arg1 = flags;
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int on_kill(struct trace_event_raw_sys_enter *ctx)
{
    __u32 target = (__u32)ctx->args[0];
    __u64 sig = ctx->args[1];
    if (sig != 1 && sig != 2 && sig != 9 && sig != 15)
        return 0;

    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_KILL_SIGNAL, target);
    e->arg1 = sig;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int on_unlink(struct trace_event_raw_sys_enter *ctx)
{
    return emit_path_event((const char *)ctx->args[0], EVENT_UNLINK_PATH);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    return emit_path_event((const char *)ctx->args[1], EVENT_UNLINK_PATH);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *pathname = (const char *)ctx->args[0];
    char fn[128];
    int len = bpf_probe_read_user_str(fn, sizeof(fn), pathname);
    if (len <= 0)
        return 0;

    const char **argv = (const char **)ctx->args[1];
    char arg1[64] = {};
    char arg2[4] = {};
    const char *a1 = 0;
    const char *a2 = 0;
    bpf_probe_read_user(&a1, sizeof(a1), &argv[1]);
    if (a1)
        bpf_probe_read_user_str(arg1, sizeof(arg1), a1);
    bpf_probe_read_user(&a2, sizeof(a2), &argv[2]);
    if (a2)
        bpf_probe_read_user_str(arg2, sizeof(arg2), a2);

    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_EXECVE_CMD, 0);
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    __builtin_memcpy(&e->target_pid, arg2, sizeof(arg2));
    __builtin_memcpy(&e->arg1, arg1, 8);
    __builtin_memcpy(&e->arg2, arg1 + 8, 8);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int on_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot = ctx->args[2];
    __u64 flags = ctx->args[3];

    if ((flags & 0x20) && (prot & 0x4))
        submit_common(EVENT_ANON_EXEC_MMAP, bpf_get_current_pid_tgid(), ctx);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int on_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot = ctx->args[2];

    if (prot & 0x4)
        submit_common(EVENT_MPROTECT_EXEC, bpf_get_current_pid_tgid(), ctx);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
