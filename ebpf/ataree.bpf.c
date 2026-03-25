// go:build ignore
//  +build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

struct proc_info
{
    __u32 ppid;
};
struct trace_entry
{
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};
typedef int pid_t;
struct trace_event_raw_sched_process_fork
{
    struct trace_entry ent;
    __u32 __data_loc_parent_comm;
    pid_t parent_pid;
    __u32 __data_loc_child_comm;
    pid_t child_pid;
    char __data[0];
};
struct trace_event_raw_sched_process_template
{
    struct trace_entry ent;
    char __data[8];
};
struct trace_event_raw_sys_enter
{
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];
    char __data[0];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct proc_info);
} process_tree SEC(".maps");

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

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
    /* args: [0]=dirfd [1]=pathname [2]=flags [3]=mode */
    const char *filename = (const char *)ctx->args[1];
    __u64 flags = ctx->args[2];

    char fn[128];
    int len = bpf_probe_read_user_str(fn, sizeof(fn), filename);
    if (len <= 0)
        return 0;

    /* ── T1562.003 / .006 / .011 / .012  write-open tracking ───────── */
    /* O_WRONLY=1, O_RDWR=2 */
    if (!((flags & 0x1) || (flags & 0x2)))
        return 0;

    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    __u32 pid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    struct proc_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    e->ppid = pi ? pi->ppid : 0;
    e->event_type = EVENT_SENSITIVE_WRITE;
    e->arg1 = flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int emit_unlink_event(const char *pathname)
{
    char fn[128];
    int len = bpf_probe_read_user_str(fn, sizeof(fn), pathname);
    if (len <= 0)
        return 0;

    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    __u32 pid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    struct proc_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    e->ppid = pi ? pi->ppid : 0;
    e->event_type = EVENT_UNLINK_PATH;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
/* T1562.001  kill() */
SEC("tracepoint/syscalls/sys_enter_kill")
int on_kill(struct trace_event_raw_sys_enter *ctx)
{
    /* args: [0]=pid [1]=sig */
    __u32 target = (__u32)ctx->args[0];
    __u64 sig = ctx->args[1];

    if (sig != 1 && sig != 2 && sig != 9 && sig != 15)
        return 0;

    struct ataree_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    __u32 pid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    struct proc_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    e->ppid = pi ? pi->ppid : 0;
    e->target_pid = target;
    e->event_type = EVENT_KILL_SIGNAL;
    e->arg1 = sig;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*  T1562.003  unlink / truncate on sensitive paths */
SEC("tracepoint/syscalls/sys_enter_unlink")
int on_unlink(struct trace_event_raw_sys_enter *ctx)
{
    /* args: [0]=pathname */
    const char *pathname = (const char *)ctx->args[0];
    return emit_unlink_event(pathname);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    /* args: [0]=dirfd [1]=pathname [2]=flags */
    const char *pathname = (const char *)ctx->args[1];
    return emit_unlink_event(pathname);
}

/*  T1562.004 / .010 / .012  execve  */
SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx)
{
    /* args: [0]=filename  [1]=argv  [2]=envp */
    const char *pathname = (const char *)ctx->args[0];
    char fn[128];
    int len = bpf_probe_read_user_str(fn, sizeof(fn), pathname);
    if (len <= 0)
        return 0;

    /* read argv[1] for flag inspection in Go */
    const char **argv = (const char **)ctx->args[1];
    char arg1[64] = {};
    char arg2[4] = {};
    const char *a1 = NULL;
    const char *a2 = NULL;
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

    __u32 pid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    struct proc_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    e->ppid = pi ? pi->ppid : 0;
    e->event_type = EVENT_EXECVE_CMD;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    /* target_pid is unused for execve events, so reuse it for argv[2]. */
    __builtin_memcpy(&e->target_pid, arg2, sizeof(arg2));
    /* pack arg1 string into the two arg uint64 fields as raw bytes */
    __builtin_memcpy(&e->arg1, arg1, 8);
    __builtin_memcpy(&e->arg2, arg1 + 8, 8);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
