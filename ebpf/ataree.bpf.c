//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

struct proc_info { __u32 ppid; };
struct trace_entry { unsigned short type; unsigned char flags; unsigned char preempt_count; int pid; };
typedef int pid_t;
struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	__u32 __data_loc_parent_comm;
	pid_t parent_pid;
	__u32 __data_loc_child_comm;
	pid_t child_pid;
	char __data[0];
};
struct trace_event_raw_sched_process_template { struct trace_entry ent; char __data[8]; };
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

static __always_inline int parse_proc_kind_local(const char *fn, int len, __u32 *pid_out, __u8 *kind)
{
    if (!fn || len < 12) return 0; // minimal /proc/x/mem
    if (fn[0] != '/' || fn[1] != 'p' || fn[2] != 'r' || fn[3] != 'o' || fn[4] != 'c' || fn[5] != '/')
        return 0;
    __u32 pid = 0; int i = 6;
    for (; i < len; i++) {
        char c = fn[i];
        if (c >= '0' && c <= '9') { pid = pid*10 + (c - '0'); continue; }
        if (c != '/') return 0;
        // check suffix
        if (i+4 <= len && fn[i+1]=='m' && fn[i+2]=='a' && fn[i+3]=='p' && fn[i+4]=='s') { *pid_out = pid; *kind = EVENT_PROC_MAPS_OPEN; return 1; }
        if (i+3 <= len && fn[i+1]=='m' && fn[i+2]=='e' && fn[i+3]=='m') { *pid_out = pid; *kind = EVENT_PROC_MEM_OPEN; return 1; }
        return 0;
    }
    return 0;
}

static __always_inline void submit_common(__u8 evtype, __u32 target, struct trace_event_raw_sys_enter *ctx)
{
    struct t1055_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;
    __builtin_memset(e, 0, sizeof(*e)); // zero out rb before filling it up
    __u32 pid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    struct proc_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    e->ppid = pi ? pi->ppid : 0;
    e->target_pid = target;
    e->event_type = evtype;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->arg1 = ctx->args[2];
    e->arg2 = ctx->args[0];
    bpf_ringbuf_submit(e, 0);
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
    if (req == 4 || req == 5) { // POKETEXT/POKEDATA
        submit_common(EVENT_PTRACE_WRITE, (__u32)ctx->args[1], ctx);
    } else if (req == 13) { // SETREGS
        submit_common(EVENT_PTRACE_SETREGS, (__u32)ctx->args[1], ctx);
    }
    return 0;
}

// Helper function to check if filename ends with .timer
static __always_inline int ends_with_timer(const char *fn, int len)
{
    if (len < 6)
        return 0;

    int i = len - 6;

    if (i < 0 || i + 5 >= 64)  // VERY IMPORTANT (bounds check)
        return 0;

    if (fn[i] != '.') return 0;
    if (fn[i+1] != 't') return 0;
    if (fn[i+2] != 'i') return 0;
    if (fn[i+3] != 'm') return 0;
    if (fn[i+4] != 'e') return 0;
    if (fn[i+5] != 'r') return 0;

    return 1;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    char fn[64];
    __builtin_memset(fn, 0, sizeof(fn));

    int ret = bpf_probe_read_user_str(fn, sizeof(fn), filename);
    if (ret <= 1)
        return 0;

    unsigned int len = (unsigned int)ret;

    __u32 target = 0;
    __u8 kind = 0;

    // /proc/ paths - avoid loop, just check fixed known offsets
    // We don't actually need to parse the PID for detection purposes
    if (len >= 12 &&
        fn[0]=='/' && fn[1]=='p' && fn[2]=='r' &&
        fn[3]=='o' && fn[4]=='c' && fn[5]=='/') {

        // Check for /proc/NNN/maps or /proc/NNN/mem
        // Skip digits manually at fixed positions (pid < 7 digits)
        // Check known fixed-offset suffixes instead of looping
        // e.g. /proc/1/maps = 12 chars, /proc/12345/mem = 14 chars
        // Strategy: scan known positions 7..18 for '/'
        #pragma unroll
        for (int k = 7; k <= 18; k++) {
            if (fn[k] == '/') {
                if (fn[k+1]=='m' && fn[k+2]=='a' &&
                    fn[k+3]=='p' && fn[k+4]=='s') {
                    kind = EVENT_PROC_MAPS_OPEN;
                } else if (fn[k+1]=='m' && fn[k+2]=='e' &&
                           fn[k+3]=='m' && fn[k+4]=='\0') {
                    kind = EVENT_PROC_MEM_OPEN;
                }
                break;
            }
        }
        target = bpf_get_current_pid_tgid();
    }

    // /etc/cron*
    if (kind == 0 && len >= 9 &&
        fn[0]=='/' && fn[1]=='e' && fn[2]=='t' && fn[3]=='c' &&
        fn[4]=='/' && fn[5]=='c' && fn[6]=='r' && fn[7]=='o' && fn[8]=='n') {
        target = bpf_get_current_pid_tgid();
        kind = EVENT_CRON_FILE_MOD;
    }

    // /var/spool/cron/atjobs/ or atspool/
    if (kind == 0 && len >= 23 &&
        fn[0]=='/' && fn[1]=='v' && fn[2]=='a' && fn[3]=='r' &&
        fn[4]=='/' && fn[5]=='s' && fn[6]=='p' && fn[7]=='o' &&
        fn[8]=='o' && fn[9]=='l' && fn[10]=='/' && fn[11]=='c' &&
        fn[12]=='r' && fn[13]=='o' && fn[14]=='n' && fn[15]=='/') {
        if ((fn[16]=='a' && fn[17]=='t' && fn[18]=='j' &&
             fn[19]=='o' && fn[20]=='b' && fn[21]=='s' && fn[22]=='/') ||
            (fn[16]=='a' && fn[17]=='t' && fn[18]=='s' &&
             fn[19]=='p' && fn[20]=='o' && fn[21]=='o' &&
             fn[22]=='l' && fn[23]=='/')) {
            target = bpf_get_current_pid_tgid();
            kind = EVENT_AT_FILE_MOD;
        }
    }

    // /var/spool/at/
    if (kind == 0 && len >= 14 &&
        fn[0]=='/' && fn[1]=='v' && fn[2]=='a' && fn[3]=='r' &&
        fn[4]=='/' && fn[5]=='s' && fn[6]=='p' && fn[7]=='o' &&
        fn[8]=='o' && fn[9]=='l' && fn[10]=='/' && fn[11]=='a' &&
        fn[12]=='t' && fn[13]=='/') {
        target = bpf_get_current_pid_tgid();
        kind = EVENT_AT_FILE_MOD;
    }

    // /etc/systemd/system/*.timer
    if (kind == 0 && len >= 20 &&
        fn[0]=='/' && fn[1]=='e' && fn[2]=='t' && fn[3]=='c' &&
        fn[4]=='/' && fn[5]=='s' && fn[6]=='y' && fn[7]=='s' &&
        fn[8]=='t' && fn[9]=='e' && fn[10]=='m' && fn[11]=='d' &&
        fn[12]=='/' && fn[13]=='s' && fn[14]=='y' && fn[15]=='s' &&
        fn[16]=='t' && fn[17]=='e' && fn[18]=='m' && fn[19]=='/') {
        if (ends_with_timer(fn, len)) {
            target = bpf_get_current_pid_tgid();
            kind = EVENT_CRON_FILE_MOD;
        }
    }

    // /lib/systemd/system/*.timer
    if (kind == 0 && len >= 20 &&
        fn[0]=='/' && fn[1]=='l' && fn[2]=='i' && fn[3]=='b' &&
        fn[4]=='/' && fn[5]=='s' && fn[6]=='y' && fn[7]=='s' &&
        fn[8]=='t' && fn[9]=='e' && fn[10]=='m' && fn[11]=='d' &&
        fn[12]=='/' && fn[13]=='s' && fn[14]=='y' && fn[15]=='s' &&
        fn[16]=='t' && fn[17]=='e' && fn[18]=='m' && fn[19]=='/') {
        if (ends_with_timer(fn, len)) {
            target = bpf_get_current_pid_tgid();
            kind = EVENT_CRON_FILE_MOD;
        }
    }

    // /usr/lib/systemd/system/*.timer
    if (kind == 0 && len >= 24 &&
        fn[0]=='/' && fn[1]=='u' && fn[2]=='s' && fn[3]=='r' &&
        fn[4]=='/' && fn[5]=='l' && fn[6]=='i' && fn[7]=='b' &&
        fn[8]=='/' && fn[9]=='s' && fn[10]=='y' && fn[11]=='s' &&
        fn[12]=='t' && fn[13]=='e' && fn[14]=='m' && fn[15]=='d' &&
        fn[16]=='/' && fn[17]=='s' && fn[18]=='y' && fn[19]=='s' &&
        fn[20]=='t' && fn[21]=='e' && fn[22]=='m' && fn[23]=='/') {
        if (ends_with_timer(fn, len)) {
            target = bpf_get_current_pid_tgid();
            kind = EVENT_CRON_FILE_MOD;
        }
    }

    if (kind == 0)
        return 0;

    struct t1055_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    __u32 pid = bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    struct proc_info *pi = bpf_map_lookup_elem(&process_tree, &pid);
    e->ppid = pi ? pi->ppid : 0;
    e->target_pid = target;
    e->event_type = kind;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    e->arg1 = ctx->args[2];
    e->arg2 = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int on_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot = ctx->args[2];
    __u64 flags = ctx->args[3];
    if ((flags & 0x20 /*MAP_ANONYMOUS*/) && (prot & 0x4 /*PROT_EXEC*/)) {
        submit_common(EVENT_ANON_EXEC_MMAP, bpf_get_current_pid_tgid(), ctx);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int on_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot = ctx->args[2];
    if (prot & 0x4 /*PROT_EXEC*/) {
        submit_common(EVENT_MPROTECT_EXEC, bpf_get_current_pid_tgid(), ctx);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


