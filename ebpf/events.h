#ifndef ATAREE_EVENTS_H
#define ATAREE_EVENTS_H

#include <linux/types.h>

#define EVENT_PTRACE_WRITE 1
#define EVENT_PTRACE_SETREGS 2
#define EVENT_PROC_MEM_OPEN 3
#define EVENT_PROC_MAPS_OPEN 4
#define EVENT_SO_LOAD 5
#define EVENT_ANON_EXEC_MMAP 6
#define EVENT_MPROTECT_EXEC 7
#define EVENT_KILL_SIGNAL 8
#define EVENT_UNLINK_PATH 9
#define EVENT_EXECVE_CMD 10
#define EVENT_SENSITIVE_WRITE 11

struct ataree_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 target_pid;
    __u8 event_type;
    __u8 pad[3];
    char comm[16];
    char filename[128];
    __u64 arg1;
    __u64 arg2;
};

#endif
