#ifndef ATAREE_EVENTS_H
#define ATAREE_EVENTS_H

#include <linux/types.h>

#define EVENT_KILL_SIGNAL 8
#define EVENT_UNLINK_PATH 9
#define EVENT_EXECVE_CMD 10
#define EVENT_SENSITIVE_WRITE 11

struct ataree_event
{
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
