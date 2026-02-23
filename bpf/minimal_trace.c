#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_execve () {
  bpf_printk("Execve called :O ! ");
  return 0;
}

char license[] SEC("license") = "GPL";
int version SEC("version") = LINUX_VERSION_CODE;
