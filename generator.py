#!/usr/bin/env python3
"""
generator.py - Parse eBPF trace output -> Docker security profiles
Usage:
    python3 generator.py <report_dir> <image_name> [runtime_seconds]
    python3 generator.py merge <output_dir> <image_name> <report_dir1> <report_dir2> [...]
"""

import sys
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path

# ================================================================
# CONSTANTS
# ================================================================

# index = capability bit number (matches kernel <linux/capability.h>)
CAPABILITIES = [
    "CAP_CHOWN",              # 0
    "CAP_DAC_OVERRIDE",       # 1
    "CAP_DAC_READ_SEARCH",    # 2
    "CAP_FOWNER",             # 3
    "CAP_FSETID",             # 4
    "CAP_KILL",               # 5
    "CAP_SETGID",             # 6
    "CAP_SETUID",             # 7
    "CAP_SETPCAP",            # 8
    "CAP_LINUX_IMMUTABLE",    # 9
    "CAP_NET_BIND_SERVICE",   # 10
    "CAP_NET_BROADCAST",      # 11
    "CAP_NET_ADMIN",          # 12
    "CAP_NET_RAW",            # 13
    "CAP_IPC_LOCK",           # 14
    "CAP_IPC_OWNER",          # 15
    "CAP_SYS_MODULE",         # 16
    "CAP_SYS_RAWIO",          # 17
    "CAP_SYS_CHROOT",         # 18
    "CAP_SYS_PTRACE",         # 19
    "CAP_SYS_PACCT",          # 20
    "CAP_SYS_ADMIN",          # 21
    "CAP_SYS_BOOT",           # 22
    "CAP_SYS_NICE",           # 23
    "CAP_SYS_RESOURCE",       # 24
    "CAP_SYS_TIME",           # 25
    "CAP_SYS_TTY_CONFIG",     # 26
    "CAP_MKNOD",              # 27
    "CAP_LEASE",              # 28
    "CAP_AUDIT_WRITE",        # 29
    "CAP_AUDIT_CONTROL",      # 30
    "CAP_SETFCAP",            # 31
    "CAP_MAC_OVERRIDE",       # 32
    "CAP_MAC_ADMIN",          # 33
    "CAP_SYSLOG",             # 34
    "CAP_WAKE_ALARM",         # 35
    "CAP_BLOCK_SUSPEND",      # 36
    "CAP_AUDIT_READ",         # 37
    "CAP_PERFMON",            # 38
    "CAP_BPF",                # 39
    "CAP_CHECKPOINT_RESTORE", # 40
]

# Syscalls always required for container runtime (never block these)
ESSENTIAL_SYSCALLS = [
    "exit", "exit_group", "futex", "rt_sigreturn",
    "restart_syscall", "rt_sigaction", "rt_sigprocmask",
]

# Conservative baseline to avoid profiles that are too narrow when traces are
# short or miss startup paths. The observed syscall set is still the primary
# signal, this list only adds common runtime plumbing calls.
BASELINE_SYSCALLS = [
    "arch_prctl", "brk", "clock_getres", "clock_gettime", "close",
    "epoll_create1", "epoll_ctl", "epoll_pwait", "fcntl", "fstat",
    "futex", "getpid", "getrandom", "gettid", "ioctl", "lseek",
    "madvise", "mmap", "mprotect", "munmap", "newfstatat", "openat",
    "pread64", "prlimit64", "read", "rt_sigaction", "rt_sigprocmask",
    "rt_sigreturn", "set_robust_list", "set_tid_address", "socket",
    "statx", "write",
]

# Docker's default capability set (no explicit cap_add needed for these)
DOCKER_DEFAULT_CAPS = {
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER",
    "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID",
    "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
}

# ================================================================
# SYSCALL ID -> NAME MAPPING
# ================================================================

def build_syscall_map() -> dict[int, str]:
    """
    Build a mapping of syscall ID -> name.
    Uses `ausyscall` (audit-tools) if available; otherwise falls back
    to a bundled x86_64 map.
    """
    mapping: dict[int, str] = {}

    # Try ausyscall (most accurate for the running kernel)
    try:
        out = subprocess.check_output(
            ["ausyscall", "--dump"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                mapping[int(parts[0])] = parts[1]
        if mapping:
            return mapping
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # Fallback: x86_64 syscall table.
    # Install `auditd` package (ships ausyscall) for the full authoritative map.
    return {
        0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
        6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect",
        11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
        15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
        19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select",
        24: "sched_yield", 25: "mremap", 26: "msync", 27: "mincore",
        28: "madvise", 29: "shmget", 30: "shmat", 31: "shmctl", 32: "dup",
        33: "dup2", 34: "pause", 35: "nanosleep", 36: "getitimer",
        37: "alarm", 38: "setitimer", 39: "getpid", 40: "sendfile",
        41: "socket", 42: "connect", 43: "accept", 44: "sendto",
        45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown",
        49: "bind", 50: "listen", 51: "getsockname", 52: "getpeername",
        53: "socketpair", 54: "setsockopt", 55: "getsockopt", 56: "clone",
        57: "fork", 58: "vfork", 59: "execve", 60: "exit", 61: "wait4",
        62: "kill", 63: "uname", 72: "fcntl", 73: "flock", 74: "fsync",
        75: "fdatasync", 78: "getdents", 79: "getcwd", 80: "chdir",
        81: "fchdir", 82: "rename", 83: "mkdir", 84: "rmdir", 85: "creat",
        86: "link", 87: "unlink", 88: "symlink", 89: "readlink",
        90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
        95: "umask", 96: "gettimeofday", 97: "getrlimit", 98: "getrusage",
        99: "sysinfo", 100: "times", 102: "getuid", 104: "getgid",
        105: "setuid", 106: "setgid", 107: "geteuid", 108: "getegid",
        109: "setpgid", 110: "getppid", 111: "getpgrp", 112: "setsid",
        113: "setreuid", 114: "setregid", 115: "getgroups", 116: "setgroups",
        117: "setresuid", 118: "getresuid", 119: "setresgid", 120: "getresgid",
        121: "getpgid", 124: "getsid", 125: "capget", 126: "capset",
        127: "rt_sigpending", 128: "rt_sigtimedwait", 129: "rt_sigqueueinfo",
        130: "rt_sigsuspend", 131: "sigaltstack", 132: "utime", 133: "mknod",
        137: "statfs", 138: "fstatfs", 157: "prctl", 158: "arch_prctl",
        160: "setrlimit", 161: "chroot", 186: "gettid", 200: "tkill",
        202: "futex", 203: "sched_setaffinity", 204: "sched_getaffinity",
        213: "epoll_create", 217: "getdents64", 218: "set_tid_address",
        228: "clock_gettime", 229: "clock_getres", 230: "clock_nanosleep",
        231: "exit_group", 232: "epoll_wait", 233: "epoll_ctl",
        234: "tgkill", 254: "inotify_init", 257: "openat", 258: "mkdirat",
        259: "mknodat", 260: "fchownat", 262: "newfstatat", 263: "unlinkat",
        264: "renameat", 265: "linkat", 266: "symlinkat", 267: "readlinkat",
        268: "fchmodat", 269: "faccessat", 270: "pselect6", 271: "ppoll",
        272: "unshare", 273: "set_robust_list", 280: "utimensat",
        281: "epoll_pwait", 282: "signalfd", 283: "timerfd_create",
        284: "eventfd", 285: "fallocate", 288: "accept4", 290: "eventfd2",
        291: "epoll_create1", 292: "dup3", 293: "pipe2", 294: "inotify_init1",
        295: "preadv", 296: "pwritev", 298: "perf_event_open", 299: "recvmmsg",
        302: "prlimit64", 306: "syncfs", 307: "sendmmsg", 308: "setns",
        309: "getcpu", 310: "process_vm_readv", 311: "process_vm_writev",
        316: "renameat2", 317: "seccomp", 318: "getrandom", 319: "memfd_create",
        321: "bpf", 322: "execveat", 323: "userfaultfd", 324: "membarrier",
        325: "mlock2", 326: "copy_file_range", 327: "preadv2", 328: "pwritev2",
        329: "pkey_mprotect", 330: "pkey_alloc", 331: "pkey_free",
        332: "statx", 333: "io_pgetevents", 334: "rseq",
        424: "pidfd_send_signal", 425: "io_uring_setup", 426: "io_uring_enter",
        427: "io_uring_register", 428: "open_tree", 429: "move_mount",
        430: "fsopen", 431: "fsconfig", 432: "fsmount", 433: "fspick",
        434: "pidfd_open", 435: "clone3", 436: "close_range", 437: "openat2",
        438: "pidfd_getfd", 439: "faccessat2", 440: "process_madvise",
        441: "epoll_pwait2", 442: "mount_setattr", 443: "quotactl_fd",
        444: "landlock_create_ruleset", 445: "landlock_add_rule",
        446: "landlock_restrict_self", 448: "process_mrelease",
        449: "futex_waitv", 450: "set_mempolicy_home_node",
    }

# ================================================================
# PARSERS
# ================================================================

def parse_trace(
    raw_file: Path,
    syscall_map: dict[int, str],
) -> tuple[list[str], list[str], list[int], dict[str, int], dict[str, int]]:
    """
    Parse combined bpftrace output containing @syscall_id and @cap_used maps.
    Returns (syscall_names, capability_names) - the actually observed ones.
    """
    if not raw_file.exists() or raw_file.stat().st_size == 0:
        print("  [!] trace-raw.txt is empty or missing")
        return [], [], [], {}, {}

    syscalls: set[str] = set()
    caps_used: set[str] = set()
    unknown_syscall_ids: set[int] = set()
    caps_ok: dict[str, int] = {}
    caps_denied: dict[str, int] = {}

    content = raw_file.read_text(errors="replace")

    for m in re.finditer(r'@syscall_id\[(\d+)\]:\s*\d+', content):
        sid = int(m.group(1))
        name = syscall_map.get(sid)
        if name:
            syscalls.add(name)
        else:
            unknown_syscall_ids.add(sid)

    for m in re.finditer(r'@cap_used\[(\d+)\]:\s*\d+', content):
        cap_num = int(m.group(1))
        if 0 <= cap_num < len(CAPABILITIES):
            caps_used.add(CAPABILITIES[cap_num])

    for m in re.finditer(r'@cap_ok\[(\d+)\]:\s*(\d+)', content):
        cap_num = int(m.group(1))
        if 0 <= cap_num < len(CAPABILITIES):
            caps_ok[CAPABILITIES[cap_num]] = int(m.group(2))

    for m in re.finditer(r'@cap_denied\[(\d+)\]:\s*(\d+)', content):
        cap_num = int(m.group(1))
        if 0 <= cap_num < len(CAPABILITIES):
            caps_denied[CAPABILITIES[cap_num]] = int(m.group(2))

    if unknown_syscall_ids:
        print(f"  [!] {len(unknown_syscall_ids)} unknown syscall IDs "
              f"(install `auditd` for full mapping): "
              f"{sorted(unknown_syscall_ids)[:10]}...")

    return sorted(syscalls), sorted(caps_used), sorted(unknown_syscall_ids), caps_ok, caps_denied


def parse_granted_caps(cap_file: Path) -> list[str]:
    """Parse /proc CapEff snapshot - only for reference in the report."""
    if not cap_file.exists():
        return []
    max_capeff = 0
    with open(cap_file) as f:
        for line in f:
            m = re.match(r'^CapEff:\s*([0-9a-fA-F]+)', line)
            if m:
                max_capeff |= int(m.group(1), 16)
    return [
        name for i, name in enumerate(CAPABILITIES)
        if max_capeff & (1 << i)
    ]

# ================================================================
# GENERATORS
# ================================================================

def build_seccomp_profile(syscalls: list[str]) -> dict:
    """Build an OCI-compatible seccomp allowlist profile."""
    all_syscalls = sorted(set(syscalls) | set(ESSENTIAL_SYSCALLS) | set(BASELINE_SYSCALLS))
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_X86",
            "SCMP_ARCH_X32"
        ],
        "syscalls": [
            {
                "names": all_syscalls,
                "action": "SCMP_ACT_ALLOW"
            }
        ]
    }


def build_compose_snippet(caps_required: list[str], seccomp_path: str) -> str:
    """Build docker-compose security_opt / cap_drop / cap_add snippet."""
    extra_caps = sorted(
        c.replace("CAP_", "")
        for c in caps_required
        if c not in DOCKER_DEFAULT_CAPS
    )

    lines = [
        "# -- Docker Compose Security Snippet --------------------",
        "# Paste under your service definition in docker-compose.yml",
        "# Capabilities listed are those OBSERVED to be used (not just granted).",
        "#",
        "    security_opt:",
        "      - no-new-privileges:true",
        f"      - seccomp:{seccomp_path}",
        "    cap_drop:",
        "      - ALL",
    ]

    if extra_caps:
        lines.append("    cap_add:")
        for cap in extra_caps:
            lines.append(f"      - {cap}")
    else:
        lines.append("    # cap_add: []  # No capabilities beyond Docker defaults observed")

    return "\n".join(lines) + "\n"


def build_report(
    image: str,
    runtime: int,
    syscalls: list[str],
    caps_used: list[str],
    caps_required: list[str],
    caps_ok: dict[str, int],
    caps_denied: dict[str, int],
    caps_granted: list[str],
    timestamp: str,
) -> str:
    """Build a human-readable Markdown report."""
    extra_caps = [c for c in caps_required if c not in DOCKER_DEFAULT_CAPS]
    service_name = image.split("/")[-1].split(":")[0]

    lines = [
        "# Docker Security Analysis Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Image** | `{image}` |",
        f"| **Analysis Date** | {timestamp} |",
        f"| **Tracing Duration** | {runtime}s |",
        f"| **Unique Syscalls Observed** | {len(syscalls)} |",
        f"| **Capabilities CHECKED (eBPF)** | {len(caps_used)} |",
        f"| **Capabilities ALLOWED (kretprobe)** | {len(caps_ok)} |",
        f"| **Capabilities DENIED (kretprobe)** | {len(caps_denied)} |",
        f"| **Capabilities GRANTED (ref.)** | {len(caps_granted)} |",
        f"| **Non-default caps to add** | {len(extra_caps)} |",
        "",
        "## How this report is produced",
        "",
        "- **Syscalls**: eBPF `raw_syscalls:sys_enter` tracepoint,",
        "  filtered by PID subtree of the container's root PID.",
        "- **Capabilities USED**: eBPF `kprobe:cap_capable` - captures every",
        "  capability check the kernel performs for container processes.",
        "  This is what the container **actually needs**.",
        "- **Capabilities GRANTED**: snapshot of `/proc/<PID>/status` `CapEff`.",
        "  Included only for reference - always reflects `--cap-add ALL`.",
        "",
        "## Generated Files",
        "",
        "| File | Description |",
        "|---|---|",
        "| `seccomp.json` | OCI seccomp allowlist profile |",
        "| `docker-compose-snippet.yml` | Drop-in security config for Compose |",
        "| `trace-raw.txt` | Raw bpftrace output (syscalls + caps used) |",
        "| `capabilities-granted-raw.txt` | Reference: what was granted |",
        "",
        "## Capabilities Checked",
        "",
    ]

    if not caps_used:
        lines += [
            "_No capability checks recorded during tracing._",
            "",
            "This may mean the workload didn't require any privileged",
            "operations, or the trace window was too short.",
        ]
    else:
        for cap in sorted(caps_used):
            marker = "non-default (checked)" if cap not in DOCKER_DEFAULT_CAPS else "docker default (checked)"
            lines.append(f"- `{cap}` - {marker}")

    lines += [
        "",
        "## Capability Check Outcomes",
        "",
        "Only capabilities with **allowed** checks are used for cap_add recommendations.",
        "Denied checks are kept as signal for app probing or blocked code paths.",
        "",
    ]

    if not caps_ok and not caps_denied:
        lines.append("_No cap_capable outcome data captured (older trace format or no checks)._")
    else:
        if caps_ok:
            lines.append("Allowed checks:")
            for cap, cnt in sorted(caps_ok.items()):
                lines.append(f"- `{cap}` - {cnt}")
        if caps_denied:
            lines.append("Denied checks:")
            for cap, cnt in sorted(caps_denied.items()):
                lines.append(f"- `{cap}` - {cnt}")

    lines += [
        "",
        "## Syscalls",
        "",
        f"{len(syscalls)} unique syscalls observed "
        f"(+ {len(ESSENTIAL_SYSCALLS)} essential syscalls always added):",
        "",
        "```",
    ]
    lines += sorted(syscalls) if syscalls else ["(none captured)"]
    lines += [
        "```",
        "",
        "## Hardening Recommendations",
        "",
        "1. **seccomp**: Use `seccomp.json` - blocks all syscalls not observed",
        "2. **Capabilities**: `cap_drop: ALL` + only add what's listed above",
        "3. **No privilege escalation**: `no-new-privileges: true`",
        "4. **Read-only filesystem**: Add `read_only: true` if the app allows it",
        "5. **Non-root user**: Add `user: '1000:1000'` where possible",
        "6. **Re-run under load**: Trace under realistic traffic for better coverage",
        "",
        "## Quick Start",
        "",
        "```yaml",
        "services:",
        f"  {service_name}:",
        f"    image: {image}",
        "    security_opt:",
        "      - no-new-privileges:true",
        "      - seccomp:./seccomp.json",
        "    cap_drop:",
        "      - ALL",
    ]

    if extra_caps:
        lines.append("    cap_add:")
        for cap in sorted(extra_caps):
            lines.append(f"      - {cap.replace('CAP_', '')}")

    lines.append("```")
    return "\n".join(lines) + "\n"


def build_merge_report(
    image: str,
    source_reports: list[Path],
    syscalls: list[str],
    caps_used: list[str],
    caps_required: list[str],
    caps_ok: dict[str, int],
    caps_denied: dict[str, int],
    caps_granted: list[str],
    unknown_syscall_ids: list[int],
    timestamp: str,
) -> str:
    """Build a report for merged analysis runs."""
    extra_caps = [c for c in caps_required if c not in DOCKER_DEFAULT_CAPS]
    service_name = image.split("/")[-1].split(":")[0]

    lines = [
        "# Docker Security Analysis Report (Merged)",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Image** | `{image}` |",
        f"| **Merge Date** | {timestamp} |",
        f"| **Source Reports** | {len(source_reports)} |",
        f"| **Unique Syscalls Observed (Union)** | {len(syscalls)} |",
        f"| **Capabilities CHECKED (Union)** | {len(caps_used)} |",
        f"| **Capabilities ALLOWED (Union)** | {len(caps_ok)} |",
        f"| **Capabilities DENIED (Union)** | {len(caps_denied)} |",
        f"| **Capabilities GRANTED (Union, ref.)** | {len(caps_granted)} |",
        f"| **Unknown Syscall IDs (Union)** | {len(unknown_syscall_ids)} |",
        f"| **Non-default caps to add** | {len(extra_caps)} |",
        "",
        "## Source Reports",
        "",
    ]

    for p in source_reports:
        lines.append(f"- `{p}`")

    lines += [
        "",
        "## Capabilities Actually Used (Union)",
        "",
    ]

    if not caps_used:
        lines.append("_No capability checks recorded across all merged traces._")
    else:
        for cap in sorted(caps_used):
            marker = "non-default (needs cap_add)" if cap not in DOCKER_DEFAULT_CAPS else "docker default"
            lines.append(f"- `{cap}` - {marker}")

    lines += [
        "",
        "## Syscalls (Union)",
        "",
        f"{len(syscalls)} unique syscalls observed across merged runs "
        f"(+ {len(ESSENTIAL_SYSCALLS)} essential + baseline set):",
        "",
        "```",
    ]
    lines += sorted(syscalls) if syscalls else ["(none captured)"]
    lines += [
        "```",
        "",
    ]

    if unknown_syscall_ids:
        lines += [
            "## Unknown Syscall IDs",
            "",
            "These IDs could not be mapped to names. Re-run with `ausyscall` available",
            "for best accuracy.",
            "",
            "```",
            "\n".join(str(i) for i in unknown_syscall_ids),
            "```",
            "",
        ]

    lines += [
        "## Quick Start",
        "",
        "```yaml",
        "services:",
        f"  {service_name}:",
        f"    image: {image}",
        "    security_opt:",
        "      - no-new-privileges:true",
        "      - seccomp:./seccomp.json",
        "    cap_drop:",
        "      - ALL",
    ]

    if extra_caps:
        lines.append("    cap_add:")
        for cap in sorted(extra_caps):
            lines.append(f"      - {cap.replace('CAP_', '')}")

    lines += [
        "```",
        "",
    ]
    return "\n".join(lines)


def generate_single_report(report_dir: Path, image: str, runtime: int) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("  [*] Building syscall ID -> name map...")
    syscall_map = build_syscall_map()
    print(f"  [+] Loaded {len(syscall_map)} syscall entries")

    print("  [*] Parsing trace data...")
    syscalls, caps_used, unknown_syscall_ids, caps_ok, caps_denied = parse_trace(
        report_dir / "trace-raw.txt", syscall_map
    )
    print(f"  [+] {len(syscalls)} unique syscalls observed")
    print(f"  [+] {len(caps_used)} capabilities checked")
    print(f"  [+] {len(caps_ok)} capabilities with allowed checks")
    print(f"  [+] {len(caps_denied)} capabilities with denied checks")

    # Strict mode by default: only capabilities with successful checks are
    # considered required. Denied checks are informative, not recommendations.
    caps_required = sorted(caps_ok.keys())

    if unknown_syscall_ids:
        unknown_file = report_dir / "unknown-syscall-ids.txt"
        unknown_file.write_text("\n".join(str(i) for i in unknown_syscall_ids) + "\n")
        print(f"  [!] {len(unknown_syscall_ids)} unknown syscall IDs found (saved to {unknown_file.name})")
        print("  [!] Install `auditd` (for `ausyscall`) and re-run for more accurate syscall naming")

    print("  [*] Reading granted-caps snapshot (reference)...")
    caps_granted = parse_granted_caps(report_dir / "capabilities-granted-raw.txt")
    print(f"  [+] {len(caps_granted)} capabilities were granted")

    profile = build_seccomp_profile(syscalls)
    (report_dir / "seccomp.json").write_text(json.dumps(profile, indent=2))
    total = len(profile["syscalls"][0]["names"])
    print(f"  [+] seccomp.json - {total} syscalls allowed")

    snippet = build_compose_snippet(caps_required, "./seccomp.json")
    (report_dir / "docker-compose-snippet.yml").write_text(snippet)
    print("  [+] docker-compose-snippet.yml written")

    report = build_report(
        image,
        runtime,
        syscalls,
        caps_used,
        caps_required,
        caps_ok,
        caps_denied,
        caps_granted,
        timestamp,
    )
    (report_dir / "report.md").write_text(report)
    print("  [+] report.md written")


def merge_reports(output_dir: Path, image: str, report_dirs: list[Path]) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_dir.mkdir(parents=True, exist_ok=True)

    print("  [*] Building syscall ID -> name map...")
    syscall_map = build_syscall_map()
    print(f"  [+] Loaded {len(syscall_map)} syscall entries")

    merged_syscalls: set[str] = set()
    merged_caps_used: set[str] = set()
    merged_caps_required: set[str] = set()
    merged_caps_ok: dict[str, int] = {}
    merged_caps_denied: dict[str, int] = {}
    merged_caps_granted: set[str] = set()
    merged_unknown_ids: set[int] = set()
    existing_sources: list[Path] = []

    for report_dir in report_dirs:
        trace_file = report_dir / "trace-raw.txt"
        if not trace_file.exists():
            print(f"  [!] Skipping {report_dir}: missing trace-raw.txt")
            continue

        existing_sources.append(report_dir)
        print(f"  [*] Merging {report_dir}")

        syscalls, caps_used, unknown_ids, caps_ok, caps_denied = parse_trace(trace_file, syscall_map)
        merged_syscalls.update(syscalls)
        merged_caps_used.update(caps_used)
        merged_unknown_ids.update(unknown_ids)

        for cap, cnt in caps_ok.items():
            merged_caps_ok[cap] = merged_caps_ok.get(cap, 0) + cnt
        for cap, cnt in caps_denied.items():
            merged_caps_denied[cap] = merged_caps_denied.get(cap, 0) + cnt

        merged_caps_granted.update(parse_granted_caps(report_dir / "capabilities-granted-raw.txt"))

    merged_caps_required.update(merged_caps_ok.keys())

    if not existing_sources:
        print("  [-] No valid report directories to merge")
        sys.exit(1)

    syscalls_sorted = sorted(merged_syscalls)
    caps_used_sorted = sorted(merged_caps_used)
    caps_required_sorted = sorted(merged_caps_required)
    caps_granted_sorted = sorted(merged_caps_granted)
    unknown_sorted = sorted(merged_unknown_ids)

    profile = build_seccomp_profile(syscalls_sorted)
    (output_dir / "seccomp.json").write_text(json.dumps(profile, indent=2))
    print(f"  [+] seccomp.json written ({len(profile['syscalls'][0]['names'])} syscalls allowed)")

    snippet = build_compose_snippet(caps_required_sorted, "./seccomp.json")
    (output_dir / "docker-compose-snippet.yml").write_text(snippet)
    print("  [+] docker-compose-snippet.yml written")

    report = build_merge_report(
        image=image,
        source_reports=existing_sources,
        syscalls=syscalls_sorted,
        caps_used=caps_used_sorted,
        caps_required=caps_required_sorted,
        caps_ok=merged_caps_ok,
        caps_denied=merged_caps_denied,
        caps_granted=caps_granted_sorted,
        unknown_syscall_ids=unknown_sorted,
        timestamp=timestamp,
    )
    (output_dir / "report.md").write_text(report)
    print("  [+] report.md written")

    (output_dir / "merged-sources.txt").write_text("\n".join(str(p) for p in existing_sources) + "\n")
    print("  [+] merged-sources.txt written")

    if unknown_sorted:
        (output_dir / "unknown-syscall-ids.txt").write_text("\n".join(str(i) for i in unknown_sorted) + "\n")
        print(f"  [!] unknown-syscall-ids.txt written ({len(unknown_sorted)} IDs)")

# ================================================================
# MAIN
# ================================================================

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 generator.py <report_dir> <image_name> [runtime_seconds]")
        print("  python3 generator.py merge <output_dir> <image_name> <report_dir1> <report_dir2> [...]")
        sys.exit(1)

    if sys.argv[1] == "merge":
        if len(sys.argv) < 6:
            print("Usage: python3 generator.py merge <output_dir> <image_name> <report_dir1> <report_dir2> [...]")
            sys.exit(1)

        output_dir = Path(sys.argv[2])
        image = sys.argv[3]
        report_dirs = [Path(p) for p in sys.argv[4:]]
        merge_reports(output_dir, image, report_dirs)
        return

    if len(sys.argv) < 3:
        print("Usage: python3 generator.py <report_dir> <image_name> [runtime_seconds]")
        sys.exit(1)

    report_dir = Path(sys.argv[1])
    image = sys.argv[2]
    runtime = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    generate_single_report(report_dir, image, runtime)


if __name__ == "__main__":
    main()
