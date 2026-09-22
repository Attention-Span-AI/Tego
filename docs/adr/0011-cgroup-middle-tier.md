# ADR 0011: a `cgroup` middle tier gives root users the hardened features without a boot change

Status: accepted 2026-09-21. Supersedes ADR 0002's two-tier statement.
Amended by ADR 0021 (accepted 2026-09-29; fanotify's arming point and no process start under marks) and ADR 0024 (accepted 2026-09-29; the plane backend is built in tier 2; tier 2 decides opens, execs and mutations in the kernel; fanotify becomes the fallback).
Amended by ADR 0042 (accepted 2026-10-05): tier `cgroup` is reached by a root launcher; "or file capabilities" is conditioned.
Decision: three tiers. `landlock` (no root); `cgroup` (root or file capabilities, no boot parameter): cgroup-attached socket programs (`cgroup/connect4,6`, `sendmsg4,6`, `bind4,6`, `connect_unix` on 6.7+) for network by host:port and UDP per cgroup, fanotify `FAN_OPEN_PERM`/`FAN_OPEN_EXEC_PERM` for path-aware open and exec deny with reasons, Landlock inside the run for delete, rename and mkdir, the full eBPF record and uprobes, adoption of daemon-created cgroups; `bpflsm` (adds `bpf` in the LSM list): delete, rename, mkdir, chmod, mknod per cgroup, `ptrace` and `bpf` hooks, in-kernel reasons on every hook.
Why: every attach type exists in the kernel headers (verified), and `IPAddressDeny=` in systemd proves the cgroup socket family works on stock distributions; fanotify permission events exist since 2.6.37/5.0 with errno replies since 6.13. Production servers get the middle tier with `sudo` on day one; only Ubuntu-family images need the boot line for the top tier (Debian 13, Fedora, RHEL 9/10, Amazon Linux 2023 already list `bpf`).
Consequence: `tier:` enum is `auto | landlock | cgroup | bpflsm`; fanotify open/exec deny is a userspace round trip on every open and is benchmarked separately; delete and rename inside adopted containers are a tier-3 property.

*Amended 2026-10-05 (ADR 0042 (2), (3)(c)):* tier `cgroup` is "root (a root launcher)" in this release. "Or file
capabilities" is not delivered: a file-capability copy of tego is refused at start with exit 125
`[privileged-path-unsupported]`, and the path may return only for single-administrator hosts by its own ADR, once
ADR 0042 (3)(c)'s five conditions hold.
