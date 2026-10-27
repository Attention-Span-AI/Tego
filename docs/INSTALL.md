# Install

Tego runs on Linux. Today the way to install it is to build it from source. There is no tagged release yet.

## Requirements

| | |
|---|---|
| Operating system | Linux, amd64 or arm64. macOS and Windows have no native build: run Tego inside a Linux VM (on Windows, WSL2 works) and install it there. |
| Kernel | Tier 1 (no root) needs Landlock ABI 2 or newer, which is Linux 5.19 or later or a backport such as RHEL 9's 5.14, and cgroup v2 with a subtree delegated to your user. The oldest kernels the project tests are 6.1 and RHEL 9's 5.14. Ubuntu 22.04's stock 5.15 has Landlock ABI 1, so no tier runs on it. Tiers 2 and 3 need root, and tier 3 needs `bpf` in the boot LSM list. [TIERS.md](TIERS.md) has the table. |
| To build | `git`, `make` and Go 1.27 (CI builds with 1.27.3). You do not need clang: the compiled BPF objects are committed. |

## Build and install from source

```sh
git clone https://github.com/attention-span-ai/tego
cd tego
make build
mkdir -p ~/.local/bin
install -m 0755 bin/tego bin/tego-control ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

`make build` writes `bin/tego-control` first, then `bin/tego` with the SHA-256 of `tego-control` built into it, and checks
the pair. Use `make build`. A plain `go build ./cmd/tego` makes a tier-1-only `tego` that has no pin for `tego-control`:
`tego doctor` reports tier 2 as not built, and `tego serve` refuses with `[control-not-installed]`, or with `[control-unpinned]` once a `tego-control` sits beside it.

**Keep the two binaries in one directory.** `tego serve` (the dashboard) hands off to the `tego-control` next to it,
never one found on `PATH`. It runs only a regular file owned by you or root, not writable by group or others, whose hash
is the pin. If you move one binary, move both. If you rebuild one, rebuild both.

The `export` is for this shell. Ubuntu's `~/.profile` adds `~/.local/bin` to `PATH` at your next login, once the folder
exists. Elsewhere, add that line to your shell's profile. Then check:

```sh
tego version
```

```text
tego=v0.0.0-<commit date>-<commit, 12 digits>
commit=<commit, 40 digits>
date=<commit date>
go=go1.27.3
contract_schema=0
record_v=1
record_readers=1
bpf_hash=<hash of the BPF objects>
parsers=anthropic
control_sha256=<hash of your tego-control>
```

A value in angle brackets is your own build's. A build from a checkout with no release tag names its commit, as here; a
release prints its tag, such as `tego=v0.1.0`. The `control_sha256=` line is the hash built into `tego`, and
`tego-control version` prints the same hash as `sha256`.

## Running with sudo

Tiers 2 and 3 need a root launcher, so you run `sudo tego run ...`. `sudo` may use a fixed `PATH` that does not include
`~/.local/bin`. If it says `command not found`, give it the full path:

```sh
sudo "$(command -v tego)" doctor
```

The launcher is root, and the agent runs as you, with your `HOME`, `USER` and `LOGNAME`. It has `sudo`'s `PATH`, so give a
program installed under your home by its full path in `command:`.

Granting `sudo` for `tego` is granting root: the launcher runs as root over a contract and config you control. Do not put
`tego` in a sudoers rule for another account. [OPERATIONS.md](OPERATIONS.md) ("Privileged path") says more.

The dashboard is the exception. `tego-control` refuses to run as root or with any capability, so start `tego serve` as
yourself, never with `sudo`. Under `sudo`, Tego looks up your account through `SUDO_UID`, so a root-tier run is recorded in
your own `~/.tego`, where the dashboard reads it. While such a run is live its folder there is root's (mode
0700), so the dashboard shows it only after it ends. Until then read it with `sudo "$(command -v tego)" status`.

## Check the machine

```sh
tego doctor
sudo "$(command -v tego)" doctor
```

The first shows what you get without root. The second shows tiers 2 and 3. On a stock Ubuntu, tier 3 is reported as
unavailable because `bpf` is not in the boot LSM list. That is a fact about the machine, not a fault in the install, and
[TIERS.md](TIERS.md#tier-3-on-ubuntu) has the boot line. The last line is about the dashboard: the kernel loads the
`inet_diag` and `tcp_diag` modules when Tego first asks, and the line warns only if they cannot load
(`sudo modprobe tcp_diag`).

**Over SSH.** Tier 1 needs a cgroup your user can place a process in. A login over SSH, or a service, starts outside
`user@<uid>.service` and cannot, so `doctor`'s cgroup check fails and `tego run` is refused. Start a shell in your user's
cgroup first: `systemd-run --user --scope bash`. If `doctor` says your user has no delegated cgroup, it prints the fix.

This is `sudo "$(command -v tego)" doctor` on a fresh Ubuntu 24.04 cloud image, with your build's own values in angle
brackets. The table is cut after five rows here; yours prints in full. `(>= 5.14.0)` on the `kernel` line is the oldest
release `doctor` accepts at all, not tier 1's minimum: tier 1 also needs the `landlock` line to show ABI 2 or newer, and
`doctor` adds a note on a release below 6.1, the tested floor.

```text
tego=v0.0.0-<commit date>-<commit, 12 digits> commit=<commit, 40 digits> date=<commit date> go=go1.27.3 contract_schema=0 record_v=1
ok   kernel: 6.8.0-147-generic (>= 5.14.0); without: Landlock ABI 5 (ioctl_dev) (6.10.0, device ioctls are not restricted), Landlock ABI 6 (scopes) (6.12.0, abstract unix sockets and signals are not scoped), Landlock ABI 7 (audit) (6.15.0, Landlock refusals are not in the audit log)
ok   btf: /sys/kernel/btf/vmlinux (6103569 bytes); all 94 kernel types and fields the BPF programs read are present
ok   cgroupv2: /sys/fs/cgroup delegated, cgroup.kill writable, controllers: cpu memory pids
ok   landlock: ABI 4
ok   seccomp: NEW_LISTENER + ADDFD(SEND) round trip on syscall 319 returned fd 8; yama ptrace_scope=1 (the supervisor is the agent's parent, which Yama exempts)
off  lsm: lockdown,capability,landlock,yama,apparmor via lsm_list_modules(2); bpf is not active: tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected; fix: add lsm=lockdown,capability,landlock,yama,apparmor,bpf to the kernel command line (GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then update-grub) and reboot
ok   programs: 27 of 27 hooks load and attach; trace_proc is its rdonly build (the kernel's BTF has bpf_rdonly_cast and bpf_loop); capture (uprobe_ssl, no tier): 6 of 6 programs load and attach at /usr/lib/x86_64-linux-gnu/libssl.so.3; optional network controls: 8 of 10 hooks load and attach; decision plane: fmod_ret (tier 2 decides opens in the kernel; tier 3 needs bpf in lsm=); build ed474b77, lsm mode no: bpf is not in the active LSM list (lockdown,capability,landlock,yama,apparmor), fmod_ret mode ok
ok   fanotify: permission marks work, FAN_DENY refuses the open, FAN_REPORT_FID=false, FAN_DENY_ERRNO=false (a refusal reaches the agent as EPERM: no kernel takes EACCES in a reply from the listener's FAN_CLASS_CONTENT group; the reason record is still exact)
ok   swap: memory.swap.max present: a run's memory cap holds swap too

capability matrix for tier cgroup on this machine:
deny file write outside contract                   yes  yes (Landlock and fanotify; fanotify refuses with EPERM) [this machine: decided by the decision plane in fmod_ret mode, not fanotify: a refusal reaches the agent as EACCES, with the reason in the record]
deny delete, rename, mkdir, mknod                  yes  via Landlock inside the run (per process tree)
deny read of secret paths                          yes  yes (fanotify, exact paths) [this machine: decided by the decision plane in fmod_ret mode, not fanotify: a refusal reaches the agent as EACCES, with the reason in the record]
deny exec                                          yes  by path (`FAN_OPEN_EXEC_PERM`) [this machine: decided by the decision plane in fmod_ret mode, not fanotify: a refusal reaches the agent as EACCES, with the reason in the record]
deny network by host:port                          yes  yes, in-kernel per cgroup, IPv4/IPv6
[... 26 more rows of this table ...]

tier: cgroup
missing for bpflsm: lsm: bpf is not in the active LSM list (lockdown,capability,landlock,yama,apparmor)
fix: add lsm=lockdown,capability,landlock,yama,apparmor,bpf to the kernel command line (GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then update-grub) and reboot

ok   dashboard: the dashboard can tell which run a connection comes from
```

## From a release

After the first tag, `scripts/install.sh` will install both binaries from a release and verify them. It reads
`TEGO_VERSION`, `TEGO_PREFIX` (default `$HOME/.local/bin`) and `TEGO_VERIFY` (`auto`, `cosign`, `gh` or `sha256`), checks
the checksums and, when `cosign` or `gh` is present, who published them. It exits with 2 for a missing dependency, 3 for an
unsupported platform, 4 for an unsupported architecture, 5 when there is no such release, 6 for a failed download, 7 for a
checksum mismatch, 8 for a failed install step and 9 when the signature or provenance did not verify.

Until a release exists it exits 5 and says so. Do not fetch `install.sh` from a branch: the installer is the root of trust,
so take it from a tagged release.

### Check the installer first

The installer is a release asset, listed in the release's checksums file. That file is signed, so you can check the
script before it runs:

```sh
tag=v0.1.0
sums=tego_${tag#v}_checksums.txt
base=https://github.com/attention-span-ai/tego/releases/download/$tag
curl -fsSL -O "$base/install.sh" -O "$base/$sums" -O "$base/$sums.sigstore.json"
cosign verify-blob --bundle "$sums.sigstore.json" \
  --certificate-identity "https://github.com/attention-span-ai/tego/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$sums"
grep '  install\.sh$' "$sums" | sha256sum -c -
TEGO_VERSION=$tag sh install.sh
```

If `cosign` fails, or `sha256sum` does not print `install.sh: OK`, do not run the script. `install-maze.sh` is checked the
same way.

This shows that the script is the one the release workflow published at that tag. It protects you only if you check before
you run:

- Piping a script into `sh` skips it. Nothing can read a checksum before a piped script runs, so someone who replaces the
  asset replaces the checks inside it too.
- It says who built the file, not that the tagged code is good. Anyone who can push a `v*` tag can run the release workflow.
- `install-maze.sh` holds the `maze` archive to a sha256 from the same release, and checks no signature, so checking the
  script does not extend to what it downloads. `install.sh` does check who published the binaries, when `cosign` or `gh`
  is present.

When you pass a release binary on, keep `tego_<version>_licenses.tar.gz` with it: it holds the licence texts and the
third-party notices that `NOTICE` refers to. `install.sh` prints where that archive is. Each maze archive holds the
same notices.

## Uninstall

```sh
rm ~/.local/bin/tego ~/.local/bin/tego-control
```

Tego's data is in `~/.tego` (runs, the chain anchor, config). Remove it only if you no longer need the records. `tego gc` sweeps orphans and expires old runs.

## Containers

To run an agent under Tego in a container, see [user/container.md](user/container.md).

## Next

[QUICKSTART.md](QUICKSTART.md) runs your first agent.
