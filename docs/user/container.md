# Run agents under Tego in a container

From v0.1.1, every release tag publishes `ghcr.io/attention-span-ai/tego` for Linux amd64 and arm64 (v0.1.0 has no
image; build it yourself as below), built from this repository's
`examples/container/Dockerfile`. The [install guide](https://github.com/Attention-Span-AI/Tego/blob/main/docs/INSTALL.md#run-in-a-container)
shows how to verify a release's image digest and run it. The image holds `tego` and `tego-control` as static
binaries, an entrypoint that prepares the container for `tego run`, and an example agent.
`examples/container/compose.yaml` runs an agent under `tego run` and the dashboard (`tego-control serve`) on the
host's loopback. This page says what each setting is for, which tier works inside a container and which does not,
and how the record is kept.

The hello flow below was run by hand once under Docker (a Debian 13 guest, `docker.io` 26.1.5, `docker-default` AppArmor, cgroup v2): it ended at tier landlock with its chain verified, and `tego events <run> --verify` and `tego receipt <run>` read the record from a second container. Nothing on this page has been run by hand under Podman. CI's `container` workflow (`.github/workflows/container.yml`) builds and runs the image on every change; the last section lists what it checks and what nobody has checked yet.

## Quick start

For a local source build, from `examples/container/`, on a Linux host with cgroup v2 and Docker with BuildKit and the
compose plugin. `docker compose` is a package of its own where Docker comes from the distribution, and the first
command fails without it (`'compose' is not a docker command`):

| Docker from | Install |
| ----------- | ------- |
| Debian 13 | `sudo apt-get install docker.io docker-compose docker-buildx` (`docker-compose` is compose 2.26) |
| Ubuntu 24.04 | `sudo apt-get install docker.io docker-compose-v2 docker-buildx` |
| Docker's own repository | `docker-ce`, `docker-compose-plugin` and `docker-buildx-plugin`, as [Docker's install guide](https://docs.docker.com/engine/install/) says |

Your user also needs to be in the `docker` group (or use `sudo` for every `docker` line below).

```sh
export TEGO_UID=$(id -u) TEGO_GID=$(id -g)   # the dashboard answers only your own uid; see "The dashboard"
docker compose build                          # builds the image; the agent service does it, the dashboard uses it
docker compose run --rm agent tego machine check     # what this host gives the container
docker compose up agent                       # one run of the example agent
docker compose up -d control                  # the dashboard (needs the build above)
docker compose logs control                   # its link: http://127.0.0.1:8484/?t=...
```

Build first. The dashboard service does not build and never pulls: `tego:local` is no registry's name, so
`docker compose up -d control` on a machine that has not built stops with an error that names the missing
`tego:local`; run `docker compose build` and then the line again. The failed attempt leaves nothing to clean up: it
made the network and the three empty volumes, and the later `docker compose up` fills and uses them (checked on Debian 13
with docker.io 26.1.5, where the dashboard printed its link two seconds after the start).

The image built here compiles the source of your checkout, which is not a release, so `tego version` inside it prints
`tego=dev commit=none`. The published image prints the release's version; to be sure of a release, run that one, by
the digest the release notes give ([the install guide](https://github.com/Attention-Span-AI/Tego/blob/main/docs/INSTALL.md#run-in-a-container)).

`docker compose up agent` runs `tego run /usr/local/share/tego/hello.yaml`: the hello agent writes
`/work/out/hello.txt`, tries to write `/work/outside.txt`, is refused, and the run ends with
`tego run: <run> ended (exited with code 0) · tier landlock · refused 1 ... · chain verified`. To run your own
agent, mount its contract and its files and set `TEGO_CONTRACT` to the contract's path in the container; build with
`--build-arg EXTRA_PACKAGES="python3 nodejs npm ..."` (or the same `EXTRA_PACKAGES` variable for compose) for the
programs it needs. A program being installed allows nothing: the contract's `exec.allow` still decides what may run.
`examples/agents/` has contracts for Claude Code, Codex and agents of your own.

Every `docker compose run` is a new container with a host id of its own, which `tego doctor` shows in its ledger line:
in a second container it calls your earlier runs in the shared ledger "minted on host `<id>`, not this one". They are
yours; the line says that no sweep in this container ends or repairs them, and `tego gc` removes them only past
retention.

## What the image holds

| Path | What it is |
| ---- | ---------- |
| `/usr/local/bin/tego`, `/usr/local/bin/tego-control` | The matched pair: static, not PIE, BPF objects embedded, `tego-control`'s SHA-256 pinned in `tego` (`tego serve` hands off only to that file). |
| `/usr/local/bin/tego-entrypoint` | The entrypoint (`examples/container/tego-entrypoint.sh`), below. |
| `/etc/tego/config.yaml` | The machine config: `ledger_root: /var/lib/tego/runs` and `lsm.list_file: /run/tego-lsm/lsm-list`. Root's, mode 0644, as tego's trust check wants. |
| `/run/tego-lsm/lsm-list` | The list of the kernel's active security modules, which the entrypoint writes as root at each start ([below](#held-file-opens-and-the-list-of-security-modules)). Not in the image: it appears when the container starts. |
| `/home/tego` | The home of the user `tego` (uid 10001 unless built with `TEGO_UID`), which every run is started as. `~/.tego` holds the chain anchor (`chain.log`) and tego's own log. |
| `/var/lib/tego/runs` | The ledger. |
| `/work` | The agent's working folder; `/work/out` is the one the example contract lets it write. |
| `/usr/local/share/tego/` | `hello.yaml`, `hello-agent.sh` and `smoke.sh` (the image's own check). |

The `binaries` target is the two binaries on an empty base, for an agent image of your own:
`COPY --from=<that image> /usr/local/bin/tego /usr/local/bin/tego-control /usr/local/bin/`. Copy both, side by side:
`tego serve` refuses a `tego-control` whose hash is not the one it was built with. Your image then needs what this
page says the entrypoint does, or that entrypoint itself.

The base images are pinned by digest (`golang:1.27.4-trixie`, the Go of `go.mod`, and `debian:trixie-slim`), and
Dependabot proposes their updates.

Published images copy the original release binaries after signature, checksum, reproduction and control-pin checks.
Local builds compile them from source with the release's flags. The binary reproduction requirement stays the same;
the complete Debian image is not claimed reproducible ([release runbook](../VERSIONING.md#5-releases)). The published
image uses uid/gid 10001; build locally with your own uid/gid for the dashboard as above.

## What the entrypoint does

`tego run` makes a cgroup for every run, at every tier: the run's limits are written there, and a stop empties it
with `cgroup.kill`. An unprivileged `tego` makes those cgroups only where systemd would delegate a subtree to the
user, `user.slice/user-<uid>.slice/user@<uid>.service`, and only when it runs inside that subtree itself. A container
has no systemd user manager, so the entrypoint, started as root, builds the same shape in the container's own cgroup
namespace and then gives everything up:

1. It checks that `/sys/fs/cgroup` is cgroup v2 and that the container has a private cgroup namespace
   (`/proc/self/cgroup` reads `0::/`). In the host's namespace it would be editing the host's tree, so it refuses.
2. Docker mounts `/sys/fs/cgroup` read-only in a container that is not privileged; the entrypoint remounts it
   read-write.
3. It moves every process of the namespace root into `/init` (cgroup v2 lets a cgroup other than the system's root
   offer controllers to its children only while it holds no process), enables `cpu`, `memory` and `pids` down the
   path, makes `user@<uid>.service/init.scope`, moves itself there, and gives the service directory and its
   `cgroup.procs`, `cgroup.subtree_control` and `cgroup.threads` to the `tego` user, which is what systemd's
   `Delegate=` hands over.
4. It hands `~tego/.tego`, `/var/lib/tego/runs` and `/work` themselves (not their contents) to the user, for a bind
   mount of a host folder that belongs to someone else, and makes `/run/user/<uid>` the user's `XDG_RUNTIME_DIR`, as
   a login session would (tego keeps a Codex run's `CODEX_HOME` there and refuses such a run without one).
5. It reads the list of the kernel's active security modules, which the container usually cannot read once it is the
   user, and writes it to `/run/tego-lsm/lsm-list` as root, with this boot's id, so that Tego can hold file opens
   ([Held file opens](#held-file-opens-and-the-list-of-security-modules)). Where it cannot read the list it says why.
6. It becomes the user with `setpriv`: the user's uid, gid and groups, no inheritable, ambient or bounding
   capabilities, and `no_new_privs`. Neither `tego` nor the agent holds any capability the container was given.

`TEGO_DELEGATE=auto` (the default) says why when step 1, 2 or 3 cannot be done and starts the command anyway, so
`tego machine check` can show what the host gave; `yes` stops the container instead; `no` skips the cgroup steps.
`TEGO_LSM_LIST` does the same for step 5: `auto` (the default) says why when the list could not be read and starts
anyway, `yes` stops the container, `no` leaves `/run/tego-lsm/lsm-list` alone. Started as
any user other than root (`docker run --user`, compose's `user:`), the entrypoint does nothing and runs the command
as given; the dashboard service starts that way.

A process started later in the same container (`docker compose exec agent tego-entrypoint tego run <contract>`) is
found in `/init`, where the runtime puts it beside PID 1, and joins the subtree the first start built. Without
`tego-entrypoint` in front, `docker exec` runs the command as root outside the subtree, and `tego run` refuses.

## Tiers inside a container

Tego's three tiers need different things from the host and from
the container. Only tier landlock has been tried in the image; the table says what each of the others would
need and that no run has shown it working.

| Tier | Host | Container | State |
| ---- | ---- | --------- | ----- |
| landlock (1) | Linux 5.14 or later (`cgroup.kill`), Landlock in the LSM list (ABI 2 or later), cgroup v2, Yama `ptrace_scope` 0 or 1 | compose.yaml's agent service: private cgroup namespace; `SYS_ADMIN`, `SYS_PTRACE`, `CHOWN`, `SETUID`, `SETGID`, `SETPCAP` for the entrypoint; `apparmor=unconfined` where AppArmor runs; `no-new-privileges` | CI runs `tego machine check --require landlock`, `tego machine test` and a hello run in it |
| cgroup (2) | The same, plus BPF (`CONFIG_BPF_SYSCALL`, BTF) and fanotify | `tego` itself as root with `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, and a seccomp profile and AppArmor that let `bpf(2)` and `fanotify_init(2)` through: in practice a privileged container | Not shown to work. The entrypoint's `TEGO_LAUNCHER=root` is an experiment CI runs, report-only |
| bpflsm (3) | `bpf` in the kernel's active LSM list, which only the host's boot line sets | Everything tier 2 needs. BPF LSM programs attach to the whole kernel and pick their runs by cgroup, so a container allowed to load them has power over the host | Not shown to work; same experiment |

### Tier landlock: each setting and what it buys

This section is about the tier tried in the image, landlock.

- `cgroup: private`: the entrypoint builds the subtree only in the container's own cgroup namespace.
- `cap_add: [SYS_ADMIN, ...]` with `cap_drop: [ALL]`: the capabilities are the entrypoint's, for setting up, and
  Docker's seccomp profile reads them too. Measured on Docker's default profile (moby v27.3.1,
  `profiles/seccomp/default.json`): it answers `clone3` with `ENOSYS` unless the container has `CAP_SYS_ADMIN`, and
  `tego` starts every agent with `clone3(CLONE_INTO_CGROUP)`; it allows `pidfd_getfd` only to a container with
  `CAP_SYS_PTRACE`, and tego's supervisor takes the agent's seccomp listener with `pidfd_getfd`. The same profile
  allows the Landlock and `seccomp` syscalls to every container. After the entrypoint, no process holds any of
  these capabilities; the syscalls stay open because a seccomp profile is fixed when the container starts. A
  profile of your own that allows `clone3` and `pidfd_getfd` unconditionally would let `SYS_PTRACE` go; `SYS_ADMIN`
  stays for the remount.
- `security_opt: apparmor=unconfined`: AppArmor's `docker-default` profile denies every mount, the remount included.
  A profile of your own that allows only that remount (the entrypoint tries `mount -o remount,bind,rw` first, then
  `mount -o remount,rw`) could replace it; none has been written or tried. Hosts without AppArmor ignore the option. SELinux hosts have not been tried: the container type may need write access to
  cgroupfs.
- `security_opt: no-new-privileges:true`: nothing in the container gains a privilege through a setuid file.
- `init: true` and `stop_grace_period: 40s`: `docker-init` reaps what the agent leaves and passes `SIGTERM` to
  `tego`, which stops the run within `stop_grace` (10 s by default) and records its end.
- Sysctls: none in the container. The ones that matter are the host's: `kernel.yama.ptrace_scope` must be 0 or 1
  (at 2 the supervisor would need `CAP_SYS_PTRACE`, which the entrypoint drops; at 3 nothing can read the agent).

On Docker's defaults (no capability added, `docker-default`), the entrypoint says the cgroup mount is read-only
(`tego-entrypoint: no delegated cgroup subtree: /sys/fs/cgroup is read-only and could not be remounted read-write: ...`),
and `tego run` refuses before it starts the agent, exit 125:
`<contract>: no enforcement tier available on this machine [tier-unavailable] missing for landlock: cgroupv2: cgroup: no delegated cgroup v2 subtree for uid 10001 (tried /sys/fs/cgroup/user.slice/user-10001.slice/user@10001.service): statfs(...): no such file or directory; fix: in a container there is no systemd to delegate a cgroup subtree: Tego needs what the example image's entrypoint and examples/container/compose.yaml give it: ...`.
The reason is the one the entrypoint printed above it. Tego knows it is in a container from `/.dockerenv` (Docker),
`/run/.containerenv` (Podman) or a `container` variable in process 1's environment, none of which a host has, and
where systemd runs as process 1 (LXC, systemd-nspawn) it keeps the host's advice, which is true there. In a container
the `fix:` names the same things this page does: the delegated cgroup subtree the entrypoint makes (`cgroup: private`
and `SYS_ADMIN` to remount `/sys/fs/cgroup` read-write), `apparmor=unconfined` where AppArmor runs, and the kernel's
list of security modules handed in at `/run/tego-lsm/lsm-list`. `tego doctor`, `tego machine check` and `tego run` say it, once per
report, and never tell you to edit a systemd unit or a WSL setting here. `tego start` and `tego setup` look for a user
session, which a container does not have: they refuse under their own names, say so, and point to the same settings
and to `tego run`. A Kubernetes pod under containerd has none of the three marks and so keeps the host's words. Were the
cgroup there, `clone3` would fail with `ENOSYS` and tego says so, naming the outer seccomp profile (moby#42680).
`--privileged` works around all of it and gives the container everything; it is not what this image asks for.

### A warning about protected-file storage

The image's binary may stay on overlay when its host layer folders are absent inside the container or named relative
to a folder the mount table does not record. A binary on FUSE, eCryptfs, aufs or shiftfs has the same stated backing
limit. These alone refuse no write or ask grant; Tego does not guess a relative layer's base folder. Absolute layers
of the same overlay remain protected. When a FUSE or eCryptfs filesystem holds a protected regular file, its existing
absolute source directory joins the protected closure with visible aliases; grants at, over or inside it refuse.
Source text cannot establish backing identity and clears neither filesystem's backing warning. Mount and layer coverage follows the
[compile-time mount boundary](../adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary);
unreadable mapped candidate identity refuses the grants concerned. Root-owned merged paths give no assurance about
hidden layers. With any of these backing limits, including a FUSE/eCryptfs mount holding another protected regular file, compile emits one
`[overlay-backing-unknown]` warning per write or ask entry that meets a visible storage mount. Relative layers
and unnamed backing exclude only their own filesystem device, so another binary's device does not hide a backing
folder. These pre-existing backing classes exclude the shared inventory's kernel interfaces and memory directory storage; regular-file binds
established by live checks can still warn on memory filesystems. The absent-only rule also excludes discovered binary overlay devices. Runtime storage or a backing folder on a memory filesystem
also mounted at a writable directory gets no warning (GAPS C65). Unlinked protected backing also warns on its own
device and on memory directory storage, excluding kernel interfaces. Unlinked directories remain uncertain and
refuse reaching write and ask grants. A single-file mount is exempt only for absent
or relative overlay backing, after live snapshot-bound mount ID, type and size checks and comparison
with every affected protected regular file. A nonempty byte-identical alias refuses, executable or not. Two empty files
prove neither identity nor difference and warn without a byte-alias refusal. FUSE/eCryptfs file binds keep the
warning because their stored bytes can differ from visible bytes. Unreadable protected files and unidentified or
changed mount points give no file-bind exemption. The captured Docker `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf`
binds stay quiet in the overlay classes when live checks pass. In the captured Podman FUSE layout, ordinary
project grants reach no file binds and stay quiet; a grant reaching a file bind warns once, including empty
`/run/.containerenv`. The warning names the grant, mount and each protected file directly on unnamed backing, including
a config layer or a contract on sshfs even when Tego is on ext4, because Tego
cannot tell whether that mount shows the folders holding its protected files, and names the reason for relative layers or
unnamed filesystem backing. Keep runtime storage and the whole host filesystem out of writable places. For unnamed
backing, keep the folder storing encrypted or mirrored files out of every write grant. Ordinary workspace volumes still compile. Every active
protected path and the directories its walk reads must still have mount identity, except that a walk across an
unlinked-root mount has unplaced backing with the conditional warning above. A plain-folder chroot whose root is
not a mount point has no `/` mount row, so every write and ask grant is refused. Compile and `tego machine check` explain
that the kernel does not show the filesystem under that root; bind the folder onto itself before entering it or
run Tego outside that root. The captured nspawn table keeps all 19 baseline contracts: its unlinked file mounts
still undergo live type, inode and snapshot mount-ID checks on both the mounted and protected files before
comparison by device and inode. Established absence or a nonregular protected target needs no comparison. An
identity read error, failed holding-mount lookup, mount-ID mismatch or missing identity refuses reaching write
and ask grants. Unlinked directories retain alias uncertainty for read-denial startup. Doctor names the mount
and says it cannot tell whether the folder is visible under another name, while retaining known alias warnings.
A former unlinked name is never used to infer a path alias. Nspawn and both chroot runtime checks are owed in a guest.
The placed-root container fixture keeps all 19 baseline
contracts; the workspace-volume fixture warns on exactly 11 of them. Without a storage mount meeting a grant
there is no backing warning; an ordinary overlay grant can still print a separate mount advisory. Runtime
tables replay 2026-11-12 captures from Docker 29.1.3 (overlay2 and its default containerd image store),
containerd 2.2.1, and rootless Podman 4.9.3 with fuse-overlayfs 1.13 on kernel 6.8.0-147-generic.
Containerd's relative lowers keep absolute upper/work; the real FUSE type is `fuse.fuse-overlayfs`.
These are compilation checks; this branch's real container reruns are
owed in a guest; GAPS C65 records this limit.

### A secret inside the work folder

A `.env` (or another `deny_read` target) inside a folder the agent writes, such as `/work/.env` under
`fs.write: ["/work/"]`, makes a tier landlock run hold its reads (`fs.reads: auto`, ADR 0069): the open deputy completes
every read and the supervisor refuses the secret by its identity, under any name the agent gives it. That needs the
secret, its folder and every protected folder on a local filesystem whose changes the kernel reports and whose files
keep their identity: ext4, xfs, btrfs, f2fs, bcachefs, tmpfs, ramfs and a few read-only ones. The folders above them
may also be overlayfs, which is what a container's `/` is.

- **Works:** `/work` as a named volume (compose.yaml's `tego-work`, Docker's `local` driver keeps it on the host's
  filesystem) or a bind mount of a host folder on a local filesystem (`./project:/work`).
- **Refused at launch:** a project copied into the image or written to the container's writable layer (it is on the
  overlay itself, whose copy-up renumbers files), and a work folder on NFS, CIFS, FUSE (Docker Desktop's file sharing
  on macOS and Windows, sshfs) or another filesystem that is not on the list: the run stops before the agent starts,
  with `held-read stable identities/replacement events unavailable on filesystem 0x...` naming the folder. Use a
  named volume, keep the secret out of the folder the agent writes, or set `fs.reads: direct` (the target is then
  unenforced at tier landlock, as compile warns).
- **Keep the mounts as they were at launch.** Unmounting or remounting the work volume, or mounting over the project,
  while the run is alive makes tego refuse every held read for the rest of the run (`held-read-identity-unknown`):
  restart the run after such a change.

### Held file opens and the list of security modules

A run holds file opens when its contract says `gate.completion: held`, asks about reads (`fs.ask_read`), or holds its
reads (`fs.reads`, which a `.env` inside a writable folder turns on, as above). Tego then opens each file itself on
the agent's behalf, and before it does it learns which security modules are active on the machine (AppArmor, SELinux,
Smack, TOMOYO) and compares the agent's label with its own. The list is read by `lsm_list_modules(2)` (Linux 6.8 and
later), where that fails from the file `/sys/kernel/security/lsm`, and where that fails too from the list file the
machine config names (`lsm.list_file`, below). **When none can be read, every held open is
refused** (`held-label-unavailable`, errno `EACCES`) and the run says so at launch (`[held-label]`) and in `tego
doctor` (`FAIL lsm: doctor: cannot read the active LSM list: ...`). That is deliberate: without the list Tego cannot
know that no module labels the agent's task differently from its own, and a label it does not compare could admit an
open the agent's own would not get. Nothing is opened that should not be; the run loses the held opens, and a dynamic
program under held reads can then fail loading its libraries.

What a container can read, as measured on Debian guests with `docker.io` 26.1.5, under the image's entrypoint or without:

| Host kernel | Container settings | What the container itself reads | Held opens |
| ----------- | ------------------ | ------------------------------- | ---------- |
| Debian 13 (6.12) | Docker's default seccomp profile and `docker-default` AppArmor | `lsm_list_modules(2)` answers `ENOSYS` (the profile does not know the call), and `/sys/kernel/security/lsm` is not there: the container's own sysfs has no securityfs | Refused, unless the list is handed in (below), and on Debian the TOMOYO and AppArmor facts too |
| Debian 13 (6.12) | `--security-opt seccomp=unconfined` (or a profile that allows `lsm_list_modules`) | The syscall reaches the kernel and answers. | Work, subject to the TOMOYO and AppArmor facts (below) |
| Debian 12 (6.1) | Docker's defaults | `lsm_list_modules(2)` answers `ENOSYS` (this kernel has no such call), and `/sys/kernel/security/lsm` is not there | Refused, unless the list is handed in, and on Debian the TOMOYO and AppArmor facts too |

**Handing the list in.** The one process in the container that can still read the list is the entrypoint, because it
starts as root, with the `SYS_ADMIN` capability and without AppArmor's `docker-default` profile that compose.yaml gives
it. It reads the kernel's list (mounting securityfs read-only on a private directory for the moment, since the
container's own `/sys` has none), writes it to `/run/tego-lsm/lsm-list` and only then becomes the `tego` user. The image's
`/etc/tego/config.yaml` names that file as `lsm.list_file`, so the documented flow needs nothing more from you:

```yaml
lsm:
  list_file: /run/tego-lsm/lsm-list
```

(`lsm.list_file` is read from `/etc/tego/config.yaml` only; a user's own config that sets it is ignored with a warning.)
The file has a directory of its own, `/run/tego-lsm`, and not `/run/tego`: the entrypoint makes the list's directory mode
0755 at every start, and `/run/tego` is Tego's host state directory, which a root `tego` (`TEGO_LAUNCHER=root`) opens only as
root's and mode 0700. Do not give `/run/tego-lsm` to a volume the agent can write: the file is refused there.
Tego uses the file only when the call and `/sys/kernel/security/lsm` both failed, and believes it only when it is what
root wrote in this boot, checked again at every open:

- it and every directory above it belong to root and cannot be written by anyone else, and no part of the path is a link;
- it is a regular file on the container's own filesystem (not FUSE, NFS, 9p or another network filesystem);
- it has exactly the three lines the entrypoint writes: the format name, the **boot id** of the running kernel, and the list
  (so a file left from an earlier boot, copied from another machine or baked into an image is refused as stale), and a
  list whose names are the ones the kernel prints, with `capability` among them;
- the task the open is for is not root and holds none of `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER` or `CAP_SYS_ADMIN` in its
  permitted set (the effective set is not enough to look at: a task could rewrite the file and then drop what is effective),
  which could rewrite or replace the file. The entrypoint's `setpriv` leaves the agent none of them.

A file that fails one of these is refused with the reason, and held opens stay refused. The file is never used to decide a
tier: `tego doctor`'s `lsm` row then reads `skip lsm: ... held file opens read this list`, and says that whether `bpf` is
active is unknown. Where the kernel's own answer is readable, the file is not read at all.

Without this entrypoint (your own image, `docker run` as root, a shell in the container), two other ways give Tego the list:

- bind the host's list into the container read-only, at a path outside `/sys/kernel/security`, and name that path:
  `docker run -v /sys/kernel/security/lsm:/run/tego-kernel-lsm:ro ...` with `lsm: {list_file: /run/tego-kernel-lsm}` in
  `/etc/tego/config.yaml`. Tego accepts it only as the host's securityfs file `lsm` on a read-only mount, so another file bound
  there, a copy and a writable bind are refused;
- write the file yourself as root before the agent starts, in the format of `examples/container/tego-entrypoint.sh`.

**The list is not the only fact a held open reads.** Debian's kernels, and Ubuntu's, run AppArmor, and Debian's run TOMOYO,
next to the modules that need no check, and a held open compares what those two say about the agent's task with what they say
about Tego's own opener. A container cannot read either from its own `/sys`, so on such a host, with the list handed in, the
held opens are still refused until the other two are given (each refusal says which):

- **TOMOYO:** bind the host's TOMOYO files read-only and name them in the machine config
  (`-v /sys/kernel/security/tomoyo:/run/tego-tomoyo:ro`, and `tomoyo: {facts_dir: /run/tego-tomoyo}` next to `lsm.list_file`
  in `/etc/tego/config.yaml`; [the operations guide](../OPERATIONS.md) has the checks Tego makes of that bind). The image's
  config does not name it, because most hosts do not run TOMOYO: mount your own config over the image's.
- **AppArmor:** the namespace depth the comparison needs cannot be read in a container, so the contract carries the
  administrator's assertion that the container sits in the root policy namespace, `fs: {apparmor_assume_root_namespace: true}`
  (accepting the hidden-ancestor risk the operations guide describes). With neither a readable
  `/sys/kernel/security/apparmor/.ns_level` nor the assertion, the held opens are refused.

On a host that runs neither (check the `lsm` line of `tego doctor` on the host, or `cat /sys/kernel/security/lsm`), the list
alone is enough.

If the entrypoint cannot read the list either (it prints `tego-entrypoint: no security-module list handed in: ...`), there
is nothing to hand in, and the fix is the compose file's settings: `cap_add: [SYS_ADMIN]` and `security_opt:
[apparmor=unconfined]` let it mount securityfs, and a host kernel 6.8 or later with a seccomp profile that allows
`lsm_list_modules` lets Tego read the list itself. Otherwise the choices are a contract that holds no opens (no
`gate.completion: held`, no `fs.ask_read`, and for a secret inside the work folder `fs.reads: direct`, which leaves that
target unenforced at tier landlock as compile warns). Tego does not guess the list from the boot line, `/proc` or the
kernel log for this decision: the boot line does not say which modules started, the per-task `/proc/<pid>/attr` directories
are fixed when the kernel is built and TOMOYO shows no label there, and the kernel log can be restricted or overwritten.
The note at launch names what each way answered, and offers only the options that exist for that answer.

### Tiers that need root

Both root tiers need `tego` to run as root (`sudo "$(command -v tego)" run` on a
host) with `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, and attach BPF programs whose reach is the kernel, not the
container. A container that can run them can change the host, so treat it as the host. `TEGO_LAUNCHER=root` makes
the entrypoint keep `tego` root with the container's capabilities, empty the namespace root into `/init` with its
controllers on (a root `tego` makes `tego.slice` there), and name the `tego` user in `SUDO_UID` so the agent runs as
that user. CI tries it in a `--privileged` container with `tego machine check --require cgroup` and a hello run at each root
tier, report-only. Until such a run has passed, run the root tiers on the host itself (`sudo "$(command -v tego)" run`), not in a
container.

## The ledger and the chain anchor

Each run's record is a hash chain in the ledger, and its last hash is appended to the chain anchor,
`~/.tego/chain.log` of the user the run belongs to. `tego events <run> --verify` checks the chain against the
anchor; the anchor is what tells a ledger cut short, or rewritten from some line on, from the one that was written.
compose.yaml keeps the two apart:

- `tego-ledger` on `/var/lib/tego/runs` (`ledger_root` in the image's machine config);
- `tego-state` on `/home/tego/.tego`: the anchor and tego's own log.

Why the anchor lives outside the run's container, on a volume of its own:

- **A container's writable layer goes with the container.** An anchor kept there is gone after
  `docker compose down` or a new image, while the ledger on its volume stays; every later `--verify` then has nothing
  to check against and cannot tell a truncated ledger from a whole one.
- **One volume is one thing to tamper with.** Whoever can write the ledger's volume (a backup restore, a log shipper,
  another container that mounts it) could rewrite a run and its anchor line in step if they shared it. The dashboard
  mounts the anchor read-only for the same reason.
- **The agent cannot reach either.** Inside the container the agent runs under `tego run`, which refuses it
  `~/.tego` and the ledger whatever the contract says (agent-contract R6a and R10: no run reads or writes tego's own
  directory or the ledger root). The volumes guard what the agent cannot: the container's life and the people and
  tools around it.

For more than that, copy `chain.log` somewhere the server cannot write: it is a few bytes a run, one line each. A root
user on the host can rewrite both volumes; no file layout on that host changes that.

To check a run from outside the container it ran in:
`docker compose run --rm --no-deps agent tego events <run> --verify` (the service mounts both volumes).
With plain `docker run`, give the same two volumes and the image's user, which owns the anchor. The published image's
user is 10001:10001; an image you built as the Quick start says has your own uid and gid, the `TEGO_UID` and `TEGO_GID`
you exported (a different `--user` is refused with `permission denied` on the run's `events.jsonl`). For the published
image:

```sh
docker run --rm --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
  -v tego-state:/home/tego/.tego -v tego-ledger:/var/lib/tego/runs \
  "$image@$digest" tego events <run> --verify
```

For the image `docker compose build` made (`tego:local`; the volumes are compose's, named after the project, so
`tego_tego-state` and `tego_tego-ledger`):

```sh
docker run --rm --user "$TEGO_UID:$TEGO_GID" --cap-drop ALL --security-opt no-new-privileges:true \
  -v tego_tego-state:/home/tego/.tego -v tego_tego-ledger:/var/lib/tego/runs \
  tego:local tego events <run> --verify
```

It prints `<run>: verified N lines, run_start to run_end, head ..., anchored in /home/tego/.tego/chain.log` and exits 0.
`tego receipt <run>` reads the same way. A run started without the `tego-state` volume has its anchor in the container's
own layer, and a verify from another container has no anchor to check against. `tego status --all` lists the runs.

## The dashboard

`docker compose up -d control` (after `docker compose build`) starts `tego-control serve --addr 127.0.0.1:8484`
(`TEGO_DASHBOARD_ADDR` changes it), and `docker compose logs control` shows its link. The dashboard listens on a loopback address only, so the service
runs on the host's network (`network_mode: host`): `127.0.0.1` is then the host's own, and a published port could
not reach a container's loopback anyway. From another machine, forward the port over SSH
(`ssh -L 8484:127.0.0.1:8484 server`) as the account whose uid the image was built with.

The dashboard answers only a browser whose socket is owned by its own uid (other users get 403 before the token is
looked at). It runs as the `tego` user, so build the image with `TEGO_UID=$(id -u)` of the person who opens it; with
the default 10001 nobody on the host can sign in.

What the dashboard service can and cannot do in its container:

- It reads the ledger and checks every chain against the anchor, which it mounts read-only.
- It refuses every change (Allow, Deny, Stop, Block, a rule change) unless it can place the asking socket in the
  cgroup tree, which it cannot inside a private cgroup namespace (ADR 0123). The service therefore runs in the
  host's (`cgroup: host`); it sees the host's cgroup tree read-only.
- Stop, Pause and the answers to a waiting request act on the run's launcher by pid. In its own pid namespace the
  dashboard cannot reach it. To act on live runs, uncomment `pid: "service:agent"` in compose.yaml; the agent
  container must then be running before the dashboard starts, and be started again with it.
- A rule change writes the contract file. The example contract is in the image, read-only; mount your contracts
  from a volume or a host folder to change them from the dashboard.

## Podman and Kubernetes

Not tried. Podman reads compose.yaml (`podman compose`); its default seccomp profile, its cgroup mount and its
`--cgroupns` default may differ from Docker's, and `tego machine check` in the container says what is missing. On
Kubernetes the agent container needs what compose.yaml's agent service has: a private cgroup namespace (the default
with cgroup v2 and containerd), the six capabilities, a seccomp profile that allows `clone3` and `pidfd_getfd`, and
AppArmor that allows the remount, with a `securityContext` that starts the entrypoint as root.

## What is verified, and what is not

Verified without a container runtime:

- The Dockerfile's build stage, run as written against a copy of the repository with the image's ignore file
  applied: the pair builds, `check-control-pin.sh` passes, both binaries are static and print one version.
- The hello contract and `smoke.sh` with the same binaries outside a container: `tego machine check`, `tego machine test`, and a
  run with one write allowed, one refused, and its chain verified against the anchor.
- The entrypoint's cgroup steps on a real cgroup v2 tree, as an unprivileged user inside a delegated systemd scope
  standing for a container's namespace root: processes moved, controllers enabled down the path, the subtree's files
  handed over, itself moved, and the later join.
- `examples/container`'s tests: the entrypoint over a stand-in tree (every refusal included), the compose settings,
  the Dockerfile's digests and Go version, and the hello contract's verdicts through `tego rules check --test`.
- The hand-in of the security-module list: the entrypoint over a stand-in tree (the kernel's file, securityfs mounted for a
  moment, every case it cannot read, a stale file removed), and Tego's reader of the file against every way a file can be
  wrong (another owner, group- or other-writable, a link, a stale boot id, a task that could rewrite it).
- `shellcheck` over the scripts and `actionlint` over the workflow.

What CI's `container` workflow checks first, on GitHub's ubuntu-24.04 runner: the image builds; `tego machine check
--require landlock` and `smoke.sh` pass with compose.yaml's settings; `docker compose up agent` exits 0; the
dashboard answers the runner's own curl on the host's loopback, lists the hello runs, and refuses a request from
another uid with 403. Report-only, it records `docker exec` through the entrypoint, the image on Docker's defaults,
and the root launcher in a privileged container.

A secret inside the work folder, without a container runtime (KVM guest, as root,
`TestHeldOpenDifferentialAcrossMounts/held-read-container-workspace`): an overlayfs mounted as the container's root with
a local directory bind-mounted into it as the work folder starts held reads and refuses a nested `.env` after a
rename; a project on the overlay itself is refused at launch. No Docker container has run it.

Not verified anywhere yet: the remount and the delegation inside a real Docker container (CI is the first run); the
entrypoint's mount of securityfs and the held opens that then work, on Debian 12 and 13 under Docker's defaults (a guest
run is owed), and the bind of the host's list under `docker-default`;
Podman, Kubernetes, SELinux hosts and arm64 images; the dashboard's changes and live-run actions from its container;
running tego as root in a container (`TEGO_LAUNCHER=root`).

## When it does not work

| The container says | It means | Do |
| ------------------ | -------- | -- |
| `tego-entrypoint: no delegated cgroup subtree: /sys/fs/cgroup is read-only and could not be remounted` | No `CAP_SYS_ADMIN`, or AppArmor's `docker-default` | compose.yaml's `cap_add` and `security_opt` |
| `... this container shares a cgroup namespace` | `--cgroupns=host` | `cgroup: private` (`--cgroupns=private`) |
| `... is not a cgroup v2 hierarchy` | A cgroup v1 or hybrid host | Boot the host with cgroup v2 (`systemd.unified_cgroup_hierarchy=1`) |
| `tego run: ... clone3 is being filtered` | The seccomp profile refuses `clone3` | `CAP_SYS_ADMIN` in the container, or a profile that allows it |
| `the host's security modules could not be read (lsm_list_modules(2) ...); a file open that tego checks and makes for the agent is refused ...` or `held-label-unavailable` in the record | The container can read neither `lsm_list_modules(2)` (Docker's default seccomp profile refuses it or does not know it; kernels before 6.8 lack it) nor `/sys/kernel/security/lsm` (a container's own `/sys` has no securityfs), and no list was handed in or the one named was refused (the note says why: another boot, writable by the agent, not root's, and so on) | [Held file opens and the list of security modules](#held-file-opens-and-the-list-of-security-modules): run the image's entrypoint as root with compose.yaml's settings, or bind the host's list |
| `tego machine check`: `FAIL landlock` | The host kernel has no Landlock in its LSM list | Add `landlock` to the host's `lsm=` boot line |
| `tego machine check`: `yama ptrace_scope=2 without CAP_SYS_PTRACE` | The host's Yama setting | Set the host's `kernel.yama.ptrace_scope` to 1 |
| `held-read stable identities/replacement events unavailable on filesystem 0x794c7630` | A secret the agent's write entry holds (a `.env` in the project) lies on the container's own layer (overlayfs, `0x794c7630`) or another unsupported filesystem | Put the project on a named volume or a bind mount of a local folder ([A secret inside the work folder](#a-secret-inside-the-work-folder)) |
| The dashboard says 403 to your browser | The image's `tego` uid is not yours | Build with `TEGO_UID=$(id -u) TEGO_GID=$(id -g)` |
| `tego machine check`: `warn dashboard: the kernel answers no TCP socket lookup` | The host has not loaded `inet_diag` and `tcp_diag`; tego-control refuses every dashboard action until it is loaded | On the host: `sudo modprobe tcp_diag` (and add it to /etc/modules-load.d) |


Root tiers, which need root, also require the kernel's initial process-id namespace, as the backends already do. A
container with a private process-id namespace cannot use cgroup or bpflsm solely by adding capabilities or `bpf`
to the LSM list. Doctor names that reason before loading root-tier probes. Auto may select landlock when its
other requirements pass; an explicitly selected root tier refuses. This does not relax the separate private-cgroup-
namespace guard on person-facing setup, approvals, scans or dashboard access.
