# Run agents under Tego in a container

Every release tag publishes `ghcr.io/attention-span-ai/tego` for Linux amd64 and arm64, built from this repository's
`examples/container/Dockerfile`. The [install guide](https://github.com/Attention-Span-AI/Tego/blob/main/docs/INSTALL.md#run-in-a-container)
shows how to verify a release's image digest and run it. The image holds `tego` and `tego-control` as static
binaries, an entrypoint that prepares the container for `tego run`, and an example agent.
`examples/container/compose.yaml` runs an agent under `tego run` and the dashboard (`tego-control serve`) on the
host's loopback. This page says what each setting is for, which tier works inside a container and which does not,
and how the record is kept.

Nothing on this page has been run by hand under Docker or Podman. CI's `container` workflow (`.github/workflows/container.yml`) is the first place the image is built and
run; the last section lists what it checks and what nobody has checked yet.

## Quick start

For a local source build, from `examples/container/`, on a Linux host with cgroup v2 and Docker with BuildKit and the
compose plugin:

```sh
export TEGO_UID=$(id -u) TEGO_GID=$(id -g)   # the dashboard answers only your own uid; see "The dashboard"
docker compose build
docker compose run --rm agent tego doctor     # what this host gives the container
docker compose up agent                       # one run of the example agent
docker compose up -d control                  # the dashboard
docker compose logs control                   # its link: http://127.0.0.1:8484/?t=...
```

`docker compose up agent` runs `tego run /usr/local/share/tego/hello.yaml`: the hello agent writes
`/work/out/hello.txt`, tries to write `/work/outside.txt`, is refused, and the run ends with
`tego run: <run> ended (exited with code 0) · tier landlock · refused 1 ... · chain verified`. To run your own
agent, mount its contract and its files and set `TEGO_CONTRACT` to the contract's path in the container; build with
`--build-arg EXTRA_PACKAGES="python3 nodejs npm ..."` (or the same `EXTRA_PACKAGES` variable for compose) for the
programs it needs. A program being installed allows nothing: the contract's `exec.allow` still decides what may run.
`examples/agents/` has contracts for Claude Code, Codex and agents of your own.

## What the image holds

| Path | What it is |
| ---- | ---------- |
| `/usr/local/bin/tego`, `/usr/local/bin/tego-control` | The matched pair: static, not PIE, BPF objects embedded, `tego-control`'s SHA-256 pinned in `tego` (`tego serve` hands off only to that file). |
| `/usr/local/bin/tego-entrypoint` | The entrypoint (`examples/container/tego-entrypoint.sh`), below. |
| `/etc/tego/config.yaml` | The machine config: `ledger_root: /var/lib/tego/runs`. Root's, mode 0644, as tego's trust check wants. |
| `/home/tego` | The home of the user `tego` (uid 10001 unless built with `TEGO_UID`), which every run is started as. `~/.tego` holds the chain anchor (`chain.log`) and tego's own log. |
| `/var/lib/tego/runs` | The ledger. |
| `/work` | The agent's working folder; `/work/out` is the one the example contract lets it write. |
| `/usr/local/share/tego/` | `hello.yaml`, `hello-agent.sh` and `smoke.sh` (the image's own check). |

The `binaries` target is the two binaries on an empty base, for an agent image of your own:
`COPY --from=<that image> /usr/local/bin/tego /usr/local/bin/tego-control /usr/local/bin/`. Copy both, side by side:
`tego serve` refuses a `tego-control` whose hash is not the one it was built with. Your image then needs what this
page says the entrypoint does, or that entrypoint itself.

The base images are pinned by digest (`golang:1.27.3-trixie`, the Go of `go.mod`, and `debian:trixie-slim`), and
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
5. It becomes the user with `setpriv`: the user's uid, gid and groups, no inheritable, ambient or bounding
   capabilities, and `no_new_privs`. Neither `tego` nor the agent holds any capability the container was given.

`TEGO_DELEGATE=auto` (the default) says why when step 1, 2 or 3 cannot be done and starts the command anyway, so
`tego doctor` can show what the host gave; `yes` stops the container instead; `no` skips the cgroup steps. Started as
any user other than root (`docker run --user`, compose's `user:`), the entrypoint does nothing and runs the command
as given; the dashboard service starts that way.

A process started later in the same container (`docker compose exec agent tego-entrypoint tego run <contract>`) is
found in `/init`, where the runtime puts it beside PID 1, and joins the subtree the first start built. Without
`tego-entrypoint` in front, `docker exec` runs the command as root outside the subtree, and `tego run` refuses.

## Tiers inside a container

Tego's three tiers need different things from the host and from
the container. Only tier landlock is the image's supported setting; the table says what each of the others would
need and that no run has shown it working.

| Tier | Host | Container | State |
| ---- | ---- | --------- | ----- |
| landlock (1) | Linux 5.14 or later (`cgroup.kill`), Landlock in the LSM list (ABI 2 or later), cgroup v2, Yama `ptrace_scope` 0 or 1 | compose.yaml's agent service: private cgroup namespace; `SYS_ADMIN`, `SYS_PTRACE`, `CHOWN`, `SETUID`, `SETGID`, `SETPCAP` for the entrypoint; `apparmor=unconfined` where AppArmor runs; `no-new-privileges` | CI runs `tego doctor --require landlock`, `tego test` and a hello run in it |
| cgroup (2) | The same, plus BPF (`CONFIG_BPF_SYSCALL`, BTF) and fanotify | `tego` itself as root with `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, and a seccomp profile and AppArmor that let `bpf(2)` and `fanotify_init(2)` through: in practice a privileged container | Not shown to work. The entrypoint's `TEGO_LAUNCHER=root` is an experiment CI runs, report-only |
| bpflsm (3) | `bpf` in the kernel's active LSM list, which only the host's boot line sets | Everything tier 2 needs. BPF LSM programs attach to the whole kernel and pick their runs by cgroup, so a container allowed to load them has power over the host | Not shown to work; same experiment |

### Tier landlock: each setting and what it buys

This section is about the image's supported tier, landlock.

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

On Docker's defaults (no capability added, `docker-default`), the entrypoint says the cgroup mount is read-only and
`tego run` refuses with `runtime: cgroup: ...`; were the cgroup there, `clone3` would fail with `ENOSYS` and tego
says so, naming the outer seccomp profile (moby#42680). `--privileged` works around all of it and gives the container
everything; it is not what this image asks for.

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

### Tiers that need root

Both root tiers need `tego` to run as root (`sudo tego run` on a
host) with `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, and attach BPF programs whose reach is the kernel, not the
container. A container that can run them can change the host, so treat it as the host. `TEGO_LAUNCHER=root` makes
the entrypoint keep `tego` root with the container's capabilities, empty the namespace root into `/init` with its
controllers on (a root `tego` makes `tego.slice` there), and name the `tego` user in `SUDO_UID` so the agent runs as
that user. CI tries it in a `--privileged` container with `tego doctor --require cgroup` and a hello run at each root
tier, report-only. Until such a run has passed, run the root tiers on the host itself (`sudo tego run`), not in a
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
`tego status --all` lists the runs.

## The dashboard

`docker compose up -d control` starts `tego-control serve --addr 127.0.0.1:8484` (`TEGO_DASHBOARD_ADDR` changes it),
and `docker compose logs control` shows its link. The dashboard listens on a loopback address only, so the service
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
`--cgroupns` default may differ from Docker's, and `tego doctor` in the container says what is missing. On
Kubernetes the agent container needs what compose.yaml's agent service has: a private cgroup namespace (the default
with cgroup v2 and containerd), the six capabilities, a seccomp profile that allows `clone3` and `pidfd_getfd`, and
AppArmor that allows the remount, with a `securityContext` that starts the entrypoint as root.

## What is verified, and what is not

Verified without a container runtime:

- The Dockerfile's build stage, run as written against a copy of the repository with the image's ignore file
  applied: the pair builds, `check-control-pin.sh` passes, both binaries are static and print one version.
- The hello contract and `smoke.sh` with the same binaries outside a container: `tego doctor`, `tego test`, and a
  run with one write allowed, one refused, and its chain verified against the anchor.
- The entrypoint's cgroup steps on a real cgroup v2 tree, as an unprivileged user inside a delegated systemd scope
  standing for a container's namespace root: processes moved, controllers enabled down the path, the subtree's files
  handed over, itself moved, and the later join.
- `examples/container`'s tests: the entrypoint over a stand-in tree (every refusal included), the compose settings,
  the Dockerfile's digests and Go version, and the hello contract's verdicts through `tego compile --test`.
- `shellcheck` over the scripts and `actionlint` over the workflow.

What CI's `container` workflow checks first, on GitHub's ubuntu-24.04 runner: the image builds; `tego doctor
--require landlock` and `smoke.sh` pass with compose.yaml's settings; `docker compose up agent` exits 0; the
dashboard answers the runner's own curl on the host's loopback, lists the hello runs, and refuses a request from
another uid with 403. Report-only, it records `docker exec` through the entrypoint, the image on Docker's defaults,
and the root launcher in a privileged container.

A secret inside the work folder, without a container runtime (KVM guest, as root,
`TestHeldOpenDifferentialAcrossMounts/held-read-container-workspace`): an overlayfs mounted as the container's root with
a local directory bind-mounted into it as the work folder starts held reads and refuses a nested `.env` after a
rename; a project on the overlay itself is refused at launch. No Docker container has run it.

Not verified anywhere yet: the remount and the delegation inside a real Docker container (CI is the first run);
Podman, Kubernetes, SELinux hosts and arm64 images; the dashboard's changes and live-run actions from its container;
running tego as root in a container (`TEGO_LAUNCHER=root`).

## When it does not work

| The container says | It means | Do |
| ------------------ | -------- | -- |
| `tego-entrypoint: no delegated cgroup subtree: /sys/fs/cgroup is read-only and could not be remounted` | No `CAP_SYS_ADMIN`, or AppArmor's `docker-default` | compose.yaml's `cap_add` and `security_opt` |
| `... this container shares a cgroup namespace` | `--cgroupns=host` | `cgroup: private` (`--cgroupns=private`) |
| `... is not a cgroup v2 hierarchy` | A cgroup v1 or hybrid host | Boot the host with cgroup v2 (`systemd.unified_cgroup_hierarchy=1`) |
| `tego run: ... clone3 is being filtered` | The seccomp profile refuses `clone3` | `CAP_SYS_ADMIN` in the container, or a profile that allows it |
| `tego doctor`: `FAIL landlock` | The host kernel has no Landlock in its LSM list | Add `landlock` to the host's `lsm=` boot line |
| `tego doctor`: `yama ptrace_scope=2 without CAP_SYS_PTRACE` | The host's Yama setting | Set the host's `kernel.yama.ptrace_scope` to 1 |
| `held-read stable identities/replacement events unavailable on filesystem 0x794c7630` | A secret the agent's write entry holds (a `.env` in the project) lies on the container's own layer (overlayfs, `0x794c7630`) or another unsupported filesystem | Put the project on a named volume or a bind mount of a local folder ([A secret inside the work folder](#a-secret-inside-the-work-folder)) |
| The dashboard says 403 to your browser | The image's `tego` uid is not yours | Build with `TEGO_UID=$(id -u) TEGO_GID=$(id -g)` |
| `tego doctor`: `warn dashboard: the kernel answers no TCP socket lookup` | The host has not loaded `inet_diag` and `tcp_diag`; tego-control refuses every dashboard action until it is loaded | On the host: `sudo modprobe tcp_diag` (and add it to /etc/modules-load.d) |
