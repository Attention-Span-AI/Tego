---
title: Containers
description: "Run agents under Tego inside a Docker container at Basic: the image, the compose file, the private cgroup namespace, required capabilities and AppArmor setting."
summary: "Run an agent under Tego inside Docker, at Basic."
section: Production
order: 4
---

Tego runs an agent inside a Docker container at Basic only. Plus and Max load kernel programs that act on the whole host and need the host's own process-id namespace, so run them on the host instead. [Protection levels](/docs/tiers/) explains the levels.

## What you need

- A Linux host with cgroup v2 (below), a kernel that meets Basic's requirements ([Supported systems](/docs/supported-systems/)), and `kernel.yama.ptrace_scope` at 0 or 1 ([Servers and CI runners](/docs/servers-and-ci-runners/#process-inspection-setting)).
- Docker with BuildKit and the compose plugin, and your user in the `docker` group (or `sudo` before every `docker` line below). Where Docker comes from your distribution, `docker compose` is a package of its own, and without it the first command fails with `'compose' is not a docker command`:

| Docker from | Install |
|---|---|
| Debian 13 | `sudo apt-get install docker.io docker-compose docker-buildx` |
| Ubuntu 24.04 | `sudo apt-get install docker.io docker-compose-v2 docker-buildx` |
| Docker's own repository | `docker-ce`, `docker-compose-plugin` and `docker-buildx-plugin`, as [Docker's install guide](https://docs.docker.com/engine/install/) says |

- A checkout of the Tego repository. The files are in [`examples/container/`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/container/).

Each release also publishes the image `ghcr.io/attention-span-ai/tego` for amd64 and arm64. Its user has uid and gid 10001.

## Run the example

From `examples/container/`:

```sh
export TEGO_UID=$(id -u) TEGO_GID=$(id -g)
docker compose build
docker compose run --rm agent tego machine check
docker compose up agent
```

`tego machine check` shows what the host gives the container. `docker compose up agent` runs `tego run /usr/local/share/tego/hello.yaml`: the example agent writes `/work/out/hello.txt`, tries to write `/work/outside.txt`, and Tego refuses that write. The session ends at `tier landlock` with one refusal.

`TEGO_UID` and `TEGO_GID` build the image with your own uid, which the dashboard needs (below).

The image built here is compiled from your checkout, not a release, so `tego version` inside it prints `tego=dev commit=none`. To run a release, use the published image.

Every `docker compose run` is a new container with its own host id. In a second container, `tego machine check` calls the sessions of the first one "minted on host `<id>`, not this one". They are still yours: no cleanup in this container ends or repairs them, and `tego gc` removes them only once they are past retention.

## Run your own agent

1. Mount the agent's rules file and project into the container, for example a bind mount `./project:/work`.
2. Set `TEGO_CONTRACT` to the rules file's path inside the container.
3. Build with the programs the agent needs: `EXTRA_PACKAGES="python3 nodejs npm" docker compose build`.

A program installed in the image is not allowed by that alone. The rules file's `exec.allow` still decides what runs. [`examples/agents/`](https://github.com/Attention-Span-AI/Tego/blob/main/examples/agents/) has rules files for Claude Code, Codex and other agents.

## Why each container setting is there

Tego places each session in its own cgroup, a kernel group of processes it uses to apply limits and stop the session. A container has no systemd user manager to hand Tego a cgroup subtree, so the image's entrypoint builds one, as root, and then drops every capability (a slice of root's power, such as `SYS_ADMIN`) before it starts Tego as the `tego` user.

| Setting in `compose.yaml` | Why |
|---|---|
| `cgroup: private` | The entrypoint builds the subtree only in the container's own cgroup namespace. In the host's namespace it refuses. |
| `cap_add: [SYS_ADMIN, SYS_PTRACE, CHOWN, SETUID, SETGID, SETPCAP]` with `cap_drop: [ALL]` | For the entrypoint's setup only. Docker's default seccomp profile (its list of allowed system calls) also allows two system calls Tego needs (`clone3` and `pidfd_getfd`) only to containers with `SYS_ADMIN` and `SYS_PTRACE`. Neither Tego nor the agent holds these capabilities. |
| `apparmor=unconfined` | AppArmor, a Linux security module, applies Docker's `docker-default` profile, which denies the remount of `/sys/fs/cgroup` the entrypoint needs. Hosts without AppArmor ignore it. |
| `no-new-privileges:true` | Nothing in the container gains a privilege through a setuid file. |
| `init: true`, `stop_grace_period: 40s` | `docker-init` passes SIGTERM to Tego, which stops the session within `stop_grace` and writes the end of its record. |

`TEGO_DELEGATE` sets what the entrypoint does when it cannot build the subtree: `auto` (the default) says why and starts the command anyway, `yes` stops the container, `no` skips the cgroup setup. `TEGO_LSM_LIST` does the same for the list of security modules the entrypoint writes to `/run/tego-lsm/lsm-list` ([below](#held-file-opens-and-the-security-module-list)): `auto` says why it could not and starts anyway, `yes` stops the container, `no` leaves the file alone.

The image's machine settings file, `/etc/tego/config.yaml`, sets two things: the records folder (`ledger_root: /var/lib/tego/runs`) and that list file (`lsm.list_file: /run/tego-lsm/lsm-list`).

To start another session in a running container, put the entrypoint in front: `docker compose exec agent tego-entrypoint tego run <rules file>`.

## Without these settings

Without the capabilities and the AppArmor setting, the entrypoint cannot remount `/sys/fs/cgroup`, and `tego run` exits 125 before the agent starts with `[tier-unavailable]`. The `fix:` line in that message is for a host with systemd. Inside a container the fix is the settings above. `--privileged` also works, and gives the container far more than Tego needs.

Tego knows it is in a container from `/.dockerenv` (Docker), `/run/.containerenv` (Podman) or a `container` variable in process 1's environment. A Kubernetes pod under containerd has none of these, so there Tego gives the host's advice, and the settings on this page are the fix.

## Podman and Kubernetes

Neither has been tried. Podman reads `compose.yaml` (`podman compose`), and `tego machine check` in the container says what is missing. On Kubernetes the agent container needs what the compose file's `agent` service has: a private cgroup namespace, the six capabilities, a seccomp profile that allows `clone3` and `pidfd_getfd`, AppArmor that allows the remount, and a `securityContext` that starts the entrypoint as root.

## Held file opens and the security-module list

Some rules make Tego open files itself on the agent's behalf: `gate.completion: held`, `fs.ask_read`, and held reads, which a `.env` inside a folder the agent writes turns on ([Secrets](/docs/secrets/)). Before each such open, Tego compares the agent's label with its own in every active security module (AppArmor, SELinux, Smack, TOMOYO). To know which modules are active, it reads the kernel's list with the `lsm_list_modules(2)` system call (Linux 6.8 and later), then the file `/sys/kernel/security/lsm`, then the list file the machine settings name (`lsm.list_file`). When none can be read, every held open fails with `EACCES` (`held-label-unavailable` in the record), and the session says so at start (`[held-label]`). Nothing is opened that should not be, but a program that needs those opens can fail, for example while loading its libraries.

Under Docker's defaults the container can read neither the call nor the file. Measured on Debian hosts with `docker.io` 26.1.5:

| Host kernel | Container settings | What the container reads | Held opens |
|---|---|---|---|
| Debian 13 (6.12) | Docker's default seccomp profile and `docker-default` AppArmor | The call answers `ENOSYS`; the container's own `/sys` has no `/sys/kernel/security/lsm` | Refused, unless the list is handed in (below) |
| Debian 13 (6.12) | `--security-opt seccomp=unconfined`, or a profile that allows `lsm_list_modules` | The call answers | Work |
| Debian 12 (6.1) | Docker's defaults | The call answers `ENOSYS` (this kernel has no such call); no `/sys/kernel/security/lsm` | Refused, unless the list is handed in |

On Debian, held opens also need the TOMOYO and AppArmor facts described below.

**The entrypoint hands the list in.** It starts as root with `SYS_ADMIN` and without `docker-default`, so it can still read the list. It writes the list to `/run/tego-lsm/lsm-list`, then becomes the `tego` user. The image's machine settings already name that file, so the example needs nothing more. If the entrypoint cannot read the list, it prints `tego-entrypoint: no security-module list handed in: ...`, and the fix is the compose file's `cap_add: [SYS_ADMIN]` and `apparmor=unconfined`.

`lsm.list_file` is read from `/etc/tego/config.yaml` only; a user's own settings file that sets it is ignored with a warning. Do not put `/run/tego-lsm` on a volume the agent can write: the file is refused there. Tego reads the file only when the call and `/sys/kernel/security/lsm` both failed, and trusts it only when all of these hold, checked again at every open:

- The file and every folder above it belong to root, nobody else can write them, and no part of the path is a link.
- It is a regular file on the container's own file system, not FUSE, NFS, 9p or another network file system.
- It has exactly the three lines the entrypoint writes: the format name, the **boot id** of the running kernel, and the list. A file from an earlier boot, another machine or the image itself is refused as stale. The list must name only modules the kernel can print, including `capability`.
- The agent's process is not root and holds none of `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER` or `CAP_SYS_ADMIN`, which could rewrite the file. The entrypoint leaves the agent none of them.

A file that fails one of these is refused with the reason. The file never decides a protection level: `tego machine check` shows `skip lsm: ... held file opens read this list`, and says that whether `bpf` is active is unknown.

Without the image's entrypoint (your own image, or `docker run` as root), hand the list in one of two other ways:

- bind the host's list into the container read-only, at a path outside `/sys/kernel/security`, and name that path, for example `docker run -v /sys/kernel/security/lsm:/run/tego-kernel-lsm:ro ...` with `lsm: {list_file: /run/tego-kernel-lsm}` in `/etc/tego/config.yaml`. Tego accepts only the host's own `lsm` file on a read-only mount, so a copy, another file or a writable bind is refused; or
- write the file yourself as root before the agent starts, in the format `examples/container/tego-entrypoint.sh` writes.

**TOMOYO and AppArmor.** Debian's and Ubuntu's kernels run AppArmor, and Debian's also run TOMOYO. A held open compares what these say about the agent with what they say about Tego, and a container can read neither from its own `/sys`. On such a host, held opens stay refused, even with the list handed in, until you give Tego both. Each refusal says which one is missing.

- **TOMOYO:** bind the host's TOMOYO files read-only, `-v /sys/kernel/security/tomoyo:/run/tego-tomoyo:ro`, and add `tomoyo: {facts_dir: /run/tego-tomoyo}` to `/etc/tego/config.yaml`. The image's settings file does not set this, because most hosts do not run TOMOYO, so mount your own settings file over it.
- **AppArmor:** a container cannot read the AppArmor namespace depth, so the rules file must state that the container is in the root AppArmor namespace: `fs: {apparmor_assume_root_namespace: true}`. You are then trusting that statement, which Tego cannot check.

On a host that runs neither (check the `lsm` line of `tego machine check` on the host), the list alone is enough.

If you cannot hand the list in, use rules that hold no opens: no `gate.completion: held`, no `fs.ask_read`, and `fs.reads: direct` for a secret inside the work folder. At Basic, `tego rules check` then warns that the secret is not enforced.

## Records and secrets

The compose file keeps three volumes: `tego-state` for `~/.tego`, which holds `chain.log`, the file each record's hash chain is checked against; `tego-ledger` for the records at `/var/lib/tego/runs`; and `tego-work` for `/work`.

A secret file such as `/work/.env` inside a folder the agent writes works when `/work` is a named volume or a bind mount of a local host folder. Tego refuses to start when that folder is on the image layer, on the container's writable layer, or on NFS, CIFS or FUSE, including Docker Desktop's file sharing. [Secrets](/docs/secrets/) explains how Tego guards reads there.

## Check a session's record

This runs the example agent from the published image with `docker run`, with the settings from the table above and the state and records on their own volumes:

```sh
image=ghcr.io/attention-span-ai/tego:0.2.0
docker run --rm --init --cgroupns=private --stop-timeout 40 \
  --cap-drop ALL --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add CHOWN \
  --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt apparmor=unconfined --security-opt no-new-privileges:true \
  -e TEGO_DELEGATE=yes \
  -v tego-state:/home/tego/.tego -v tego-ledger:/var/lib/tego/runs -v tego-work:/work \
  "$image" tego run /usr/local/share/tego/hello.yaml
```

To read and check the record from a fresh container, give it the same two volumes and the image's user, which owns `chain.log`. Another `--user` fails with `permission denied`. For the published image the user is 10001:10001. Copy the session name from the line `tego run` printed at the end:

```sh
run=<session name>
docker run --rm --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
  -v tego-state:/home/tego/.tego -v tego-ledger:/var/lib/tego/runs \
  "$image" tego events "$run" --verify
```

For the image `docker compose build` made, the user is your own `TEGO_UID` and `TEGO_GID`, and the volumes are named after the compose project, `tego`:

```sh
docker run --rm --user "$TEGO_UID:$TEGO_GID" --cap-drop ALL --security-opt no-new-privileges:true \
  -v tego_tego-state:/home/tego/.tego -v tego_tego-ledger:/var/lib/tego/runs \
  tego:local tego events <run> --verify
```

`docker compose run --rm --no-deps agent tego events <run> --verify` does the same, since the service mounts both volumes.

Each command exits 0 when the record's hash chain matches `chain.log`. A session started without the `tego-state` volume has no `chain.log` outside its own container to check against. [Sessions and records](/docs/sessions-and-records/) explains the check.

## Open the dashboard

```sh
docker compose up -d control
docker compose logs control
```

Build first. The `control` service never builds or pulls its image, so on a machine that has not run `docker compose build` it stops with an error that names `tego:local`. Build, then run the line again; the failed attempt leaves nothing to clean up.

The log prints the sign-in link, `http://127.0.0.1:8484/?t=...`. The `control` service uses the host's network, so the address is the host's loopback. The dashboard answers only a browser whose connection belongs to the uid the image was built with, which is why you set `TEGO_UID` to your own. To stop, pause or answer live sessions from it, uncomment `pid: "service:agent"` in `compose.yaml`. [Dashboard](/docs/dashboard/) describes its pages.

## Next steps

- [Rules files](/docs/rules-files/): write the rules for your agent.
- [Protection levels](/docs/tiers/): what Basic enforces.
- [Services](/docs/services/): run an agent all the time on the host instead.
- [Troubleshooting](/docs/troubleshooting/): common errors and their fixes.
