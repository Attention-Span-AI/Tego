---
title: Containers
description: "Run agents under Tego inside a Docker container at Basic: the image, the compose file, the private cgroup namespace, required capabilities and AppArmor setting."
summary: "Run an agent under Tego inside Docker, at Basic."
section: Production
order: 4
---

Tego runs an agent inside a Docker container at Basic only. Plus and Max load kernel programs that act on the whole host and need the host's own process-id namespace, so run them on the host instead. [Protection levels](/docs/tiers/) explains the levels.

## What you need

- A Linux host with cgroup v2 (below), a kernel that meets Basic's requirements ([Supported systems](/docs/supported-systems/)), and `kernel.yama.ptrace_scope` at 0 or 1 ([Servers and CI runners](/docs/servers-and-ci-runners/#process-inspection-setting-ptrace-scope)).
- Docker with BuildKit and the compose plugin.
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

`TEGO_DELEGATE` sets what the entrypoint does when it cannot build the subtree: `auto` (the default) says why and starts the command anyway, `yes` stops the container, `no` skips the cgroup setup.

To start another session in a running container, put the entrypoint in front: `docker compose exec agent tego-entrypoint tego run <rules file>`.

## Without these settings

Without the capabilities and the AppArmor setting, the entrypoint cannot remount `/sys/fs/cgroup`, and `tego run` exits 125 before the agent starts with `[tier-unavailable]`. The `fix:` line in that message is for a host with systemd. Inside a container the fix is the settings above. `--privileged` also works, and gives the container far more than Tego needs.

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

To read and check the record from a fresh container, give it the same two volumes and the image's user, uid and gid 10001. Copy the session name from the line `tego run` printed at the end:

```sh
run=<session name>
docker run --rm --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
  -v tego-state:/home/tego/.tego -v tego-ledger:/var/lib/tego/runs \
  "$image" tego events "$run" --verify
```

It exits 0 when the record's hash chain matches `chain.log`. A session started without the `tego-state` volume has no `chain.log` outside its own container to check against. [Sessions and records](/docs/sessions-and-records/) explains the check.

## Open the dashboard

```sh
docker compose up -d control
docker compose logs control
```

The log prints the sign-in link, `http://127.0.0.1:8484/?t=...`. The `control` service uses the host's network, so the address is the host's loopback. The dashboard answers only a browser whose connection belongs to the uid the image was built with, which is why you set `TEGO_UID` to your own. To stop, pause or answer live sessions from it, uncomment `pid: "service:agent"` in `compose.yaml`. [Dashboard](/docs/dashboard/) describes its pages.

## Next steps

- [Rules files](/docs/rules-files/): write the rules for your agent.
- [Protection levels](/docs/tiers/): what Basic enforces.
- [Services](/docs/services/): run an agent all the time on the host instead.
- [Troubleshooting](/docs/troubleshooting/): common errors and their fixes.
