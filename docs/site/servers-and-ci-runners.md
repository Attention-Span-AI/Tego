---
title: Servers and CI runners
description: "Get a Linux server or CI runner ready for Tego: tego setup, SSH logins, cgroup delegation, service accounts, ptrace_scope and RHEL 9 CPU limits."
summary: "Get a server or runner ready: SSH, service accounts and kernel settings."
section: Production
order: 1
---

`tego setup` checks a server for the three things that differ from a desktop: SSH logins, service accounts and kernel settings. It checks from the shell you are in and names the next command to type. On a desktop login Tego works right after install. On a server you reach it over SSH, agents can run as a service account that never logs in, and the kernel settings can be stricter.

## Check the machine with `tego setup`

Run `tego setup` as the user who will run the agents, without `sudo`:

```sh
tego setup
```

On a machine where Tego works and nothing has run yet, it prints:

```
Tego on this machine, step by step:
  [x] 1 Install             tego v0.0.0-fixture (commit f1x7ure)
  [x] 2 Check this machine  ready: tier 1 (landlock) from a shell in your user manager's cgroup, checked 2026-11-11 09:30 UTC
  [ ] 3 Find your agents    Tego has recorded no run here yet
  [ ] 4 Record one run      no run has been recorded with tego watch yet
  [ ] 5 Make its contract   no contract in the registries
  [ ] 6 Enforce it          no run under a contract has ended
Not known:
  - No saved scan. Run tego scan from your project folder.
  - agents outside a scan's rules and sources, or activity between scans
  - a contract in no registry (a file given by its path) that no run used

next: record your own agent. From its folder, start it as you always do:
  tego watch -- <the command you start it with>
```

In this output, "tier 1" is Basic and "contract" is the older name for a rules file.

`tego setup` needs no root and changes nothing on the machine. It stores its check in `~/.tego/state/check.json`, which the dashboard's Overview page reads. Run it again after each step and after each reboot.

| Flag | What it does |
|---|---|
| `--json` | Prints one JSON object (schema `tego.setup/1`) and no `next:` lines. |
| `--no-scope` | Checks this shell without trying to open a user scope (below). |
| `-v` | Also prints where each fact was read and why it chose the next step. |

Step 2 is the same check `tego machine check` runs. [Self-check](/docs/self-check/) explains that output.

## Over SSH

Tego places every session in a cgroup, a kernel group of processes that Tego uses to apply limits and to stop the whole session at once. As an ordinary user, Tego can make cgroups only inside the part of the tree that systemd hands your user manager, the per-user systemd instance. An SSH login starts outside that part.

`tego run`, `tego watch` and `tego machine test` handle this themselves. From an SSH shell they open a user scope through your user manager and print:

```
tego: opened a user scope for this run
```

If that fails (no `systemd-run`, the manager refuses, or it takes longer than 10 seconds), the command exits 125 before the session starts. Open a shell inside your user manager by hand and run from there:

```sh
systemd-run --user --scope bash
```

## Cgroup delegation

Every level needs cgroup v2 with a subtree that systemd delegates to your user, holding the controllers a session's limits use (`cpu`, `memory`, `pids`). `tego machine check` lists the controllers your user has and, when delegation is missing, prints a `fix:` line. The fix is a systemd drop-in, run once by an administrator:

```sh
sudo mkdir -p /etc/systemd/system/user@.service.d
printf '[Service]\nDelegate=cpu memory pids\n' | sudo tee /etc/systemd/system/user@.service.d/delegate.conf
sudo systemctl daemon-reload
```

Log out and in again, then run `tego setup`.

## RHEL 9 and AlmaLinux 9: CPU limits

RHEL 9's systemd turns on `memory` and `pids` for users and for root, but not `cpu`. Basic runs there. A session whose rules file sets `limits.cpu` or `limits.cpu_weight` is refused at start with exit 125, and a `limits.cpu` ceiling in `/etc/tego/config.yaml` refuses every session. To allow CPU limits, an administrator runs this once, then reboots:

```sh
sudo mkdir -p /etc/systemd/system/user@.service.d /etc/systemd/user/app.slice.d /etc/systemd/system/system.slice.d
printf '[Service]\nDelegate=cpu memory pids\n' | sudo tee /etc/systemd/system/user@.service.d/60-tego-cpu.conf
printf '[Slice]\nCPUWeight=100\n' | sudo tee /etc/systemd/user/app.slice.d/60-tego-cpu.conf
printf '[Slice]\nCPUWeight=100\n' | sudo tee /etc/systemd/system/system.slice.d/60-tego-cpu.conf
```

The first file offers `cpu` to each user's systemd. The second makes the user's systemd turn it on. The third keeps `cpu` on for sessions started as root.

## A service account

A service account is a user with a `nologin` shell that you reach with `sudo -u` or `su -s`. It has no user manager running unless you start one, because it never logs in. Tego starts no session for such a user, not even `tego watch`. Set it up in this order, typing each line in your own administrator shell. The example account is `svc` with uid 1002.

1. Create the account with a name that starts with a letter. systemd starts no user manager for a name made only of digits.

   ```sh
   sudo useradd --create-home --shell /usr/sbin/nologin svc
   ```

2. Install Tego as that account, into its own `~/.local/bin`. [Install](/docs/install/) has the command.
3. Start a user manager for it that runs without a login:

   ```sh
   sudo loginctl enable-linger svc
   ```

4. Open a shell inside that user manager and check the account:

   ```sh
   sudo -u svc XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash
   tego setup
   ```

Without `sudo -u svc`, the line in step 4 opens a shell in your own user manager, and `tego setup` answers for you. Linger keeps the account's processes running after logout and starts its manager at boot. Turn it off with `sudo loginctl disable-linger svc` when the account no longer runs agents.

To run the agent as a systemd unit under that account, see [Services](/docs/services/).

## Ptrace scope setting

Yama is a kernel security module. Its `kernel.yama.ptrace_scope` setting decides which processes may read another process's memory. Tego's supervisor reads the agent's arguments and addresses that way, as the agent's parent, so the value decides which protection levels work:

| `ptrace_scope` | Effect |
|---|---|
| `0` or `1` | Every level works. `1` is the Debian and Ubuntu default. |
| `2` | Only sessions started as root work: Plus and Max. Basic does not. |
| `3` | No level works, and only a reboot can lower the value. |

Read the current value with `cat /proc/sys/kernel/yama/ptrace_scope`. To set it to 1, put `kernel.yama.ptrace_scope=1` in a file in `/etc/sysctl.d`, in place of the line that set the current value, and apply it with `sudo sysctl --system`. At 3, boot with `kernel.yama.ptrace_scope=1` instead.

## CI runners

A hosted runner is a fresh machine for each job. [CI](/docs/ci/) shows how to check the runner's protection level as the job's first step and run the agent there.

## Next steps

- [Services](/docs/services/): keep an agent running under systemd.
- [CI](/docs/ci/): run an agent in GitHub Actions and keep a signed receipt.
- [Supported systems](/docs/supported-systems/): the kernel and distribution each level needs.
- [Protection levels](/docs/tiers/): what Basic, Plus and Max enforce and which need root.
