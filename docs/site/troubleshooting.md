---
title: Troubleshooting
description: "Fixes for the errors people hit first with Tego: command not found, exit code 125, SSH logins, the Mac VM, shared folders, pytest and a busy dashboard port."
summary: "Common errors, and the fix for each."
section: Reference
group: Help
order: 1
---

Find the message or symptom you see, then apply its fix. If yours is not here, [open an issue](https://github.com/Attention-Span-AI/Tego/issues) with the output of `tego version` and `tego machine check`.

## Installing

### `tego: command not found`

The folder Tego installed into, `~/.local/bin`, is not on your `PATH` yet. Run the `export PATH=...` line the installer printed, or open a new terminal. On a Mac, open a new Terminal window. [Install](/docs/install/) covers each platform.

### A Mac install stopped while downloading the VM image

Remove the incomplete VM, then run the install line again:

```sh
limactl delete tego
```

### No `sudo` line: a folder is group-writable

Tego prints a `sudo "$(command -v tego)" ...` line only when no other user can replace the `tego` binary. When a folder on its path is group-writable and Tego cannot tell who is in that group, it shows no `sudo` line and prints one `chmod g-w` command for every such folder. Run it, then the step again.

## On a Mac

### `tego: Tego's VM is missing`

The Lima VM named `tego` no longer exists. Run the install line the message prints to set it up again.

### `tego: the VM didn't start`

The `tego` command starts a stopped VM by itself. When that fails, start it by hand to see Lima's error:

```sh
limactl start tego
```

### A rules file on a folder shared from the Mac is refused

Keep the rules file, and every file it extends, in your Linux home, for example `~/tego/`. The project itself can stay on the share. [Supported systems](/docs/supported-systems/#macos) explains why.

## Exit code 125: the session did not start

Exit 125: the session did not start. The lines above it name the cause and a `fix:`.

### No protection level works (`[tier-unavailable]`)

Run `tego machine check`. Its `missing for` and `fix:` lines name what the machine lacks ([Self-check](/docs/self-check/)). [Supported systems](/docs/supported-systems/) lists what each level needs.

### Over SSH: the user scope did not open

Start a shell inside your user manager and run from there:

```sh
systemd-run --user --scope bash
```

For a service account with no user manager, see [Servers and CI runners](/docs/servers-and-ci-runners/#run-as-a-service-account).

### Machine settings not trusted (`[config-untrusted]`)

A machine config file can be changed by another user. Make it yours or root's, with no group or other write permission ([Machine settings](/docs/machine-settings/#which-files-tego-trusts)).

### The rules file sits where the agent could rewrite it

Tego refuses to run a rules file that lies inside a folder its `fs.write` allows. Move the rules file out of every writable folder, for example to `~/tego/`, and run it from there.

### Budget cannot be counted (`[budget-unmetered]`)

The rules file sets `tokens`, `cost_usd` or `repeats`, and nothing in this session can count them. [Budgets](/docs/budgets/) explains what each budget needs.

### `limits.cpu` refused on RHEL 9 or AlmaLinux 9

systemd there does not give users the `cpu` controller. [Servers and CI runners](/docs/servers-and-ci-runners/#cpu-limits-on-rhel-9-and-almalinux-9) has the administrator's fix.

### A message about `XDG_RUNTIME_DIR`

Run `tego run` as yourself, without `sudo`, from a normal login, which sets `XDG_RUNTIME_DIR` to `/run/user/<uid>`. Otherwise export `XDG_RUNTIME_DIR` as an absolute folder only you can write, then retry.

## Agents and tools

### Machine check names `ptrace_scope` 2 or 3

Basic needs `kernel.yama.ptrace_scope` at 0 or 1. [Servers and CI runners](/docs/servers-and-ci-runners/#process-inspection-setting) shows how to set it.


### File opens refused in a container (`held-label-unavailable`)

The container could not read the kernel's list of security modules, so Tego refuses every file open it would make for the agent. [Containers](/docs/containers/#held-file-opens-and-the-security-module-list) shows how to hand the list in.

## The dashboard

### The page says to open the dashboard from your terminal

The link needs its sign-in token. Run `tego dashboard` and open the link it prints, not the bare address.

### Port 8484 is in use

On Linux, start the dashboard on another loopback port:

```sh
tego serve --addr 127.0.0.1:8485
```

To make that port the default, set `serve.port` ([Machine settings](/docs/machine-settings/)). On a Mac, the `tego` command's tunnel to the VM is set up for port 8484 only, so keep the dashboard on 8484 there. [Dashboard](/docs/dashboard/) covers the rest.

### The dashboard cannot start: no message bus

The dashboard runs in your user service manager, which needs a message bus (D-Bus). Debian and Ubuntu cloud images leave out the package that gives it one. The installer and `tego start` say so. Install it, then log out and log in again:

```sh
sudo apt install dbus-user-session
```

### Windows: the dashboard doesn't open in the browser

If WSL uses mirrored networking, `tego dashboard` says so and opens nothing, because that mode reserves the dashboard's port for Tego's Linux. Set `networkingMode=nat` in `%USERPROFILE%\.wslconfig`, then run `wsl --shutdown`. Until then, `tego session list` shows your sessions in the terminal.

For any other failure, the message shows the last lines of the dashboard's log. To read the whole log from Windows:

```powershell
tego shell -c "tail -n 40 ~/.tego/dashboard.log"
```

## Next steps

- [Self-check](/docs/self-check/): read `tego machine check` line by line.
- [Exit codes](/docs/exit-codes/): what each code means.
- [Refusals](/docs/refusals/): what the agent sees when Tego refuses an action.
- [FAQ](/docs/faq/): short answers to common questions.
