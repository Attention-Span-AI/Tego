---
title: Supported systems
description: "Which Linux kernels, distributions, Macs and Windows versions Tego runs on, what Basic, Plus and Max each need, and how to turn on Max with one boot setting."
summary: "Platforms, kernels and what each protection level needs."
section: Reference
group: Machine
order: 1
---

Tego runs on Linux. On macOS it runs in a Linux VM that the installer sets up, and on Windows in a WSL distribution that the installer sets up. Which [protection level](/docs/tiers/) you get depends on the Linux kernel and its settings. `tego machine check` tells you what your machine supports.

## Platforms

| Platform | Needs |
|---|---|
| Linux | x86-64 (amd64) or arm64, and a kernel from [Linux kernels](#linux-kernels) |
| macOS | macOS 13.5 or later, Apple silicon or Intel, Lima 2.0 or later, about 5 GB free |
| Windows | Windows 10 version 21H2 (build 19044) or later, or Windows 11, x64 or arm64, virtualization turned on, WSL 2.6.3 or later, at least 5 GB free |

[Protection levels](/docs/tiers/#which-level-your-machine-gets) says which level each platform gets.

[Install](/docs/install/) has the install command for each platform. To run Tego inside a Docker container, see [Containers](/docs/containers/).

## Linux kernels

Tego needs Linux 5.14 or later and Landlock ABI 2. Landlock is the Linux feature Basic is built on, and its ABI version says which Landlock rules the kernel supports. Upstream kernels have ABI 2 from 5.19. RHEL 9's 5.14 kernel has it as a backport.

| Kernel | What changes |
|---|---|
| Before 5.19, without a backport | No level. `tego run` exits with code 125. Ubuntu 22.04's stock 5.15 kernel is one of these. |
| 5.14 (RHEL 9), 5.19 and later | Basic works. |
| 6.1 | The oldest upstream kernel Tego is tested on. |
| 6.7 | At Basic, the kernel also enforces TCP port rules. Before 6.7, Tego's supervisor alone decides each connection. |

`tego machine check` prints your kernel's Landlock ABI.

## What each level needs

### Basic

- A kernel from [Linux kernels](#linux-kernels).
- cgroup v2 delegated to your user ([Servers and CI runners](/docs/servers-and-ci-runners/#let-your-user-group-processes-cgroup-delegation)). A cgroup (control group) is how Linux groups a session's processes.
- `ptrace_scope`, the kernel setting for which processes may inspect others, at 0 or 1 ([how to set it](/docs/servers-and-ci-runners/#process-inspection-setting)).

[Servers and CI runners](/docs/servers-and-ci-runners/) covers SSH sessions, service accounts and RHEL 9's CPU limits.

### Plus

- Root, through `sudo`.
- The kernel's BTF type information, which BPF programs (small programs the kernel runs) use to read kernel data.
- cgroup v2.
- A readable tracefs, the kernel's tracing file system at `/sys/kernel/tracing` or `/sys/kernel/debug/tracing`. Tego reads the layout of system call events there.
- The machine's own process-ID namespace. A session started inside a container or another private process-ID namespace, such as WSL's, cannot use Plus or Max.
- Kernel checks that `sudo "$(command -v tego)" machine check` runs. Where one fails, it withholds Plus and Max and says why.

### Max

- Everything Plus needs.
- `bpf` in the kernel's list of active security modules (LSM list). Check it with:

```sh
cat /sys/kernel/security/lsm
```

## Distributions

| Distribution | Basic | Max |
|---|---|---|
| Debian 13, Fedora 40 and later, RHEL 9 and 10, AlmaLinux 9, Rocky Linux 9, Amazon Linux 2023 | Yes | Yes, with no change |
| Ubuntu 24.04, 25.10 and 26.04 | Yes | After one [boot setting](#turn-on-max) |
| Debian 12, and other 6.1 kernels | Yes, without kernel TCP port rules | Run `sudo "$(command -v tego)" machine check` |
| Ubuntu 22.04 with its stock 5.15 kernel | No | No |

AlmaLinux 9 and Rocky Linux 9 run RHEL 9's kernel.

On Debian 12 and 13, the stock kernel lists TOMOYO, a Linux security module, as active with no policy loaded. At Basic, Tego refuses every file open it would hold for a person, so [read approvals and held reads](/docs/approvals/) do not work there: Basic cannot read TOMOYO's settings to prove nothing is enforced. At Plus and Max they work while no TOMOYO mode is enforcing. `tego machine check` says which check admitted them.

Plus works wherever Basic does and you have root, unless a requirement above is missing.

## Where Tego is tested

Tego's GitHub workflows test these systems:

| System | What runs |
|---|---|
| Ubuntu 24.04 (6.8), Ubuntu 25.10 (6.17), Debian 13 (6.12), RHEL 9 through AlmaLinux 9 (5.14), Amazon Linux 2023 (6.1 and 6.12), Fedora kernels 7.0 and 7.2 | Each distribution's kernel boots in a VM on an x86-64 runner and runs Tego's kernel tests. This matrix is started by hand. |
| Ubuntu 22.04 (5.15) | `tego machine check` only: it must say no level works. |
| Linux on arm64 | Build, unit tests and the kernel program checks, on GitHub's `ubuntu-24.04-arm` runner. |
| macOS 15, Apple silicon | The installer and its tools. GitHub's Apple silicon runners cannot start a VM inside them. |
| macOS 15, Intel | The real installer, and Tego's VM where the runner can boot one. |
| Windows Server 2025, x64 | The real installer, from Windows PowerShell 5.1 and from PowerShell 7. |

Windows on arm64 has release builds, and the installer installs them, but no workflow runs them.

Before the v0.2.0 release, its release files were also tested by hand in VMs. On each system a new user installed Tego, ran `tego machine check` and `tego machine test`, and ran a session at Basic with one allowed write, one refused write and one refused program; root ran the same session at each level the machine offers.

| System | Kernel | Level as a user | Highest level as root |
|---|---|---|---|
| AlmaLinux 9.8 (RHEL 9) | 5.14 | Basic | Max |
| Amazon Linux 2023 | 6.1 | Basic | Max |
| Ubuntu 24.04 | 6.8 | Basic | Plus |
| Ubuntu 26.04.1 | 7.0 | Basic | Plus |
| Fedora 44 | 6.19 | Basic | Max |

Ubuntu stops at Plus until you [turn on Max](#turn-on-max). A fresh install also passed on Ubuntu 24.04 and Debian 12, and an update from v0.1.3 on Ubuntu 24.04 and Debian 13.

## Turn on Max

Max needs `bpf` in the kernel's boot list of security modules. Where it is missing, this command prints the `lsm=` value to use, built from the list your machine runs now:

```sh
sudo "$(command -v tego)" machine check
```

> **Warning:** Use only the `lsm=` value `tego machine check` printed on this machine. A line copied from elsewhere replaces the whole list and can switch off other security modules.

<div class="os-tabs">
<section data-os="linux" aria-label="Linux">

On Ubuntu, put the printed `lsm=...` into `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`, then:

```sh
sudo update-grub
sudo reboot
```

On an Ubuntu cloud image, `/etc/default/grub.d/50-cloudimg-settings.cfg` sets the same variable after `/etc/default/grub` is read. Add a file that is read later instead, then run `sudo update-grub` and reboot:

```sh
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=<the list tego machine check printed>"' | sudo tee /etc/default/grub.d/99-tego-lsm.cfg
```

On Fedora and RHEL, use:

```sh
sudo grubby --update-kernel=ALL --args="lsm=<the list tego machine check printed>"
```

</section>
<section data-os="macos" aria-label="macOS">

Tego's VM runs an Ubuntu 24.04 cloud image. Open a shell in it with `tego shell`, follow the Ubuntu cloud image steps in the Linux tab without the reboot, then restart the VM from your Mac:

```sh
limactl stop tego
limactl start tego
```

</section>
<section data-os="windows" aria-label="Windows">

Max is not available in WSL. Plus and Max need the machine's own process-ID namespace, and WSL runs each distribution in a private one. Adding `bpf` to WSL's LSM list does not change that.

</section>
</div>

To check it worked, `cat /sys/kernel/security/lsm` lists `bpf`, and `sudo "$(command -v tego)" machine check` prints `tier: bpflsm`. Max needs root, so the check runs through `sudo`.

## macOS

The installer sets up a Lima VM named `tego`:

- Ubuntu 24.04, 4 CPUs, 4 GiB of memory and a 20 GiB disk.
- No Mac folder is shared into the VM. Projects, rules files and records live in the VM's own home.

You can share a Mac folder into the VM yourself with `limactl edit tego`. Inside a shared folder:

- The built-in refusals do not protect secrets. They name paths in the VM's home, not on the Mac.
- Tego refuses to load a rules file, because the share does not keep real file owners and permissions, and anything on the Mac can change the file between sessions. The same holds on 9p, virtiofs, SMB, FAT, exFAT and NTFS file systems.
- Tego cannot hold reads there, so a session that needs held reads in that folder refuses to start.

## Windows

The installer turns on WSL, updating it if needed, and creates its own WSL distribution named `tego`, running Ubuntu 24.04.

Keep rules files in your Linux home inside WSL. Tego's Linux mounts no Windows drive, so a rules file or project folder given as a Windows path (`C:\work\rules.yaml`, `/mnt/c/...`, `\\wsl$\tego\...` or `\\wsl.localhost\...`) is refused with `[path-missing]`. The message says where to copy the file and which Linux path to type; for a `\\wsl$\tego\...` path it names the same file's Linux path under `/home/tego`. If you installed Tego in another WSL distribution, such as your own Ubuntu, Tego refuses a rules file on `/mnt/c` or another Windows drive, because WSL makes up the owner and permissions of files there and any Windows program can change them.

Windows stops Tego's Linux when nothing is attached to it, and that ends any session still running. Keep a `tego` command or a Linux shell open while an agent works; `tego start` reminds you.

`tego dashboard` opens the dashboard in your browser through a small relay that admits only your own Windows account's programs. While the relay or the dashboard runs, Tego's Linux stays up, also after you close the window. To let it stop:

```powershell
tego dashboard --stop
```

With no session running, this ends the relay and the dashboard, and Tego's Linux stops by itself within about 15 seconds. With sessions running, it ends only the relay and says how many sessions keep Tego's Linux up; run it again when they end. It counts only your own sessions, the ones `tego session list` shows. `wsl --terminate tego` stops Tego's Linux at once.

## Next steps

- [Install](/docs/install/): the install command for each platform.
- [Protection levels](/docs/tiers/): what Basic, Plus and Max enforce.
- [Self-check](/docs/self-check/): check what this machine can enforce.
- [Servers and CI runners](/docs/servers-and-ci-runners/): SSH logins, service accounts and kernel settings.
