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
| Windows | Windows build 19044 or later, x64 or arm64, virtualization turned on, WSL 2.6.3 or later, at least 5 GB free |

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
- cgroup v2 delegated to your user ([Servers and CI runners](/docs/servers-and-ci-runners/#cgroup-delegation)). A cgroup (control group) is how Linux groups a session's processes.
- `ptrace_scope`, the kernel setting for which processes may inspect others, at 0 or 1 ([how to set it](/docs/servers-and-ci-runners/#ptrace-scope-setting)).

[Servers and CI runners](/docs/servers-and-ci-runners/) covers SSH sessions, service accounts and RHEL 9's CPU limits.

### Plus

- Root, through `sudo`.
- The kernel's BTF type information, which BPF programs (small programs the kernel runs) use to read kernel data.
- cgroup v2.
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
| Debian 13, Fedora, RHEL 9 and 10, Amazon Linux 2023 | Yes | Yes, with no change |
| Ubuntu 24.04 and later | Yes | After one boot setting |
| Debian 12, and other 6.1 kernels | Yes, without kernel TCP port rules | Run `sudo "$(command -v tego)" machine check` |
| Ubuntu 22.04 with its stock 5.15 kernel | No | No |

Plus works wherever Basic does and you have root, unless a requirement above is missing.

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

Keep rules files in your Linux home inside WSL. Tego refuses to load a rules file from `/mnt/c` or another Windows drive, because WSL makes up the owner and permissions of files there and any Windows program can change them. A project on a Windows drive works; its rules file goes in your Linux home.

## Next steps

- [Install](/docs/install/): the install command for each platform.
- [Protection levels](/docs/tiers/): what Basic, Plus and Max enforce.
- [Self-check](/docs/self-check/): check what this machine can enforce.
- [Servers and CI runners](/docs/servers-and-ci-runners/): SSH logins, service accounts and kernel settings.
