# ADR 0009: macOS and Windows run the Linux engine in a VM

Status: accepted 2026-09-21; amended below for the Mac installer and native Windows command. The engine remains Linux-only. See docs/INSTALL.md for the current paths and measured coverage.
Decision: the engine stays Linux-only. On macOS, `tego` starts a small Linux VM (lima with the Apple Virtualization backend, an image whose kernel has `bpf` in the LSM list and BTF) with the project mounted by virtiofs; on Windows, WSL2 (unprivileged tier on the stock kernel, hardened tier with a custom kernel via `.wslconfig`). The native CLI proxies `run`, `status`, `approve`, `stop` to the engine inside; same binary, contract and ledger.
Why: it is the Docker Desktop model developers already accept; one engine to test; kernel facts stay uniform.
Consequence: agents that need macOS-native tools run outside the VM and are enforce-only via a later Seatbelt backend (I11b); inode-ancestry rules depend on the VM mount preserving stable inodes, which the verification pass checks for virtiofs.

Amended 2026-09-21: no purpose-built kernel is needed anywhere. macOS: Lima's Fedora template already lists `bpf` and `landlock` and ships BTF; Ubuntu images need one GRUB drop-in written by a `provision` script. Windows: the stock WSL2 kernel has `CONFIG_BPF_LSM=y`, Landlock and BTF; the hardened tier needs one `.wslconfig` line (`kernelCommandLine = lsm=<current list>,bpf`) and `wsl --shutdown`. `compile` and inode resolution run inside the VM, and `doctor` runs a mount-identity check on the virtiofs mount before enforcing on it.

Amended 2026-11-16: the one-line installer on a Mac now creates the VM from the release's Lima template (`examples/lima/tego.yaml`, docs/INSTALL.md), and the `tego` command it installs on the Mac is a shell wrapper that runs the engine in that VM; there is still no native macOS engine. What ships differs from the decision above in one point: no Mac folder is mounted (projects live in the VM; a person adds a mount on purpose). The installer verifies the template and the VM's installer at the selected release before Lima starts, refuses a release whose template does not take the pinned version and digests as parameters (marker `# tego-mac-provisioning: 1`), and passes the SHA-256 of the checksums file it verified into provisioning, so the VM's binaries are bound to what the Mac verified even when the VM has no verifier. The dashboard is reached through an SSH forward bound to 127.0.0.1 whose control socket, folder and listening process must belong to the caller before it is reused. The socket has one path in the VM's folder: a caller-owned socket whose master no longer answers is replaced there while the port is free, and an unsafe folder (another owner, or writable by group or others) or a linked or foreign socket is refused in one line, with no fallback folder. None of this has been run on a Mac by the repository's CI: the installer's tests use stand-ins for Lima, SSH and the browser.

Amended 2026-11-17: the Lima template keeps only the dated Ubuntu images with SHA-256 digests for Apple silicon and Intel; if no pinned image can be fetched, the Mac installer asks the person to update the installer rather than accepting an unpinned fallback.


## Amendment 2026-11-17: Windows command, installation and shared WSL host

The Windows installer imports the SHA-256-pinned Ubuntu 24.04.5 point-release filesystem into a distribution
named `tego`. It creates only that distribution, checks registration ownership by its Lxss `BasePath`, leaves
other registrations and any existing default-distribution choice alone, and never invokes global WSL shutdown. The image is a
third-party download, checked against the installer pin; it is not a Tego-signed artifact. Its stable locations are
[amd64](https://releases.ubuntu.com/24.04.5/ubuntu-24.04.5-wsl-amd64.wsl) and
[arm64](https://cdimages.ubuntu.com/releases/24.04.5/release/ubuntu-24.04.5-wsl-arm64.wsl). Import avoids store
onboarding and permits checking the exact bytes before registration.

The Windows build floor is 19044; the source-audited WSL floor is 2.6.3. These are implementation floors, not
certification of every supported release. [Microsoft's WSL installation documentation](https://learn.microsoft.com/en-us/windows/wsl/install)
and the [2.6.3 client source](https://github.com/microsoft/WSL/tree/2.6.3/src/windows/wslclient) establish the used
flags; [systemd support](https://learn.microsoft.com/en-us/windows/wsl/systemd) starts independently at WSL 0.67.6.
Before enabling WSL the installer explains the administrator prompt, launches the elevated operation in its own
console, reads a result file including feature/restart state, and prints the exact line to paste after a required
restart. Native probes receive closed input and plain captured stderr. Downloads suppress PowerShell 5.1's
costly progress rendering. Physical processor architecture comes from CIM, including ARM64 under x64 emulation.

`cmd/tego-windows` builds a native `tego.exe` for windows/amd64 and windows/arm64. Both are release assets in
the signed checksums. The installer checks the executable's checksum before placement. The native command
starts `%SystemRoot%\System32\wsl.exe` by absolute path and carries UTF-8 JSON arguments as base64 data to the
root-owned entry point, which decodes only after entering a systemd user scope. No batch file or PowerShell
argument binder sits between the native command and WSL. Standard input/output/error pass through; Linux
nonzero exit statuses cause no repair message. Empty and quoted arguments remain subject to the calling
shell's own native-command rules, measured separately in the guest and documented in the install guide.
Executable certificate signing remains an owner decision; a signed checksums file is a separate boundary.

The `tego` user has uid/gid 26743, outside the common first-user 1000, and receives no sudo grant. Provisioning
checks that numeric identity and startup configuration for repeatability. All WSL2 distributions belonging to
one Windows account share one Linux kernel, loopback network and numeric uid space. Root in any of them is
root over that kernel and can assume Tego's uid. The distinctive uid reduces accidental overlap; it creates no
boundary against that root. Windows-facing wording is “Tego's Linux, inside Windows.” Mac wording stays separate.

Provisioning disables Windows drive automount, fstab, ldconfig, Windows program interop, appended Windows PATH,
and GPU settings in the dedicated root-owned `/etc/wsl.conf`. The normal entry checks that its process actually
entered this user's manager cgroup. A cold WSL launch was observed to start before the lingering user's bus,
printing a WSL failure line even when Linux returned its intended status. The native launcher now starts a
private fixed-entry client, waits for a scoped readiness token, and keeps that client attached while the person's
command runs. Only bootstrap diagnostics are captured; command streams/status remain direct. It accepts no
caller command on the readiness channel and grants no additional namespace authority. A fresh Windows guest
returned silent exit 37 after a cold start in 18.41 seconds. The native/reference argument vectors, 1 MiB binary
stdin/status and real-console Ctrl-C were measured in cmd.exe, Windows PowerShell 5.1 and PowerShell 7.7.0.

The four-step guide remains blocked on the measured default WSL configuration: its existing governed-caller
check refuses a private cgroup namespace whose hidden ancestors it cannot prove safe (exit 125). The installer
now runs `setup --json` after checking the kernel tier and leaves the verified diagnostics/removal command
while returning 8 on that refusal, rather than printing Ready or a working first-session promise. No guard was
relaxed and no global `isolateDistroCgroup=false` setting was selected. A manually prepared copy of the actual
sample project completed a supervised run, refused its fake-secret read and kept the correct session record;
that is not a successful beginner guide. Repair stops the distribution only when startup settings need a restart,
explains that stop and requires fresh consent when it was running. Unchanged repair preserves active sessions
and does not overwrite an identical running Windows image. Interrupted-import files are retained in a named
folder before another import. Registry PATH edits use unexpanded values and preserve their registry type, then
broadcast the environment change. Removal defaults to no; its `-Yes` applies only to that invocation. It unregisters only
the owned distribution, and delegates executable deletion to a system PowerShell that waits for the exact
launcher process to exit. Install-time `TEGO_YES=1` never answers removal.

Global `.wslconfig` is kept by default. Only the separately named `-DisableWslg` switch requests disabling Linux
windows and sound for every distribution. Installation yes never selects it. The optional edit follows command
installation; ambiguity, concurrent edits and filesystem errors produce a note without stopping installation.
An unchanged written file can be restored on removal; later edits are kept and explained. No other distribution
is stopped to apply that global setting.

### Browser design stopped by a guest measurement

The dashboard's existing Host, Linux peer uid, token and cookie checks remain unchanged. Native WSL forwarding
cannot establish the Linux same-user client socket they require. The proposed design placed the dashboard and
an exclusive native relay at 127.0.0.2, carrying connections as Tego's Linux user through WSL standard streams.
Measurements preceded implementation, in Windows 11 Enterprise evaluation build 26300.9457 under KVM on the
developers' machine with WSL 3.0.5 and kernel 6.18.58.1.

In NAT mode a Linux-specific 127.0.0.2 listener was unreachable from Windows while the 127.0.0.1 control worked.
Windows exclusive .2 binds rejected same-account and different-account second binds with Winsock 10013; the
other account could bind an unused port as control. Random 64 MiB transfers were bit-identical in both directions.
Twenty fresh WSL connection operations averaged 1065.94 ms (median 1069.25 ms, p95 1428.71 ms), already above
the 150 ms threshold before user-scope overhead; a future relay must multiplex one long-lived WSL process.

Mirrored mode also left the Linux-specific .2 listener unreachable. **A Linux wildcard listener, however,
answered at Windows 127.0.0.2 and prevented the Windows exclusive bind.** That contradicts the proposed origin
ownership assumption. Relay construction stopped under the design's stop rule. `tego start` does not start a
Windows dashboard unit; `tego dashboard` and `tego serve` open nothing, print the cause and name the session
commands. No 127.0.0.1 browser workaround is offered. A safe revised design needs a decision.
This is an open Windows browser gap; terminal coverage is recorded separately in the install guide.

*Amended 2026-11-19:* the browser path is the dashboard relay inside the native
`tego.exe`, recorded with its measurements in ADR 0123, "A browser on Windows". It listens on Windows `[::1]` at
the dashboard's own port with `SO_EXCLUSIVEADDRUSE`, admits only processes of the person's Windows user, and
carries their connections over one `wsl.exe` child to a Linux end that connects to the dashboard as the person,
from the person's user scope. Measured first: after the exclusive bind no Linux listener shared or took `[::1]`
in NAT or mirrored networking, and no Linux process reached it. Mirrored networking reserves the dashboard's port
on Windows, so there the relay refuses with that reason. The dashboard's checks are unchanged.

### Remaining Windows reach

The [per-distribution parser](https://github.com/microsoft/WSL/blob/2.6.3/src/linux/init/WslDistributionConfig.cpp)
contains keys beyond the [configuration guide](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).
`general.guiApplications` affects generated units; WSLg mounts and GUI/audio sockets can remain despite it in
other configurations.
The measured guest retained `/mnt/wsl`, base `/run/WSL` sockets and kernel-wide binfmt registration with interop
disabled. In the fully provisioned diagnostic distribution, common X11, PulseAudio and Wayland sockets were
absent and `/mnt/wslg` was an ordinary directory. `/dev/dxg` remained a character node; a read-open returned
EBADF, which does not establish GPU access. The same copied Windows cmd.exe bytes executed through binfmt
and direct `/init` in the person's Ubuntu uid 1000, and both paths refused as Tego uid 26743. No Windows drive
mount or Windows PATH was present for Tego. Retained init sockets and binfmt entries alone do not prove Windows
execution works. Global WSLg disable removed GUI
mounts/sockets in the facts experiment, without removing `/mnt/wsl` or the shared network. Root can re-enable
root-owned distro configuration. Network reach depends on listener, firewall and
[NAT or mirrored mode](https://learn.microsoft.com/en-us/windows/wsl/networking); it is not established closed.

[DrvFs](https://github.com/microsoft/WSL/blob/2.6.3/src/linux/init/drvfs.cpp) uses AF_VSOCK ports 50002/50003.
Disabling automount and interop does not establish that direct unprivileged protocol access is closed; server
availability and access controls remain unmeasured. Existing ADR 0018 handling refuses new AF_VSOCK sockets
under a `net:` section, without a claim for absent `net:` or inherited descriptors. No built-in refusal changes.
Doctor names visible channels, an open session interop signal when present, and transport uncertainty, with
bounded detail and no change to tier selection. GAPS and the install guide state the same shared-kernel limits.

A lingering user manager did not keep the distribution alive after the last attached WSL client: the diagnostic
journal shut down about 17 seconds after the last command. A dedicated supervised user-unit measurement then
established a live heartbeat and zero Windows wsl.exe clients: the distribution stopped within 23.21 seconds,
the run ended by signal 15 after 22.4 seconds, and PID 1 changed on the next attach. The foreground native command
keeps its WSL clients attached while it runs; unattended detached lifetime remains an open limit. No persistent
relay was built to claim otherwise.
