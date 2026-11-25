# Install

Tego runs on Linux. On macOS it runs in a Linux VM; on Windows it runs in its own WSL2 distribution. Each has a one-command install, below; building from
source is the other way.

| System | Install | Tested on |
|---|---|---|
| Linux | `curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh \| sh` | The published v0.1.1 as a new user, tier landlock: AlmaLinux 9.8, Ubuntu 24.04 and 26.04.1, Debian 13, Fedora 44, Amazon Linux 2023 ([details](TIERS.md#the-published-release-as-a-new-user)). Release files built for v0.2.0, as a user and as root: AlmaLinux 9.8, Amazon Linux 2023, Ubuntu 24.04 and 26.04.1, Fedora 44 ([details](TIERS.md#platforms-checked-for-v020)) |
| macOS | `curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh \| sh` | By hand on an Apple silicon Mac, through to a Claude Code session; in CI on GitHub's hosted macOS 15 runners when a pull request changes the installer or the Mac setup ([details](#macos)) |
| Windows | `irm https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.ps1 \| iex` | Windows 11 Enterprise evaluation, build 26300.9457 under KVM; WSL 3.0.5.0. The guide's WSL blocker was lifted by the rule's switch-on (below); the ordinary build passed the six beginner steps there (below), from a local mirror, unsigned, without a real mouse or HTTPS release; the browser dashboard opens |

## Requirements

| | |
|---|---|
| Operating system | Linux, amd64 or arm64. The engine runs in a Linux VM on macOS and a WSL2 distribution on Windows (below); their host commands enter Linux. |
| Kernel | Tier 1 (no root) needs Landlock ABI 2 or newer, which is Linux 5.19 or later or a backport such as RHEL 9's 5.14, and cgroup v2 with a subtree delegated to your user. The oldest kernels the project tests are 6.1 and RHEL 9's 5.14. Ubuntu 22.04's stock 5.15 has Landlock ABI 1, so no tier runs on it. Tiers 2 and 3 need root and the kernel's initial process-id namespace, and tier 3 needs `bpf` in the boot LSM list. [TIERS.md](TIERS.md) has the table. |
| To install a release | `curl` and `sha256sum` (or `shasum`). With `cosign`, or a `gh` that is logged in, on `PATH`, the installer also checks who published the release. |
| To build | `git`, `make` and Go 1.27 (CI builds with 1.27.4). You do not need clang: the compiled BPF objects are committed. |

## Linux

```sh
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh
```

`install.sh` is an asset of the latest release, listed in its signed checksums file. It downloads that release's `tego`
and `tego-control` for your architecture, checks each against the release's
sha256 checksums, and installs both into `~/.local/bin`. When available,
cosign verifies the checksums file's signature; gh verifies each asset's build provenance attestation.
Both require this repository's release workflow at the selected tag; without either the installer says
that only the checksum was checked, and how to get cosign
([Sigstore's install page](https://docs.sigstore.dev/cosign/system_config/installation/)) or log `gh` in (`gh auth login`). It runs the new `tego` before it replaces anything, and it needs no root. It ends
with the next steps: the `export PATH` line if `~/.local/bin` is not on your `PATH` yet, over SSH the
`systemd-run --user --scope bash` line (automatic entry is built, with SSH validation owed in a guest), a line that
a service account needs its own copy (below), then one next command: `tego start` when the installed `tego` has it, else
`tego setup`, else `tego doctor`. The installer does not change your `PATH`, so until you run that line, or log in again, the shell
answers `tego: command not found`; for that reason the next command names `tego` by its full path while the folder is not
on your `PATH` (and as a bare `tego` once it is), so it runs in the shell you are in. For the default folder the line is `export PATH="/home/<you>/.local/bin:$PATH"`,
with your own home folder. Ubuntu's `~/.profile` adds `~/.local/bin` at login; elsewhere, add the line to your shell's
profile.

Settings are environment variables, given to `sh`:

```sh
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | TEGO_VERSION=v0.1.2 sh
```

`TEGO_VERSION` picks a tag (default: the latest release), `TEGO_PREFIX` the folder (default `$HOME/.local/bin`) and
`TEGO_VERIFY` the check (`auto`, `cosign`, `gh` or `sha256`).
`TEGO_CHECKSUMS_SHA256`, when given, pins the downloaded checksums file to that SHA-256 before any entries are used.
The Mac installer supplies it from its release verification; a Linux install without it keeps the checks above.
The installer exits with 2 for a missing dependency, 3 for an unsupported platform, 4 for an unsupported architecture, 5 when there is no such release, 6 for a failed download, 7
for a checksum mismatch, 8 for a failed install step and 9 when the signature or provenance did not verify. Run it again
to upgrade.

Do not fetch `install.sh` from a branch: the installer is the root of trust, so take it from a tagged release, as the
line above does. Piped into `sh`, it still runs before anything checks it. To run only a script you have checked, verify
it first: [Check the installer first](#check-the-installer-first).

**Tested on** 2026-11-11 with the published v0.1.1, as a new user, on AlmaLinux 9.8, Ubuntu 24.04, Debian 13,
Fedora 44, Amazon Linux 2023 and Ubuntu 26.04.1: [Check the installer first](#check-the-installer-first) with `tag=v0.1.1`,
then `tego doctor --require landlock`, `tego test`, a run and the record's checks, all at tier landlock
([TIERS.md](TIERS.md#the-published-release-as-a-new-user)). On a fresh Ubuntu 24.04, the first line of this section, as written,
installed v0.1.1 with the checksum check only, since that image has no `cosign`. `scripts/install_test.sh` covers each
check, the piped form and the exit codes.

On 2026-11-24, release files built from v0.2.0's code were installed with the release's `install.sh` from a local
folder (the checksum check only) on AlmaLinux 9.8, Amazon Linux 2023, Ubuntu 24.04, Ubuntu 26.04.1 and Fedora 44, then
run as a user and as root ([TIERS.md](TIERS.md#platforms-checked-for-v020)). A fresh install passed on Ubuntu 24.04 and
Debian 12, and an update from the published v0.1.3 on Ubuntu 24.04 and Debian 13. The published v0.2.0 files were not
part of those runs.

## macOS

Tego runs in an Ubuntu 24.04 VM made by [Lima](https://lima-vm.io), on Apple silicon or Intel.

```sh
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh
tego start
```

The installer offers to install or upgrade Lima, create or start Tego's VM, and add the Mac `tego` command. Follow
its printed shell restart line if needed. `tego start` runs the guide inside the VM, opens the dashboard in your
Mac browser and leaves you in a VM shell in the project. `tego shell` opens that shell again.

Before creating a VM, the installer resolves the selected release tag, downloads `tego.yaml` and `install.sh` into
a private temporary directory, and checks their release checksums. It uses the same `TEGO_VERIFY` setting as Linux:
cosign verifies the checksums signature at that tag; gh verifies the template, installer and the guest architecture's
Linux binaries against their provenance attestations and checks their entries in the checksums file. An explicit
verifier failure stops creation. Lima starts from the verified local template, with no Mac mounts, and receives
the selected tag, the verified installer digest and the SHA-256 of the verified checksums file. Provisioning checks
the installer digest before executing it and passes the tag and checksums digest to the Linux installation.
The guest refuses a changed checksums file before checking or installing any binary, even without a verifier in
the VM. For example, `TEGO_VERSION=v0.2.0` selects that version inside the VM too.
Pinned Mac creation requires a release template with `# tego-mac-provisioning: 1`; older templates are refused
before creation. For an existing VM, a release without this marker leaves Tego inside it as it is, without asking
or failing. Updating it from the Mac needs a later release.
The initial piped Mac script has the same trust limit as Linux; [verify it first](#check-the-installer-first) if needed.

The template, [examples/lima/tego.yaml](../examples/lima/tego.yaml), boots Ubuntu 24.04 LTS with 4 CPUs, 4 GiB of
memory and a 20 GiB disk. Tier 1 needs nothing more there: Ubuntu's kernel has Landlock and systemd delegates a
cgroup to your user.

Rerunning the Mac installer refreshes its Mac command before any release lookup or guest update; a later failure
keeps that command refreshed and returns its failure status. For a compatible release, a matching guest version
is up to date. An older, missing or broken installation gets `Update Tego inside the VM from X to Y?`, default yes.
A newer guest gets `Replace Tego X inside the VM with older version Y?`, default no (including prerelease tags).
`TEGO_YES=1` explicitly accepts either; without a terminal it prints one retry command and stops. Unsupported
releases produce one note and finish normally, including with `TEGO_YES=1` or no terminal.
The update uses the same release base URL and verified checksums digest as the Mac, without recreating the VM
or changing projects, contracts or records. Existing runs keep their old executable until they finish: the Linux
installer renames new files into place. New commands use the selected release. Declining leaves the guest as it was.

If a new VM's image download fails, first run `limactl delete tego` to remove that incomplete instance before
retrying. The installer leaves deletion to you so you can inspect the instance and log. Only a not-found diagnostic
says the image is unavailable and suggests updating the installer; other download failures suggest checking the
connection and running it again.

No Mac folders are mounted in the VM by default: neither your Mac home nor `/tmp/lima` is shared. Programs in
it cannot read or write Mac files through a filesystem share. Lima stores the VM disk and configuration on the Mac;
Tego's data and projects live in the VM's own home. The Mac command enters that home or the last project inside the
VM; `tego start` asks for a project path inside the VM.

To share a folder explicitly, stop the VM with `limactl stop tego`, then run `limactl edit tego` and replace
`mounts: []` with a limited mount, for example:

```yaml
mounts:
  - location: /Users/you/shared-project
    writable: false
```

Start it again with `limactl start tego`. An agent in the VM can read files in that mount, including any secrets in
it; the built-in secret paths refer to the VM home and do not protect secrets in a Mac mount. With `writable: true`,
an agent can also change Mac files there, subject to its contract. Existing VMs keep their mounts: stop and edit
one to set `mounts: []` if it was created with an older template.

`limactl shell` logs in over SSH. Automatic entry is built; validation is **owed in a guest**. Keep the manual path:

```sh
limactl shell tego
cd ~
systemd-run --user --scope bash
tego test
```

The dashboard answers only connections made by its own user. Lima forwards the VM's ports to the Mac itself,
connecting as root inside the VM; Tego's own tunnel is set up for 8484, which the template excludes from Lima's
forwarding. For a manual forward of the default dashboard, start `tego dashboard` in the VM, run this in another Mac
terminal, and open the URL it printed:

```sh
ssh -F ~/.lima/tego/ssh.config -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8484:127.0.0.1:8484 lima-tego
```

The Mac command still reads the port from the dashboard link. If another process holds a different dashboard
port on the Mac, Lima's own forwarding is a likely cause. Put the dashboard back on 8484, or run `limactl stop tego`,
then `limactl edit tego` and add this rule under `portForwards` (8599 is the example port):

```yaml
  - guestPort: 8599
    ignore: true
```

Then run `limactl start tego` and `tego dashboard`. Other dashboard ports have not yet been verified on a Mac.
This leaves Lima's forwarding of other VM ports available.

The Mac command keeps its dashboard tunnel at `~/.lima/tego/tego-dashboard.sock`, reuses a confirmed live tunnel,
uses `tego-dashboard-PORT.sock` for a different dashboard port, and replaces an owned leftover socket when its
master no longer answers and that port is free. A foreign listener on the selected port is refused. It leaves a linked
or foreign-owned socket untouched. If the socket folder belongs to someone else or is writable by group or others,
it names the folder and asks you to correct its ownership and write permissions before trying again. These refusals
start no tunnel and open no browser; they create no temporary socket folder.

`limactl stop tego` stops the VM and `limactl delete tego` removes it.

**Tested on** an Apple silicon Mac by hand, in zsh, with Lima 2.3: install, `tego start` with a Claude subscription, a
session with both blocked actions, and `tego dashboard`. On each pull request that changes the installer, the Mac test
scripts or the Lima template, CI runs on GitHub's hosted macOS 15 runners, Apple silicon and Intel
(`.github/workflows/mac-install.yml`): Lima validates the template on both.
On Intel, when a Lima driver can boot a VM there, CI runs the real installer, the Mac command, the guide, the
dashboard tunnel and a rerun; when none can, it checks that the installer fails cleanly. Apple silicon runners cannot
start a nested VM. `scripts/install_mac_test.sh` covers every installer path
with stand-ins for Homebrew, Lima, SSH and the browser.

## Windows

Tego keeps AI agents inside rules. It needs Linux; the installer sets up **Tego's Linux, inside Windows**.
WSL (Windows Subsystem for Linux) is the Windows feature that runs Linux. Allow about 5 to 10 minutes for
first setup, about 500 MB of downloads, and at least 5 GB free disk space.

**Preview limitation:** Windows and WSL are not fully qualified. The default WSL configuration (a private cgroup
namespace) used to refuse the guide's safety check; since the run-membership rule was switched on for WSL
(ADR 0100), setup and the four steps proceed where WSL shows two of its marks. A Windows 11 guest ran the ordinary
build, installed with the one line from release assets, through all six beginner steps (install, `tego start`, a
supervised run with its refusals, `tego dashboard`, approving a held request in the browser, and uninstall); what
that did and did not prove is listed under "Tested on" below. Where WSL shows one mark only the refusal stays. If the installer ends with “The guide is not ready on this WSL setup”, it
leaves the verified command for diagnostics and removal, reports the refusal and prints one next command. Do not
change machine-wide WSL settings to bypass it. `tego dashboard` opens the dashboard in your browser (below).

To inspect this path, open PowerShell from Start (Windows PowerShell 5.1 or PowerShell 7) and paste:

```powershell
irm https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.ps1 | iex
```

Before Windows asks for administrator permission, the installer explains why it needs to enable or update WSL.
Choose Yes in that Windows prompt. It reads back the elevated step's result. If a restart is needed, save your
work, restart Windows, open PowerShell again, and paste the same line. After installing Linux, the installer
checks both available protection and whether the guide can run. On the guest as first measured, before the rule was switched on, it ended with “The guide is not ready on this WSL
setup” and the full Windows command for `setup --json`, which reported the cgroup-namespace refusal; where the guide
can run, the next step is:

```powershell
tego start
```

The intended four steps choose your agent, login, project and rules. With no agent installed and signed in, the first
choice is the demonstration agent, which needs no account: the guide runs it once and ends with the commands that show
the run. Otherwise choose your agent and the test project for the first run. In the Ready panel, copy the command beginning with `cd` and press Enter. The sample's poisoned dependency tries to
read a fake secret; Tego should refuse that read and keep the record. Then type `tego session list` and
`tego session show --last`. Type `exit` to return to Windows.

For a saved installer file, read it first, then run `powershell.exe -ExecutionPolicy Bypass -File .\install.ps1`.
`-Yes` or `$env:TEGO_YES='1'` accepts installation questions. These never consent to removal or to changing Linux
windows and sound for all installations. Without a terminal and without install consent, the installer prints the manual
next step and stops.
A declined step says what was kept. Running the one line leaves no installer functions, switches or preference
changes in the PowerShell session; the command path is intentionally updated.

### What is installed

The engine remains Linux-only. The host command is a native **tego.exe**, built for Windows x64 and arm64 and
listed in the release checksums. Its checksum is checked before placement under `%LocalAppData%\Tego\bin`.
It starts the system's `wsl.exe` by absolute path and carries arguments as base64 UTF-8 JSON, without cmd.exe or
PowerShell in the argument path. Standard input goes to Linux and command exit statuses return without added
repair messages. The Windows executable is currently unsigned; release-checksum authentication and Windows
executable signing are separate things.

The installer imports the pinned Ubuntu **24.04.5 point release**, checks its SHA-256, and creates only the `tego`
distribution. Your existing Linux installations and default-distribution choice are kept. The normal `tego` user
has uid and gid **26743**, outside the usual first-user 1000, with no sudo grant. Provisioning is repeatable.
The checked Linux installer runs as that user; commands enter the systemd user manager's scope. A private
native startup client waits for that scope before
passing through the person's command; it closes when the command ends. A systemd scope alone does not resolve
the private-cgroup-namespace refusal of a build from before the rule was switched on; the rule decides now (above).
`tego doctor` shows the measured checks and remaining Windows reach.

The requested minimum is Windows build **19044** and WSL **2.6.3**. This is an implementation floor, not a claim
that every version, architecture or PC has been tested. See the exact tested-on statement below.

`tego` without arguments enters the home or last project's shell. `tego shell` accepts shell arguments too.
The banner identifies Tego's Linux, inside Windows, and says how to return. Projects live there. To copy your
project, open File Explorer and paste `\\wsl$\tego\home\tego` in its address bar, then drag the project folder in.
Use `~/my-app` in the guide, or paste the Explorer path itself, with or without its surrounding quotes.
A Windows drive path such as `C:\code\app` gets the same copy instructions.

### Dashboard connection

`tego dashboard` in PowerShell or cmd starts the dashboard inside Tego's Linux and opens it in your default
browser at `http://[::1]:8484/` (the dashboard's own port), signed in by a link that works once, within a minute.
A small hidden helper, the dashboard relay (`tego.exe` itself, with no window), carries your browser's
connections into Tego's Linux. The first `tego dashboard` starts it; later ones reuse it, after checking that it is
yours and that it reaches your dashboard. It admits only programs running as your own Windows account:
connections from other Windows accounts are refused, and programs inside WSL cannot reach it. Its log is
`%LOCALAPPDATA%\Tego\relay.log`.

- `tego dashboard --stop` ends the relay. It also ends when you sign out of Windows, when Tego's Linux stops, and
  before the installer updates or removes Tego. The next `tego dashboard` starts a new one.
- While the relay runs it keeps Tego's Linux, and so the dashboard, running, also after you close the window.
- In a shell inside Tego's Linux, `tego dashboard` starts the dashboard but cannot open a Windows browser: type
  `exit`, then run `tego dashboard` in Windows.
- `http://127.0.0.1:8484` does not work from Windows: WSL's own forwarding answers there, and the dashboard refuses
  connections it cannot trace to your Linux user. No Host, peer, token, cookie or governed check is relaxed.
- WSL **mirrored networking** (`networkingMode=mirrored` in `.wslconfig`) is not supported for the browser
  dashboard: WSL then reserves the dashboard's port on Windows, so the relay cannot listen there. `tego dashboard`
  says so and opens nothing; the terminal commands still work.
- Answering a held request with Allow once in the browser works on the ordinary build where WSL shows two of its marks:
  in the Windows guest the held write continued within seconds of the click, with no "unauthorized peer". A guest on
  a build from before the rule was switched on, or a distribution that shows one mark, still refuses it ("Not done:
  unauthorized peer"). The record names the answer as given in the dashboard by the signed-in person (see `tego
  session show`), not as the dashboard's own process.

### Windows host reach

All WSL2 distributions of one Windows account share **one Linux kernel, loopback network and numeric user-id
space**. Root in any of those distributions is root over that kernel. The distinctive Tego uid reduces accidental
identity overlap; it does not protect against that root user. This differs from the Mac's separate Linux VM.

| Channel | Default here | Remaining reach |
| --- | --- | --- |
| Windows drive mounts and fstab | Off in `/etc/wsl.conf` | Root can re-enable or mount them. The normal user has no sudo grant. |
| Windows programs | Interop off | Kernel-wide binfmt and base init sockets can still exist. Their presence alone does not prove Windows execution works. |
| Windows PATH | Off | Doctor examines the environment the command actually receives. |
| Cross-distribution `/mnt/wsl` | Open | Other distributions can publish files and sockets accessible to Tego's user. |
| Linux GUI/audio (WSLg) | No common sockets found in the measured provisioned distribution | An ordinary `/mnt/wslg` directory is not a socket. Other WSL versions/configurations may expose GUI/audio sockets; doctor reports actual socket nodes, without claiming access was tested. |
| Windows network services | Not established closed | Reach depends on the actual Windows firewall, listener and networking mode; NAT or mirrored mode is not a blanket isolation boundary. |
| DrvFs VM sockets | Not established closed | Automount and interop settings do not prove direct unprivileged protocol access is closed. A contract's `net:` section refuses new AF_VSOCK sockets; this does not cover absent `net:` or inherited descriptors. |
| GPU | Settings off | Doctor reports `/dev/dxg` if present; the settings alone do not prove device isolation. |
| Explorer/editor access into Linux | Available | Windows can deliberately edit `\\wsl$\tego`; this grants no Linux-to-Windows drive mount. |

The default install keeps `%UserProfile%\.wslconfig`. Only the separately named **-DisableWslg** switch turns off
Linux windows and sound for **all** your Linux installations. Choose that only if you do not use their GUI apps.
`-Yes` and `TEGO_YES=1` never select it. The step comes after the command is installed, preserves unrelated
settings and a backup, and is optional: a refused or failed edit does not block installation. The installer never
stops your other Linux installations to apply it. Save their work and restart them yourself if you opt in.
Global `networkingMode=none` also prevents the agent's network access; it is not selected by this installer.
[Known limits](GAPS.md#wsl2-host-reach) names the remaining channels.

### Repair and removal

Rerun the same installer to repair a missing command or engine. It checks startup settings first and restarts
Tego's distribution only if those settings changed; it asks explicitly before that stop. A normal repair keeps
running sessions alive. Registration ownership is checked against Tego's installation folder, so a missing
marker can be repaired. A conflicting installation is kept, with an explicit diagnostic/removal command.

Keep a Windows `tego` command or Linux shell attached while work runs. In the measured guest, with no Windows
`wsl.exe` clients, WSL stopped a live detached supervised user unit within **23.21 seconds**; its receipt ended
by signal 15 after 22.4 seconds. Linger does not keep the distribution alive. Unattended lifetime is an open limit.

To stop Tego's Linux, type `wsl --terminate tego` in Windows. Save your work first.

To remove Tego, its projects and all run records, type `tego uninstall`. Enter means **no**. To explicitly consent
on that invocation:

```powershell
tego uninstall -Yes
```

A saved installer also accepts `-Uninstall -Yes`. An install-time `TEGO_YES=1` does not answer removal.
WSL itself and your other Linux installations remain. Tego's installation folder and command-path entry are
removed. The running native command exits before a short cleanup process deletes its executable.
Later edits to global settings are kept with an explanation.

### Arguments at the Windows shell boundary

The native command preserves the arguments it receives. A shell can change them before starting any native
program. Quote metacharacters in cmd.exe, and use the shell's normal literal-string syntax in PowerShell.

| Shell measured | What reaches a native program |
| --- | --- |
| cmd.exe, delayed expansion off; UTF-8 CRLF batch with `chcp 65001` | Quoted `&`, `|`, `<`, `>`, `^`, `!`, empty strings, spaces, dashes, colon switches and non-ASCII survived. `%VAR%` expanded even inside quotes. Unquoted metacharacters remain cmd.exe syntax. Embedded quotes required native-command escaping. The tested CRLF batch fixture preserved a 20,000-character argument on this build. |
| Windows PowerShell 5.1 | Its native binder dropped the empty string and removed the embedded quotes in `say "hi"`; the same happened to an ordinary native reference program. The remaining hostile arguments, including 20,000 characters, survived. UTF-8 script files need a BOM for literal non-ASCII text in this shell. |
| PowerShell 7.7.0, default native argument mode | The whole vector survived, including embedded quotes, the empty string and 20,000 characters. |

**Tested on:** a Windows 11 Enterprise evaluation guest under KVM on the developers' machine, build
**26300.9457**, WSL **3.0.5.0**, kernel **6.18.58.1-1**, Windows PowerShell **5.1.26100.9444**.
PowerShell **7.7.0** ran the complete argument matrix. Fresh release-shaped files from committed source
proved the manual test project's supervised refusal and session views, stdin/status, Ctrl-C, and closed Windows
program/drive/PATH controls against the person's ordinary Ubuntu. They also exposed the guide blocker described above, which the rule's switch-on (ADR 0100) later lifted.
A later guest round (same build) opened the dashboard in Edge from PowerShell 5.1, PowerShell 7 and cmd through the
relay, with one relay reused by all three, a second Windows account refused and no Linux connection reaching it. Defender real-time protection was on; the unsigned executable ran without a detected threat,
prompt or block in that run. A cold native command returned silent exit 37 in 18.41 seconds. Binary stdin/status
and real-console Ctrl-C were checked from cmd.exe and both PowerShell editions.

**The ordinary build, end to end (2026-11-19).** On the same guest (WSL 3.0.5.0, Windows PowerShell 5.1, Edge 157,
Defender real-time protection on), the ordinary release build, not a test build, installed from release assets with the
documented one line, with every question asked and answered (the Windows restart and a second paste of the same line
included), then passed all six steps: `tego start` reached the Ready panel with the test project, the sample run was
refused twice (the secret read and the send) and `tego session show --last` said so, `tego dashboard` opened Edge on the
Overview signed in and showed both runs and their refusals, a held write was approved with Allow once in the browser
and the run continued, and `tego uninstall` removed Tego, its projects, records and the Windows command and left no
process, listener, scheduled task or Run key. On a base that already had WSL, PowerShell 7.7.0 installed, ran the guide,
had the sample run refused twice and uninstalled, and cmd installed (the installer started from cmd through PowerShell)
and ran the guide. The 37 proof rows ran on the ordinary build: 34 passed and 3 stayed unknown (the console-window shell
kind, two rows, which nothing could drive, and the FUSE namespace-file forgery, which is not scripted); none failed.

This did **not** prove: a real keyboard and a mouse click (keys went in as keyboard events and Allow once was a click sent
through the browser's debugging port); a signed executable (it is unsigned, so Windows' SmartScreen was not exercised);
a real HTTPS release (the files came from a local HTTP mirror with the test switches, so no publisher or signature
check ran); ARM64; Windows 10; a domain-managed PC or Windows Home; PowerShell 7 and cmd on a PC with no WSL yet (the
restart path was walked from PowerShell 5.1 only); Windows Terminal or an editor's terminal; Claude Code or Codex (the
runs used a sample project and a fixture rules file); WSL's mirrored networking, which is not supported for the browser
dashboard; and Tego's Linux staying up unattended around the clock. Executable certificate signing remains an owner
decision.

## Run in a container

Signing runs in an isolated job after the binary and image builds. The certificate identity remains this
repository's `release.yml` workflow at the tag; job names do not enter it. The verification commands below therefore
use the same workflow/tag identity as the binary installer.

Releases from v0.1.1 on publish `ghcr.io/attention-span-ai/tego` for Linux amd64 and arm64; v0.1.0 has no image. A
stable release such as `v0.1.2` has image tags `0.1.2`, `0.1` and `latest`; prereleases have only their full version tag,
such as `0.1.1-rc.1`. The image contains the
exact `tego` and `tego-control` binaries checked by the release's signed checksums and reproduction job.

Copy the image digest from the chosen release's notes into `digest` below. Verify it with cosign before running,
using that release's exact tag identity (including the leading `v`). Docker selects your machine's architecture
from the signed multi-platform index. The digest pins the image even if a tag later moves.

```sh
tag=v0.1.2
image=ghcr.io/attention-span-ai/tego
digest='sha256:REPLACE_WITH_THE_RELEASE_NOTES_DIGEST'
cosign verify \
  --certificate-identity "https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$image@$digest" &&
docker run --rm --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges:true "$image@$digest" tego version
```

Build provenance is stored in GitHub and GHCR for the same digest. With an authenticated GitHub CLI:

```sh
gh attestation verify "oci://$image@$digest" --repo Attention-Span-AI/Tego \
  --cert-identity "https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/$tag" \
  --source-ref "refs/tags/$tag"
```

To run the included hello agent after verification succeeds, the entrypoint needs a private cgroup v2 namespace and
capabilities to prepare the user's subtree. It drops them before starting Tego. Keep its state and ledger on separate
volumes:

```sh
docker run --rm --init --cgroupns=private --stop-timeout 40 \
  --cap-drop ALL --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add CHOWN \
  --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt apparmor=unconfined --security-opt no-new-privileges:true \
  -e TEGO_DELEGATE=yes \
  -v tego-state:/home/tego/.tego -v tego-ledger:/var/lib/tego/runs -v tego-work:/work \
  "$image@$digest" tego run /usr/local/share/tego/hello.yaml
```

The run prints a line such as `tego run: r-... ended (exited with code 0) · tier landlock · refused 1 ... · chain
verified`: the agent wrote the one file its contract allows and was refused the other. To read and check the record from
a fresh container, give it the same two volumes and the image's user (copy the run name from that line):

```sh
run=r-REPLACE_WITH_THE_RUN_NAME
docker run --rm --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true \
  -v tego-state:/home/tego/.tego -v tego-ledger:/var/lib/tego/runs \
  "$image@$digest" tego events "$run" --verify
```

It prints `verified 16 lines, run_start to run_end, ... anchored in /home/tego/.tego/chain.log` and exits 0. Replace
`events "$run" --verify` with `receipt "$run"` for a plain-words account of what the run wrote and was refused. A
run started without the `tego-state` volume has no anchor outside its own container to check against.

This flow was run on Debian 13 with Docker 26.1.5 and ended at tier landlock. Inside a container Tego may be unable to
read the kernel's security-module list (Docker's default seccomp profile refuses the system call, and the file may not be
readable either); held file opens are then refused, as on Debian 12 (kernel 6.1). See
[the container guide](user/container.md).

The host's Linux kernel still determines which tier works. See [the container guide](user/container.md) for the
settings, the hosts it was tried on and a Compose setup. The published image uses uid/gid 10001; build it locally with your own
uid/gid when opening the dashboard from the host. First publication also needs an organization/package admin to make
the GHCR package public once; see [the release runbook](VERSIONING.md#72-how-the-tag-is-made).

## Build from source

```sh
git clone https://github.com/Attention-Span-AI/Tego
cd Tego
make build
mkdir -p ~/.local/bin
install -m 0755 bin/tego bin/tego-control ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

`make build` writes `bin/tego-control` first, then `bin/tego` with the SHA-256 of `tego-control` built into it, and checks
the pair. Use `make build`. A plain `go build ./cmd/tego` makes a tier-1-only `tego` that has no pin for `tego-control`:
`tego machine check` reports tier 2 as not built, and `tego serve` refuses with `[control-not-installed]`, or with `[control-unpinned]` once a `tego-control` sits beside it.

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
go=go1.27.4
contract_schema=0
record_v=1
record_readers=1
bpf_hash=<hash of the BPF objects>
parsers=anthropic
control_sha256=<hash of your tego-control>
```

A value in angle brackets is your own build's. A build from a checkout with no release tag names its commit, as here; a
release prints its tag, such as `tego=v0.1.2`. The `control_sha256=` line is the hash built into `tego`, and
`tego-control version` prints the same hash as `sha256`.

## A service account

The shipped user units use `%h/.local/bin/tego`. Install both binaries as the service account there,
or place them in a root-owned shared directory and change the units' `ExecStart` paths to match.
The agent unit sets `PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin`; it does not read a shell profile.
That user-owned folder also reaches the agent when its contract passes `PATH` through `env.pass`.
A manual or automatic user scope inherits its caller's PATH, including sudo's `secure_path` after
`sudo -u`; it adds no binary directories. In the account's scope shell, add its `~/.local/bin` to PATH.

A bare Tego program name after sudo is looked up through sudo's own `PATH` (`secure_path` in the sudoers file), not
yours. That path has no `~/.local/bin`, so the installer's copy is not found, and AlmaLinux 9.8's has no `/usr/local/bin`
either (`sudo: tego: command not found`, measured). A copy in the administrator's home does not help: on Ubuntu 24.04 a
new home is mode 0750 and the service account cannot enter it. Install tego as the account, into its own
`~/.local/bin`. Before the setup command below, put the installed folder on the service account's login-shell
`PATH` in its `~/.profile`. The explicit `sh -lc` reads that profile even if the account's configured shell is `nologin`:

```sh
sudo -u svc -H sh -c 'curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh'
sudo -u svc -H sh -lc 'exec "$(command -v tego)" setup'
```

(`svc` is the account. The login shell needs that account's installed Tego on `PATH`.) Every line that
`tego setup` and the other commands print for you to type with `sudo` then names that copy by its full path, quoted, and
a command that must run in a folder uses a shell as the account, changes folder there, and executes that checked binary.
That form needs a sudoers grant that lets you run a shell as the account; a grant for the `tego`
binary alone refuses it, Tego cannot read the policy, and its line says it may be refused (then run the command from a
shell opened as the account). If the running `tego` cannot be named safely (its path is unreadable, no longer the running
file, holds a control or invisible character, or is not executable by the account), the `next:` line says so and gives no
command. Tego also withholds a command if the file or a resolved ancestor is owned by someone other than root or the
process's effective account. Files refuse group/world write; non-sticky folders refuse world write.
A sticky directory such as `/tmp` is allowed when its next child has a trusted owner: another user cannot rename that child there. The file itself must still refuse writes by
other users. Install Tego in a folder only root or you can write if this check refuses the path.
Directory group write is allowed for the effective user's private primary group, or a group with no
members and no passwd primary users, such as an empty Debian staff group. Bounded local passwd/group reads
and the standard-library account lookup determine membership; only files-only NSS sources establish an empty
group. When membership is unknown (directory services, unreadable or oversized files), only the effective
user's primary gid by id is allowed, and the folder must still be owned by that user or root. Known foreign
local members always refuse. This fallback cannot rule out an unseen account sharing that gid. Non-sticky
group-writable folders with an access ACL or unavailable ACL metadata also refuse: a named ACL writer need
not belong to that group. The executable itself must never be group/world writable.
In the account's own scope shell the lines stay `tego ...`, so `~/.local/bin` must be on that shell's `PATH`
(measured on AlmaLinux 9.8: it is, with the account's home made by `useradd --create-home`).
[setup.md](user/setup.md) ("A user with no user manager") gives the whole order.

## Running with sudo

The command form used throughout these docs is:

```sh
sudo "$(command -v tego)" machine check
```

Your shell resolves `command -v tego` before sudo starts. Put your installed copy on that shell's `PATH` first;
this works for any install folder and does not depend on sudo's `secure_path`. Check that the lookup names the
copy you intend to run. This is a choice made by the reader's shell. A command Tego itself prints instead names
and checks the currently running binary by its absolute path; it does not perform this PATH lookup.

Tiers 2 and 3 need a root launcher, so use the same form with `run` and its arguments.

The launcher is root, and the agent runs as you, with your `HOME`, `USER` and `LOGNAME`. It has `sudo`'s `PATH`, so give a
program installed under your home by its full path in `command:`.

Granting `sudo` for `tego` is granting root: the launcher runs as root over a contract and config you control. Do not put
`tego` in a sudoers rule for another account. [OPERATIONS.md](OPERATIONS.md) ("Privileged path") says more.

The dashboard is the exception. `tego-control` refuses to run as root or with any capability, so start `tego dashboard` as
yourself, never with `sudo`. Under `sudo`, Tego looks up your account through `SUDO_UID`, so a root-tier run is recorded in
your own `~/.tego`, where the dashboard reads it. While such a run is live its folder there is root's (mode
0700), so the dashboard shows it only after it ends. Until then read it with `sudo "$(command -v tego)" status`.

## Check the machine

```sh
tego machine check
sudo "$(command -v tego)" machine check
```

The first shows what you get without root. The second shows tiers 2 and 3. Each says the tier it found on its `summary:`
line, after the checks and before the table. In a terminal, each then ends on stderr with a `Ready:` or `Not ready:`
line and the next step to type (`TEGO_HINTS=off` leaves them out). On a stock Ubuntu, tier 3 is reported as unavailable because `bpf` is not
in the boot LSM list. That is a fact about the machine, not a fault in the install, and
[TIERS.md](TIERS.md#tier-3-on-ubuntu) has the boot line. The last line is about the dashboard: the kernel loads the
`inet_diag` and `tcp_diag` modules when Tego first asks, and the line warns only if they cannot load
(`sudo modprobe tcp_diag`).

**Over SSH.** Automatic user-scope entry is built for `tego run`, `tego watch` and `tego test` when the current
shell cannot place a run and the user manager answers. SSH and console validation is **owed in a guest** on
Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44. Keep the previously checked manual path available:

```sh
systemd-run --user --scope bash
tego setup
```

After a committed handoff, Tego prints `tego: opened a user scope for this run` once. Setup and doctor still check
the original shell. Missing systemd-run, manager refusal or a ten-second startup timeout refuses the run before
run state and keeps the existing `next:` advice; startup cancellation exits 130 without that advice. Tego never
enables lingering. `tego run --service` keeps its unit. [user/setup.md](user/setup.md) has the account and lifetime details.

This is `sudo "$(command -v tego)" machine check` on a fresh Ubuntu 24.04 cloud image, with your build's own values in angle
brackets. The table is cut after five rows here; yours prints in full. `(>= 5.14.0)` on the `kernel` line is the oldest
release the check accepts at all, not tier 1's minimum: tier 1 also needs the `landlock` line to show ABI 2 or newer, and
the check adds a note on a release below 6.1, the upstream tested floor. The Landlock entries after `without:` come
from the ABI the kernel answers, the one the `landlock` line shows, so a kernel with a backported Landlock (RHEL 9's
5.14 answers ABI 6) lists only what it lacks.

```text
tego=v0.0.0-<commit date>-<commit, 12 digits> commit=<commit, 40 digits> date=<commit date> go=go1.27.4 contract_schema=0 record_v=1
ok   kernel: 6.8.0-147-generic (>= 5.14.0); without: Landlock ABI 5 (ioctl_dev) (6.10.0, device ioctls are not restricted), Landlock ABI 6 (scopes) (6.12.0, abstract unix sockets and signals are not scoped), Landlock ABI 7 (audit) (6.15.0, Landlock refusals are not in the audit log)
ok   btf: /sys/kernel/btf/vmlinux (6103569 bytes); all 94 kernel types and fields the BPF programs read are present
ok   cgroupv2: /sys/fs/cgroup delegated, cgroup.kill writable, controllers: cpu memory pids
ok   landlock: ABI 4
ok   seccomp: NEW_LISTENER + ADDFD(SEND) round trip on syscall 319 returned fd 8; yama ptrace_scope=1 (the supervisor is the agent's parent, which Yama exempts)
off  lsm: lockdown,capability,landlock,yama,apparmor via lsm_list_modules(2); bpf is not active: tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected; fix: add lsm=lockdown,capability,landlock,yama,apparmor,bpf to the kernel command line (GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then update-grub) and reboot
ok   programs: 27 of 27 hooks load and attach; trace_proc is its rdonly build (the kernel's BTF has bpf_rdonly_cast and bpf_loop); capture (uprobe_ssl, no tier): 6 of 6 programs load and attach at /usr/lib/x86_64-linux-gnu/libssl.so.3; optional network controls: 8 of 10 hooks load and attach; decision plane: fmod_ret (tier 2 decides opens in the kernel; tier 3 needs bpf in lsm=); build ed474b77, lsm mode no: bpf is not in the active LSM list (lockdown,capability,landlock,yama,apparmor), fmod_ret mode ok
ok   fanotify: permission marks work, FAN_DENY refuses the open, FAN_REPORT_FID=false, FAN_DENY_ERRNO=false (a refusal reaches the agent as EPERM: no kernel takes EACCES in a reply from the listener's FAN_CLASS_CONTENT group; the reason record is still exact)
ok   swap: memory.swap.max present: a run's memory cap holds swap too

summary: tier cgroup; bpflsm needs lsm

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

## Check the installer first

The installer is a release asset, listed in the release's checksums file. That file is signed, so you can check the
script before it runs:

```sh
tag=v0.1.2
sums=tego_${tag#v}_checksums.txt
base=https://github.com/Attention-Span-AI/Tego/releases/download/$tag
curl -fsSL -O "$base/install.sh" -O "$base/$sums" -O "$base/$sums.sigstore.json"
cosign verify-blob --bundle "$sums.sigstore.json" \
  --certificate-identity "https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$sums"
grep '  install\.sh$' "$sums" | sha256sum -c -
TEGO_VERSION=$tag sh install.sh
```

If `cosign` fails, or `sha256sum` does not print `install.sh: OK`, do not run the script. The macOS
template `tego.yaml` is checked the same way: download it from `$base` and give its name to the `grep`.

Set `tag` to the release you install (the releases page names the latest). The identity names that tag, because the
release workflow signs as itself, run for that tag.

This shows that the script is the one the release workflow published at that tag. It protects you only if you check before
you run:

- Piping a script into `sh` skips it. Nothing can read a checksum before a piped script runs, so someone who replaces the
  asset replaces the checks inside it too.
- It says who built the file, not that the tagged code is good. Anyone who can push a `v*` tag can run the release workflow.

When you pass a release binary on, keep `tego_<version>_licenses.tar.gz` with it: it holds the licence texts and the
third-party notices that `NOTICE` refers to. `install.sh` prints where that archive is. The `tego` and `tego-control` binaries carry the same texts, and `tego licenses` and
`tego-control licenses` print them.

## Uninstall

### Linux

```sh
tego uninstall
```

It shows what it will remove and asks once (`[Y/n]`). It removes:

- the user units `tego start` and `tego dashboard` made: `tego-dashboard`, and the clean-up timer and job `tego-gc`;
- the installed `tego`, and the `tego-control` beside it when it is the one that `tego` was built with. Both are
  checked by name and by content first, and a program in a source checkout (a `go.mod` beside it) is left alone;
- the line `tego start` added to `~/.bashrc` to load your saved agent sign-ins, and the installer's `PATH` line in a
  shell start-up file if one exists. Only that exact line goes, after a copy of the file named `<file>.tego-backup`
  beside it; the `PATH` line stays while `~/.local/bin` still holds other files;
- the dashboard's log, the guide's installer log, your saved sign-ins (`~/.config/tego/agent.env`) and the last-project
  note.

It keeps, and asks about separately, each defaulting to **no**:

- **your records and contracts**: `~/.tego` (runs, chain anchor, logs, config) and `~/.config/tego` (your agents'
  contracts). They are the proof of what your agents did, so deleting them is a second question of its own, and it
  refuses while a session is still running;
- **services you set up**: `tego-agent@<name>` instances, their planned restarts and the example unit files you copied
  into `~/.config/systemd/user`. It lists them and never stops one without your yes.

For a script, `tego uninstall --yes` answers the first question only. `--stop-agents` and `--delete-records` answer the
other two. Run twice, it finds nothing more to do, and it works when the dashboard or the units are already gone.

If Tego was installed for the whole machine (files owned by root in `/usr/local/bin`, `/etc/tego`, units in
`/etc/systemd/system`, or a `tego` in a folder you cannot write), `tego uninstall` does not use `sudo` for you. It
prints the exact `sudo` lines to type. If you moved your records with `ledger_root`, delete that folder yourself.

### macOS

Run `tego uninstall` in your Mac terminal. The Mac command runs it on the Mac, before the VM is asked. It lists and asks
once, then removes the `tego` command in `~/.local/bin`, the `PATH` line the installer added (with a backup beside the
file, and only while `~/.local/bin` holds nothing else), the dashboard's tunnel, and Tego inside the VM (the Linux steps
above, answered `--yes`). The VM `tego`, with your records and contracts inside it, stays unless you answer yes to a
second question (default no) or pass `--delete-records`; it is deleted only when its Lima template carries the
installer's marker. Lima and Homebrew stay: `brew uninstall lima` removes Lima when you no longer need it.

What is proven: the Mac command's shell code runs against stand-ins for Lima and SSH (`scripts/install_mac_test.sh`:
the lists, the answers, `--yes`, a second run, the exact `PATH` line, a VM that is gone or not Tego's). It has not run
against a real Lima VM on a Mac; whether Lima keeps the installer's marker in the instance's `lima.yaml` (which decides
whether the VM may be deleted) is unproven there.

### Windows

`tego uninstall` in PowerShell removes Tego's Linux and everything in it, records included ([Repair and
removal](#repair-and-removal)).

## Containers

To run an agent under Tego in a container, see [user/container.md](user/container.md). A project with a `.env` inside
the folder the agent writes needs that folder on a local filesystem: a named volume or a bind mount of a local folder,
not the image's own layer and not a network or FUSE share (Docker Desktop's file sharing on macOS and Windows is one);
[user/container.md](user/container.md#a-secret-inside-the-work-folder) says why. The same holds outside containers: on
NFS, sshfs or a VM's shared folder, keep such a project on the machine's own disk.

## Next

[QUICKSTART.md](QUICKSTART.md) runs your first agent.
