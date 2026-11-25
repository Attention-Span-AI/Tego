---
title: Install
description: "Install Tego with one command on Linux, macOS or Windows, check the download, update to a new release, uninstall, or build Tego from source."
summary: "One command on Linux, macOS or Windows. Update, uninstall or build from source."
section: Get started
order: 1
---

One command installs Tego. Tego needs a Linux kernel, so on a Mac or a Windows PC the installer also sets up a small Linux virtual machine (VM) and a `tego` command that runs Tego inside it. The requirements for each system are on [Supported systems](/docs/supported-systems/).

<a id="platforms"></a>

<div class="os-tabs">
<section data-os="linux" aria-label="Linux">

```sh wrap title="Terminal"
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh
```

The installer puts `tego` and `tego-control` (the program behind the dashboard) in `~/.local/bin`. It needs no root. It checks each binary against the release's checksums, runs the new `tego` once, and only then replaces an older install.

The installer doesn't change your `PATH`. When `~/.local/bin` isn't on it, the installer prints the line to add, and names `tego` by its full path until you do:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Add that line to your shell's profile (`~/.bashrc` or `~/.zshrc`) to keep it.

</section>
<section data-os="macos" aria-label="macOS">

```sh wrap title="Terminal on your Mac"
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh
```

The same command works on Apple silicon and Intel Macs.

The installer asks before each step. It:

1. checks that the Mac meets the [requirements](/docs/supported-systems/#platforms),
2. installs or upgrades [Lima](https://lima-vm.io/) through Homebrew,
3. creates a VM named `tego` (Ubuntu 24.04) and installs Tego inside it,
4. adds a `tego` command to your Mac, in `~/.local/bin`, that runs each Tego command inside the VM.

Setting up the VM takes about 2 minutes the first time. Without Homebrew, the installer prints where to get Lima and stops.

When `~/.local/bin` isn't on your `PATH`, the installer adds a line to your shell's profile, marked `# added by the Tego installer`. Open a new Terminal window before you type `tego`.

Your agent and projects live inside the VM. To open a shell there, type `tego shell`.

</section>
<section data-os="windows" aria-label="Windows">

```powershell title="PowerShell"
irm https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.ps1 | iex
```

The same command works on x64 and arm64 PCs, from Windows PowerShell or PowerShell 7.

The installer:

1. checks that Windows meets the [requirements](/docs/supported-systems/#platforms),
2. turns on or updates WSL, the Windows feature that runs Linux (Windows asks for administrator permission),
3. downloads Ubuntu 24.04 (about 500 MB) and makes it a separate WSL installation named `tego`, leaving your other Linux installations alone,
4. installs Tego inside it and adds a `tego` command to Windows.

The first install takes 5 to 10 minutes. If Windows asks for a restart, restart, open PowerShell and paste the same line again.

Open a new terminal window before you type `tego`. The `tego` command works in PowerShell and in cmd. To open a shell inside Tego's Linux, type `tego shell`.

</section>
</div>

## Check it worked

The installer's last line says what to type next:

```sh
tego start
```

`tego start` sets up your first agent. The [Quickstart](/docs/getting-started/) walks through it.

If the shell answers `tego: command not found`, open a new terminal window, or run the `export PATH=…` line the installer printed.

## Update

Run the install command again. It installs the latest release.

- On Linux, it replaces `tego` and `tego-control` together.
- On a Mac, it updates the Mac's `tego` command, then asks `Update Tego inside the VM from <old> to <new>?`. Your projects, rules files and records in the VM stay. Sessions that are running keep the old program until they end.
- On Windows, it asks `Set up or repair Tego now?`, then installs the latest release inside Tego's Linux. Your projects and records there stay.

To install one release in place of the latest, set `TEGO_VERSION`:

```sh wrap title="Terminal"
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | TEGO_VERSION=v0.2.0 sh
```

On a Mac, `TEGO_VERSION` must be v0.2.0 or later.

## Installer settings

The installers read these environment variables:

| Variable | What it sets | Default |
|---|---|---|
| `TEGO_VERSION` | The release to install, such as `v0.2.0` | The latest release |
| `TEGO_PREFIX` | The install folder (Linux) | `~/.local/bin` |
| `TEGO_VERIFY` | How the download is checked: `auto`, `cosign`, `gh` or `sha256` (Windows: no `gh`) | `auto` |
| `TEGO_CHECKSUMS_SHA256` | The SHA-256 the release's checksums file must have | None |
| `TEGO_YES` | `1` answers yes to every question (macOS) | Unset |
| `TEGO_MAX_TIME` | Seconds one download may take | `300` |
| `TEGO_BASE_URL` | Where releases are downloaded from, for a mirror | GitHub releases |

## Verify the download

The installer checks every binary against the SHA-256 checksums file published with the release. That proves the download is intact. To prove who published the release, the installer also uses a signature checker when one is on your `PATH`:

- With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), it checks the checksums file's signature. The signature must come from Tego's release workflow, run for the tag you install.
- Without cosign, but with a GitHub CLI (`gh`) that is logged in, it checks each binary's build provenance for that tag.
- With neither, it checks the checksums alone and says so.

When a checker is present and fails, nothing is installed. Set `TEGO_VERIFY=cosign` or `TEGO_VERIFY=gh` to make that check required.

To check the installer script itself before it runs, download it with the checksums file and its signature:

```sh
tag=v0.2.0
sums=tego_${tag#v}_checksums.txt
base=https://github.com/Attention-Span-AI/Tego/releases/download/$tag
curl -fsSL -O "$base/install.sh" -O "$base/$sums" -O "$base/$sums.sigstore.json"
cosign verify-blob --bundle "$sums.sigstore.json" \
  --certificate-identity "https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$sums"
grep '  install\.sh$' "$sums" | sha256sum -c -
TEGO_VERSION=$tag sh install.sh
```

If `cosign` fails, or `sha256sum` doesn't print `install.sh: OK`, don't run the script.

## Installer exit codes

| Code | Meaning |
|---|---|
| 0 | Installed, or you answered no and nothing changed |
| 2 | A required program is missing (`curl`, `sha256sum` or `shasum`, Lima on a Mac), WSL couldn't be turned on, or a setting is wrong |
| 3 | This system doesn't meet the [requirements](/docs/supported-systems/#platforms) (on a Mac, too little disk space is exit 8) |
| 4 | This processor isn't supported (Tego ships amd64 and arm64) |
| 5 | No release was found for `TEGO_VERSION` |
| 6 | A download failed; try again |
| 7 | A checksum didn't match, or `TEGO_VERSION` on a Mac is older than v0.2.0 |
| 8 | An install step failed, or too little disk space on a Mac |
| 9 | The signature or build provenance didn't verify |
| 130, 143 | The installer was interrupted or stopped |

## Uninstall

`tego uninstall` lists what it will remove and asks once.

<div class="os-tabs">
<section data-os="linux" aria-label="Linux">

```sh
tego uninstall
```

It stops and removes the dashboard and the clean-up timer that Tego started, removes `tego` and `tego-control`, and removes the lines Tego added to your shell's start-up files, keeping a backup of each file.

Two more questions follow, both with the answer no unless you type yes:

- delete your records (`~/.tego`) and saved rules files and logins (`~/.config/tego`),
- stop and remove the `tego-agent@` services you set up.

For a script, `--yes` answers the first question. `--delete-records` and `--stop-agents` answer the other two. Run `tego uninstall` outside every session: an agent can't remove Tego.

</section>
<section data-os="macos" aria-label="macOS">

```sh title="Terminal on your Mac"
tego uninstall
```

It removes the Mac's `tego` command, the `PATH` line the installer added (with a backup of the file), the dashboard's connection to the VM, and Tego inside the VM.

The VM holds your projects, rules files and records. A second question asks whether to delete the VM too. The answer is no unless you type yes, and `--delete-records` deletes it without asking. Lima stays installed.

</section>
<section data-os="windows" aria-label="Windows">

```powershell title="PowerShell or cmd"
tego uninstall
```

It removes Tego's Linux installation and the Windows `tego` command. That deletes everything inside Tego's Linux, your projects and records included, so the question's answer is no unless you type yes. `tego uninstall -Yes` removes it without asking. WSL and your other Linux installations stay.

</section>
</div>

## Build from source

You need `git`, `make` and Go 1.27, on Linux or inside Tego's VM.

```sh
git clone https://github.com/Attention-Span-AI/Tego
cd Tego
make build
mkdir -p ~/.local/bin
install -m 0755 bin/tego bin/tego-control ~/.local/bin/
tego version
```

Use `make build`, not `go build`. `make build` builds `tego-control` first and records its SHA-256 inside `tego`, and `tego` runs only that `tego-control`. Keep the two binaries in the same folder, and rebuild them together.

## Next steps

- [Quickstart](/docs/getting-started/): run your first agent under Tego.
- [Supported systems](/docs/supported-systems/): the requirements for each protection level.
- [Troubleshooting](/docs/troubleshooting/): fixes for the first errors.
