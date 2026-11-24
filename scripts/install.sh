#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Installs the tego binary for this host, and beside it tego-control, the binary tego hands `tego serve` and
# its other control commands to (ADR 0100 (1b): tego looks for it in its own directory only and runs it only when
# its SHA-256 is the one this tego was built with). Downloads the release archive goreleaser built for this OS/arch, the release's
# tego-control for the same target when its checksums file lists one, and the checksums file; checks who
# published the checksums when it can (below), verifies each binary against the published sha256 and tego's pin
# against tego-control's before anything is replaced, and moves the verified binaries into place with `mv` — not
# `cp` over the old file — because VERSIONING.md §5 is explicit that overwriting a live binary in place fails with
# ETXTBSY while a run holds it open, and a rename does not: a supervisor that opened the old inode keeps running it
# to completion. tego-control is moved first, so a failure between the two moves leaves the old tego working.
#
# A sha256 file fetched from the same place as the binary proves the download is intact, not who made it:
# whoever can replace the binary there can replace its checksum too. So the checksums file is also checked
# for authenticity, when a verifier is available: release.yml signs it with cosign, keyless, as the release
# workflow of this repository at this tag (the bundle is published beside it as <checksums>.sigstore.json),
# and attests each binary's build provenance, which `gh attestation verify` checks. A binary for a root-run
# enforcement tool is worth that step.
#
# Both verifiers are held to the requested tag, not merely to the release workflow: cosign to the certificate
# identity release.yml@refs/tags/<tag>, gh to that same identity and to the source ref refs/tags/<tag>.
# Whoever can replace release assets could otherwise serve an older release's genuine, signed binary under a
# newer tag, and the user would get an older build, perhaps one with a fixed vulnerability, believing it is
# the version they asked for. In gh mode the checksums file itself is not signature-checked, so that binding on
# the binary's own attestation is the whole of the tag check.
#
# The one-line install docs/INSTALL.md gives pipes this script into sh from the latest release, where it is an asset
# (.goreleaser.yaml), with no configuration: it installs that release into ~/.local/bin and ends with the next steps.
# Nothing checks a piped script before it runs (docs/GAPS.md B11); the binaries it downloads are checked as above, and
# docs/INSTALL.md shows how to check the script first.
#
# Configuration is env vars, not flags, to match the one already documented in VERSIONING.md §5:
#   TEGO_VERSION    tag to install, e.g. v0.1.0 (default: the latest published release)
#   TEGO_PREFIX     install directory (default: $HOME/.local/bin — no root needed)
#   TEGO_BASE_URL   release download base (default: the real GitHub releases URL; override to install from
#                    a mirror, or to point this script at a local goreleaser snapshot's dist/ output for testing)
#   TEGO_MAX_TIME   seconds one download may take before it is given up as a network failure (default: 300)
#   TEGO_API_URL    GitHub API URL used only to resolve "latest" when TEGO_VERSION is unset
#   TEGO_YES        on macOS, 1 answers yes to every question (install or upgrade Lima, create or start the VM)
#   TEGO_CHECKSUMS_SHA256  expected SHA-256 of the checksums file (optional, carried from Mac verification)
#   TEGO_VERIFY     how the release's authenticity is checked (default: auto):
#                      auto    cosign when it is on PATH, else gh when it is on PATH and logged in, else the
#                              checksum alone, saying so; a verifier that is present and fails stops the install
#                      cosign  require cosign to verify the checksums file's signature bundle
#                      gh      require gh to verify the binary's build provenance attestation
#                      sha256  the checksum alone: integrity against the download's own origin, nothing more
set -eu

repo_owner="Attention-Span-AI"
repo_name="Tego"

# mac_setup runs instead of the Linux install on macOS. Tego needs a Linux kernel, so on a Mac it lives in a Lima
# VM: this checks the Mac, offers to install or upgrade Lima, to create or start the VM (whose own provisioning runs
# this script inside it), and to add a `tego` command to the Mac that runs tego in the VM. Each step asks first, on
# the terminal; with no terminal and no TEGO_YES=1 it prints the remaining commands and stops. Lima's and Homebrew's
# own output goes to a log file, shown only when a step fails.
mac_setup() {
	vm=tego
	install_line="curl -fsSL https://github.com/${repo_owner}/${repo_name}/releases/latest/download/install.sh | sh"
	log="${workdir}/install.log"
	: >"$log"

	# Colour and animation only on a terminal, and never with NO_COLOR or TERM=dumb (clig.dev).
	# The terminal's settings, put back before the handoff and at the end: a step can leave the terminal raw (no
	# carriage return on a newline), and everything printed after it then steps down the screen like a staircase.
	restore_term() { [ -z "$term_state" ] || stty "$term_state" </dev/tty 2>/dev/null || :; }
	term_state=$({ stty -g </dev/tty; } 2>/dev/null || true)
	tty=0
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
		tty=1
		green=$(printf '\033[32m') red=$(printf '\033[31m') dim=$(printf '\033[2m') bold=$(printf '\033[1m') off=$(printf '\033[0m')
	else
		green='' red='' dim='' bold='' off=''
	fi
	ok() { printf '  %s✓%s %s\n' "$green" "$off" "$1"; }
	bad() { printf '  %s✗%s %s\n' "$red" "$off" "$1"; }
	todo() { printf '  %s○%s %s\n' "$dim" "$off" "$1"; }
	note() { printf '    %s%s%s\n' "$dim" "$1" "$off"; }
	# done_ TEXT: a step's status line and its question become one ✓ line. On a terminal the cursor goes back up
	# over those two lines; elsewhere the ✓ line is added below.
	done_() {
		[ "$tty" = 1 ] && printf '\033[2A\r\033[J'
		ok "$1"
	}

	ask() { # ask QUESTION [yes|no]: 0 yes, 1 no, 2 nobody to ask
		ask_default=${2:-yes}
		ask_choices='[Y/n]'
		[ "$ask_default" != no ] || ask_choices='[y/N]'
		if [ "${TEGO_YES:-}" = 1 ]; then
			printf '    %s %s yes\n' "$1" "$ask_choices"
			return 0
		fi
		(: </dev/tty) 2>/dev/null || return 2
		printf '    %s %s ' "$1" "$ask_choices" >/dev/tty
		read -r answer </dev/tty || return 1
		case "$answer" in "") [ "$ask_default" = yes ] ;; [Yy]*) return 0 ;; *) return 1 ;; esac
	}
	# SemVer precedence: core numbers, then prerelease identifiers (numeric before text).
	# Compare numeric strings by length to avoid integer limits; build metadata has no precedence.
	compare_versions() {
		LC_ALL=C awk -v left="$1" -v right="$2" '
function number(a, b) {
    sub(/^0+/, "", a); sub(/^0+/, "", b)
    if (length(a) != length(b)) return length(a) > length(b) ? 1 : -1
    return ("x" a) == ("x" b) ? 0 : (("x" a) > ("x" b) ? 1 : -1)
}
function compare(a, b, ac, bc, ap, bp, an, bn, i, c, ai, bi) {
    sub(/^v/, "", a); sub(/^v/, "", b)
    sub(/\+.*/, "", a); sub(/\+.*/, "", b)
    if (a !~ /^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?$/ ||
        b !~ /^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?$/) exit 1
    i=index(a, "-"); if (i) { ap=substr(a, i+1); a=substr(a, 1, i-1) }
    i=index(b, "-"); if (i) { bp=substr(b, i+1); b=substr(b, 1, i-1) }
    split(a, ac, /[.]/); split(b, bc, /[.]/)
    for (i=1; i<=3; i++) { c=number(ac[i], bc[i]); if (c) return c }
    if (ap == "" || bp == "") return ap == bp ? 0 : (ap == "" ? 1 : -1)
    an=split(ap, ac, /[.]/); bn=split(bp, bc, /[.]/)
    for (i=1; i<=an && i<=bn; i++) {
        if (ac[i] == "" || bc[i] == "") exit 1
        ai=ac[i] ~ /^[0-9]+$/; bi=bc[i] ~ /^[0-9]+$/
        if (ai && bi) c=number(ac[i], bc[i])
        else if (ai != bi) c=ai ? -1 : 1
        else c=("x" ac[i]) == ("x" bc[i]) ? 0 : (("x" ac[i]) > ("x" bc[i]) ? 1 : -1)
        if (c) return c
    }
    return an == bn ? 0 : (an > bn ? 1 : -1)
}
BEGIN { print compare(left, right) }'
	}
	stop() { # stop CODE LINE...: what is left to type, then exit
		code=$1
		shift
		echo ""
		[ "$#" -eq 0 ] || echo "  To finish, run:"
		for line in "$@"; do printf '      %s%s%s\n' "$bold" "$line" "$off"; done
		echo ""
		echo "  Then run this installer again: ${install_line}"
		exit "$code"
	}
	# quietly CMD...: runs CMD with its output in the log. On a terminal a fish swims while it runs. On failure it
	# shows the log's last lines and where the whole log is.
	quietly() {
		"$@" >>"$log" 2>&1 &
		pid=$!
		if [ "$tty" = 1 ]; then
			start=$(date +%s) pos=0 dir=1 width=34
			while kill -0 "$pid" 2>/dev/null; do
				if [ "$dir" = 1 ]; then fish='><(((º>'; else fish='<º)))><'; fi
				t=$(($(date +%s) - start))
				printf '\r       %*s%s%*s %s%d:%02d%s' "$pos" '' "$fish" $((width - pos)) '' "$dim" $((t / 60)) $((t % 60)) "$off"
				pos=$((pos + dir))
				if [ "$pos" -ge "$width" ] || [ "$pos" -le 0 ]; then dir=$((0 - dir)); fi
				sleep 0.15
			done
			printf '\r\033[K'
		fi
		if wait "$pid"; then return 0; fi
		echo ""
		tail -n 5 "$log" | sed 's/^/      /'
		note "The full log is in $log"
		return 1
	}

	echo ""
	echo "  Tego needs Linux. On a Mac, it runs in a small Linux VM."
	echo ""
	macos=$(sw_vers -productVersion 2>/dev/null || echo 0)
	major=${macos%%.*}
	minor=${macos#*.}
	minor=${minor%%.*}
	[ "$minor" = "$macos" ] && minor=0
	if [ "$major" -gt 13 ] 2>/dev/null || { [ "$major" -eq 13 ] && [ "$minor" -ge 5 ]; } 2>/dev/null; then
		ok "macOS ${macos}"
	else
		bad "macOS ${macos}. Tego's VM needs macOS 13.5 or later."
		exit 3
	fi
	free_gb=$(($(df -k "$HOME" | awk 'NR==2 {print $4}') / 1048576))
	if [ "$free_gb" -ge 5 ]; then
		ok "${free_gb} GB free"
	else
		bad "${free_gb} GB free. The VM needs about 5 GB. Free some space and run this again."
		exit 8
	fi

	lima=""
	if command -v limactl >/dev/null 2>&1; then
		lima=$(limactl --version 2>/dev/null | awk '{print $NF}')
	fi
	if [ -z "$lima" ] || [ "${lima%%.*}" -lt 2 ] 2>/dev/null; then
		if [ -z "$lima" ]; then
			bad "Lima isn't installed. Tego uses this free program to run its Linux VM."
			verb=install
		else
			bad "Lima ${lima} is too old. Tego needs 2.0 or later."
			verb=upgrade
		fi
		if ! command -v brew >/dev/null 2>&1; then
			note "Install Lima from https://lima-vm.io/docs/installation/."
			note "For its Homebrew option, first install Homebrew from https://brew.sh."
			note "Then run: $install_line"
			exit 2
		fi
		if [ "$verb" = install ]; then question="Install Lima now with Homebrew?"; else question="Upgrade Lima now with Homebrew?"; fi
		ask "$question" && rc=0 || rc=$?
		case $rc in
			0) quietly brew "$verb" lima || exit 2 ;;
			2) stop 2 "brew ${verb} lima" ;;
			*) note "Tego needs Lima on a Mac. Nothing was changed."; exit 2 ;;
		esac
		done_ "Lima $(limactl --version 2>/dev/null | awk '{print $NF}')"
	else
		ok "Lima ${lima}"
	fi

	verify_guest_install() {
		grep -qxF '# tego-mac-provisioning: 1' "$archive_path" ||
			die "v0.2.0 is the first release to support a pinned Mac install; unset TEGO_VERSION to install the latest" 7
		# The VM executes install.sh: verify that asset too, then give the guest its digest.
		download "${base_url}/${tag}/install.sh" "${workdir}/install.sh" "the installer"
		[ "$verify" != gh ] || attested "${workdir}/install.sh" install.sh
		installer_sha256=$(awk '$2=="install.sh" {print $1}' "$checksums_path")
		[ -n "$installer_sha256" ] && [ "$installer_sha256" = "$(sha256_of "${workdir}/install.sh")" ] ||
			die "checksum mismatch or missing entry for install.sh; not installing Tego" 7
		# Cosign authenticated the whole checksums file. gh attests assets instead:
		# authenticate the guest binaries and their entries before carrying this file's digest.
		if [ "$verify" = gh ]; then
			for guest_asset in "tego_${version_no_v}_linux_${arch}" "tego-control_${version_no_v}_linux_${arch}"; do
				guest_path="${workdir}/${guest_asset}"
				download "${base_url}/${tag}/${guest_asset}" "$guest_path" "the guest Linux binary"
				attested "$guest_path" "$guest_asset"
				guest_expected=$(awk -v f="$guest_asset" '$2==f {print $1}' "$checksums_path")
				[ -n "$guest_expected" ] && [ "$guest_expected" = "$(sha256_of "$guest_path")" ] ||
					die "checksum mismatch or missing entry for ${guest_asset}; not installing Tego" 7
			done
		fi
		checksums_sha256=$(sha256_of "$checksums_path")
	}

	state=$(limactl list --format '{{.Status}}' "$vm" 2>/dev/null || true)
	case "$state" in
		Running) ok "Tego's VM is running" ;;
		Stopped)
			todo "Tego's VM is stopped"
			ask "Start it?" && rc=0 || rc=$?
			[ "$rc" = 0 ] || stop 0 "limactl start ${vm}"
			quietly limactl start "$vm" || exit 8
			done_ "Tego's VM is running"
			;;
		*)
			todo "Tego's VM isn't set up yet. It takes about 2 minutes, only the first time."
			ask "Set it up now?" && rc=0 || rc=$?
			[ "$rc" = 0 ] || stop 0
			prepare_release
			verify_guest_install
			quietly limactl start --tty=false --name="$vm" --mount-none --param="tego_version=$tag" \
				--param="installer_sha256=$installer_sha256" --param="checksums_sha256=$checksums_sha256" \
				--param="release_base=$base_url" "$archive_path" || {
				if grep -q 'failed to download .*cloud-images[.]ubuntu[.]com/' "$log"; then
					# Lima keeps a newly created instance even when its image download fails.
					# Leave deletion explicit so the person can inspect it and its diagnostic log.
					[ -n "$state" ] || note "First remove the incomplete VM: limactl delete ${vm}"
					if grep -q 'failed to download .*cloud-images[.]ubuntu[.]com/.*unexpected HTTP status Not Found' "$log"; then
						note "The pinned VM image is no longer available. Update the installer and try again:"
						note "$install_line"
					else
						note "The VM image download failed. Check the connection and run this installer again."
					fi
				fi
				exit 8
			}
			done_ "Tego's VM is ready"
			;;
	esac

	# The tego command on the Mac: it runs tego in the VM, from the VM's home folder, in the user's cgroup, which
	# a limactl shell login is outside of. It lives in ~/.local/bin, a folder of the user's own, not one another tool
	# manages; a shell that started before the PATH line below was added does not find it until it starts again.
	bin="$HOME/.local/bin"
	shim="$bin/tego"
	reopen=0
	# A tego command this installer wrote before is rewritten without asking, so an update reaches it.
	had=0
	if [ -x "$shim" ] && grep -q "Tego's installer" "$shim" 2>/dev/null; then
		had=1
	fi
	{
		if [ "$had" = 1 ]; then
			rc=0
		else
			todo "The tego command isn't in your terminal yet"
			ask "Add it?" && rc=0 || rc=$?
		fi
		if [ "$rc" = 0 ]; then
			mkdir -p "$bin"
			cat >"$shim" <<EOF
#!/bin/sh
# tego on a Mac, written by Tego's installer: runs tego inside Tego's Linux VM (the Lima instance "${vm}").
# "tego shell" opens a shell in the VM, in the project tego start set up last. "tego uninstall" removes Tego from the Mac.
vm=${vm}
install_line='${install_line}'
EOF
			cat >>"$shim" <<'EOF'
# tego uninstall runs here on the Mac, before the VM is asked: the Mac's side (this command, the PATH line the installer
# added, the dashboard's tunnel) goes after one question; Tego inside the VM is removed with it, and the VM itself, which
# holds your records and contracts, only after a second question whose answer is no unless you say yes.
if [ "${1:-}" = uninstall ]; then
	shift
	assume_yes=0 stop_agents=0 delete_records=0
	for arg in "$@"; do
		case "$arg" in
			--yes|-yes) assume_yes=1 ;;
			--stop-agents|-stop-agents) stop_agents=1 ;;
			--delete-records|-delete-records) delete_records=1 ;;
			*) echo "usage: tego uninstall [--yes] [--stop-agents] [--delete-records]" >&2; exit 2 ;;
		esac
	done
	bin="$HOME/.local/bin"
	path_line='export PATH="$HOME/.local/bin:$PATH" # added by the Tego installer'
	fish_line='fish_add_path "$HOME/.local/bin" # added by the Tego installer'
	fish_file="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/tego.fish"
	vm_state=$(limactl list --format '{{.Status}}' "$vm" 2>/dev/null) || vm_state=""
	vm_dir=""
	[ -z "$vm_state" ] || vm_dir=$(limactl list --format '{{.Dir}}' "$vm" 2>/dev/null) || vm_dir=""
	# The VM is Tego's only when the instance's own template says so: this installer creates it from the release's Lima
	# template, which carries the marker. Without it the VM is named, never deleted.
	vm_is_tego=0
	[ -z "$vm_dir" ] || ! grep -qxF '# tego-mac-provisioning: 1' "$vm_dir/lima.yaml" 2>/dev/null || vm_is_tego=1
	uninstall_ask() { # QUESTION CHOICES: 0 yes, 1 no or nobody to ask
		(: </dev/tty) 2>/dev/null || return 1
		printf '  ? %s %s ' "$1" "$2" >/dev/tty
		read -r answer </dev/tty || return 1
		case "$answer" in
			"") [ "$2" = '[Y/n]' ] ;;
			[Yy]*) return 0 ;;
			*) return 1 ;;
		esac
	}
	# FILE LINE KIND: removes that one exact line, after a backup beside the file; a fish file of Tego's own that holds
	# nothing else afterwards goes too.
	remove_line() {
		rl_file=$1 rl_line=$2
		[ -f "$rl_file" ] && grep -qFx -- "$rl_line" "$rl_file" 2>/dev/null || return 0
		rl_backup="$rl_file.tego-backup" rl_n=0
		while [ -e "$rl_backup" ]; do rl_n=$((rl_n + 1)); rl_backup="$rl_file.tego-backup-$rl_n"; done
		cp -p "$rl_file" "$rl_backup" || { echo "tego: could not write a backup of $rl_file; it is unchanged" >&2; return 1; }
		rl_tmp=$(mktemp "${TMPDIR:-/tmp}/tego-rc.XXXXXX") || return 1
		grep -vFx -- "$rl_line" "$rl_file" >"$rl_tmp" || :
		if [ "${3:-}" = fish ] && [ -z "$(tr -d ' \t\r\n' <"$rl_tmp")" ]; then rm -f "$rl_file"; else cat "$rl_tmp" >"$rl_file"; fi
		rm -f "$rl_tmp"
	}
	others=0
	for entry in "$bin"/* "$bin"/.[!.]*; do
		{ [ -e "$entry" ] || [ -L "$entry" ]; } || continue
		[ "${entry##*/}" = tego ] || others=$((others + 1))
	done
	has_line=""
	for f in "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
		if [ -f "$f" ] && grep -qFx -- "$path_line" "$f" 2>/dev/null; then has_line="$has_line $f"; fi
	done
	if [ -f "$fish_file" ] && grep -qFx -- "$fish_line" "$fish_file" 2>/dev/null; then has_line="$has_line $fish_file"; fi
	echo ""
	echo "  Remove Tego from this Mac"
	echo ""
	echo "  Tego will remove"
	echo "    - the tego command ($bin/tego)"
	[ -z "$has_line" ] || [ "$others" -gt 0 ] || echo "    - the PATH line the installer added (only that line; a backup is kept beside the file):$has_line"
	[ -z "$vm_state" ] || echo "    - Tego inside its VM: the dashboard and its units, the program and the lines it added (your records and contracts stay)"
	[ -z "$vm_state" ] || echo "    - the dashboard's tunnel to the VM"
	if [ -n "$vm_state" ]; then
		echo ""
		if [ "$vm_is_tego" = 1 ]; then
			echo "  Your records and contracts live in the VM \"$vm\" and stay unless you say so:"
			echo "    - delete the VM \"$vm\" and everything in it, including your records and contracts (cannot be undone; frees about 5 GB)"
		else
			echo "  The Lima instance \"$vm\" is not marked as made by Tego's installer, so it is left alone. To delete it yourself: limactl delete -f $vm"
		fi
	fi
	if [ -n "$has_line" ] && [ "$others" -gt 0 ]; then
		echo ""
		echo "  Left the PATH line: $bin still holds $others other file(s) that may need it."
	fi
	echo ""
	if [ "$assume_yes" != 1 ]; then
		if ! (: </dev/tty) 2>/dev/null; then
			echo "tego uninstall asks before it removes anything, so it runs in a terminal; for a script: tego uninstall --yes (the VM, with your records and contracts, stays unless you add --delete-records)" >&2
			exit 2
		fi
		uninstall_ask 'Remove what is listed under "Tego will remove"?' '[Y/n]' || { echo "  Nothing was changed."; exit 0; }
	fi
	with_vm=0
	if [ "$vm_is_tego" = 1 ]; then
		if [ "$delete_records" = 1 ]; then
			with_vm=1
		elif [ "$assume_yes" != 1 ] && uninstall_ask "Also delete the VM and your records and contracts in it? They are the proof of what your agents did. This cannot be undone." '[y/N]'; then
			with_vm=1
		else
			echo "  Kept: the VM \"$vm\", with your records and contracts. Add --delete-records to delete it."
		fi
	fi
	failed=0
	# Tego inside the VM first (its own question is answered here), while the VM still runs: not needed when the VM is deleted.
	if [ -n "$vm_state" ] && [ "$with_vm" != 1 ]; then
		if [ "$vm_state" = Stopped ]; then limactl start "$vm" >/dev/null 2>&1 || vm_state=unreachable; fi
		if [ "$vm_state" != unreachable ]; then
			guest_flags="--yes"
			[ "$stop_agents" != 1 ] || guest_flags="--yes --stop-agents"
			# shellcheck disable=SC2086 # the two flags are fixed words above
			if limactl shell --workdir / "$vm" sh -c 'cd "$HOME" && if test -x "$HOME/.local/bin/tego"; then export PATH="$HOME/.local/bin:$PATH" && exec systemd-run --user --scope --quiet "$(command -v tego)" uninstall "$@"; fi' tego $guest_flags; then
				echo "  ✓ Removed Tego inside the VM"
			else
				echo "  ✗ Tego inside the VM was not removed completely; run: limactl shell $vm, then tego uninstall" >&2
				failed=1
			fi
		else
			echo "  ✗ The VM did not start, so Tego inside it was not removed: limactl start $vm" >&2
			failed=1
		fi
	fi
	# The dashboard's tunnel: the SSH master this command started, ended by its own control socket.
	if [ -n "$vm_dir" ]; then
		for sock in "$vm_dir"/tego-dashboard.sock "$vm_dir"/tego-dashboard-*.sock; do
			[ -S "$sock" ] || [ -f "$sock" ] || continue
			ssh -F "$vm_dir/ssh.config" -S "$sock" -O exit "lima-$vm" >/dev/null 2>&1 || :
			echo "  ✓ Closed the dashboard's tunnel"
		done
	fi
	if [ "$with_vm" = 1 ]; then
		limactl stop "$vm" >/dev/null 2>&1 || :
		if limactl delete -f "$vm" >/dev/null 2>&1; then
			echo "  ✓ Deleted the VM \"$vm\", with your records and contracts"
		else
			echo "  ✗ The VM was not deleted; run: limactl delete -f $vm" >&2
			failed=1
		fi
	fi
	if [ "$others" -eq 0 ]; then
		for f in "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
			case "$has_line" in *" $f"*) remove_line "$f" "$path_line" && echo "  ✓ Removed the PATH line from $f (backup: $f.tego-backup)" || failed=1 ;; esac
		done
		case "$has_line" in *" $fish_file"*) remove_line "$fish_file" "$fish_line" fish && echo "  ✓ Removed the PATH line from $fish_file" || failed=1 ;; esac
	fi
	# This command goes last: the shell has read it, and a removed file stays readable to a running shell.
	if grep -q "Tego's installer" "$bin/tego" 2>/dev/null; then
		rm -f "$bin/tego" && echo "  ✓ Removed the tego command ($bin/tego)" || failed=1
	fi
	echo ""
	if [ "$failed" != 0 ]; then
		echo "  ✗ Some steps did not finish; what is left is listed above. Run tego uninstall again, or remove it yourself." >&2
		exit 125
	fi
	if [ "$with_vm" = 1 ]; then
		echo "  ✓ Tego is removed, with the VM and your records. Lima (brew uninstall lima) and Homebrew stay."
	elif [ -n "$vm_state" ]; then
		echo "  ✓ Tego is removed. The VM \"$vm\" and your records stay; run the installer again to use Tego, or limactl delete -f $vm to free the space."
	else
		echo "  ✓ Tego is removed."
	fi
	exit 0
fi
if [ "${1:-}" = shell ] && [ $# -ne 1 ]; then
	echo "usage: tego shell (no arguments)" >&2
	exit 2
fi
case "$(limactl list --format '{{.Status}}' "$vm" 2>/dev/null)" in
	Running) ;;
	Stopped)
		echo "Starting Tego's VM..." >&2
		limactl start "$vm" >/dev/null 2>&1 || { echo "tego: the VM didn't start. Try: limactl start $vm" >&2; exit 125; }
		;;
	*)
		echo "tego: Tego's VM is missing. Set it up again with:" >&2
		echo "  $install_line" >&2
		exit 125
		;;
esac
if [ "${1:-}" = shell ]; then
	echo "In Tego's Linux VM. Type exit to go back to your Mac." >&2
	exec limactl shell --workdir / "$vm" sh -c 'cd "$HOME"; d=$(cat "$HOME/.config/tego/last-project" 2>/dev/null); [ -d "$d" ] && cd "$d"; exec systemd-run --user --scope --quiet bash -l'
fi
# The dedicated SSH control socket belongs to this VM. Reuse requires its master's PID to own the
# only listener on the dashboard port, bound to loopback. A process merely named ssh is not proof of our tunnel.
control_dir_private() {
	[ "$(stat -f '%u' "${control%/*}" 2>/dev/null)" = "$caller_uid" ] || return 1
	dir_mode=$(stat -f '%Lp' "${control%/*}" 2>/dev/null) || return 1
	case "$dir_mode" in ''|*[!0-7]*) return 1 ;; esac
	[ $((0$dir_mode & 0022)) -eq 0 ]
}
control_private() {
	[ ! -L "$control" ] || return 1
	control_dir_private && [ "$(stat -f '%u' "$control" 2>/dev/null)" = "$caller_uid" ]
}
tunnel_ready() {
	control_private || return 1
	master=$(ssh -F "$ssh_config" -S "$control" -O check "lima-$vm" 2>&1) || return 1
	master_pid=$(printf '%s\n' "$master" | sed -n 's/^Master running (pid=\([0-9][0-9]*\))\r\{0,1\}$/\1/p')
	[ -n "$master_pid" ] || return 1
	listeners=$(lsof -nP -iTCP:$port -sTCP:LISTEN -Fp 2>/dev/null | sed -n 's/^p//p')
	[ "$listeners" = "$master_pid" ] || return 1
	process_uid=$(ps -o uid= -p "$master_pid" 2>/dev/null | awk '{$1=$1; print}')
	[ "$process_uid" = "$caller_uid" ] || return 1
	bound=$(lsof -nP -a -p "$master_pid" -iTCP:$port -sTCP:LISTEN -Fn 2>/dev/null | sed -n 's/^n//p')
	[ "$bound" = 127.0.0.1:$port ]
}
open_dashboard() {
	port=$(printf '%s\n' "$1" | sed -n 's#^http://127[.]0[.]0[.]1:\([0-9][0-9]*\)/.*#\1#p')
	port=${port:-8484}
	if ! { [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; } 2>/dev/null; then
		echo "tego: invalid dashboard port in $1. Run tego dashboard to try again." >&2
		return 1
	fi
	caller_uid=$(id -u)
	vm_dir=$(limactl list --format '{{.Dir}}' "$vm") || {
		echo "tego: the dashboard tunnel is not up. Could not find this VM's SSH configuration." >&2
		return 1
	}
	ssh_config="$vm_dir/ssh.config"
	control="$vm_dir/tego-dashboard.sock"
	[ "$port" = 8484 ] || control="$vm_dir/tego-dashboard-$port.sock"
	if ! control_dir_private; then
		echo "tego: the dashboard tunnel is not up. Unsafe socket folder $vm_dir; it must belong to you and other users must not be allowed to write to it. Fix its ownership and write permissions, then run tego dashboard." >&2
		return 1
	fi
	if { [ -e "$control" ] || [ -L "$control" ]; } && ! control_private; then
		echo "tego: the dashboard tunnel is not up. Socket $control is linked or not owned by you; move it away yourself, then try again." >&2
		return 1
	fi
	if ! tunnel_ready; then
		# Never open the URL when some other listener holds the port, or forwarding fails.
		listeners=$(lsof -nP -iTCP:$port -sTCP:LISTEN -Fp 2>/dev/null)
		# Only an owned, non-answering socket in our private folder is a leftover.
		# Keep the stable path so the next invocation can find and reuse the new master.
		if [ -z "$listeners" ] && [ -e "$control" ] &&
			! ssh -F "$ssh_config" -S "$control" -O check "lima-$vm" >/dev/null 2>&1; then
			rm -f "$control" 2>/dev/null
		fi
		if [ -n "$listeners" ] || [ -e "$control" ] || ! ssh -F "$ssh_config" -S "$control" -M -f -N \
			-o ExitOnForwardFailure=yes -o ClearAllForwardings=no \
			-L 127.0.0.1:$port:127.0.0.1:$port "lima-$vm" >/dev/null 2>&1 || ! tunnel_ready; then
			if [ "$port" != 8484 ] && [ -n "$listeners" ]; then
				echo "tego: port $port is in use. Lima forwards the VM's ports to the Mac itself; Tego's own tunnel is set up for 8484." >&2
				echo "Put the dashboard back on 8484, or run limactl stop $vm, then limactl edit $vm and add under portForwards:" >&2
				printf '  - guestPort: %s\n    ignore: true\n' "$port" >&2
				echo "Then run limactl start $vm and tego dashboard. Other dashboard ports have not yet been verified on a Mac." >&2
			else
			echo "tego: the dashboard tunnel is not up. Port $port must be free or held by this VM's dashboard tunnel; try again." >&2
			fi
			return 1
		fi
	fi
	open "$1" 2>/dev/null || { echo "tego: could not open the dashboard in your browser." >&2; return 1; }
}
# tego start (and tego setup) runs the guide in the VM, which starts the dashboard there; then the dashboard opens in the
# Mac's browser, and the person is left in the VM, in the project, where the commands the guide printed work. When the
# guide fails or is stopped, the person is back on the Mac with its error, never in a shell with no next step.
if { [ "${1:-}" = start ] || [ "${1:-}" = setup ]; } && [ $# -eq 1 ]; then
	sub=$1 # start or setup: a fixed word, put into the VM's command line here
	limactl shell --workdir / "$vm" sh -c 'cd "$HOME" && test -x "$HOME/.local/bin/tego" && export PATH="$HOME/.local/bin:$PATH" && exec systemd-run --user --scope --quiet env TEGO_ON_MAC=1 "$(command -v tego)" '"$sub" || exit $?
	url=$(limactl shell --workdir / "$vm" sh -c 'grep -o "http://127[.]0[.]0[.]1:[0-9][0-9]*/[^ ]*" "$HOME/.tego/dashboard.log" 2>/dev/null | head -n 1')
	if [ -z "$url" ]; then
		echo "tego: the dashboard is not running. Run tego dashboard to start it." >&2
	elif ! open_dashboard "$url" 2>/dev/null; then
		echo "tego: could not open the dashboard at $url. Run tego dashboard to try again." >&2
	fi
	exec limactl shell --workdir / "$vm" sh -c 'cd "$HOME"; d=$(cat "$HOME/.config/tego/last-project" 2>/dev/null); [ -d "$d" ] && cd "$d"; exec systemd-run --user --scope --quiet bash -l'
fi
# tego dashboard (and tego serve --open): the one dashboard runs in the VM and opens in the Mac's browser.
if { [ "${1:-}" = dashboard ] && [ $# -eq 1 ]; } || { [ "${1:-}" = serve ] && [ "${2:-}" = --open ] && [ $# -eq 2 ]; }; then
	# the VM's tego dashboard says whether one is running and asks before starting a new one; the Mac opens its link
	limactl shell --workdir / "$vm" sh -c 'cd "$HOME" && test -x "$HOME/.local/bin/tego" && export PATH="$HOME/.local/bin:$PATH" && exec systemd-run --user --scope --quiet env TEGO_ON_MAC=1 "$(command -v tego)" dashboard' || exit $?
	url=$(limactl shell --workdir / "$vm" sh -c 'grep -o "http://127[.]0[.]0[.]1:[0-9][0-9]*/[^ ]*" "$HOME/.tego/dashboard.log" 2>/dev/null | head -n 1')
	if [ -z "$url" ]; then
		echo "The dashboard did not start. Run tego dashboard to try again. For details, run tego shell, then cat ~/.tego/dashboard.log" >&2
		exit 1
	fi
	open_dashboard "$url" || exit 1
	echo "  ✓ Opened it in your browser"
	exit 0
fi
exec limactl shell --workdir / "$vm" sh -c 'cd "$HOME" && test -x "$HOME/.local/bin/tego" && export PATH="$HOME/.local/bin:$PATH" && exec systemd-run --user --scope --quiet "$(command -v tego)" "$@"' tego "$@"
EOF
			chmod 0755 "$shim"
			case ":${PATH}:" in
				*":$bin:"*) ;;
				*)
					case "$(basename "${SHELL:-sh}")" in
						zsh) rcfile="$HOME/.zshrc" ;;
						fish)
							rcfile="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/tego.fish"
							mkdir -p "$(dirname "$rcfile")"
							;;
						bash) # the first of these a login bash reads; a new .bash_profile would hide an existing .profile
							rcfile="$HOME/.bash_profile"
							for f in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
								[ -f "$f" ] && { rcfile=$f; break; }
							done
							;;
						*) rcfile="$HOME/.profile" ;;
					esac
					if ! grep -qs '# added by the Tego installer' "$rcfile"; then
						# shellcheck disable=SC2016 # the line is written as is, for the shell to expand when it starts
						case "$(basename "${SHELL:-sh}")" in
							fish) printf '\nfish_add_path "$HOME/.local/bin" # added by the Tego installer\n' >>"$rcfile" ;;
							*) printf '\nexport PATH="$HOME/.local/bin:$PATH" # added by the Tego installer\n' >>"$rcfile" ;;
						esac
					fi
					reopen=1
					;;
			esac
			if [ "$had" = 1 ]; then ok "tego command is up to date"; else done_ "tego command added"; fi
		else
			shim=""
			note "Skipped adding the Mac command. To open the VM, run: limactl shell ${vm}"
		fi
	}

	if [ "$state" = Running ] || [ "$state" = Stopped ]; then
		prepare_release
		guest_version=''
		# shellcheck disable=SC2016 # expanded by the guest shell
		if guest_output=$(limactl shell --workdir / "$vm" sh -c 'exec "$HOME/.local/bin/tego" version' 2>/dev/null); then
			guest_version=$(printf '%s\n' "$guest_output" | sed -n 's/^tego=//p')
		fi
		guest_order=$(compare_versions "$guest_version" "$tag") || guest_order=-1
		if [ "$guest_order" = 0 ]; then
			ok "Tego ${tag} inside the VM is up to date"
		elif ! grep -qxF '# tego-mac-provisioning: 1' "$archive_path"; then
			selection=''
			[ -z "${TEGO_VERSION:-}" ] || selection=" Selected with TEGO_VERSION=${TEGO_VERSION}."
			note "Tego inside the VM was left as it is; updating it from the Mac needs a later release.${selection}"
		else
			[ -n "$guest_version" ] || guest_version='missing or not working'
			if [ "$guest_order" = 1 ]; then
				ask "Replace Tego ${guest_version} inside the VM with older version ${tag}?" no && rc=0 || rc=$?
			else
				ask "Update Tego inside the VM from ${guest_version} to ${tag}?" && rc=0 || rc=$?
			fi
			case $rc in
				0)
					verify_guest_install
					# Fixed code; release values are positional arguments, never shell source.
					# shellcheck disable=SC2016 # fixed guest code, expanded only inside the VM
					quietly limactl shell --workdir / "$vm" sh -c '
set -eu
work=$(mktemp -d)
trap '\''rm -rf "$work"'\'' EXIT
curl -fsSL "$2/$1/install.sh" -o "$work/install.sh"
printf '\''%s  %s\n'\'' "$3" "$work/install.sh" | sha256sum -c -
TEGO_VERSION="$1" TEGO_BASE_URL="$2" TEGO_CHECKSUMS_SHA256="$4" sh "$work/install.sh"
' sh "$tag" "$base_url" "$installer_sha256" "$checksums_sha256" || exit 8
					ok "Tego ${tag} inside the VM is ready"
					note "Existing runs keep running with the old program until they finish; new commands use ${tag}."
					;;
				2)
					install_line="curl -fsSL ${base_url}/${tag}/install.sh | TEGO_YES=1 TEGO_VERSION=${tag} sh"
					stop 2 ;;
				*) note "Skipped the VM update. Tego inside the VM was not changed." ;;
			esac
		fi
	fi

	# The installer ends here, with the one step that comes next: tego start walks through the rest.
	restore_term
	echo ""
	printf '  %sNext steps%s\n' "$bold" "$off"
	if [ "$reopen" = 1 ]; then
		# this script cannot change the PATH of the shell that started it; a new shell reads the PATH line
		# a login shell, the kind a new terminal window starts: it reads the file the PATH line went into
		printf '    Open a new Terminal window, then type %stego start%s (or run exec %s -l here first).\n' "$bold" "$off" "$(basename "${SHELL:-sh}")"
	else
		printf '    Run   %stego start%s\n' "$bold" "$off"
	fi
	echo ""
	exit 0
}

# shell_word prints $1 as one shell word a person can paste: as it is when it holds only characters no shell treats
# specially, else in double quotes with the four characters that stay special there escaped.
shell_word() {
	case "$1" in
		*[!A-Za-z0-9_./:@%+=,~-]* | "")
			printf '"%s"\n' "$(printf '%s' "$1" | sed 's/[\\"$`]/\\&/g')"
			;;
		*) printf '%s\n' "$1" ;;
	esac
}

# Everything below runs from main, called on the script's last line. Piped into sh (`curl -fsSL .../install.sh | sh`,
# the one-line install), the shell has then read the whole script before it runs any of it: a download cut short
# defines main partly or not at all and installs nothing, and no command the script starts can read the rest of the
# script from stdin, which is the pipe. The script reads nothing from stdin itself; mac_setup's questions read the
# terminal (/dev/tty).
main() {
	prog=$(basename "$0")
	# Piped into sh, $0 is the shell's own name; the messages then name the script instead.
	case "$prog" in
		sh | dash | bash | ash | ksh | zsh | busybox) prog=install.sh ;;
	esac
	# A transfer that stalls after the connection is made ends at this many seconds (curl exit 28, which the
	# callers report as the network failure it is, exit 6) instead of hanging the install.
	max_time="${TEGO_MAX_TIME:-300}"

	version="${TEGO_VERSION:-}"
	prefix="${TEGO_PREFIX:-$HOME/.local/bin}"
	base_url="${TEGO_BASE_URL:-https://github.com/${repo_owner}/${repo_name}/releases/download}"
	api_url="${TEGO_API_URL:-https://api.github.com/repos/${repo_owner}/${repo_name}/releases/latest}"

	# die prints one line to stderr and exits with a code a caller can branch on: 2 missing dependency, 3
	# unsupported platform, 4 unsupported architecture, 5 no such release, 6 download failed, 7 checksum
	# mismatch, 8 local install step failed, 9 the release's signature or provenance did not verify.
	die() {
		echo "${prog}: $1" >&2
		exit "$2"
	}

	case "${1:-}" in
		-h | --help)
			echo "usage: TEGO_VERSION=v0.1.0 ${prog}    (installs the given tag; unset for latest)"
			echo "       TEGO_PREFIX=DIR ${prog}        (default: \$HOME/.local/bin)"
			exit 0
			;;
	esac

	# ---- required tools -----------------------------------------------------------------------------------
	# curl and a sha256 tool are not part of POSIX and some minimal images lack one or the other; everything
	# else below (uname, mktemp, awk, sed, mv, chmod) is base POSIX utilities present on any target this
	# script's own `os` check will accept.
	command -v curl >/dev/null 2>&1 || die "curl is required to download the release archive; install it and re-run" 2

	have_sha256sum=0
	have_shasum=0
	command -v sha256sum >/dev/null 2>&1 && have_sha256sum=1
	command -v shasum >/dev/null 2>&1 && have_shasum=1
	if [ "$have_sha256sum" -eq 0 ] && [ "$have_shasum" -eq 0 ]; then
		die "no sha256 tool found (need sha256sum or shasum); install one and re-run" 2
	fi

	sha256_of() {
		if [ "$have_sha256sum" -eq 1 ]; then
			sha256sum "$1" | awk '{print $1}'
		else
			shasum -a 256 "$1" | awk '{print $1}'
		fi
	}

	# ---- platform ------------------------------------------------------------------------------------------
	# Tego enforces from Landlock, cgroups and eBPF: kernel facilities a Darwin or NT kernel does not have.
	# On macOS, mac_setup sets up the Lima VM instead; elsewhere the answer is a Linux VM or WSL2.
	os_raw=$(uname -s)
	case "$os_raw" in
		Linux) os=linux ;;
		Darwin) os=darwin ;;
		*)
			die "unsupported operating system '${os_raw}': tego ships Linux binaries only. On Windows, install inside WSL2 (a real Linux kernel) and run this script there." 3
			;;
	esac

	arch_raw=$(uname -m)
	case "$arch_raw" in
		x86_64 | amd64) arch=amd64 ;;
		aarch64 | arm64) arch=arm64 ;;
		*) die "unsupported architecture '${arch_raw}': tego ships amd64 and arm64 only" 4 ;;
	esac

	# ---- version ---------------------------------------------------------------------------------------------
	workdir=$(mktemp -d "${TMPDIR:-/tmp}/tego-install.XXXXXX") || die "could not create a temporary directory" 8
	tmp_bin=""
	tmp_control=""
	term_state=""
	cleanup() {
		cleanup_status=$?
		[ -z "${term_state:-}" ] || restore_term
		# Keep a failed Mac step's private diagnostic log at the path shown to the person.
		if [ "$cleanup_status" -eq 0 ] || [ ! -s "$workdir/install.log" ]; then
			rm -rf "$workdir"
		fi
		[ -n "$tmp_bin" ] && rm -f "$tmp_bin"
		[ -n "$tmp_control" ] && rm -f "$tmp_control"
		return 0
	}
	# INT and TERM end the install as well as clean up: a trap that only cleaned up let the shell carry on with the
	# next step after the temporary directory was gone. 130 and 143 are the shell's own codes
	# for a command ended by those signals.
	trap cleanup EXIT
	trap 'cleanup; exit 130' INT
	trap 'cleanup; exit 143' TERM

	# fetch downloads $1 to $2 and prints "<curl exit>:<HTTP status>". curl -f reports every HTTP error as exit
	# 22, so the status is read with -w, and the callers below judge the pair: a 404 or 410 (or a missing file
	# under a file:// mirror, exit 37) says the thing is not there, while any other status and any failure to
	# connect say nothing about the tag, and telling the user their tag is wrong on a 403, a 500 or a 503 sends
	# them looking in the wrong place.
	fetch() {
		set +e
		# --proto keeps a redirect (or a base URL) from leaving https; file is for the tests' local mirror.
		protocols='=https,file'
        if [ "${TEGO_HOST_KIND:-}" = windows ] && [ "${TEGO_TEST_HTTP:-}" = 1 ] && [ -n "${TEGO_CHECKSUMS_SHA256:-}" ]; then
            protocols='=https,file,http'
        fi
        fetched_status=$(curl -fsSL --proto "$protocols" --proto-redir '=https' --connect-timeout 10 --max-time "$max_time" -o "$2" -w '%{http_code}' "$1")
		fetched_rc=$?
		set -e
		echo "${fetched_rc}:${fetched_status}"
	}
	# host_of is a URL's scheme and host, which is all a network failure's message needs.
	host_of() {
		echo "$1" | sed -E 's#(https?://[^/]+).*#\1#'
	}

	# Shared release selection and verification for Linux binaries and the Mac VM template.
	prepare_release() {
		if [ -z "$version" ]; then
			meta="${workdir}/latest.json"
			# GitHub answers /releases/latest with 404 while a repository has no release, and with 403 or 429 when
			# its unauthenticated rate limit is spent, which is common on a shared CI address.
			got=$(fetch "$api_url" "$meta")
			case "$got" in
				0:*) ;;
				22:404 | 22:410 | 37:*)
					die "${repo_owner}/${repo_name} has no published release yet (${api_url} names none); set TEGO_VERSION=vX.Y.Z once one exists" 5
					;;
				22:*)
					die "${api_url} answered HTTP ${got#*:} when asked for the latest release (403 and 429 are GitHub's rate limit); try again later, or set TEGO_VERSION=vX.Y.Z to skip the lookup" 6
					;;
				*)
					die "could not reach $(host_of "$api_url") to find the latest release (curl exit ${got%%:*}); check the network, or set TEGO_VERSION=vX.Y.Z to skip the lookup" 6
					;;
			esac
			# No jq dependency: one field, pulled with the tools already required above.
			version=$(grep -m1 '"tag_name"' "$meta" | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')
			if [ -z "$version" ]; then
				die "${repo_owner}/${repo_name} has no published release yet (GitHub API returned no tag_name); set TEGO_VERSION=vX.Y.Z once one exists" 5
			fi
		fi
		case "$version" in
			v*) tag="$version" ;;
			*) tag="v${version}" ;;
		esac
		version_no_v="${tag#v}"

		# Matches the archives.name_template in .goreleaser.yaml exactly (one per binary of its tego archive): change one,
		# change the other.
		archive="tego_${version_no_v}_${os}_${arch}"
		[ "$os" != darwin ] || archive=tego.yaml
		control="tego-control_${version_no_v}_${os}_${arch}"
		checksums="tego_${version_no_v}_checksums.txt"
		archive_path="${workdir}/${archive}"
		control_path="${workdir}/${control}"
		checksums_path="${workdir}/${checksums}"

		# download fetches one release asset. Only an asset that is not there (fetch says which answers mean that)
		# is a question about the tag, exit 5; the server's own trouble, named by its status, and a network failure
		# are exit 6, which a retry may cure.
		download() {
			url="$1"
			dest="$2"
			label="$3"
			got=$(fetch "$url" "$dest")
			case "$got" in
				0:*) return 0 ;;
				22:404 | 22:410 | 37:*)
					die "no release found at ${url} — is '${tag}' a real tego release? Check TEGO_VERSION, or unset it to install the latest" 5
					;;
				22:*) die "the server answered HTTP ${got#*:} for ${label} at ${url}; try again later" 6 ;;
				6:* | 7:* | 28:*) die "could not reach $(host_of "$url") to download ${label}; check the network and try again" 6 ;;
				*) die "download of ${label} failed (curl exit ${got%%:*}): ${url}" 6 ;;
			esac
		}

		download "${base_url}/${tag}/${archive}" "$archive_path" "the ${os}/${arch} archive"
		download "${base_url}/${tag}/${checksums}" "$checksums_path" "the checksums file"

		# A Mac-verified checksums digest binds guest binaries even without a guest verifier.
		# Check before interpreting any entries, including the optional control binary.
		if [ -n "${TEGO_CHECKSUMS_SHA256:-}" ] && [ "$TEGO_CHECKSUMS_SHA256" != "$(sha256_of "$checksums_path")" ]; then
			die "checksum mismatch for the pinned checksums file; not installing it" 7
		fi

		# ---- who published it ------------------------------------------------------------------------------------
		# The checksums file is authenticated before anything below trusts it. A verifier that is present and says
		# no is a finding, never a reason to fall back to the checksum: a bundle stripped from a tampered release
		# must not be the thing that lets it install. Only its absence falls back, and only in auto mode.
		verify="${TEGO_VERIFY:-auto}"
		case "$verify" in
			auto)
				if command -v cosign >/dev/null 2>&1; then
					verify=cosign
				elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
					verify=gh
				else
					verify=none
				fi
				;;
			cosign | gh | sha256) ;;
			*) die "TEGO_VERIFY must be auto, cosign, gh or sha256, got '${verify}'" 2 ;;
		esac

		# The identity release.yml signs as: that workflow of this repository, run for this very tag.
		signer="https://github.com/${repo_owner}/${repo_name}/.github/workflows/release.yml@refs/tags/${tag}"
		# attested FILE NAME: in gh mode, the binary FILE (the asset NAME) must carry a build provenance attestation by the
		# release workflow at this tag. --cert-identity is the identity cosign mode checks, the workflow at this tag, and
		# --source-ref the ref the build ran from: with only the workflow's path, any tag's attested binary would pass as
		# this one.
		attested() {
			if ! gh attestation verify "$1" --repo "${repo_owner}/${repo_name}" \
				--cert-identity "$signer" --source-ref "refs/tags/${tag}" >"$verifier_out" 2>&1; then
				show_verifier gh
				die "gh could not verify a build provenance attestation for $2 by ${signer} from refs/tags/${tag} (its output is above). An attestation for another tag, or none, means this is not the ${tag} tego's release workflow published; a gh without network or not logged in fails here too. Not installing it." 9
			fi
		}
		verifier_out="${workdir}/verifier.out"
		# show_verifier prints what the verifier itself said, indented under its name: exit 9 below says only that
		# verification failed, and the verifier's own words are what tell a forged release from an outdated tool or
		# an unreachable trust root.
		show_verifier() {
			sed "s/^/  $1: /" "$verifier_out" >&2
		}
		case "$verify" in
			cosign)
				command -v cosign >/dev/null 2>&1 || die "TEGO_VERIFY=cosign but cosign is not on PATH; install it or choose another TEGO_VERIFY" 2
				bundle_path="${checksums_path}.sigstore.json"
				bundle_url="${base_url}/${tag}/${checksums}.sigstore.json"
				# A bundle the server says is not there is told apart from one that could not be fetched: the first is
				# what a stripped release looks like and stops the install as unverifiable (9), the second is the
				# server's or the network's failure (6) that a retry may cure. Neither falls back to the checksum.
				got=$(fetch "$bundle_url" "$bundle_path")
				case "$got" in
					0:*) ;;
					22:404 | 22:410 | 37:*)
						die "${tag} has no signature bundle (${checksums}.sigstore.json) where its release is; every release tego's release workflow publishes carries one, and a release stripped of it cannot be told from one altered after signing. Not installing it." 9
						;;
					22:*) die "the server answered HTTP ${got#*:} for the signature bundle ${bundle_url}; try again later" 6 ;;
					*) die "could not download the signature bundle ${bundle_url} (curl exit ${got%%:*}); check the network and try again" 6 ;;
				esac
				if ! cosign verify-blob --bundle "$bundle_path" --certificate-identity "$signer" \
					--certificate-oidc-issuer https://token.actions.githubusercontent.com "$checksums_path" >"$verifier_out" 2>&1; then
					show_verifier cosign
					die "cosign could not verify ${checksums} as signed by ${signer} (its output is above). A signature by another identity, or a file changed after signing, means this is not what tego's release workflow published; a cosign too old to read the bundle, or no network to fetch Sigstore's trust root, fails here too. Not installing it." 9
				fi
				;;
			gh)
				command -v gh >/dev/null 2>&1 || die "TEGO_VERIFY=gh but gh is not on PATH; install it or choose another TEGO_VERIFY" 2
				attested "$archive_path" "$archive"
				;;
			none)
				echo "${prog}: note: neither cosign nor a logged-in gh is on PATH, so only the checksum is checked. It proves the download is intact, not who published it: install cosign (how: https://docs.sigstore.dev/cosign/system_config/installation/) or log gh in (gh auth login) and run this again, or set TEGO_VERIFY=sha256 to silence this." >&2
				;;
		esac

		# ---- verify before unpacking ------------------------------------------------------------------------------
		# The whole reason a release ships checksums is so this step happens; an installer that skips it is worse
		# than none, because it looks safe.
		expected=$(awk -v f="$archive" '$2==f {print $1}' "$checksums_path")
		if [ -z "$expected" ]; then
			die "${checksums} has no entry for ${archive}; the release for ${tag} looks incomplete" 7
		fi
		actual=$(sha256_of "$archive_path")
		if [ "$expected" != "$actual" ]; then
			die "checksum mismatch for ${archive}: expected ${expected}, got ${actual}. The download is corrupt or was tampered with — not installing it. Try again, and report it if it repeats." 7
		fi

		# tego-control, when the release has one: the checksums file, authenticated above, says whether it does (a release
		# from before tego-control lists none). It is held to the same checks as tego: its provenance in gh mode, and its
		# checksum.
		control_expected=$(awk -v f="$control" '$2==f {print $1}' "$checksums_path")
		if [ -n "$control_expected" ]; then
			download "${base_url}/${tag}/${control}" "$control_path" "the ${os}/${arch} tego-control"
			[ "$verify" = gh ] && attested "$control_path" "$control"
			control_actual=$(sha256_of "$control_path")
			if [ "$control_expected" != "$control_actual" ]; then
				die "checksum mismatch for ${control}: expected ${control_expected}, got ${control_actual}. The download is corrupt or was tampered with — not installing it. Try again, and report it if it repeats." 7
			fi
		fi
	}
	if [ "$os" = darwin ]; then
		mac_setup
	fi
	prepare_release

	# ---- install --------------------------------------------------------------------------------------------
	mkdir -p "$prefix" || die "could not create install directory ${prefix}" 8
	# archives.formats is [binary] in .goreleaser.yaml: the verified download already is the executable, nothing
	# to extract. Land it in $prefix under a temp name first so the final `mv` below is a same-filesystem rename.
	tmp_bin="${prefix}/.tego.tmp.$$"
	cp "$archive_path" "$tmp_bin" || die "could not write to ${prefix}" 8
	chmod 755 "$tmp_bin" || die "could not make ${tmp_bin} executable (existing install untouched)" 8
	# Run the new binary where it sits (same directory, same mount options as its final place) before it replaces
	# anything: one that will not run must not cost the user the install that works. Its version names the
	# tego-control SHA-256 it was built with (control_sha256, or none).
	if ! version_out=$("$tmp_bin" version 2>/dev/null); then
		die "the downloaded tego would not run (an Exec format error here usually means an architecture mismatch); any existing install is untouched; please report this" 8
	fi
	pin=$(echo "$version_out" | sed -n 's/^control_sha256=//p')
	# tego runs only the tego-control its pin names: a pair that does not match is refused at every handed-off command
	# ([control-mismatch]), so it is not installed. tego-control itself is not run here: it refuses euid 0, and an
	# install under sudo is one.
	if [ -n "$control_expected" ]; then
		if [ "$pin" != "$control_actual" ]; then
			die "the release's tego is built for tego-control ${pin:-(no pin)}, but its ${control} has SHA-256 ${control_actual}; the release looks inconsistent — not installing it" 7
		fi
		tmp_control="${prefix}/.tego-control.tmp.$$"
		cp "$control_path" "$tmp_control" || die "could not write to ${prefix}" 8
		# 755: tego's handoff refuses a tego-control its group or others can write, or that the user may not execute.
		chmod 755 "$tmp_control" || die "could not make ${tmp_control} executable (existing install untouched)" 8
	elif [ -n "$pin" ] && [ "$pin" != none ]; then
		die "the release's tego is built for tego-control ${pin}, but ${checksums} lists no ${control}; the release for ${tag} looks incomplete" 7
	fi
	# mv into a directory named tego would move the binary inside it and report success with nothing installed.
	for name in tego tego-control; do
		if [ -d "${prefix}/${name}" ]; then
			die "${prefix}/${name} is a directory, not a ${name} binary; move it away or choose another TEGO_PREFIX (nothing installed)" 8
		fi
	done
	control_moved=""
	if [ -n "$tmp_control" ]; then
		mv -f "$tmp_control" "${prefix}/tego-control" || die "could not install ${prefix}/tego-control (existing install untouched)" 8
		tmp_control=""
		control_moved=1
	fi
	# The failure names what this install already replaced: tego-control, when it moved one, else nothing.
	if ! mv -f "$tmp_bin" "${prefix}/tego"; then
		[ -n "$control_moved" ] ||
			die "could not install ${prefix}/tego (existing install untouched)" 8
		die "could not install ${prefix}/tego; ${prefix}/tego-control is already ${tag}'s, so the old tego refuses its control commands ([control-mismatch]) until this install is run again" 8
	fi
	tmp_bin="" # moved: nothing left for cleanup to remove under that name

	installed="${prefix}/tego"

	if [ -n "$control_moved" ]; then
		echo "installed tego ${tag} (${os}/${arch}) to ${installed}, and tego-control beside it"
	else
		echo "installed tego ${tag} (${os}/${arch}) to ${installed}"
		echo "note: ${tag} has no tego-control, which serve and the other commands tego hands to it need: they say [control-not-installed]"
	fi
	echo "licence notices: ${base_url}/${tag}/tego_${version_no_v}_licenses.tar.gz"

	# What comes next, short: the PATH block only when it is needed (with the line for this shell's profile), the
	# scope line only over SSH (tier 1 needs a cgroup the user can place a process in, and an SSH login starts outside
	# one; docs/INSTALL.md "Check the machine"), then the one next command in tego's own hint format (a line starting
	# "next: ", the command on the line after it, indented two spaces).
	echo "Quickstart: https://github.com/${repo_owner}/${repo_name}/blob/main/docs/QUICKSTART.md"
	# tego_cmd is how the next command names tego: by its bare name when this shell finds it there, and by the full path
	# where it does not. The installer cannot change the PATH of the shell that started it, so a bare name printed right
	# after the install was "command not found" for a person who had not yet typed the export line (acceptance 4).
	tego_cmd=tego
	case ":${PATH}:" in
		*":${prefix}:"*) ;;
		*)
			tego_cmd=$(shell_word "$installed")
			echo ""
			case "${SHELL:-}" in
				*/fish)
					echo "${prefix} is not on your PATH. Run this line; fish keeps it for later shells too:"
					echo "  fish_add_path \"${prefix}\""
					echo "Until you do, the command below names tego by its full path."
					;;
				*)
					# shellcheck disable=SC2088 # the profile is named for a person to read, not expanded
					case "${SHELL:-}" in
						*/zsh) profile="~/.zshrc" ;;
						*/bash) profile="~/.bashrc" ;;
						*) profile="your shell's profile (~/.profile)" ;;
					esac
					echo "${prefix} is not on your PATH. Run this line, and add it to ${profile} too:"
					echo "  export PATH=\"${prefix}:\$PATH\""
					echo "Until you do, the command below names tego by its full path."
					;;
			esac
			;;
	esac
	# A tego that opens a user scope itself makes a shell outside the user manager's cgroup no blocker: tego setup
	# rehearses that entry from this shell and says whether it works; the manual line is the one fix when it does not
	# (ADR 0142, amended 2026-11-19, round 4). An older tego needs the manual shell first.
	installed_help=$("$installed" help -a </dev/null 2>/dev/null || :)
	if [ -n "${SSH_CONNECTION:-}" ]; then
		echo ""
		if printf '%s\n' "$installed_help" | grep -Eq '^ {2,3}run .*opens a user scope'; then
			echo "this shell is outside your user manager's cgroup: run, watch and test open a user scope for each run; the setup command below checks that this works from here, and if it does not, the one fix is a shell inside it:"
			echo "  systemd-run --user --scope bash"
		else
			echo "over SSH, this release needs a shell in your user manager's cgroup before a run:"
			echo "  systemd-run --user --scope bash"
		fi
	fi
	# sudo replaces PATH with its own secure_path, which has no ~/.local/bin (and on AlmaLinux no /usr/local/bin):
	# A bare Tego program name after sudo does not find this copy, and a copy in this home is closed to an account that cannot
	# enter it. One line, before the next step, which stays last.
	echo "to run tego as another account (sudo -u <account>), install both binaries in that account's ~/.local/bin, or in a root-owned shared directory and adjust the service units; type its absolute path after sudo, which does not search ~/.local/bin (docs/INSTALL.md, \"A service account\")."
	echo ""
	# tego start walks a new user through the rest; tego setup, before it, says which step this machine is on (ADR 0142). A
	# release made before them lacks both, and this script installs any tag, so the installed tego's own
	# command list decides: the line never names a command that tego lacks. Its stdin is not the script's (see the
	# version check above).
	if printf '%s\n' "$installed_help" | grep -Eq '^ {2,3}start '; then
		echo "next: set up Tego and connect your first agent:"
		echo "  ${tego_cmd} start"
	elif printf '%s\n' "$installed_help" | grep -Eq '^ {2,3}setup '; then
		echo "next: see where this machine is, step by step, and what to type next:"
		echo "  ${tego_cmd} setup"
	else
		echo "next: check this machine:"
		echo "  ${tego_cmd} doctor"
	fi
}

main "$@"
