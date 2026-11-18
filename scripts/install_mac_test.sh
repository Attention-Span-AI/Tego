#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests install.sh's macOS path (mac_setup) with stand-ins for uname, sw_vers, df, brew and limactl, so it runs on
# any machine: each case checks what the script prints, which commands it runs, and its exit code. Nothing real is
# installed or started.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script=${TEGO_INSTALLER_TEST_SCRIPT:-"$here/install.sh"}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/install-mac-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
fails=0

# Fixture hashes use the platform's checksum tool. Do not put an adapter on the
# installer's Mac PATH: that must exercise its native shasum branch on macOS.
suite_sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
# The suite executes Linux guest shell bodies locally. Only those bodies need
# Linux's sha256sum spelling; shasum has the same -c format and failure status.
guest_tools="$tmp/guest-tools"
mkdir -p "$guest_tools"
if ! PATH=/usr/bin:/bin command -v sha256sum >/dev/null 2>&1; then
	printf '#!/bin/sh\nexec /usr/bin/shasum -a 256 "$@"\n' >"$guest_tools/sha256sum"
	chmod +x "$guest_tools/sha256sum"
fi

# stubs FAKEBIN: writes the stand-ins. limactl goes in its own folder, which a case puts on PATH when Lima is
# "installed"; brew install/upgrade copies it into FAKEBIN, as a real install would put it on PATH.
# shellcheck disable=SC2016 # the stand-ins are written as is, for their own shell to expand
stubs() {
	b=$1
	mkdir -p "$b" "$b.lima"
	printf '#!/bin/sh\n[ "$1" = -s ] && echo Darwin || echo arm64\n' >"$b/uname"
	printf '#!/bin/sh\necho "${FAKE_MACOS:-15.1}"\n' >"$b/sw_vers"
	printf '#!/bin/sh\necho "Filesystem 1K-blocks Used Available"\necho "/dev/x 1 1 ${FAKE_FREE_KB:-20971520}"\n' >"$b/df"
	cat >"$b/stty" <<'EOF'
#!/bin/sh
echo "stty $*" >>"$FAKE_LOG"
if [ "$1" = -g ]; then
	echo saved-terminal-settings
	[ "${FAKE_SAVE_SIGNAL:-}" != TERM ] || kill -TERM "$PPID"
else
	[ "${FAKE_RESTORE_FAIL:-}" != 1 ]
fi
EOF
	chmod +x "$b/stty"
	cat >"$b/brew" <<EOF
#!/bin/sh
echo "brew \$*" >>"\$FAKE_LOG"
if [ -n "\${FAKE_BREW_SIGNAL:-}" ]; then kill -"\$FAKE_BREW_SIGNAL" "\$PPID"; exit 1; fi
[ "\${FAKE_BREW_FAIL:-}" != 1 ] || { echo "brew failure details"; exit 1; }
cp "$b.lima/limactl" "$b/limactl"
EOF
	cat >"$b.lima/limactl" <<'EOF'
#!/bin/sh
case "$1" in
	--version) echo "limactl version ${FAKE_LIMA:-2.3.0}" ;;
	list)
		case "$*" in *'{{.Dir}}'*) [ "${FAKE_VM_DIR_FAIL:-}" != 1 ] || exit 1; echo "$HOME/.lima/tego" ;;
			*) [ -n "${FAKE_VM:-}" ] && echo "$FAKE_VM" || exit 1 ;;
		esac ;;
	shell)
		echo "limactl $*" >>"$FAKE_LOG"
		case "$*" in
			*' version') [ "${FAKE_GUEST_VERSION:-v0.1.3}" != broken ] || exit 126; printf 'tego=%s\n' "${FAKE_GUEST_VERSION:-v0.1.3}"; [ "${FAKE_GUEST_FAIL:-}" != 1 ] ;;
			*'curl -fsSL'* )
				[ "${FAKE_UPDATE_FAIL:-}" != 1 ] || exit 42
				# Execute the update's fixed shell body locally, with downloads still stubbed.
				shift
				while [ "$1" != sh ]; do shift; done
				# limactl does not export the Mac installer environment into the guest.
				(unset TEGO_BASE_URL; PATH="$PATH:$FAKE_GUEST_TOOLS" FAKE_CORRUPT_INSTALLER=${FAKE_CORRUPT_GUEST_INSTALLER:-0} "$@") ;;
			*'TEGO_ON_MAC=1'*' start'|*'TEGO_ON_MAC=1'*' setup') exit "${FAKE_GUIDE_STATUS:-0}" ;;
			*'grep -o'*) [ "${FAKE_NO_URL:-}" != 1 ] || exit 1; mkdir -p "$HOME/.tego"
				printf '%s\n' "${FAKE_URL:-http://127.0.0.1:8484/?t=test}" >"$HOME/.tego/dashboard.log"
				shift
				while [ "$1" != sh ]; do shift; done
				"$@" ;; esac ;;
	start)
		echo "limactl $*" >>"$FAKE_LOG"
		for arg do
			case "$arg" in
				*.yaml)
					[ -f "$arg" ] || { echo 'template must be local' >&2; exit 1; }
					[ "$(ls -ld "${arg%/*}" | cut -c1-10)" = drwx------ ] || exit 1
					cmp "$arg" "${0%/*}/tego.yaml" || exit 1
					echo 'verified local template in private directory' >>"$FAKE_LOG"
					;;
			esac
		done
		[ "${FAKE_START_FAIL:-}" != 1 ] || { echo 'Lima start failure details' >&2; exit 1; }
		case "${FAKE_IMAGE_FAIL:-}" in
			1) echo 'failed to download "https://cloud-images.ubuntu.com/releases/noble/pinned.img": unexpected HTTP status Not Found' >&2; exit 1 ;;
			network|digest) echo "failed to download \"https://cloud-images.ubuntu.com/releases/noble/pinned.img\": $FAKE_IMAGE_FAIL failure" >&2; exit 1 ;;
		esac ;;
	*) echo "limactl $*" >>"$FAKE_LOG" ;;
esac
EOF
	# All downloads stay in this case's release fixture; no network is used.
	cp "$here/../examples/lima/tego.yaml" "$b/tego.yaml"
	printf '#!/bin/sh\necho "guest installed $TEGO_VERSION checksums=${TEGO_CHECKSUMS_SHA256:-missing} base=${TEGO_BASE_URL:-missing}" >>"$FAKE_LOG"\n' >"$b/install.sh"
	printf 'guest binary fixture\n' >"$b/tego_0.1.3_linux_arm64"
	printf 'guest control fixture\n' >"$b/tego-control_0.1.3_linux_arm64"
	(cd "$b" && suite_sha256 -- tego.yaml install.sh *linux_arm64) >"$b/checksums"
	cat >"$b/curl" <<'EOF'
#!/bin/sh
out='' url=''
while [ "$#" -gt 0 ]; do
	case "$1" in
		-o) out=$2; shift 2 ;;
		--proto|--proto-redir|--connect-timeout|--max-time|-w) shift 2 ;;
		-*) shift ;;
		*) url=$1; shift ;;
	esac
done
echo "curl $url" >>"$FAKE_LOG"
[ "${FAKE_DOWNLOAD_FAIL:-}" != 1 ] || exit 7
b=${0%/*}
case "$url" in
	*/latest) printf '{"tag_name":"v0.1.3"}\n' >"$out" ;;
	*/tego.yaml) cp "$b/tego.yaml" "$out"; [ "${FAKE_CORRUPT:-}" != 1 ] || echo corrupt >>"$out" ;;
	*/tego_0.1.3_linux_arm64|*/tego-control_0.1.3_linux_arm64) cp "$b/${url##*/}" "$out" ;;
	*/install.sh) cp "$b/install.sh" "$out"; [ "${FAKE_CORRUPT_INSTALLER:-}" != 1 ] || echo corrupt >>"$out" ;;
	*_checksums.txt) cp "$b/checksums" "$out" ;;
	*.sigstore.json) echo bundle >"$out" ;;
	*) echo "unexpected URL: $url" >&2; exit 1 ;;
esac
printf 200
EOF
	cat >"$b/cosign" <<'EOF'
#!/bin/sh
echo "cosign $*" >>"$FAKE_LOG"
[ "${FAKE_VERIFY_FAIL:-}" != 1 ]
EOF
	cat >"$b/gh" <<'EOF'
#!/bin/sh
echo "gh $*" >>"$FAKE_LOG"
[ "${FAKE_VERIFY_FAIL:-}" != 1 ] || exit 1
case "$*" in *"${FAKE_GH_REFUSE:-//none//}"*) exit 1 ;; esac
EOF
	chmod +x "$b/curl" "$b/cosign" "$b/gh"
	chmod +x "$b/uname" "$b/sw_vers" "$b/df" "$b/brew" "$b.lima/limactl"
}

# check NAME WANT_CODE WANT_TEXT... : runs install.sh with the environment already exported by the caller
# (via env in the case) and checks the exit code and that output plus the command log contain each text.
check() {
	name=$1 want=$2
	shift 2
	if [ "$code" != "$want" ]; then
		echo "FAIL $name: exit $code, want $want"
		sed 's/^/    /' "$tmp/out"
		fails=$((fails + 1))
		return
	fi
	for t in "$@"; do
		if ! grep -qF -- "$t" "$tmp/out" "$tmp/log" 2>/dev/null; then
			echo "FAIL $name: no \"$t\""
			sed 's/^/    out: /' "$tmp/out"
			sed 's/^/    log: /' "$tmp/log" 2>/dev/null || true
			fails=$((fails + 1))
			return
		fi
	done
	echo "ok   $name"
}
absent() { # absent NAME TEXT: the text must not be in the output or the log
	if grep -qF -- "$2" "$tmp/out" "$tmp/log" 2>/dev/null; then
		echo "FAIL $1: unexpected \"$2\""
		fails=$((fails + 1))
	fi
}

finish_once() {
	if [ "$(grep -c 'curl -fsSL .*install.sh |' "$tmp/out")" != 1 ]; then
		echo "FAIL M4 $1: installer command repeated or missing"; fails=$((fails + 1))
	else
		echo "ok   M4 $1: installer command once"
	fi
}

# run CASE [VAR=value...]: a fresh set of stubs per case. LIMA=1 puts limactl on PATH; BREW=0 removes brew.
run() {
	c=$1
	shift
	bin="$tmp/$c/bin"
	stubs "$bin"
	: >"$tmp/log"
	path="$bin:/usr/bin:/bin"
	for kv in "$@"; do
		case "$kv" in
			LIMA=1) cp "$bin.lima/limactl" "$bin/limactl" ;;
			BREW=0) rm -f "$bin/brew" ;;
			OLD_TEMPLATE=1)
				# v0.1.3 provisioning ignores all parameters and fetches mutable latest.
				printf 'provision:\n  - mode: user\n    script: |\n      curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh\n' >"$bin/tego.yaml"
				(cd "$bin" && suite_sha256 tego.yaml install.sh) >"$bin/checksums"
				;;
		esac
	done
	code=0
	env -i HOME="$tmp" TMPDIR="$tmp" SHELL=/bin/zsh PATH="$path" FAKE_LOG="$tmp/log" FAKE_GUEST_TOOLS="$guest_tools" "$@" /bin/sh "$script" >"$tmp/out" 2>&1 </dev/null || code=$?
}

# Give /dev/tty a real terminal while stdin remains the piped install script.
# Python is test infrastructure only; the Mac installer itself has no new dependency.
tty_run() {
	code=0
	python3 - "$script" "$tmp" "$bin" "$@" <<'PYTTY' >"$tmp/out" 2>&1 || code=$?
import os, pty, select, sys, time
script, tmp, bin, answer = sys.argv[1:5]
pid, fd = pty.fork()
if pid == 0:
    env = dict(HOME=tmp, TMPDIR=tmp, SHELL='/bin/zsh', PATH=bin+':/usr/bin:/bin',
               FAKE_LOG=tmp+'/log', FAKE_GUEST_TOOLS=tmp+'/guest-tools', FAKE_VM='Running', FAKE_GUEST_VERSION='v0.1.2')
    env.update(x.split('=', 1) for x in sys.argv[5:])
    os.execve('/bin/sh', ['sh', '-c', 'cat "$1" | sh', 'sh', script], env)
output = b''
sent = False
end = time.monotonic() + 10
while time.monotonic() < end:
    if select.select([fd], [], [], 0.1)[0]:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        output += data
        if not sent and (b'? [Y/n]' in output or b'? [y/N]' in output):
            os.write(fd, answer.encode() + b'\n')
            sent = True
else:
    os.kill(pid, 9)
    print('FAIL terminal test timed out')
_, status = os.waitpid(pid, 0)
os.close(fd)
sys.stdout.buffer.write(output)
sys.exit(os.waitstatus_to_exitcode(status))
PYTTY
}

latest="https://github.com/Attention-Span-AI/Tego/releases/download/v0.1.3/tego.yaml"

run fresh TEGO_YES=1
check "fresh Mac: installs Lima, sets up the VM, adds tego" 0 "Lima isn't installed. Tego uses this free program to run its Linux VM." "Install Lima now with Homebrew?" "brew install lima" \
	"limactl start --tty=false --name=tego --mount-none --param=tego_version=v0.1.3" "--param=checksums_sha256=$(suite_sha256 "$tmp/fresh/bin/checksums" | awk '{print $1}')" "verified local template in private directory" "✓ Lima 2.3.0" "✓ Tego's VM is ready" "✓ tego command added" \
	"Next steps" "Open a new Terminal window, then type tego start"
[ -x "$tmp/.local/bin/tego" ] || { echo "FAIL fresh Mac: no tego command in ~/.local/bin"; fails=$((fails + 1)); }
grep -q 'added by the Tego installer' "$tmp/.zshrc" 2>/dev/null || { echo "FAIL fresh Mac: PATH line not added to ~/.zshrc"; fails=$((fails + 1)); }
absent "fresh Mac: hides Lima's own output" "INFO["

# bash: the PATH line goes in the profile a login bash already reads, never a new .bash_profile that would hide it
mkdir -p "$tmp/bashhome" && echo '# mine' >"$tmp/bashhome/.profile"
c=bashprofile; b2="$tmp/$c/bin"; stubs "$b2"; cp "$b2.lima/limactl" "$b2/limactl"; : >"$tmp/log"; code=0
env -i HOME="$tmp/bashhome" TMPDIR="$tmp" SHELL=/bin/bash PATH="$b2:/usr/bin:/bin" FAKE_LOG="$tmp/log" FAKE_VM=Running TEGO_YES=1 \
	sh "$script" >"$tmp/out" 2>&1 </dev/null || code=$?
check "bash with only a .profile: the line goes there" 0 "Open a new Terminal window, then type tego start" "exec bash -l"
grep -q 'added by the Tego installer' "$tmp/bashhome/.profile" || { echo "FAIL bash: PATH line not in .profile"; fails=$((fails + 1)); }
[ ! -e "$tmp/bashhome/.bash_profile" ] || { echo "FAIL bash: a .bash_profile now hides .profile"; fails=$((fails + 1)); }

run fish LIMA=1 FAKE_VM=Running TEGO_YES=1 SHELL=/usr/bin/fish XDG_CONFIG_HOME="$tmp/fish-config"
check "fish receives its own PATH configuration" 0 "exec fish -l"
fishfile="$tmp/fish-config/fish/conf.d/tego.fish"
# shellcheck disable=SC2016 # this is the literal fish configuration
if ! grep -qF 'fish_add_path "$HOME/.local/bin"' "$fishfile" 2>/dev/null; then
	echo 'FAIL fish: no fish PATH configuration'; fails=$((fails + 1))
fi
run fishagain LIMA=1 FAKE_VM=Running TEGO_YES=1 SHELL=/usr/bin/fish XDG_CONFIG_HOME="$tmp/fish-config"
check "fish configuration is idempotent" 0
[ "$(grep -c 'added by the Tego installer' "$fishfile" 2>/dev/null || true)" = 1 ] || {
	echo 'FAIL fish: PATH configuration missing or duplicated'; fails=$((fails + 1));
}

# Dotfile managers commonly link fish itself or conf.d to the caller's own tree.
# Keep writing the PATH line through those links, once across repeated installs.
for linked in fish conf.d; do
	config="$tmp/linked-$linked-config"
	target="$tmp/linked-$linked-target"
	mkdir -p "$config" "$target"
	case "$linked" in
		fish) mkdir -p "$target/conf.d"; ln -s "$target" "$config/fish"; fishfile="$target/conf.d/tego.fish" ;;
		conf.d) mkdir -p "$config/fish"; ln -s "$target" "$config/fish/conf.d"; fishfile="$target/tego.fish" ;;
	esac
	for pass in first second; do
		run "linked-$linked-$pass" LIMA=1 FAKE_VM=Running TEGO_YES=1 SHELL=/usr/bin/fish XDG_CONFIG_HOME="$config"
		check "linked fish $linked receives PATH ($pass install)" 0 "exec fish -l"
	done
	# shellcheck disable=SC2016 # this is literal fish code, expanded by fish on startup
	if ! grep -qF 'fish_add_path "$HOME/.local/bin"' "$fishfile" || [ "$(grep -c 'added by the Tego installer' "$fishfile")" != 1 ]; then
		echo "FAIL linked fish $linked: PATH line absent or duplicated"; fails=$((fails + 1))
	fi
done

run again LIMA=1 FAKE_VM=Running TEGO_YES=1
check "second run: nothing to redo" 0 "✓ Lima 2.3.0" "✓ Tego's VM is running" "✓ tego command is up to date" "tego start"
[ "$(grep -c 'added by the Tego installer' "$tmp/.zshrc")" = 1 ] || { echo "FAIL second run: PATH line added twice"; fails=$((fails + 1)); }
absent "second run: nothing to redo" "limactl start"
absent "second run: nothing to redo" "brew "

run old LIMA=1 FAKE_LIMA=1.0.1 TEGO_YES=1
check "old Lima: upgrades it" 0 "✗ Lima 1.0.1 is too old" "brew upgrade lima" "limactl start --tty=false --name=tego"

run stopped LIMA=1 FAKE_VM=Stopped TEGO_YES=1
check "VM stopped: starts it" 0 "○ Tego's VM is stopped" "limactl start tego" "✓ Tego's VM is running"

run pinned LIMA=1 TEGO_YES=1 TEGO_VERSION=v0.1.3
check "TEGO_VERSION picks that release's template" 0 \
	"curl $latest" "--param=tego_version=v0.1.3" "verified local template in private directory"

run freshmirror LIMA=1 TEGO_YES=1 TEGO_BASE_URL=https://mirror.example/tego/releases/download
check "fresh mirror is carried into provisioning" 0 "--param=release_base=https://mirror.example/tego/releases/download"

run imagesgone LIMA=1 TEGO_YES=1 FAKE_IMAGE_FAIL=1
check "M3 missing image gives deletion before retry" 8 "First remove the incomplete VM: limactl delete tego" "The pinned VM image is no longer available" "Update the installer" "releases/latest/download/install.sh | sh"
absent "M3 installer leaves deletion to person" "limactl delete --force"
for failure in network digest; do
	run "image-$failure" LIMA=1 TEGO_YES=1 "FAKE_IMAGE_FAIL=$failure"
	check "M3 $failure gets connection advice" 8 "First remove the incomplete VM: limactl delete tego" "The VM image download failed. Check the connection and run this installer again."
	absent "M3 $failure does not claim missing image" "image is no longer available"
	absent "M3 $failure does not claim old installer" "Update the installer"
done

run incompatible LIMA=1 TEGO_YES=1 TEGO_VERSION=v0.1.3 OLD_TEMPLATE=1
check "old verified template is refused before Lima starts" 7 "v0.2.0 is the first release to support a pinned Mac install" "unset TEGO_VERSION to install the latest"
absent "old template never starts Lima" "limactl start"

run nobrew BREW=0
check "no Homebrew: says where to get Lima" 2 "✗ Lima isn't installed" "https://lima-vm.io/docs/installation/" "first install Homebrew from https://brew.sh" "Then run: curl"

run brewfail TEGO_YES=1 FAKE_BREW_FAIL=1
check "failed Lima installation keeps its diagnostic log" 2 "brew failure details" "The full log is in"
logpath=$(sed -n 's/^.*The full log is in //p' "$tmp/out" | tail -n 1)
[ -f "$logpath" ] || { echo 'FAIL diagnostic log disappeared'; fails=$((fails + 1)); }

run oldmac FAKE_MACOS=12.6
check "macOS too old" 3 "✗ macOS 12.6. Tego's VM needs macOS 13.5 or later."
run macos135 LIMA=1 FAKE_VM=Running FAKE_MACOS=13.5
check "macOS 13.5 is enough" 0 "✓ macOS 13.5"

run disk FAKE_FREE_KB=2097152
check "too little disk" 8 "✗ 2 GB free. The VM needs about 5 GB."

run nocolor LIMA=1 FAKE_VM=Running TEGO_YES=1
absent "no colour when not a terminal" "$(printf '\033[')"

# With no terminal and no TEGO_YES the script asks nobody: it prints what is left and changes nothing. A run from
# an interactive terminal can open /dev/tty, so this case only runs where it cannot (CI).
if (: </dev/tty) 2>/dev/null; then
	echo "skip no terminal: /dev/tty is open here"
else
	run notty
	finish_once "install Lima"
	check "no terminal: prints the commands, runs none" 2 "To finish, run:" "brew install lima" \
		"releases/latest/download/install.sh | sh" "Then run this installer again: curl"
	if [ -s "$tmp/log" ]; then
		echo "FAIL no terminal: ran commands it should only print:"
		sed 's/^/    /' "$tmp/log"
		fails=$((fails + 1))
	fi
fi

if ! (: </dev/tty) 2>/dev/null; then
	run nocreate LIMA=1
	check "M4 no consent to create" 0 "Then run this installer again:"
	finish_once "create VM"
fi

run normalized LIMA=1 TEGO_YES=1 TEGO_VERSION=0.1.3 TEGO_VERIFY=gh
check "normalized tag binds template provenance and guest version" 0 "curl $latest" \
	"--source-ref refs/tags/v0.1.3" "--param=tego_version=v0.1.3"
check "gh authenticates guest Linux binaries before digest handoff" 0 "linux_arm64 --repo Attention-Span-AI/Tego" "tego-control_0.1.3_linux_arm64"
run guestattestation LIMA=1 TEGO_YES=1 TEGO_VERIFY=gh FAKE_GH_REFUSE=tego_0.1.3_linux_arm64
check "failed guest binary attestation refuses VM creation" 9 "gh could not verify"
absent "unattested guest binary never starts Lima" "limactl start"
run corrupt LIMA=1 TEGO_YES=1 FAKE_CORRUPT=1 TEGO_VERIFY=sha256
check "corrupt template refuses before VM creation" 7 "checksum mismatch for tego.yaml"
absent "corrupt template never starts" "limactl start"
run signature LIMA=1 TEGO_YES=1 FAKE_VERIFY_FAIL=1 TEGO_VERIFY=cosign
check "explicit cosign failure refuses before VM creation" 9 "cosign could not verify"
absent "bad signature never starts" "limactl start"
run attestation LIMA=1 TEGO_YES=1 FAKE_VERIFY_FAIL=1 TEGO_VERIFY=gh
check "explicit gh failure refuses before VM creation" 9 "gh could not verify"
absent "bad attestation never starts" "limactl start"
run pinnedexisting LIMA=1 FAKE_VM=Running TEGO_YES=1 TEGO_VERSION=v0.1.3
check "existing VM already at selected release" 0 "Tego v0.1.3 inside the VM is up to date"
absent "matching guest is not reinstalled" "guest installed"
for old in v0.1.2 broken; do
	run "update-$old" LIMA=1 FAKE_VM=Running TEGO_YES=1 TEGO_VERSION=0.1.3 FAKE_GUEST_VERSION="$old"
	from=$old; [ "$old" != broken ] || from='missing or not working'
	check "existing guest $old is updated in place" 0 "Update Tego inside the VM from $from to v0.1.3? [Y/n] yes" \
		"guest installed v0.1.3 checksums=$(suite_sha256 "$bin/checksums" | awk '{print $1}')" "Existing runs keep running"
	absent "update does not recreate or stop VM" "limactl start"
	absent "update does not stop VM" "limactl stop"
done
for reply in n ''; do
	: >"$tmp/log"
	tty_run "$reply"
	if [ "$reply" = n ]; then
		check "terminal no declines only the guest update" 0 "Skipped the VM update"
		absent "declined update never installs" "guest installed"
	else
		check "terminal Enter accepts the guest update by default" 0 "guest installed v0.1.3"
	fi
done

# Semantic version precedence, including releases and numeric prerelease identifiers.
for pair in 'v0.3.0-rc.1 v0.2.0' 'v0.1.3 v0.1.3-rc.1' 'v0.1.3-rc.10 v0.1.3-rc.2' 'v0.1.3-beta v0.1.3-alpha' 'v0.10.0 v0.2.0'; do
	guest=${pair% *}; selected=${pair#* }
	: >"$tmp/log"
	tty_run '' "FAKE_GUEST_VERSION=$guest" "TEGO_VERSION=$selected"
	check "M8 newer $guest defaults to no for $selected" 0 "Replace Tego $guest inside the VM with older version $selected? [y/N]" "Skipped the VM update"
	absent "M8 default no keeps newer guest" "guest installed"
done
for pair in 'v0.1.3-rc.1 v0.1.3' 'v0.1.3-rc.2 v0.1.3-rc.10' 'v0.1.3-1 v0.1.3-alpha' 'v0.1.2 v0.1.3'; do
	guest=${pair% *}; selected=${pair#* }
	: >"$tmp/log"
	tty_run '' "FAKE_GUEST_VERSION=$guest" "TEGO_VERSION=$selected"
	check "M8 older $guest still defaults to update $selected" 0 "Update Tego inside the VM from $guest to $selected? [Y/n]" "guest installed $selected"
done
: >"$tmp/log"
tty_run '' FAKE_GUEST_VERSION=v0.1.3-rc.2 TEGO_VERSION=v0.1.3-rc.2
check "M8 equal prerelease is up to date" 0 "inside the VM is up to date"
absent "M8 equal prerelease never asks" "Update Tego inside"
run explicitolder LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.2.0 TEGO_VERSION=v0.1.3
check "M8 explicit yes replaces newer version" 0 "with older version v0.1.3? [y/N] yes" "guest installed v0.1.3"

run mirrorupdate LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.2 TEGO_BASE_URL=https://mirror.example/tego/releases/download
check "M9 guest receives Mac release base and verified checksums" 0 \
	"curl https://mirror.example/tego/releases/download/v0.1.3/install.sh" \
	"guest installed v0.1.3 checksums=$(suite_sha256 "$bin/checksums" | awk '{print $1}') base=https://mirror.example/tego/releases/download"

run updatebadversion LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_FAIL=1
check "failing version command is repaired even if it prints a version" 0 "from missing or not working to v0.1.3?" "guest installed"
run updateguestcorrupt LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.2 FAKE_CORRUPT_GUEST_INSTALLER=1
check "changed installer is refused again inside guest" 8 "FAILED"
absent "changed installer never executes inside guest" "guest installed"
run updateoldtemplate LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.2 OLD_TEMPLATE=1
check "M1 unsupported release leaves guest unchanged normally" 0 "Tego inside the VM was left as it is; updating it from the Mac needs a later release."
absent "M1 unsupported release never asks" "Update Tego inside"
absent "M1 unset version is not mentioned" "TEGO_VERSION"
absent "incompatible update never enters guest" "sha256sum -c -"
for mode in yes notty pinned; do
	case "$mode" in
		yes) run unsupportedyes LIMA=1 FAKE_VM=Running FAKE_GUEST_VERSION=broken OLD_TEMPLATE=1 TEGO_YES=1 ;;
		notty) run unsupportednotty LIMA=1 FAKE_VM=Running FAKE_GUEST_VERSION=v0.1.2 OLD_TEMPLATE=1 ;;
		pinned) run unsupportedpinned LIMA=1 FAKE_VM=Running FAKE_GUEST_VERSION=v0.1.2 OLD_TEMPLATE=1 TEGO_VERSION=v0.1.3 TEGO_YES=1 ;;
	esac
	check "M1 unsupported $mode finishes normally" 0 "Tego inside the VM was left as it is; updating it from the Mac needs a later release." "Next steps"
	absent "M1 unsupported $mode never asks" "Update Tego inside"
	absent "M1 unsupported $mode never downloads installer" "/v0.1.3/install.sh"
	if [ "$mode" = pinned ]; then
		check "M1 explicit version identified" 0 "Selected with TEGO_VERSION=v0.1.3."
	fi
done

run updatecorrupt LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.2 FAKE_CORRUPT_INSTALLER=1
check "changed update installer is refused on Mac" 7 "checksum mismatch or missing entry for install.sh"
absent "changed update installer never enters guest" "sha256sum -c -"
run updateattestation LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.2 TEGO_VERIFY=gh FAKE_GH_REFUSE=tego_0.1.3_linux_arm64
check "guest update requires binary provenance in gh mode" 9 "gh could not verify"
absent "unattested update never enters guest" "sha256sum -c -"
run updatefail LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.2 FAKE_UPDATE_FAIL=1
check "failed guest update stops installer" 8 "The full log is in"
if ! (: </dev/tty) 2>/dev/null; then
	run updatenotty LIMA=1 FAKE_VM=Running FAKE_GUEST_VERSION=v0.1.2
	finish_once "guest update"
	absent "M4 empty finish list has no header" "To finish, run:"
	check "no terminal prints update retry and stops" 2 "TEGO_YES=1 TEGO_VERSION=v0.1.3 sh"
	absent "no terminal never installs guest update" "sha256sum -c -"
fi

# A failed or declined guest update must still leave the refreshed Mac command.
stale_command() {
	printf "#!/bin/sh\n# Tego's installer\n# stale-mac-command\n" >"$tmp/.local/bin/tego"
	chmod +x "$tmp/.local/bin/tego"
}
refreshed_command() {
	if grep -qF stale-mac-command "$tmp/.local/bin/tego"; then
		echo "FAIL $1: stale Mac command survived"; fails=$((fails + 1))
	else
		echo "ok   $1: Mac command refreshed"
	fi
}
for problem in lookup verification update notty; do
	stale_command
	case "$problem" in
		lookup) run refreshlookup LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_DOWNLOAD_FAIL=1; want=6 ;;
		verification) run refreshverify LIMA=1 FAKE_VM=Running TEGO_YES=1 TEGO_VERIFY=cosign FAKE_VERIFY_FAIL=1; want=9 ;;
		update) run refreshupdate LIMA=1 FAKE_VM=Running TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.2 FAKE_UPDATE_FAIL=1; want=8 ;;
		notty)
			if (: </dev/tty) 2>/dev/null; then continue; fi
			run refreshnotty LIMA=1 FAKE_VM=Running FAKE_GUEST_VERSION=v0.1.2; want=2 ;;
	esac
	check "M0 $problem retains update status" "$want" "tego command is up to date"
	refreshed_command "M0 $problem"
done
stale_command
: >"$tmp/log"
tty_run n
check "M0 decline keeps refreshed command" 0 "Skipped the VM update"
refreshed_command "M0 decline"

# Execute only the extracted provisioning shell against the same download stand-ins.
# The fixture installer records its selected version; it never runs a Tego binary.
awk '/^    script: \|/ && !seen {seen=1; inside=1; next} /^probes:/ {inside=0} inside {sub(/^      /, ""); print}' \
	"$here/../examples/lima/tego.yaml" >"$tmp/provision.sh"
bin="$tmp/normalized/bin"
checksums_digest=$(suite_sha256 "$bin/checksums" | awk '{print $1}')
digest=$(suite_sha256 "$bin/install.sh" | awk '{print $1}')
: >"$tmp/log"; code=0
env -i PATH="$bin:/usr/bin:/bin:$guest_tools" HOME="$tmp/guest" TMPDIR="$tmp" FAKE_LOG="$tmp/log" \
	PARAM_release_base=https://mirror.example/tego/releases/download PARAM_checksums_sha256="$checksums_digest" PARAM_tego_version=v0.1.3 PARAM_installer_sha256="$digest" bash "$tmp/provision.sh" >"$tmp/out" 2>&1 || code=$?
check "guest provisioning installs selected release" 0 "guest installed v0.1.3 checksums=$checksums_digest base=https://mirror.example/tego/releases/download" "curl https://mirror.example/tego/releases/download/v0.1.3/install.sh"
absent "pinned guest never fetches latest" "releases/latest"
: >"$tmp/log"; code=0
env -i PATH="$bin:/usr/bin:/bin:$guest_tools" HOME="$tmp/guest" TMPDIR="$tmp" FAKE_LOG="$tmp/log" FAKE_CORRUPT_INSTALLER=1 \
	PARAM_release_base=https://mirror.example/tego/releases/download PARAM_checksums_sha256="$checksums_digest" PARAM_tego_version=v0.1.3 PARAM_installer_sha256="$digest" bash "$tmp/provision.sh" >"$tmp/out" 2>&1 || code=$?
check "guest refuses changed installer" 1 "FAILED"
absent "changed guest installer never executes" "guest installed"

# Run only the generated shell command, with every external VM, SSH and browser call replaced.
cat >"$bin/lsof" <<'EOF'
#!/bin/sh
echo "lsof $*" >>"$FAKE_LOG"
case "$*" in *"-iTCP:${FAKE_PORT:-8484}"*) ;; *) exit 1 ;; esac
[ "${FAKE_LISTENER:-}" != none ] || [ -f "$FAKE_LOG.tunnel" ] || exit 1
case "$*" in
	*-Fc*) echo cssh ;;
	*-Fp*) echo "p${FAKE_PID:-4321}" ;;
	*-Fn*) echo "n${FAKE_BIND:-127.0.0.1:${FAKE_PORT:-8484}}" ;;
esac
EOF
# Emulate macOS stat, including lookup failures. Overrides apply to the original
# VM socket only; other fixture paths have the caller's metadata.
cat >"$bin/stat" <<'EOF'
#!/bin/sh
[ "$1" = -f ] || exit 1
format=$2
path=$3
[ "${FAKE_DIR_STAT_FAIL:-}" != 1 ] || [ "$path" != "$HOME/.lima/tego" ] || exit 1
if [ -x /usr/bin/sw_vers ]; then
	case "$path:$format" in
		"$HOME/.lima/tego:%u") [ -n "${FAKE_DIR_UID:-}" ] || exec /usr/bin/stat "$@" ;;
		"$HOME/.lima/tego:%Lp") [ -n "${FAKE_DIR_MODE:-}${FAKE_DIR_STAT_FAIL:-}" ] || exec /usr/bin/stat "$@" ;;
		"$HOME/.lima/tego/tego-dashboard.sock:"*) [ -n "${FAKE_SOCKET_UID:-}" ] || exec /usr/bin/stat "$@" ;;
		*) exec /usr/bin/stat "$@" ;;
	esac
fi
case "$path" in
	"$HOME/.lima/tego")
		[ "${FAKE_DIR_STAT_FAIL:-}" != 1 ] || exit 1
		case "$format" in %u) echo "${FAKE_DIR_UID:-$(id -u)}" ;; %Lp) echo "${FAKE_DIR_MODE:-700}" ;; esac ;;
	"$HOME/.lima/tego/tego-dashboard.sock") echo "${FAKE_SOCKET_UID:-$(id -u)}" ;;
	*) case "$format" in %u) id -u ;; %Lp) echo 700 ;; esac ;;
esac
EOF
cat >"$bin/ps" <<'EOF'
#!/bin/sh
[ ! -f "$FAKE_LOG.tunnel" ] || { id -u; exit; }
[ "${FAKE_PS_FAIL:-}" != 1 ] || exit 1
printf '  %s\n' "${FAKE_PROCESS_UID:-$(id -u)}"
EOF
cat >"$bin/ssh" <<'EOF'
#!/bin/sh
echo "ssh $*" >>"$FAKE_LOG"
case "$*" in
	*'ClearAllForwardings=yes'*) exit 255 ;;
	*'-O check'*)
		{ [ "${FAKE_STALE:-}" != 1 ] && [ "${FAKE_LISTENER:-}" != none ]; } || [ -f "$FAKE_LOG.tunnel" ] || exit 255
		echo 'Master running (pid=4321)' >&2; exit 0 ;;
esac
[ "${FAKE_SSH_FAIL:-}" != 1 ] || exit 255
# Record the socket path so the next invocation can find this same master.
while [ "$#" -gt 0 ]; do
	if [ "$1" = -S ]; then
		[ ! -e "$2" ] || exit 255
		printf 'new master\n' >"$2"
		printf '%s\n' "$2" >"$FAKE_LOG.tunnel"
		break
	fi
	shift
done
EOF
cat >"$bin/open" <<'EOF'
#!/bin/sh
echo "open $*" >>"$FAKE_LOG"
[ "${FAKE_OPEN_FAIL:-}" != 1 ]
EOF
chmod +x "$bin/lsof" "$bin/ssh" "$bin/open" "$bin/stat" "$bin/ps"
shim_call() {
	shim_command=dashboard
	for kv in "$@"; do
		case "$kv" in SHIM_COMMAND=*) shim_command=${kv#*=} ;; esac
	done
	code=0
	env -i HOME="$tmp" TMPDIR="$tmp/shim-tmp" PATH="$bin:/usr/bin:/bin" FAKE_VM=Running FAKE_LOG="$tmp/log" "$@" \
		sh "$tmp/.local/bin/tego" "$shim_command" >"$tmp/out" 2>&1 || code=$?
	if [ -n "$(find "$tmp/shim-tmp" -mindepth 1 -print)" ]; then
		echo 'FAIL tunnel left files in TMPDIR'; fails=$((fails + 1))
	fi
}
shim_run() {
	: >"$tmp/log"; rm -f "$tmp/log.tunnel"
	mkdir -p "$tmp/.lima/tego" "$tmp/shim-tmp"
	chmod 700 "$tmp/.lima/tego"
	rm -f "$tmp/.lima/tego/tego-dashboard.sock"
	# Socket contents stand in for the old and replacement masters.
	printf 'old master\n' >"$tmp/.lima/tego/tego-dashboard.sock"
	shim_call "$@"
}
shim_run FAKE_LISTENER=none FAKE_SSH_FAIL=1
check "failed SSH forwarding refuses browser" 1 "dashboard tunnel is not up"
absent "failed SSH forwarding never opens browser" "open http"
shim_run SHIM_COMMAND=start FAKE_LISTENER=none FAKE_SSH_FAIL=1
check "start enters project shell after tunnel failure" 0 "could not open the dashboard at http://127.0.0.1:8484/?t=test. Run tego dashboard to try again." "last-project"
[ "$(wc -l <"$tmp/out")" -eq 1 ] || { echo 'FAIL start tunnel failure: expected one line'; fails=$((fails + 1)); }
shim_run SHIM_COMMAND=setup FAKE_OPEN_FAIL=1
check "setup enters project shell after browser failure" 0 "Run tego dashboard to try again" "last-project"
shim_run SHIM_COMMAND=start FAKE_NO_URL=1
check "M5 start without link says dashboard is not running" 0 "tego: the dashboard is not running. Run tego dashboard to start it." "last-project"
if grep -qF 'http://' "$tmp/out"; then
	echo 'FAIL M5 missing link names an address'; fails=$((fails + 1))
fi
shim_run SHIM_COMMAND=setup FAKE_NO_URL=1
check "M5 setup without link says dashboard is not running" 0 "tego: the dashboard is not running. Run tego dashboard to start it." "last-project"
if grep -qF 'http://' "$tmp/out"; then
	echo 'FAIL M5 setup names an address'; fails=$((fails + 1))
fi
shim_run SHIM_COMMAND=start FAKE_GUIDE_STATUS=37
check "failed guide keeps its exit status" 37
absent "failed guide opens no project shell" "last-project"
shim_run SHIM_COMMAND=start FAKE_LISTENER=none FAKE_SSH_FAIL=1
absent "start never opens browser on tunnel failure" "open http"
shim_run FAKE_VM_DIR_FAIL=1 FAKE_LISTENER=none
check "missing VM SSH metadata fails clearly" 1 "dashboard tunnel is not up"
absent "missing VM metadata never opens browser" "open http"
shim_run FAKE_LISTENER=ssh FAKE_PID=9999
check "unrelated SSH listener is refused" 1 "dashboard tunnel is not up"
absent "unrelated listener never opens browser" "open http"
shim_run FAKE_LISTENER=none
check "new tunnel binds loopback and confirms forwarding" 0 "-o ExitOnForwardFailure=yes" \
	"-L 127.0.0.1:8484:127.0.0.1:8484" "tego-dashboard.sock" "open http"
: >"$tmp/log"; rm -f "$tmp/log.tunnel" "$tmp/.lima/tego/tego-dashboard.sock"
shim_call FAKE_LISTENER=none
check "missing socket starts a confirmed tunnel at the usual path" 0 "-L 127.0.0.1:8484:127.0.0.1:8484" "open http"
shim_run FAKE_LISTENER=ssh
check "own VM tunnel can be reused" 0 "-O check lima-tego" "open http"
absent "own VM tunnel is reused without a second forward" "-L "
# A non-answering owned master is replaced at the stable name, then reused.
shim_run FAKE_LISTENER=none FAKE_STALE=1
check "leftover socket is replaced and confirmed" 0 "-L 127.0.0.1:8484:127.0.0.1:8484" "open http"
control="$tmp/.lima/tego/tego-dashboard.sock"
if [ ! -f "$tmp/log.tunnel" ] || [ "$(cat "$tmp/log.tunnel")" != "$control" ] || [ "$(cat "$control")" != 'new master' ]; then
	echo 'FAIL leftover socket: replacement did not use the stable path'; fails=$((fails + 1))
fi
: >"$tmp/log"
shim_call FAKE_LISTENER=ssh FAKE_STALE=1
check "next invocation reuses the replacement master" 0 "-O check lima-tego" "open http"
absent "replacement master needs no second forward" "-L "
other_uid=$(($(id -u) + 1))
for listener in none ssh; do
	for unsafe in "FAKE_DIR_UID=$other_uid" FAKE_DIR_MODE=770 FAKE_DIR_MODE=707 FAKE_DIR_STAT_FAIL=1; do
		shim_run "FAKE_LISTENER=$listener" "$unsafe"
		check "unsafe socket folder ($unsafe, $listener) is refused" 1 "$tmp/.lima/tego" "it must belong to you" "Fix its ownership and write permissions"
		absent "unsafe folder never starts a master" "-M -f -N"
		absent "unsafe folder never opens browser" "open http"
		[ "$(wc -l <"$tmp/out")" -eq 1 ] || { echo 'FAIL unsafe folder: expected one line'; fails=$((fails + 1)); }
	done
	shim_run "FAKE_LISTENER=$listener" "FAKE_SOCKET_UID=$other_uid"
	check "foreign socket ($listener) is refused" 1 "$control" "move it away yourself"
	absent "foreign socket never starts a master" "-M -f -N"
	absent "foreign socket never opens browser" "open http"
	[ "$(cat "$control")" = 'old master' ] || { echo 'FAIL foreign socket changed'; fails=$((fails + 1)); }
	[ "$(wc -l <"$tmp/out")" -eq 1 ] || { echo 'FAIL foreign socket: expected one line'; fails=$((fails + 1)); }
	printf 'keep\n' >"$tmp/socket-target"
	rm -f "$control"
	ln -s "$tmp/socket-target" "$control"
	: >"$tmp/log"; rm -f "$tmp/log.tunnel"
	shim_call "FAKE_LISTENER=$listener"
	check "linked socket ($listener) is refused" 1 "$control" "move it away yourself"
	absent "linked socket never starts a master" "-M -f -N"
	absent "linked socket never opens browser" "open http"
	if [ ! -L "$control" ] || [ "$(cat "$tmp/socket-target")" != keep ]; then
		echo 'FAIL linked socket or target changed'; fails=$((fails + 1))
	fi
	[ "$(wc -l <"$tmp/out")" -eq 1 ] || { echo 'FAIL linked socket: expected one line'; fails=$((fails + 1)); }
done
for unsafe in "FAKE_PROCESS_UID=$other_uid" FAKE_PS_FAIL=1; do
	shim_run FAKE_LISTENER=ssh "$unsafe"
	check "unsafe process metadata ($unsafe) refuses occupied port" 1 "dashboard tunnel is not up"
	absent "unsafe process never starts a master" "-M -f -N"
	absent "unsafe process never opens browser" "open http"
	shim_run FAKE_LISTENER=none FAKE_STALE=1 "$unsafe"
	check "stale master with unavailable process metadata ($unsafe) is replaced" 0 "-L 127.0.0.1:8484:127.0.0.1:8484" "open http"
done
shim_run FAKE_LISTENER=ssh FAKE_BIND='*:8484'
check "wildcard listener is not accepted" 1 "dashboard tunnel is not up"
absent "wildcard listener never opens browser" "open http"

shim_run FAKE_URL='http://127.0.0.1:8599/?t=other' FAKE_PORT=8599 FAKE_LISTENER=none
check "engine link selects dashboard forward and listener port" 0 "-L 127.0.0.1:8599:127.0.0.1:8599" \
    "-iTCP:8599" "tego-dashboard-8599.sock" "open http://127.0.0.1:8599/?t=other"
shim_run FAKE_URL='http://127.0.0.1:8599/?t=other' FAKE_PORT=8599 FAKE_LISTENER=ssh FAKE_PID=9999
check "M2 foreign listener explains Lima forwarding on nondefault port" 1 "Lima forwards the VM's ports to the Mac itself" "Tego's own tunnel is set up for 8484" "Put the dashboard back on 8484" "limactl edit tego" "- guestPort: 8599" "ignore: true"
absent "foreign selected-port listener never opens browser" "open http"

: >"$tmp/log"; code=0
# These literal arguments must be rejected without being executed or entering the VM shell.
env -i HOME="$tmp" PATH="$bin:/usr/bin:/bin" FAKE_VM=Running FAKE_LOG="$tmp/log" \
    sh "$tmp/.local/bin/tego" shell 'printf "unexpected"' '; touch should-not-exist' >"$tmp/out" 2>&1 || code=$?
check "shell rejects trailing arguments with usage" 2 "usage: tego shell (no arguments)"
absent "shell arguments never reach VM" "limactl shell"
for state in Stopped missing; do
	: >"$tmp/log"; code=0
	env -i HOME="$tmp" PATH="$bin:/usr/bin:/bin" FAKE_VM="$state" FAKE_LOG="$tmp/log" \
		sh "$tmp/.local/bin/tego" shell extra >"$tmp/out" 2>&1 || code=$?
	check "M6 shell usage before $state VM work" 2 "usage: tego shell (no arguments)"
	absent "M6 invalid shell never starts $state VM" "limactl start"
	absent "M6 invalid shell never enters $state VM" "limactl shell"
	[ "$(wc -l <"$tmp/out")" -eq 1 ] || { echo "FAIL M6 $state: expected only usage"; fails=$((fails + 1)); }
done
shim_run SHIM_COMMAND=shell
check "shell without arguments still enters project" 0 "last-project" "Type exit to go back to your Mac"

shim_run FAKE_NO_URL=1
check "missing dashboard link gives a retry and log command" 1 "The dashboard did not start. Run tego dashboard to try again." "cat ~/.tego/dashboard.log"

# Plant the former predictable log path: installation must leave its target unchanged.
echo keep >"$tmp/outside"
rm -f "$tmp/tego-install.log"
ln -s "$tmp/outside" "$tmp/tego-install.log"
run loglink LIMA=1 FAKE_VM=Running TEGO_YES=1
check "installer log stays in private temporary directory" 0
[ "$(cat "$tmp/outside")" = keep ] || { echo 'FAIL installer followed log link'; fails=$((fails + 1)); }

# Every exit after saving settings restores them, even before a VM exists.
bin="$tmp/terminal/bin"; stubs "$bin"
for failure in macos brew lima INT TERM saveTERM restore; do
    : >"$tmp/log"
    rm -f "$bin/limactl"
    case "$failure" in
        macos) tty_run '' TEGO_YES=1 FAKE_MACOS=12.6; want=3 ;;
        brew) tty_run '' TEGO_YES=1 FAKE_BREW_FAIL=1; want=2 ;;
        lima)
            cp "$bin.lima/limactl" "$bin/limactl"
            tty_run '' TEGO_YES=1 FAKE_VM=Stopped FAKE_START_FAIL=1; want=8 ;;
        INT|TERM)
            tty_run '' TEGO_YES=1 "FAKE_BREW_SIGNAL=$failure"
            want=130; [ "$failure" != TERM ] || want=143 ;;
        saveTERM) tty_run '' TEGO_YES=1 FAKE_SAVE_SIGNAL=TERM; want=143 ;;
        restore)
            cp "$bin.lima/limactl" "$bin/limactl"
            tty_run '' TEGO_YES=1 FAKE_GUEST_VERSION=v0.1.3 FAKE_RESTORE_FAIL=1; want=0 ;;
    esac
    check "terminal settings restored after $failure, preserving exit status" "$want" "stty saved-terminal-settings"
done

rm -f "$tmp/.local/bin/tego"
: >"$tmp/log"
tty_run n FAKE_GUEST_VERSION=v0.1.3
check "declining Mac command explains how to open the VM" 0 "Skipped adding the Mac command. To open the VM, run: limactl shell tego"

# The VM has no Mac filesystem shares; provisioning and the shim use only VM paths.
if ! grep -qx 'mounts: \[\]' "$here/../examples/lima/tego.yaml"; then
	echo "FAIL template: Mac folders must not be mounted by default"
	fails=$((fails + 1))
fi
[ "$fails" -eq 0 ] || { echo "install_mac_test: $fails failed"; exit 1; }
echo "install_mac_test: all passed"
