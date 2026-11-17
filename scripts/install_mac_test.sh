#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests install.sh's macOS path (mac_setup) with stand-ins for uname, sw_vers, df, brew and limactl, so it runs on
# any machine: each case checks what the script prints, which commands it runs, and its exit code. Nothing real is
# installed or started.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="$here/install.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/install-mac-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
fails=0

# stubs FAKEBIN: writes the stand-ins. limactl goes in its own folder, which a case puts on PATH when Lima is
# "installed"; brew install/upgrade copies it into FAKEBIN, as a real install would put it on PATH.
# shellcheck disable=SC2016 # the stand-ins are written as is, for their own shell to expand
stubs() {
	b=$1
	mkdir -p "$b" "$b.lima"
	printf '#!/bin/sh\n[ "$1" = -s ] && echo Darwin || echo arm64\n' >"$b/uname"
	printf '#!/bin/sh\necho "${FAKE_MACOS:-15.1}"\n' >"$b/sw_vers"
	printf '#!/bin/sh\necho "Filesystem 1K-blocks Used Available"\necho "/dev/x 1 1 ${FAKE_FREE_KB:-20971520}"\n' >"$b/df"
	cat >"$b/brew" <<EOF
#!/bin/sh
echo "brew \$*" >>"\$FAKE_LOG"
cp "$b.lima/limactl" "$b/limactl"
EOF
	cat >"$b.lima/limactl" <<'EOF'
#!/bin/sh
case "$1" in
	--version) echo "limactl version ${FAKE_LIMA:-2.3.0}" ;;
	list) [ -n "${FAKE_VM:-}" ] && echo "$FAKE_VM" || exit 1 ;;
	*) echo "limactl $*" >>"$FAKE_LOG" ;;
esac
EOF
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
		esac
	done
	code=0
	env -i HOME="$tmp" TMPDIR="$tmp" SHELL=/bin/zsh PATH="$path" FAKE_LOG="$tmp/log" "$@" sh "$script" >"$tmp/out" 2>&1 </dev/null || code=$?
}

latest="https://github.com/Attention-Span-AI/Tego/releases/latest/download/tego.yaml"

run fresh TEGO_YES=1
check "fresh Mac: installs Lima, sets up the VM, adds tego" 0 "✗ Lima isn't installed" "brew install lima" \
	"limactl start --tty=false --name=tego --mount-none $latest" "✓ Lima 2.3.0" "✓ Tego's VM is ready" "✓ tego command added" \
	"Next steps" "Run   exec zsh -l   (or open a new terminal window), then   tego start"
[ -x "$tmp/.local/bin/tego" ] || { echo "FAIL fresh Mac: no tego command in ~/.local/bin"; fails=$((fails + 1)); }
grep -q 'added by the Tego installer' "$tmp/.zshrc" 2>/dev/null || { echo "FAIL fresh Mac: PATH line not added to ~/.zshrc"; fails=$((fails + 1)); }
absent "fresh Mac: hides Lima's own output" "INFO["

# bash: the PATH line goes in the profile a login bash already reads, never a new .bash_profile that would hide it
mkdir -p "$tmp/bashhome" && echo '# mine' >"$tmp/bashhome/.profile"
c=bashprofile; b2="$tmp/$c/bin"; stubs "$b2"; cp "$b2.lima/limactl" "$b2/limactl"; : >"$tmp/log"; code=0
env -i HOME="$tmp/bashhome" TMPDIR="$tmp" SHELL=/bin/bash PATH="$b2:/usr/bin:/bin" FAKE_LOG="$tmp/log" FAKE_VM=Running TEGO_YES=1 \
	sh "$script" >"$tmp/out" 2>&1 </dev/null || code=$?
check "bash with only a .profile: the line goes there" 0 "Run   exec bash -l   (or open a new terminal window)"
grep -q 'added by the Tego installer' "$tmp/bashhome/.profile" || { echo "FAIL bash: PATH line not in .profile"; fails=$((fails + 1)); }
[ ! -e "$tmp/bashhome/.bash_profile" ] || { echo "FAIL bash: a .bash_profile now hides .profile"; fails=$((fails + 1)); }

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
	"limactl start --tty=false --name=tego --mount-none https://github.com/Attention-Span-AI/Tego/releases/download/v0.1.3/tego.yaml"

run nobrew BREW=0
check "no Homebrew: says where to get Lima" 2 "✗ Lima isn't installed" "https://lima-vm.io/docs/installation/"

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
	check "no terminal: prints the commands, runs none" 2 "To finish, run:" "brew install lima" \
		"limactl start --name=tego --mount-none $latest" "Then run this installer again."
	if [ -s "$tmp/log" ]; then
		echo "FAIL no terminal: ran commands it should only print:"
		sed 's/^/    /' "$tmp/log"
		fails=$((fails + 1))
	fi
fi

# The VM has no Mac filesystem shares; provisioning and the shim use only VM paths.
if ! grep -qx 'mounts: \[\]' "$here/../examples/lima/tego.yaml"; then
	echo "FAIL template: Mac folders must not be mounted by default"
	fails=$((fails + 1))
fi
[ "$fails" -eq 0 ] || { echo "install_mac_test: $fails failed"; exit 1; }
echo "install_mac_test: all passed"
