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
[ "\${FAKE_BREW_FAIL:-}" != 1 ] || { echo "brew failure details"; exit 1; }
cp "$b.lima/limactl" "$b/limactl"
EOF
	cat >"$b.lima/limactl" <<'EOF'
#!/bin/sh
case "$1" in
	--version) echo "limactl version ${FAKE_LIMA:-2.3.0}" ;;
	list) [ -n "${FAKE_VM:-}" ] && echo "$FAKE_VM" || exit 1 ;;
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
		done ;;
	*) echo "limactl $*" >>"$FAKE_LOG" ;;
esac
EOF
	# All downloads stay in this case's release fixture; no network is used.
	cp "$here/../examples/lima/tego.yaml" "$b/tego.yaml"
	printf '#!/bin/sh\necho "guest installed $TEGO_VERSION" >>"$FAKE_LOG"\n' >"$b/install.sh"
	(cd "$b" && sha256sum tego.yaml install.sh) >"$b/checksums"
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
b=${0%/*}
case "$url" in
	*/latest) printf '{"tag_name":"v0.1.3"}\n' >"$out" ;;
	*/tego.yaml) cp "$b/tego.yaml" "$out"; [ "${FAKE_CORRUPT:-}" != 1 ] || echo corrupt >>"$out" ;;
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
[ "${FAKE_VERIFY_FAIL:-}" != 1 ]
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

latest="https://github.com/Attention-Span-AI/Tego/releases/download/v0.1.3/tego.yaml"

run fresh TEGO_YES=1
check "fresh Mac: installs Lima, sets up the VM, adds tego" 0 "✗ Lima isn't installed" "brew install lima" \
	"limactl start --tty=false --name=tego --mount-none --param=tego_version=v0.1.3" "verified local template in private directory" "✓ Lima 2.3.0" "✓ Tego's VM is ready" "✓ tego command added" \
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
	"curl $latest" "--param=tego_version=v0.1.3" "verified local template in private directory"

run nobrew BREW=0
check "no Homebrew: says where to get Lima" 2 "✗ Lima isn't installed" "https://lima-vm.io/docs/installation/"

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
	check "no terminal: prints the commands, runs none" 2 "To finish, run:" "brew install lima" \
		"releases/latest/download/install.sh | sh" "Then run this installer again."
	if [ -s "$tmp/log" ]; then
		echo "FAIL no terminal: ran commands it should only print:"
		sed 's/^/    /' "$tmp/log"
		fails=$((fails + 1))
	fi
fi

run normalized LIMA=1 TEGO_YES=1 TEGO_VERSION=0.1.3 TEGO_VERIFY=gh
check "normalized tag binds template provenance and guest version" 0 "curl $latest" \
	"--source-ref refs/tags/v0.1.3" "--param=tego_version=v0.1.3"
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
check "existing VM explains separate guest upgrade" 0 "updates only the Mac command" "tego shell" "TEGO_VERSION=v0.1.3 sh"

# Execute only the extracted provisioning shell against the same download stand-ins.
# The fixture installer records its selected version; it never runs a Tego binary.
awk '/^    script: \|/ && !seen {seen=1; inside=1; next} /^probes:/ {inside=0} inside {sub(/^      /, ""); print}' \
	"$here/../examples/lima/tego.yaml" >"$tmp/provision.sh"
bin="$tmp/normalized/bin"
digest=$(sha256sum "$bin/install.sh" | awk '{print $1}')
: >"$tmp/log"; code=0
env -i PATH="$bin:/usr/bin:/bin" HOME="$tmp/guest" TMPDIR="$tmp" FAKE_LOG="$tmp/log" \
	PARAM_tego_version=v0.1.3 PARAM_installer_sha256="$digest" bash "$tmp/provision.sh" >"$tmp/out" 2>&1 || code=$?
check "guest provisioning installs selected release" 0 "guest installed v0.1.3" "releases/download/v0.1.3/install.sh"
absent "pinned guest never fetches latest" "releases/latest"
: >"$tmp/log"; code=0
env -i PATH="$bin:/usr/bin:/bin" HOME="$tmp/guest" TMPDIR="$tmp" FAKE_LOG="$tmp/log" FAKE_CORRUPT_INSTALLER=1 \
	PARAM_tego_version=v0.1.3 PARAM_installer_sha256="$digest" bash "$tmp/provision.sh" >"$tmp/out" 2>&1 || code=$?
check "guest refuses changed installer" 1 "FAILED"
absent "changed guest installer never executes" "guest installed"

# Plant the former predictable log path: installation must leave its target unchanged.
echo keep >"$tmp/outside"
rm -f "$tmp/tego-install.log"
ln -s "$tmp/outside" "$tmp/tego-install.log"
run loglink LIMA=1 FAKE_VM=Running TEGO_YES=1
check "installer log stays in private temporary directory" 0
[ "$(cat "$tmp/outside")" = keep ] || { echo 'FAIL installer followed log link'; fails=$((fails + 1)); }

# The VM has no Mac filesystem shares; provisioning and the shim use only VM paths.
if ! grep -qx 'mounts: \[\]' "$here/../examples/lima/tego.yaml"; then
	echo "FAIL template: Mac folders must not be mounted by default"
	fails=$((fails + 1))
fi
[ "$fails" -eq 0 ] || { echo "install_mac_test: $fails failed"; exit 1; }
echo "install_mac_test: all passed"
