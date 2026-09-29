#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests two things root-suites.sh decides before a suite runs.
#
# 1. Its copy of the tree into the guests' source directory: a copy that fails must end the run there, before anything
#    is built, rather than run the suites against a tree missing files. tar is a stand-in that fails, and go one that
#    answers `go list -m` and logs every other call; the run must exit non-zero having asked go for nothing else.
#
# 2. The kernel-matrix row (TEGO_VM_ROW, ADR 0017's `where.row` and enforce/landlock's ABI floor of fedora-7.2): a
#    name that is not a row, a doctor-only row, a row without a guest, or a kernel set by hand for another row is a
#    usage error before anything is built, since a suite that ran on one kernel under another's name would be judged
#    by the wrong row's expectations; and a row the run accepts reaches every guest, as its kernel and by name in its
#    environment. The second part runs root-suites.sh from a copy of test/vm in a tree of stand-ins (a go that
#    "builds" by writing a file, a kvm-run.sh that records its arguments and the kernel it was given), as
#    matrix_test.sh runs matrix.sh. Nothing boots and no network is used.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-root-suites-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

fail() {
	echo "FAIL $*" >&2
	exit 1
}

# 1. A failed copy of the tree ends the run before anything is built.
mkdir "$tmp/bin"
cat >"$tmp/bin/tar" <<'EOF'
#!/bin/sh
cat >/dev/null
exit 2
EOF
cat >"$tmp/bin/go" <<EOF
#!/bin/sh
if [ "\$1 \$2" = "list -m" ]; then echo github.com/attention-span-ai/tego; exit 0; fi
echo "\$*" >>"$tmp/go.log"
exit 0
EOF
chmod +x "$tmp/bin/tar" "$tmp/bin/go"

status=0
PATH="$tmp/bin:$PATH" GO="$tmp/bin/go" VM_OUT="$tmp/out" VM_BPF=no VM_HOST=kvm \
	"$here/root-suites.sh" internal/bpf >"$tmp/run.log" 2>&1 || status=$?
if [ "$status" = 0 ]; then
	echo "FAIL root-suites.sh went on after its copy of the tree failed" >&2
	cat "$tmp/run.log" >&2
	exit 1
fi
if [ -s "$tmp/go.log" ]; then
	echo "FAIL root-suites.sh built after its copy of the tree failed:" >&2
	cat "$tmp/go.log" >&2
	exit 1
fi
grep -q 'copying the tree' "$tmp/run.log" || { echo "FAIL no message names the failed copy" >&2; cat "$tmp/run.log" >&2; exit 1; }

# TEGO_CONFORMANCE_REQUIRE per boot (conformance-require.sh): every root boot requires tier cgroup and fmod_ret, and
# a boot with bpf among its LSMs the lsm mode and tier bpflsm too, when the objects are built.
req_fail=0
check_require() {
	got=$(bash -c '. "$1/conformance-require.sh" && conformance_require "$2" "$3" "$4" "$5"' check "$here" "$1" "$2" "$3" "$4")
	if [ "$got" != "$5" ]; then
		echo "FAIL conformance_require $1 $2 '$3' '$4' = '$got', want '$5'" >&2
		req_fail=1
	fi
}
check_require kvm on "lockdown,capability,landlock,yama,apparmor,bpf" "" cgroup,fmod_ret,lsm,bpflsm # VM_BOOTS=both's lsm-bpf
check_require kvm on "lockdown,capability,landlock,yama,apparmor" "" cgroup,fmod_ret             # its default-lsm boot
check_require kvm on "" "" cgroup,fmod_ret,lsm,bpflsm                                          # one guest: the host's list plus bpf
check_require kvm on kernel "" cgroup,fmod_ret                                                 # the kernel's own list: unknown
check_require kvm off "landlock,bpf" "" cgroup,fmod_ret                                        # no objects: no plane axis to require
check_require kvm on "landlock,bpffs" "" cgroup,fmod_ret                                       # a name that only starts with bpf
check_require sudo on "" "lockdown,capability,landlock,yama,apparmor" cgroup,fmod_ret          # a hosted runner
check_require sudo on "lockdown,landlock,bpf" "landlock,yama,bpf" cgroup,fmod_ret,lsm,bpflsm    # sudo reads the host's own list
check_require sudo on "landlock,bpf" "landlock" cgroup,fmod_ret
[ "$req_fail" = 0 ] || exit 1
# The suites get the per-boot list, in both host modes, never a fixed one.
if grep -nF 'TEGO_CONFORMANCE_REQUIRE=cgroup' "$here/root-suites.sh" >&2; then
	echo "FAIL root-suites.sh passes a fixed TEGO_CONFORMANCE_REQUIRE instead of conformance_require's" >&2
	exit 1
fi
# shellcheck disable=SC2016 # root-suites.sh's own text, expansions and all
[ "$(grep -cF 'TEGO_CONFORMANCE_REQUIRE=$conformance_required" ' "$here/root-suites.sh")" = 2 ] ||
	{ echo "FAIL root-suites.sh does not pass conformance_require's list to both host modes" >&2; exit 1; }
# The conformance budget, report and matrix row reach the suite in both host modes when set (a guest's environment
# and sudo's are both fresh), and only those.
for v in TEGO_CONFORMANCE_BUDGET TEGO_CONFORMANCE_REPORT TEGO_VM_ROW; do
	grep -qF "$v" "$here/root-suites.sh" || { echo "FAIL root-suites.sh does not pass $v through" >&2; exit 1; }
done
# shellcheck disable=SC2016 # root-suites.sh's own text, expansions and all
[ "$(grep -cF '"${conformance_env[@]+"${conformance_env[@]}"}"' "$here/root-suites.sh")" = 1 ] &&
	[ "$(grep -cF '"${conformance_env_args[@]+"${conformance_env_args[@]}"}"' "$here/root-suites.sh")" = 1 ] ||
	{ echo "FAIL root-suites.sh does not pass the conformance settings to both host modes" >&2; exit 1; }

# 2a. A row the run refuses is a usage error (exit 2) with its reason, and nothing was built. The real script runs here,
# beside the real fetch-kernel.py, which answers the questions about rows without a network.
refused_row() {
	name=$1 want=$2
	shift 2
	: >"$tmp/go.log"
	rc=0
	env "$@" PATH="$tmp/bin:$PATH" GO="$tmp/bin/go" VM_OUT="$tmp/out" VM_BPF=no \
		"$here/root-suites.sh" internal/bpf >"$tmp/run.log" 2>&1 || rc=$?
	[ "$rc" = 2 ] || fail "$name: exited $rc, want 2: $(cat "$tmp/run.log")"
	grep -qF -- "$want" "$tmp/run.log" || fail "$name: the message lacks \"$want\": $(cat "$tmp/run.log")"
	[ ! -s "$tmp/go.log" ] || fail "$name: built after the row was refused: $(cat "$tmp/go.log")"
}
refused_row "a name that is not a row" "is not a kernel-matrix row" TEGO_VM_ROW=no-such-row VM_HOST=kvm
refused_row "a doctor-only row" "doctor-only" TEGO_VM_ROW=ubuntu-22.04 VM_HOST=kvm
refused_row "a row on the host's own run" "needs VM_HOST=kvm" TEGO_VM_ROW=fedora-7.2 VM_HOST=sudo
refused_row "a kernel set by hand for another row" "says another kernel" TEGO_VM_ROW=fedora-7.2 TEGO_VM_KERNEL=matrix-rhel-9 VM_HOST=kvm

# 2b. A row the run accepts reaches every guest. The tree of stand-ins: root-suites.sh from a copy of test/vm, with the
# files it reads beside it, a go that writes the file it is asked to build, a tree-files.sh that names one file, a skipgate
# that passes, and a kvm-run.sh that records its arguments, the kernel it was given and the row it was told, then reports
# a guest that ran. The suites' own verdicts are not what is judged here, so the script's exit is not either.
repo="$tmp/repo"
mkdir -p "$repo/test/vm" "$repo/scripts" "$repo/internal/bpf" "$repo/internal/runtime/enforce/landlock" "$tmp/stub"
cp "$here/root-suites.sh" "$here/fwd-run.sh" "$here/suites.sh" "$here/summarize.py" "$here/bounded-run.sh" "$here/go-shim.sh" \
	"$here/root-skips.txt" "$here/root-must-pass.txt" "$here/fetch-kernel.py" "$here/kernel_auth.py" "$here/conformance-require.sh" "$repo/test/vm/"
cp -r "$here/keys" "$repo/test/vm/keys"
cat >"$repo/scripts/tree-files.sh" <<'EOF'
#!/bin/sh
printf 'x\0'
EOF
printf '#!/bin/sh\nexit 0\n' >"$repo/scripts/skipgate.sh"
: >"$repo/x"
cat >"$repo/test/vm/kvm-run.sh" <<'EOF'
#!/bin/sh
# The stand-in guest: it records one line per boot (the kernel it was given, then every argument), writes the console and
# the status the real one does, and reports that the command ran.
{ printf 'KERNEL=%s LSM=%s ' "${TEGO_VM_KERNEL:-unset}" "${TEGO_VM_LSM:-unset}"; printf '%s ' "$@" | tr '\n\t' '  '; echo; } >>"$STUB_BOOTS"
log="" status=""
while [ $# -gt 0 ]; do
	case "$1" in
	--log) log="$2"; shift 2 ;;
	--status) status="$2"; shift 2 ;;
	--file | --env | --cwd | --module | --timeout) shift 2 ;;
	--sudo) shift ;;
	--) break ;;
	*) shift ;;
	esac
done
echo "=== RUN   TestStandIn" >"$log"
echo "--- PASS: TestStandIn (0.00s)" >>"$log"
echo "guest 0" >"$status"
exit 0
EOF
chmod +x "$repo/test/vm/kvm-run.sh" "$repo/scripts/tree-files.sh" "$repo/scripts/skipgate.sh"
cat >"$tmp/stub/go" <<'EOF'
#!/bin/sh
# list -m names the module; build and test -c write the file they were asked for with -o; everything else says nothing.
case "$1 $2" in
"list -m") echo github.com/attention-span-ai/tego; exit 0 ;;
"tool test2json") cat; exit 0 ;;
esac
out=""
while [ $# -gt 0 ]; do
	[ "$1" != -o ] || out="$2"
	shift
done
[ -z "$out" ] || {
	# what it built records, when asked, its own path and the isolation it was given (part 3)
	printf '#!/bin/sh\n[ -z "${STUB_RUNS:-}" ] || echo "$0 config=${TEGO_CONFIG:-} anchor=${TEGO_TEST_CHAIN_ANCHOR:-} ownlog=${TEGO_TEST_OWN_LOG_HOME:-}" >>"$STUB_RUNS"\nexit 0\n' >"$out"
	chmod +x "$out"
}
exit 0
EOF
chmod +x "$tmp/stub/go"
# The stand-in sudo, for VM_HOST=sudo: it resets the environment as sudo does (only what its command line names reaches
# the command, and the stand-ins' own log), logs its command, and runs it.
cat >"$tmp/stub/sudo" <<'EOF'
#!/bin/sh
{ printf 'sudo '; printf '%s ' "$@" | tr '\n\t' '  '; echo; } >>"$STUB_SUDO"
exec env -i PATH="/usr/bin:/bin" STUB_RUNS="$STUB_RUNS" "$@"
EOF
chmod +x "$tmp/stub/sudo"

# run_stub runs the copy with the given variables and reports its boots in $tmp/boots.
run_stub() {
	: >"$tmp/boots"
	env -i PATH="$tmp/stub:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/stub/go" VM_OUT="$tmp/stubout" VM_BPF=no STUB_BOOTS="$tmp/boots" "$@" \
		"$repo/test/vm/root-suites.sh" internal/runtime/enforce/landlock >"$tmp/stub.log" 2>&1 || true
	[ -s "$tmp/boots" ] || fail "the stand-in tree booted nothing: $(tail -5 "$tmp/stub.log")"
}

# A row named, with its kernel named too (the script fetches the kernel itself only when none is named, which needs the
# network): every guest boots that kernel, and the suite's guest, the one whose tests read the row, is told its name.
run_stub VM_HOST=kvm TEGO_VM_ROW=fedora-7.2 TEGO_VM_KERNEL=matrix-fedora-7.2
if grep -qv 'KERNEL=matrix-fedora-7.2 ' "$tmp/boots"; then fail "a guest booted another kernel than the row's: $(cat "$tmp/boots")"; fi
grep -F -- "--cwd /src/internal/runtime/enforce/landlock" "$tmp/boots" | grep -qF -- "--env TEGO_VM_ROW=fedora-7.2" ||
	fail "the suite's guest was not told its row: $(cat "$tmp/boots")"

# With no row named, no guest is told one, and the kernel is whatever the caller set.
run_stub VM_HOST=kvm
if grep -qF -- "TEGO_VM_ROW" "$tmp/boots"; then fail "a guest was told a row the caller never named: $(cat "$tmp/boots")"; fi

# Modules: kvm-run.sh can fetch a module package for this host's own kernel only, so the default overlay and btrfs would end
# every guest of a row's distro kernel at exit 97. A row's guests load none unless VM_MODULES names some (even an empty
# VM_MODULES is a choice), and a run without a row, or on the host row, keeps the default.
run_stub VM_HOST=kvm TEGO_VM_ROW=fedora-7.2 TEGO_VM_KERNEL=matrix-fedora-7.2
if grep -qF -- "--module" "$tmp/boots"; then fail "a row's guest was asked for modules nobody can fetch for its kernel: $(cat "$tmp/boots")"; fi
run_stub VM_HOST=kvm TEGO_VM_ROW=fedora-7.2 TEGO_VM_KERNEL=matrix-fedora-7.2 VM_MODULES=overlay
grep -F -- "--cwd /src/internal/runtime/enforce/landlock" "$tmp/boots" | grep -qF -- "--module overlay " ||
	fail "a row's guest was not given the module the caller named: $(cat "$tmp/boots")"
run_stub VM_HOST=kvm
grep -F -- "--cwd /src/internal/runtime/enforce/landlock" "$tmp/boots" | grep -qF -- "--module overlay --module btrfs " ||
	fail "a run with no row lost the default modules: $(cat "$tmp/boots")"
run_stub VM_HOST=kvm TEGO_VM_ROW=host
grep -F -- "--cwd /src/internal/runtime/enforce/landlock" "$tmp/boots" | grep -qF -- "--module overlay --module btrfs " ||
	fail "the host row lost the default modules: $(cat "$tmp/boots")"

# VM_BOOTS names one boot, or both: a CI job whose bound holds one boot's suites (vm-matrix's tier-3 parts) runs that boot
# alone, with its results under VM_OUT/<boot> as with both. lsm-bpf adds bpf to the host's list, default-lsm leaves it out.
# (sysfs reports the file's size as 0, so its content is what says the list is there.)
host_lsm="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
if [ -n "$host_lsm" ]; then
	host_lsm="$(printf '%s\n' "$host_lsm" | tr ',' '\n' | grep -vx bpf | paste -sd, -)"
	for b in lsm-bpf default-lsm; do
		rm -rf "$tmp/stubout"
		run_stub VM_HOST=kvm VM_BOOTS=$b
		want="$host_lsm"
		[ "$b" = default-lsm ] || want="$host_lsm,bpf"
		if grep -qv -- "LSM=$want " "$tmp/boots"; then fail "VM_BOOTS=$b booted another lsm list than $want: $(cat "$tmp/boots")"; fi
		[ -d "$tmp/stubout/$b" ] || fail "VM_BOOTS=$b left no results under VM_OUT/$b: $(tail -5 "$tmp/stub.log")"
		other=lsm-bpf
		if [ "$b" = lsm-bpf ]; then other=default-lsm; fi
		[ ! -e "$tmp/stubout/$other" ] || fail "VM_BOOTS=$b also ran the $other boot"
	done
	rm -rf "$tmp/stubout"
	run_stub VM_HOST=kvm VM_BOOTS=both
	[ -d "$tmp/stubout/lsm-bpf" ] && [ -d "$tmp/stubout/default-lsm" ] || fail "VM_BOOTS=both did not run both boots: $(ls "$tmp/stubout")"
fi
: >"$tmp/boots"
rc=0
env -i PATH="$tmp/stub:$PATH" HOME="$tmp" VM_BOOTS=lsm "$repo/test/vm/root-suites.sh" >"$tmp/stub.log" 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "VM_BOOTS=lsm is no boot, and was not a usage error: $(tail -3 "$tmp/stub.log")"

# 3. VM_HOST=sudo runs `tego doctor` as root on this host, not in a guest (identity-config.md R27). On a machine nobody
# said is disposable it is the tegotesthooks build with a machine config, chain anchor and own-log home of the run's
# own, so that nothing reaches the invoking user's ~/.tego (a product build under sudo logs to SUDO_UID's
# ~/.tego/tego.log, and ignores the two test variables); with TEGO_DISPOSABLE_HOST set (a CI runner) it is the
# product build, run as a root user would run it.
run_sudo_stub() {
	: >"$tmp/runs"
	: >"$tmp/sudo.log"
	rm -rf "$tmp/sudoout"
	env -i PATH="$tmp/stub:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/stub/go" VM_OUT="$tmp/sudoout" VM_BPF=no VM_HOST=sudo \
		STUB_RUNS="$tmp/runs" STUB_SUDO="$tmp/sudo.log" "$@" \
		"$repo/test/vm/root-suites.sh" internal/runtime/enforce/landlock >"$tmp/stub.log" 2>&1 || true
	grep -F "/prebuilt/tego" "$tmp/runs" >"$tmp/doctor.runs" || fail "VM_HOST=sudo ran no tego doctor: $(tail -5 "$tmp/stub.log")"
}
run_sudo_stub
grep -vqF "$tmp/sudoout/prebuilt/tego.testhooks config=" "$tmp/doctor.runs" &&
	fail "VM_HOST=sudo on a machine not said to be disposable ran another doctor than the tegotesthooks build: $(cat "$tmp/doctor.runs")"
while read -r _ config anchor ownlog; do
	config=${config#config=} anchor=${anchor#anchor=} ownlog=${ownlog#ownlog=}
	for v in "$config" "$anchor" "$ownlog"; do
		case "$v" in "$tmp/sudoout/"?*) ;; *) fail "the host's doctor was given an isolation outside the run's own directory: '$v'" ;; esac
	done
	[ -f "$config" ] || fail "the host's doctor's TEGO_CONFIG names no file: $config"
	grep -q "^ledger_root: $tmp/sudoout/" "$config" || fail "the host's doctor's machine config names no ledger_root of its own: $(cat "$config")"
done <"$tmp/doctor.runs"
grep -F "/prebuilt/tego.testhooks" "$tmp/sudo.log" | grep -qF "env TEGO_CONFIG=" ||
	fail "the host's doctor did not get its isolation on sudo's command line (sudo resets the environment): $(cat "$tmp/sudo.log")"
grep -qF "tegotesthooks build" "$tmp/stub.log" || fail "the console does not say which doctor build ran on the host: $(grep -F '== tego-doctor' "$tmp/stub.log")"
run_sudo_stub TEGO_DISPOSABLE_HOST=ci
grep -vqF "$tmp/sudoout/prebuilt/tego config= anchor= ownlog=" "$tmp/doctor.runs" &&
	fail "VM_HOST=sudo on a disposable machine did not run the product doctor as a root user would: $(cat "$tmp/doctor.runs")"

echo "ok root-suites_test.sh"
