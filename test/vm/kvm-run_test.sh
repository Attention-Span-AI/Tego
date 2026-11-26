#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests kvm-run.sh's cache writes against the interruptions that once left them corrupt, with kvm-run.sh's own
# functions (cut out of the script) run against stand-ins:
#   - fetch_kernel: a cp that dies part way (ENOSPC, Ctrl-C) must not leave a vmlinuz behind, which every later run
#     would take for the cached kernel and boot into a guest that never reports;
#   - write_console_cpio: a run that dies while writing must leave the console.cpio another run reads as it was;
#   - the run pins its base and console archive into its own directory before it drops the build lock;
#   - guest-init.sh's console_pipe gives the guest's command a pipe, not the console's terminal, and returns once the
#     command has exited and its output is copied, whatever it left behind holding the pipe.
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-kvm-run-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
fail() { echo "FAIL $*" >&2; exit 1; }

# func NAME: the body of the top-level function NAME in kvm-run.sh.
func() { awk -v n="$1" '$0 == n "() {" { p = 1 } p { print } p && $0 == "}" { exit }' "$here/kvm-run.sh"; }
for f in fetch_kernel write_console_cpio write_cgroup_chain; do
	func "$f" >"$tmp/$f.sh"
	[ -s "$tmp/$f.sh" ] || fail "kvm-run.sh has no function $f"
done

# The matrix needs a delegated user even when CI starts it in a root-owned service scope.
# Its explicit fixture must not inherit the host's ownership or controller set.
# shellcheck source=/dev/null
. "$tmp/write_cgroup_chain.sh"
# shellcheck disable=SC2034 # read by the extracted function
delegate_user=1
write_cgroup_chain 1001 1002 >"$tmp/chain"
cat >"$tmp/want-chain" <<'EOF'
user.slice|cpu memory pids|0:0
user.slice/user-1001.slice|cpu memory pids|0:0
user.slice/user-1001.slice/user@1001.service|cpu memory pids|1001:1002
EOF
diff -u "$tmp/want-chain" "$tmp/chain" || fail "the matrix user delegation depends on the host cgroup"
rc=0
"$here/kvm-run.sh" --delegate-user -- /bin/true >"$tmp/no-sudo" 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "--delegate-user without --sudo exited $rc, want usage (2)"

mkdir "$tmp/bin" "$tmp/badcp" "$tmp/badstat"
# cp writes half of its source, then dies, as a full disk does.
cat >"$tmp/badcp/cp" <<'EOF'
#!/bin/sh
head -c 4 "$1" >"$2"
exit 1
EOF
# stat fails: write_console_cpio dies after it has written the archive's entries.
cat >"$tmp/badstat/stat" <<'EOF'
#!/bin/sh
exit 1
EOF
cat >"$tmp/bin/apt-get" <<'EOF'
#!/bin/sh
exit 1
EOF
# dpkg-deb -x DEB DIR: an image whose vmlinuz is 16 bytes.
cat >"$tmp/bin/dpkg-deb" <<'EOF'
#!/bin/sh
mkdir -p "$3/boot"
printf '0123456789abcdef' >"$3/boot/vmlinuz-$KVER"
EOF
chmod +x "$tmp/bin/"* "$tmp/badcp/cp" "$tmp/badstat/stat"

# 1. A cp that fails part way leaves no vmlinuz.
export KVER=6.0.0-test
CACHE="$tmp/cache"
KDIR="$CACHE/kernel/$KVER"
VMLINUZ="$KDIR/vmlinuz"
mkdir -p "$CACHE/debs" "$KDIR"
: >"$CACHE/debs/linux-image-unsigned-${KVER}_1_amd64.deb"
log() { :; }
# shellcheck disable=SC2329 # the extracted functions call it
env_fail() { echo "env_fail: $*" >&2; exit 97; }
# shellcheck source=/dev/null
. "$tmp/fetch_kernel.sh"
# (Not `|| rc=$?` after the subshell: that would switch errexit off inside it.)
set +e
# shellcheck disable=SC2030,SC2031 # the stand-ins go on PATH for this call only: the subshell is the point
(set -e; PATH="$tmp/badcp:$tmp/bin:$PATH"; fetch_kernel) 2>/dev/null
rc=$?
set -e
[ "$rc" != 0 ] || fail "fetch_kernel succeeded although its copy failed"
[ ! -e "$VMLINUZ" ] || fail "a truncated vmlinuz ($(stat -c %s "$VMLINUZ" 2>/dev/null || wc -c <"$VMLINUZ") bytes) was left as the cached kernel"
# With a working cp the image is cached whole, and a second call does not fetch again.
set +e
# shellcheck disable=SC2030,SC2031 # the stand-ins go on PATH for this call only: the subshell is the point
(set -e; PATH="$tmp/bin:$PATH"; fetch_kernel)
rc=$?
set -e
[ "$rc" = 0 ] || fail "fetch_kernel failed with a working cp"
[ "$(wc -c <"$VMLINUZ")" = 16 ] || fail "the cached vmlinuz is not the whole image"
[ ! -e "$VMLINUZ.part" ] || fail "fetch_kernel left $VMLINUZ.part"

# 2. A console.cpio write that dies leaves the existing file whole.
# shellcheck source=/dev/null
. "$tmp/write_console_cpio.sh"
out="$tmp/console.cpio"
write_console_cpio "$out" || fail "write_console_cpio failed with a working stat"
good="$(sha256sum <"$out")"
[ "$(($(wc -c <"$out") % 512))" = 0 ] || fail "console.cpio is not padded to 512"
set +e
# shellcheck disable=SC2030,SC2031 # the stand-ins go on PATH for this call only: the subshell is the point
(set -e; PATH="$tmp/badstat:$PATH"; write_console_cpio "$out") 2>/dev/null
rc=$?
set -e
[ "$rc" != 0 ] || fail "write_console_cpio succeeded although stat failed"
[ "$(sha256sum <"$out")" = "$good" ] || fail "a write that died changed the console.cpio another run may be reading"

# 3. The run links its base and console archive into its run directory before it releases the lock.
awk '/^\tln "\$f" "\$run_dir\// { l = NR } /^flock -u 9$/ { u = NR } END { exit !(l && u && l < u) }' "$here/kvm-run.sh" ||
	{ grep -n 'flock -u 9' "$here/kvm-run.sh" >&2; fail "kvm-run.sh releases the build lock before pinning BASE and CONSOLE_CPIO into the run directory"; }
# shellcheck disable=SC2016 # kvm-run.sh's own text, expansions and all
grep -q 'cat "\$run_dir/\${CONSOLE_CPIO##\*/}" "\$run_dir/\${BASE##\*/}"' "$here/kvm-run.sh" ||
	fail "the initrd is not assembled from the run's own links"
# 4. console_pipe (guest-init.sh, the guest's PID 1, run under busybox's sh): the command's stdout and stderr are a
# pipe; its output reaches the console whole and in order, an unfinished last line included; its status comes back;
# and a process it left behind holding the pipe (the service wrapper's sleep) does not keep it waiting.
awk '$0 == "console_pipe() {" { p = 1 } p { print } p && $0 == "}" { exit }' "$here/guest-init.sh" >"$tmp/console_pipe.sh"
[ -s "$tmp/console_pipe.sh" ] || fail "guest-init.sh has no function console_pipe"
# The guest runs it under busybox's sh with busybox's applets; a host without a busybox that has awk runs it under
# /bin/sh with its own tools.
bb="" sh=/bin/sh
if [ -x /usr/bin/busybox ] && /usr/bin/busybox --list >"$tmp/applets" && grep -qx awk "$tmp/applets"; then
	bb=/usr/bin/busybox sh="/usr/bin/busybox sh"
fi
cat >"$tmp/console_pipe_case.sh" <<'EOF'
fatal() { echo "FATAL $*"; exit 1; }
. "$CP_FUNC"
nonce=n0nce console_fifo="$CP_FIFO"
cmd() {
	if [ -t 1 ] || [ -t 2 ]; then echo "a terminal"; else echo "a pipe"; fi
	echo "to stderr" >&2
	(sleep 15 &)
	seq 1 2000 | tail -n 1
	printf 'no newline'
	return 3
}
console_pipe cmd
echo "status $?"
EOF
# The console is a file here, as it is a device in the guest: nothing waits for its end, so the time is the
# function's own (a $(...) would wait for the leftover sleep, which holds what the shell saved of its stdout).
t0=$(date +%s)
code=0
# shellcheck disable=SC2086 # $sh is a command and its argument
CP_FUNC="$tmp/console_pipe.sh" CP_FIFO="$tmp/console.fifo" bb="$bb" timeout 20 $sh "$tmp/console_pipe_case.sh" \
	>"$tmp/console.out" 2>&1 || code=$?
took=$(($(date +%s) - t0))
out=$(cat "$tmp/console.out")
[ "$code" = 0 ] || fail "console_pipe under $sh: exit $code (a leftover writer kept it waiting?): $out"
want=$(printf 'a pipe\nto stderr\n2000\nno newline\nstatus 3')
[ "$out" = "$want" ] || fail "console_pipe under $sh printed $(printf '%q' "$out"), want $(printf '%q' "$want")"
[ "$took" -lt 10 ] || fail "console_pipe under $sh took ${took}s with a leftover writer; it waited on it"
[ ! -e "$tmp/console.fifo" ] || fail "console_pipe left its pipe at $tmp/console.fifo"

# 5. guest_end: how the guest ended, from the console, qemu's exit status (timeout(1)'s and bounded-run.sh's, 128+n for a
# signal), qemu's stderr and the time it took. A qemu a signal from outside ended (2026-11-11: the host's memory guard
# SIGKILLed a guest, which kvm-run.sh then called a timeout) is EXIT_LOST with a GUEST-LOST line in the console and on
# stderr; only this script's own bound is a timeout; a guest that ended on its own without the sentinel is no-report.
func guest_end >"$tmp/guest_end.sh"
[ -s "$tmp/guest_end.sh" ] || fail "kvm-run.sh has no function guest_end"
# shellcheck source=/dev/null
. "$tmp/guest_end.sh"
# shellcheck disable=SC2034 # read by the extracted function
nonce=c0ffee TIMEOUT=1500 EXIT_LOST=98 EXIT_TIMEOUT=124 EXIT_NOREPORT=125 logfile=""
statusfile="$tmp/status"
status() { echo "$*" >"$statusfile"; }
# end_case NAME CONSOLE-TEXT QEMU-STATUS QEMU-STDERR ELAPSED WANT-CODE WANT-STATUS WANT-LOST(0|1)
end_case() {
	local c="$tmp/end-$1" rc=0
	printf '%s' "$2" >"$c.console"
	printf '%s' "$4" >"$c.stderr"
	: >"$statusfile"
	guest_end "$c.console" "$3" "$c.stderr" "$5" 2>"$c.err" || rc=$?
	[ "$rc" = "$6" ] || fail "guest_end $1: exit $rc, want $6"
	[ "$(cat "$statusfile")" = "$7" ] || fail "guest_end $1: status '$(cat "$statusfile")', want '$7'"
	if [ "$8" = 1 ]; then
		grep -q '^GUEST-LOST: .*this is not a test result' "$c.err" || fail "guest_end $1: no GUEST-LOST line on stderr: $(cat "$c.err")"
		grep -q '^GUEST-LOST: ' "$c.console" || fail "guest_end $1: the console log does not say GUEST-LOST"
	elif grep -q GUEST-LOST "$c.err" "$c.console"; then
		fail "guest_end $1: a GUEST-LOST line where the guest was not lost"
	fi
}
end_case sentinel $'--- PASS: TestX\nTEGO-VM-EXIT:c0ffee:3\n' 0 "" 20 3 "guest 3" 0
end_case sentinel-then-killed $'TEGO-VM-EXIT:c0ffee:0\n' 137 "" 20 0 "guest 0" 0
end_case other-nonce $'TEGO-VM-EXIT:bad:0\n' 137 "" 20 98 "lost signal 9" 1
end_case sigkill $'=== RUN   TestIntegrationStopAfterPidReuseSignalsNothing\n' 137 "" 611 98 "lost signal 9" 1
end_case sigterm-caught $'=== RUN   TestX\n' 0 "qemu-system-x86_64: terminating on signal 15 from pid 4242 (kill)"$'\n' 30 98 "lost signal 15" 1
end_case our-bound 'x' 124 "qemu-system-x86_64: terminating on signal 15 from pid 77 (timeout)" 1500 124 timeout 0
end_case our-escalation 'x' 137 "" 1510 124 timeout 0
end_case uutils-bound 'x' 125 "" 1500 124 timeout 0
end_case panic $'Kernel panic - not syncing: Attempted to kill init!\n' 0 "" 5 125 no-report 1
# An initramfs that did not unpack is an environment failure (97) with its reason, whatever the guest then reported: its
# command was "not found" (127) for lack of the file, which is no test result.
nonce_line=$'TEGO-VM-EXIT:c0ffee:127\n'
unpack=$'[    2.809640] Initramfs unpacking failed: write error\n/.vm/cmd: 2: exec: /vm/test_conformance.test: not found\n'
# shellcheck disable=SC2034 # read by the extracted guest_end
MEM=1536M staged_mb=786 EXIT_ENV=97
# shellcheck disable=SC2329 # guest_end calls it
env_fail() { echo "kvm-run: FAIL: $*" >&2; status env; }
end_case unpack-failed "$unpack$nonce_line" 0 "" 5 97 env 0
grep -q 'Initramfs unpacking failed) in 1536M RAM, with 786 MB staged' "$tmp/end-unpack-failed.err" || fail "the unpack failure's line lacks its reason: $(cat "$tmp/end-unpack-failed.err")"
[ "$(grep -c 'did not unpack' "$tmp/end-unpack-failed.err")" = 1 ] || fail "the unpack failure is not one line: $(cat "$tmp/end-unpack-failed.err")"
# a test that prints the words is not the kernel
end_case unpack-words-in-test $'    foo_test.go:1: Initramfs unpacking failed\nTEGO-VM-EXIT:c0ffee:1\n' 0 "" 5 1 "guest 1" 0
# (public issue 91: held labels on fedora-7.0) the console cut off in the middle of the dmesg that follows the marker. The marker is
# printed before the dmesg, so a cut dmesg still carries it; a console with neither the marker nor a result stays lost.
end_case cut-dmesg-after-marker $'--- PASS: TestX\nTEGO-VM-EXIT:c0ffee:0\n---- tego-vm: dmesg ----\n[    1.693] SELinux:  Class io_uring not defin' 0 "" 51 0 "guest 0" 0
end_case cut-dmesg-no-marker $'--- PASS: TestX\n---- tego-vm: dmesg ----\n[    1.693] SELinux:  Class io_uring not defin' 0 "" 51 125 no-report 1
init_marker=$(grep -n 'TEGO-VM-EXIT' "$here/guest-init.sh" | head -1 | cut -d: -f1)
# shellcheck disable=SC2016 # guest-init.sh's own text
init_dmesg=$(grep -n '^	\$bb dmesg$' "$here/guest-init.sh" | head -1 | cut -d: -f1)
{ [ -n "$init_marker" ] && [ -n "$init_dmesg" ] && [ "$init_marker" -lt "$init_dmesg" ]; } ||
	fail "guest-init.sh prints its exit marker (line ${init_marker:-none}) after the dmesg (line ${init_dmesg:-none})"
# shellcheck source=/dev/null
. <(func env_fail) # the real one again, for the cases below
end_case qemu-failed '' 1 "qemu-system-x86_64: failed to initialize kvm" 0 125 no-report 1
grep -q 'signal 9' "$tmp/end-sigkill.err" || fail "the GUEST-LOST line does not name the signal: $(cat "$tmp/end-sigkill.err")"

# 6. sq quotes a word for the guest's sh whole: quotes, an empty word, and trailing newlines, which the old command
# substitution around sed trimmed ("a\n\n" reached the guest as "a").
func sq >"$tmp/sq.sh"
[ -s "$tmp/sq.sh" ] || fail "kvm-run.sh has no function sq"
# shellcheck source=/dev/null
. "$tmp/sq.sh"
nl2=$(printf 'a\n\nx') nl2=${nl2%x}
nlonly=$(printf '\n\nx') nlonly=${nlonly%x}
# shellcheck disable=SC2016,SC1003 # the last word is literal on purpose: what sh must not expand
for w in "it's" "" "'" "a'b'c" "$nl2" "$nlonly" "two words" '$HOME `id` \'; do
	got=$(sh -c "printf '%sx' $(sq "$w")")
	[ "${got%x}" = "$w" ] || fail "sq $(printf '%q' "$w") reached sh as $(printf '%q' "${got%x}")"
done

# The guest's userland holds node, so the root rows run the dashboard's script tests (builder, place, twin, live)
# and the runtime's node cells rather than skipping them, and no root skip still says the guest has none.
pkgs=$(awk '/^HOST_PKGS="/ { p = 1 } p { print } p && /"$/ { exit }' "$here/kvm-run.sh")
case " $(printf '%s' "$pkgs" | tr '\n"' '  ') " in *" nodejs "*) ;; *) fail "kvm-run.sh's HOST_PKGS does not copy nodejs into the guest: $pkgs" ;; esac
if grep -nE 'no node|node is not installed' "$here/root-skips.txt"; then
	fail "root-skips.txt still allows a skip for a guest without node"
fi

# 7. node's shared builtins. The host's libnode loads six files from /usr/share/nodejs, a tree the package copy
# skips, and aborts at startup without them ("Cannot load externalized builtin": 2026-11-19, three root tests
# failed on it). The staged tree must hold every file its staged libnode names, read from the libnode itself.
# shellcheck source=/dev/null
. <(func node_builtin_paths)
# shellcheck source=/dev/null
. <(func missing_node_builtins)
# shellcheck source=/dev/null
. <(func stage_node_builtins)
# shellcheck source=/dev/null
. <(func stage_path)
# shellcheck disable=SC2034 # read by the extracted stage_path
declare -A INODE_OF=()
nb="$tmp/nb"
mkdir -p "$nb/lib"
printf 'junk\0/usr/share/nodejs/acorn/dist/acorn.js\0more\0/usr/share/nodejs/undici/undici-fetch.js\0/usr/share/nodejs/acorn/dist/acorn.js\0/usr/share/other/x.js\0/usr/share/nodejs/\0' >"$nb/fake"
[ "$(node_builtin_paths "$nb/fake")" = "$(printf '/usr/share/nodejs/acorn/dist/acorn.js\n/usr/share/nodejs/undici/undici-fetch.js')" ] ||
	fail "node_builtin_paths read: $(node_builtin_paths "$nb/fake")"
# A staged libnode whose builtins are not staged is caught, and each missing file is named.
STAGE="$nb/stage"
mkdir -p "$STAGE/usr/lib"
cp "$nb/fake" "$STAGE/usr/lib/libnode.so.99"
[ "$(missing_node_builtins | wc -l)" = 2 ] || fail "missing_node_builtins did not name both files: $(missing_node_builtins)"
# A builtin the host lacks stops the build with the file named.
printf '/usr/share/nodejs/tego-no-such-package/x.js\0' >"$STAGE/usr/lib/libnode.so.99"
out=$( (stage_node_builtins) 2>&1) && rc=0 || rc=$?
[ "$rc" = 97 ] || fail "a builtin the host lacks was not refused (rc $rc): $out"
case "$out" in *tego-no-such-package/x.js*) ;; *) fail "the refusal does not name the missing file: $out" ;; esac
# The real host: stage its node and libnode the way build_base does, and every file the libnode names is staged.
if nodebin="$(command -v node)" && libnode="$(ldd "$nodebin" 2>/dev/null | awk '/libnode/ { print $3; exit }')" && [ -n "$libnode" ]; then
	STAGE="$nb/real"
	mkdir -p "$STAGE"
	stage_path "$nodebin" >/dev/null
	stage_path "$libnode" >/dev/null
	[ -n "$(node_builtin_paths "$(readlink -f "$libnode")")" ] || fail "the host's libnode names no builtin (the read is broken)"
	[ -n "$(missing_node_builtins)" ] || fail "the staged libnode already had its builtins before stage_node_builtins ran"
	stage_node_builtins
	[ -z "$(missing_node_builtins)" ] || fail "staged node still lacks: $(missing_node_builtins)"
	while read -r p; do [ -s "$STAGE$p" ] || fail "staged builtin $p is empty"; done < <(node_builtin_paths "$(readlink -f "$libnode")")
fi

echo "ok kvm-run_test.sh"
