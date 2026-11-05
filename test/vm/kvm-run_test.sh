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

echo "ok kvm-run_test.sh"
