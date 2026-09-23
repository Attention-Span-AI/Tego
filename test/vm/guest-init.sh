#!/usr/lib/tego-vm/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# guest-init.sh — PID 1 of the throwaway KVM guest test/vm/kvm-run.sh boots. It exists because the
# privileged half of Tego (tier 2 cgroup BPF + fanotify, tier 3 BPF LSM, uprobe capture) needs root
# and `bpf` in lsm=, and the development box has neither root nor that boot line: the guest gives
# both without touching the host. kvm-run.sh installs this file as /init of an initramfs-only root
# (no disk, no modules needed for the root itself) and runs it under busybox's sh, which is why the
# interpreter line points at the busybox applet directory rather than at /bin/sh.
#
# It mounts what a systemd host would have mounted (proc, sysfs, devtmpfs, cgroup2 with the
# controllers enabled at the root, bpffs, tracefs, debugfs, securityfs, a tmpfs /tmp and /run),
# loads the modules kvm-run.sh was asked for, runs /.vm/cmd as root in a leaf cgroup of its own,
# prints "TEGO-VM-EXIT:<nonce>:<code>" on the console and powers off. The host side greps the
# console for that sentinel; no sentinel means the guest died before the command finished, or a setup
# step the tests depend on (a mount, the cgroup leaf) failed: that prints "tego-vm: FATAL: ..." and
# powers off without a sentinel, so a broken guest never passes for a test result.
#
# The command itself runs from the host's own /bin/sh with sudo's secure_path. busybox and its applet
# directory serve this script only: on the command's PATH they would stand in, silently, for any host
# tool kvm-run.sh did not copy (tar, which, nc, ...), where the host would say "not found".
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/lib/tego-vm/bin
export PATH

bb=/usr/lib/tego-vm/busybox
say() { echo "tego-vm: $*"; }
# fatal ends the guest without the exit sentinel: kvm-run.sh then reports "no-report" (125).
fatal() {
	say "FATAL: $*"
	$bb sync
	$bb poweroff -f
	exit 1
}

$bb mount -t devtmpfs devtmpfs /dev 2>/dev/null
exec 0</dev/null 1>/dev/console 2>&1

$bb mkdir -p /proc /sys /tmp /run /root /dev/pts /dev/shm
$bb mount -t proc proc /proc || fatal "mount proc"
$bb mount -t sysfs sysfs /sys || fatal "mount sysfs"
# Options as this Ubuntu host's systemd mounts them (/proc/mounts), so a test sees the same flags.
$bb mount -t devpts -o nosuid,noexec,gid=5,mode=620,ptmxmode=000 devpts /dev/pts || fatal "mount devpts"
$bb mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /dev/shm || fatal "mount /dev/shm"
$bb mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /tmp || fatal "mount /tmp"
$bb mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs /run || fatal "mount /run"
$bb mount -t cgroup2 -o nosuid,nodev,noexec,nsdelegate,memory_recursiveprot cgroup2 /sys/fs/cgroup ||
	fatal "mount cgroup2"
$bb mount -t bpf -o nosuid,nodev,noexec,mode=700 bpf /sys/fs/bpf || fatal "mount bpffs"
$bb mount -t securityfs -o nosuid,nodev,noexec securityfs /sys/kernel/security || fatal "mount securityfs"
$bb mount -t tracefs -o nosuid,nodev,noexec tracefs /sys/kernel/tracing || say "mount tracefs failed"
$bb mount -t debugfs -o nosuid,nodev,noexec debugfs /sys/kernel/debug || say "mount debugfs failed"
[ -e /dev/fd ] || $bb ln -s /proc/self/fd /dev/fd
[ -e /dev/stdin ] || $bb ln -s /proc/self/fd/0 /dev/stdin
[ -e /dev/stdout ] || $bb ln -s /proc/self/fd/1 /dev/stdout
[ -e /dev/stderr ] || $bb ln -s /proc/self/fd/2 /dev/stderr

$bb hostname tego-vm
$bb ip link set lo up 2>/dev/null || $bb ifconfig lo 127.0.0.1 up

# The dynamic loader cache: the host's own ldconfig rebuilds it from the libraries that were copied
# in, so `ldconfig -p` (which the uprobe tests use to find libssl) answers for this guest, not the host.
if [ -x /usr/sbin/ldconfig.real ]; then
	/usr/sbin/ldconfig.real 2>/dev/null || say "ldconfig failed; ldconfig -p will be empty"
fi

# The host's hardening sysctls (kvm-run.sh copies them in /.vm/sysctl as "<path under /proc/sys> <value>").
if [ -f /.vm/sysctl ]; then
	while read -r key value; do
		[ -n "$key" ] || continue
		[ -e "/proc/sys/$key" ] || continue
		echo "$value" >"/proc/sys/$key" 2>/dev/null ||
			[ "$($bb cat "/proc/sys/$key")" = "$value" ] || say "could not set $key to the host's $value"
	done </.vm/sysctl
fi

# Modules kvm-run.sh --module asked for, already decompressed and listed in dependency order.
if [ -f /.vm/modules.order ]; then
	while read -r ko; do
		[ -n "$ko" ] || continue
		$bb insmod "/.vm/modules/$ko" || fatal "insmod $ko"
	done </.vm/modules.order
fi

# A systemd host enables controllers at the root and keeps every process in a leaf; do the same.
# The set is the host's own root cgroup.subtree_control (kvm-run.sh copies it into /.vm/controllers),
# falling back to every controller this kernel offers.
ctrls=""
want="$($bb cat /.vm/controllers 2>/dev/null)"
[ -n "$want" ] || want="$($bb cat /sys/fs/cgroup/cgroup.controllers)"
for c in $want; do ctrls="$ctrls +$c"; done
[ -z "$ctrls" ] || echo "$ctrls" >/sys/fs/cgroup/cgroup.subtree_control 2>/dev/null ||
	say "could not enable controllers:$ctrls"
$bb mkdir -p /sys/fs/cgroup/init.scope
echo 1 >/sys/fs/cgroup/init.scope/cgroup.procs 2>/dev/null

# The command's leaf: a bare /tego-vm.scope, or, under kvm-run.sh --sudo, the host shell's own
# cgroup chain rebuilt level by level with its controllers and its delegated owners.
leaf=/sys/fs/cgroup/tego-vm.scope
leaf_owner=0:0
if [ -s /.vm/cgroup-chain ]; then
	while IFS='|' read -r rel ctrls owner; do
		dir="/sys/fs/cgroup/$rel"
		$bb mkdir -p "$dir"
		want=""
		for c in $ctrls; do want="$want +$c"; done
		[ -z "$want" ] || echo "$want" >"$dir/cgroup.subtree_control" 2>/dev/null ||
			say "could not enable$want in $rel"
		[ "$owner" = 0:0 ] || $bb chown "$owner" "$dir" "$dir/cgroup.procs" "$dir/cgroup.threads" \
			"$dir/cgroup.subtree_control"
		leaf="$dir/tego-vm.scope"
		leaf_owner="$owner"
	done </.vm/cgroup-chain
fi
$bb mkdir -p "$leaf" || fatal "mkdir $leaf"
[ "$leaf_owner" = 0:0 ] || $bb chown "$leaf_owner" "$leaf" "$leaf/cgroup.procs" "$leaf/cgroup.threads" \
	"$leaf/cgroup.subtree_control"

# kvm-run.sh --sudo: the invoking user exists here too, with a home, as it does behind a real sudo.
if [ -f /.vm/sudo ]; then
	read -r sudo_uid sudo_gid sudo_user </.vm/sudo
	$bb grep -q "^$sudo_user:" /etc/passwd ||
		echo "$sudo_user:x:$sudo_uid:$sudo_gid::/home/$sudo_user:/bin/bash" >>/etc/passwd
	$bb grep -q "^[^:]*:x:$sudo_gid:" /etc/group || echo "$sudo_user:x:$sudo_gid:" >>/etc/group
	$bb mkdir -p "/home/$sudo_user"
	$bb chown "$sudo_uid:$sudo_gid" "/home/$sudo_user"
fi

say "kernel $($bb uname -r); lsm=$($bb cat /sys/kernel/security/lsm 2>/dev/null)" \
	"lockdown=$($bb cat /sys/kernel/security/lockdown 2>/dev/null)"
say "cgroup root controllers: $($bb cat /sys/fs/cgroup/cgroup.subtree_control); command cgroup: ${leaf#/sys/fs/cgroup}"
[ ! -f /.vm/sudo ] || say "as if run with sudo by $sudo_user (uid $sudo_uid, gid $sudo_gid)"

# console_pipe CMD...: runs CMD with its stdout and stderr on a pipe whose reader copies it to this shell's stdout (the
# console), and returns CMD's status. `go test` and CI's sudo suites give a test binary a pipe; the console is a
# terminal, and a test that hands its own stdout to an agent killed by a signal printed tego's terminal reset there,
# glued to a result line that test2json then counted as a failure with no message. The reader stops at an end line
# this shell writes once CMD has exited, not at the pipe's end: a process the command left behind holding the pipe
# (the service wrapper's sleep, an agent a test did not reap) would keep that end from ever coming. Every byte CMD
# wrote comes before the end line, since a pipe keeps order; a line the end line lands on (a leftover's unfinished
# one) is printed up to it, and a leftover's later writes fail with EPIPE. The end line names the run's nonce, which
# no test prints. console_fifo is the pipe's path; one that cannot be made ends the guest without the sentinel.
console_pipe() {
	cp_end="TEGO-VM-CONSOLE-END:$nonce"
	$bb mkfifo -m 600 "$console_fifo" || fatal "mkfifo $console_fifo"
	# shellcheck disable=SC2016 # awk's program, not the shell's
	$bb awk -v end="$cp_end" '{ i = index($0, end); if (i) { if (i > 1) print substr($0, 1, i - 1); exit } print; fflush() }' \
		<"$console_fifo" &
	cp_reader=$!
	exec 3>"$console_fifo"
	"$@" >&3 2>&3 3>&-
	cp_code=$?
	printf '%s\n' "$cp_end" >&3
	exec 3>&-
	wait "$cp_reader"
	$bb rm -f "$console_fifo"
	return "$cp_code"
}

# run_cmd runs /.vm/cmd in its own leaf cgroup, as root, from a fresh host shell that reads the environment
# kvm-run.sh wrote; the subshell moves itself before it execs anything.
# shellcheck disable=SC2329 # console_pipe runs it, as "$@"
run_cmd() {
	(
		if ! echo 0 >"$leaf/cgroup.procs"; then
			: >/run/tego-vm-setup-failed
			exit 1
		fi
		# sudo's secure_path on Ubuntu; /sbin and /bin are the host's own merged-/usr links.
		PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
		export PATH HOME=/root USER=root LOGNAME=root TMPDIR=/tmp LANG=C.UTF-8 TERM=dumb
		if [ -f /.vm/sudo ]; then
			export SUDO_UID="$sudo_uid" SUDO_GID="$sudo_gid" SUDO_USER="$sudo_user"
			SUDO_COMMAND="$($bb cat /.vm/sudo-command)"
			export SUDO_COMMAND
		fi
		[ -f /.vm/env ] && . /.vm/env
		exec "$cmd_sh" /.vm/cmd
	) </dev/null
}

nonce="$($bb cat /.vm/nonce 2>/dev/null)"
console_fifo=/run/tego-vm-console
code=125
cmd_sh=/bin/sh
[ -x "$cmd_sh" ] || fatal "the guest has no /bin/sh (kvm-run.sh copies dash from the host)"
if [ -f /.vm/cmd ]; then
	console_pipe run_cmd
	code=$?
	[ ! -e /run/tego-vm-setup-failed ] || fatal "could not move the command into $leaf"
else
	say "no /.vm/cmd in the initramfs; nothing to run"
fi

if [ -f /.vm/dmesg ]; then
	echo "---- tego-vm: dmesg ----"
	$bb dmesg
	echo "---- tego-vm: end of dmesg ----"
fi
$bb sync
printf '\nTEGO-VM-EXIT:%s:%s\n' "$nonce" "$code"
$bb poweroff -f
# poweroff -f returns only when the power-off syscall failed; ending PID 1 panics the kernel, and
# panic=-1 plus qemu's -no-reboot turn that into a qemu exit, so the host never hangs here.
exit "$code"
