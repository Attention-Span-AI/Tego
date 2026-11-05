#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kvm-run.sh — run one command as root inside a throwaway KVM guest, without root on the host.
#
# Why it exists: the privileged half of Tego (tier 2: cgroup BPF programs, fanotify permission
# events, the ring-buffer recorder; tier 3: BPF LSM; uprobe capture) only runs as root, and tier 3
# also needs `bpf` in the kernel's lsm= list. A development box often has neither: no usable sudo,
# no qemu, no virtme-ng, `bpf` not in lsm=. What such a box usually
# does have is /dev/kvm (group or ACL), `apt-get download` and `dpkg-deb -x`, which need no root. This
# script builds everything else from those, caches it under $TEGO_VM_CACHE, and boots:
#
#   1. qemu-system-x86_64 and its firmware, from this distro's .debs, plus whatever shared libraries
#      the host lacks (found with ldd, fetched round by round from the packages' direct Depends);
#   2. this host's own kernel (linux-image-unsigned-$(uname -r), else linux-image-$(uname -r)), so a
#      guest result says something about the kernel the box really runs; modules only on --module. A
#      vmlinuz already under $TEGO_VM_CACHE/kernel/$TEGO_VM_KERNEL/ is booted as it is, which is how
#      test/vm/matrix.sh boots each kernel-matrix row's distro kernel (test/vm/fetch-kernel.py puts it there,
#      and with --modules the row's own module tree beside it, where --module reads it);
#   3. an initramfs-only root: static busybox, test/vm/guest-init.sh as /init, and a copy of the host
#      userland the tests exec (dash, coreutils, python3, bwrap, ldconfig, openssl + libssl, ...);
#   4. a boot with console=ttyS0 panic=-1, lsm= set to the host's own list plus bpf, and the host's
#      own lockdown mode and hardening sysctls (guest-init.sh applies those), so the guest differs from
#      the host in the one way the tests need and as few others as possible.
#
# The command runs as root in the guest; its exit code comes back through a sentinel line the guest
# prints on the serial console, and becomes this script's exit code.
#
# Usage: test/vm/kvm-run.sh [options] [--] <command> [args...]
#   --file SRC[:DST]  copy SRC (file or directory) into the guest at DST (default /vm/<basename SRC>)
#   --env K=V         set K=V in the command's environment
#   --cwd DIR         guest working directory (default /vm)
#   --module NAME     load kernel module NAME (and its dependencies) before the command
#   --timeout SECS    kill the guest after SECS seconds (default $TEGO_VM_TIMEOUT or 1800)
#   --log FILE        keep the full console log in FILE
#   --dmesg           print the guest's dmesg after the command
#   --sudo            run it the way `sudo <command>` from this very shell would: SUDO_UID, SUDO_GID,
#                     SUDO_USER and SUDO_COMMAND name the invoking user (who also gets a passwd entry
#                     and a home), and the command sits in a copy of this shell's own cgroup chain
#                     (same path, same subtree_control, same delegated ownership), not in a bare scope
#   --delegate-user   with --sudo, provide cpu/memory/pids delegation in user@<uid>.service instead of copying
#                     the host chain; the matrix needs a usable user tier even on CI's undelegated service scopes
#   --prepare         fetch and build everything that is cached, then exit without booting
#   --status FILE     write one line saying where the exit code came from: "guest <code>" when the
#                     guest ran the command, else "timeout", "no-report", "env" or "usage" (see below)
# When <command> is an existing host file named by a relative path (./x.test, bin/tego) or under
# $HOME or /tmp, it is copied to /vm/<basename> and run from there, so `kvm-run.sh ./pkg.test -test.v`
# just works; an absolute system path such as /bin/sh names the guest's own copy.
#
# Environment: TEGO_VM_CACHE (default ~/.cache/tego-vm), TEGO_VM_KERNEL (default uname -r),
# TEGO_VM_MEM (default 4G), TEGO_VM_SMP (default 4), TEGO_VM_TIMEOUT, TEGO_VM_LSM (the full lsm=
# value; default: the host's /sys/kernel/security/lsm plus bpf; "kernel" passes no lsm= at all, so the
# kernel's own CONFIG_LSM decides, as on a freshly installed machine), TEGO_VM_LOCKDOWN (none, integrity or
# confidentiality; default: the host's own /sys/kernel/security/lockdown), TEGO_VM_APPEND (extra
# kernel args), TEGO_VM_QEMU (use this qemu-system-x86_64 instead of fetching one).
#
# Exit code: the inner command's own exit code when the guest ran it; 97 when this box cannot boot a
# guest at all (no /dev/kvm access, a download failed), with a message naming what is missing; 124
# when the guest ran past --timeout; 125 when the guest ended without reporting an exit code (kernel
# panic, init died, a mount the guest needs failed); 2 on a usage error. tego's own exit codes include
# 2, 124 and 125 (pkg/spec/identity/exit.go), so a caller that must tell the two apart reads --status.
set -euo pipefail
# The guest's files are archived with the modes they have here, so this shell's umask (Ubuntu's 002)
# must not leak into them as group-writable system directories that the host does not have.
umask 022

EXIT_ENV=97
EXIT_USAGE=2
EXIT_TIMEOUT=124
EXIT_NOREPORT=125

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${TEGO_VM_CACHE:-$HOME/.cache/tego-vm}"
KVER="${TEGO_VM_KERNEL:-$(uname -r)}"
MEM="${TEGO_VM_MEM:-4G}"
SMP="${TEGO_VM_SMP:-4}"
TIMEOUT="${TEGO_VM_TIMEOUT:-1800}"

statusfile=""
log() { echo "kvm-run: $*" >&2; }
# status records where this script's exit code came from, for --status (a no-op without it).
status() { [ -z "$statusfile" ] || echo "$*" >"$statusfile" || true; }
env_fail() {
	echo "kvm-run: FAIL: $*" >&2
	status env
	exit "$EXIT_ENV"
}
usage() {
	sed -n '/^# Usage:/,/^# Exit code:/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//' >&2
	status usage
	exit "$EXIT_USAGE"
}

# ---- arguments ---------------------------------------------------------------------------------

files=()
envs=()
modules=()
cwd=/vm
logfile=""
dmesg=0
prepare=0
sudo=0
delegate_user=0
while [ $# -gt 0 ]; do
	case "$1" in
	--file) [ $# -ge 2 ] || usage; files+=("$2"); shift 2 ;;
	--file=*) files+=("${1#*=}"); shift ;;
	--env) [ $# -ge 2 ] || usage; envs+=("$2"); shift 2 ;;
	--env=*) envs+=("${1#*=}"); shift ;;
	--cwd) [ $# -ge 2 ] || usage; cwd="$2"; shift 2 ;;
	--module) [ $# -ge 2 ] || usage; modules+=("$2"); shift 2 ;;
	--timeout) [ $# -ge 2 ] || usage; TIMEOUT="$2"; shift 2 ;;
	--log) [ $# -ge 2 ] || usage; logfile="$2"; shift 2 ;;
	--dmesg) dmesg=1; shift ;;
	--sudo) sudo=1; shift ;;
	--delegate-user) delegate_user=1; shift ;;
	--prepare) prepare=1; shift ;;
	--status) [ $# -ge 2 ] || usage; statusfile="$2"; : >"$statusfile"; shift 2 ;;
	-h | --help) usage ;;
	--) shift; break ;;
	-*) echo "kvm-run: unknown option $1" >&2; usage ;;
	*) break ;;
	esac
done
[ "$delegate_user" = 0 ] || [ "$sudo" = 1 ] || usage
[ "$prepare" = 1 ] || [ $# -ge 1 ] || usage
for e in "${envs[@]+"${envs[@]}"}"; do
	case "$e" in [A-Za-z_]*=*) ;; *) echo "kvm-run: --env wants K=V, got \"$e\"" >&2; status usage; exit "$EXIT_USAGE" ;; esac
done

for tool in apt-get dpkg-deb cpio gzip ldd flock timeout; do
	command -v "$tool" >/dev/null 2>&1 || env_fail "$tool is not on PATH (needed to build the guest)"
done
[ -r /dev/kvm ] && [ -w /dev/kvm ] || env_fail \
	"/dev/kvm is not readable and writable by $(id -un); add the user to the kvm group or grant an ACL (setfacl -m u:$(id -un):rw /dev/kvm)"

mkdir -p "$CACHE/debs" "$CACHE/tmp"
exec 9>"$CACHE/.lock"
flock 9 # one builder at a time; released before the boot so guests may run side by side
# What an interrupted build or a killed run left behind: no builder can be running (the lock is
# ours), and a guest still running after a day is past any --timeout.
chmod -R u+w "$CACHE"/tmp/base.* 2>/dev/null || true
rm -rf "$CACHE"/tmp/base.*
find "$CACHE/tmp" -maxdepth 1 -name 'run.*' -mmin +1440 -exec rm -rf {} + 2>/dev/null || true

# ---- 1. qemu ------------------------------------------------------------------------------------

QROOT="$CACHE/root"
QEMU="${TEGO_VM_QEMU:-$QROOT/usr/bin/qemu-system-x86_64}"
QLIBS="$QROOT/usr/lib/x86_64-linux-gnu:$QROOT/lib/x86_64-linux-gnu"

installed() { dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^ii'; }

# fetch_debs downloads the named packages into $CACHE/debs (skipping any already there) and
# extracts each into $2. apt-get download needs no root; dpkg-deb -x needs none either.
fetch_debs() {
	local dest="$1" p deb
	shift
	for p in "$@"; do
		deb="$(find "$CACHE/debs" -maxdepth 1 -name "${p}_*.deb" -print -quit)"
		if [ -z "$deb" ]; then
			(cd "$CACHE/debs" && apt-get download "$p" >/dev/null 2>&1) ||
				env_fail "apt-get download $p failed (package unknown to this box's apt sources, or no network)"
			deb="$(find "$CACHE/debs" -maxdepth 1 -name "${p}_*.deb" -print -quit)"
			[ -n "$deb" ] || env_fail "apt-get download $p reported success but left no ${p}_*.deb"
		fi
		mkdir -p "$dest"
		dpkg-deb -x "$deb" "$dest"
		echo "$p" >>"$dest/.fetched"
	done
}

# direct_deps prints the direct Depends/PreDepends of the given packages that this host lacks.
direct_deps() {
	apt-cache depends --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces \
		--no-enhances "$@" 2>/dev/null |
		awk '$1 ~ /^\|?(Pre)?Depends:$/ && $2 !~ /^</ && $2 !~ /:/ {print $2}' | sort -u |
		while read -r d; do installed "$d" || echo "$d"; done
}

qemu_missing() { LD_LIBRARY_PATH="$QLIBS" ldd "$QEMU" 2>/dev/null | awk '/not found/ {print $1}'; }

fetch_qemu() {
	[ -z "${TEGO_VM_QEMU:-}" ] || return 0
	[ -f "$QROOT/.qemu-ready" ] && return 0
	log "fetching qemu-system-x86 and its firmware into $QROOT"
	fetch_debs "$QROOT" qemu-system-x86 qemu-system-common qemu-system-data seabios
	local round missing want p
	for round in 1 2 3 4 5 6; do
		missing="$(qemu_missing)"
		[ -n "$missing" ] || break
		want=""
		# shellcheck disable=SC2046 # one argument per fetched package name
		for p in $(direct_deps $(sort -u "$QROOT/.fetched")); do
			grep -qx "$p" "$QROOT/.fetched" || want="$want $p"
		done
		# $(echo $missing) joins the missing libraries' lines with single spaces.
		# shellcheck disable=SC2086,SC2116
		[ -n "$want" ] || env_fail "qemu still lacks $(echo $missing) and no uninstalled dependency is left to fetch"
		# shellcheck disable=SC2086,SC2116
		log "round $round: qemu lacks $(echo $missing); fetching$want"
		# shellcheck disable=SC2086
		fetch_debs "$QROOT" $want
	done
	missing="$(qemu_missing)"
	# shellcheck disable=SC2086,SC2116 # joins the lines with single spaces
	[ -z "$missing" ] || env_fail "qemu still lacks shared libraries after fetching: $(echo $missing)"
	LD_LIBRARY_PATH="$QLIBS" "$QEMU" --version >/dev/null 2>&1 || env_fail "the extracted $QEMU does not run"
	touch "$QROOT/.qemu-ready"
}

# ---- 2. kernel ----------------------------------------------------------------------------------

KDIR="$CACHE/kernel/$KVER"
VMLINUZ="$KDIR/vmlinuz"

fetch_kernel() {
	[ -f "$VMLINUZ" ] && return 0
	log "fetching the $KVER kernel image"
	local pkg found=""
	for pkg in "linux-image-unsigned-$KVER" "linux-image-$KVER"; do
		if (cd "$CACHE/debs" && { ls "${pkg}"_*.deb >/dev/null 2>&1 || apt-get download "$pkg" >/dev/null 2>&1; }); then
			rm -rf "$KDIR/img"
			# shellcheck disable=SC2012 # a package file name, which has no newline in it
			dpkg-deb -x "$(ls "$CACHE/debs/${pkg}"_*.deb | head -1)" "$KDIR/img"
			found="$(find "$KDIR/img/boot" -maxdepth 1 -name "vmlinuz-$KVER" -print -quit 2>/dev/null)"
			[ -n "$found" ] && break
		fi
	done
	[ -n "$found" ] || env_fail "no vmlinuz-$KVER from linux-image-unsigned-$KVER or linux-image-$KVER; set TEGO_VM_KERNEL to a version apt can fetch"
	# Through a .part and a rename, as build_base does: a copy cut short (ENOSPC, Ctrl-C, an OOM kill) must
	# not leave a truncated kernel that every later run takes for the cached one.
	cp "$found" "$VMLINUZ.part"
	mv "$VMLINUZ.part" "$VMLINUZ"
}

# fetch_module_tree extracts linux-modules-$KVER (and -extra when asked) for --module only: the root
# is an initramfs and the console is a built-in 8250 UART, so an ordinary boot needs no module. apt has
# that package only for a kernel it knows. A kernel-matrix row's kernel (matrix-<row>) is not one: its tree
# is the one test/vm/fetch-kernel.py --modules extracts from the row's own package, stamped with that
# package's digest (.package-sha256), and it is all the modules the row has, with no -extra to add.
fetch_module_tree() {
	if [ ! -d "$KDIR/mods/lib/modules/$KVER" ]; then
		case "$KVER" in
		matrix-*) env_fail "--module on the kernel-matrix row ${KVER#matrix-} needs its own authenticated module tree: test/vm/fetch-kernel.py --modules ${KVER#matrix-} prepares it (Debian, Amazon Linux and Fedora rows)" ;;
		esac
		fetch_debs "$KDIR/mods" "linux-modules-$KVER"
	fi
	if [ "${1:-}" = extra ] && [ ! -f "$KDIR/mods/.package-sha256" ] &&
		! grep -qx "linux-modules-extra-$KVER" "$KDIR/mods/.fetched" 2>/dev/null; then
		fetch_debs "$KDIR/mods" "linux-modules-extra-$KVER"
	fi
}

# ---- 3. the base initramfs ------------------------------------------------------------------------

BUSYBOX="${TEGO_VM_BUSYBOX:-/usr/bin/busybox}"
BASE_VERSION=4

# The host packages copied into the guest, whole (minus /usr/share): what the privileged tests and
# their helpers exec by absolute path or PATH lookup (sh, sleep, true, df, ldconfig -p, python3,
# bwrap), a real OpenSSL for the uprobe tests (libssl3t64 + openssl), and bpftool/strace for looking
# at a failure from inside the guest, and git for the exec command-rule tests (ADR 0048 C6), which run
# its real subcommands and helpers. A package this host does not have is skipped.
# shellcheck source=test/vm/python-pkgs.sh
. "$here/python-pkgs.sh"
# The python packages are the host's own (python_host_pkgs), not a version named here.
HOST_PKGS="dash bash coreutils coreutils-from-uutils rust-coreutils gnu-coreutils findutils grep sed
mawk util-linux mount procps iproute2 libc-bin kmod python3-minimal $(python_host_pkgs)
bubblewrap openssl libssl3t64 bpftool strace git apparmor"
# Names that live outside any package list (update-alternatives links) or that must exist.
HOST_EXTRA="/usr/bin/awk /usr/bin/python3 /usr/bin/sh /etc/ld.so.conf /etc/ld.so.conf.d /etc/os-release
/usr/lib/os-release /etc/ssl/openssl.cnf /usr/lib/ssl"

declare -A INODE_OF=()

# stage_path copies one absolute host path into $STAGE, resolving it the way the kernel does: every
# symlink met on the way is recreated as the same symlink and resolution continues at its target, so
# the guest sees the host's own layout (/bin -> usr/bin, coreutils' ../lib/cargo links, alternatives)
# while no write ever goes through a staged symlink. Hard links (uutils' one multicall binary behind
# a hundred names) stay hard links. Prints the canonical path; returns 1 when the path is missing.
stage_path() {
	local path="$1" hops=0 cur rest comp next t key restarted
	while :; do
		cur=""
		rest="${path#/}"
		restarted=0
		while [ -n "$rest" ]; do
			comp="${rest%%/*}"
			if [ "$comp" = "$rest" ]; then rest=""; else rest="${rest#*/}"; fi
			case "$comp" in "" | .) continue ;; ..) cur="${cur%/*}"; continue ;; esac
			next="$cur/$comp"
			if [ -L "$next" ]; then
				t="$(readlink "$next")"
				if [ ! -L "$STAGE$next" ]; then
					mkdir -p "$STAGE$cur"
					ln -s "$t" "$STAGE$next"
				fi
				case "$t" in /*) path="$t" ;; *) path="$cur/$t" ;; esac
				[ -z "$rest" ] || path="$path/$rest"
				hops=$((hops + 1))
				[ "$hops" -lt 40 ] || return 1
				restarted=1
				break
			elif [ -d "$next" ]; then
				[ -d "$STAGE$next" ] || mkdir -p "$STAGE$next"
				cur="$next"
			elif [ -f "$next" ]; then
				if [ ! -e "$STAGE$next" ]; then
					key="$(stat -L -c '%d:%i' "$next")"
					if [ -n "${INODE_OF[$key]:-}" ]; then
						ln "$STAGE${INODE_OF[$key]}" "$STAGE$next"
					else
						cp -p "$next" "$STAGE$next" 2>/dev/null || return 1
						INODE_OF[$key]="$next"
					fi
				fi
				cur="$next"
			else
				return 1
			fi
		done
		if [ "$restarted" = 0 ]; then
			echo "$cur"
			return 0
		fi
	done
}

is_elf() { [ "$(head -c 4 "$1" 2>/dev/null | od -An -c | tr -d ' ')" = '177ELF' ]; }

build_base() {
	local key base_dir
	# The cache key: what goes into the archive, not this script's every byte, so a change to the
	# boot flags does not rebuild it. Bump BASE_VERSION when build_base or stage_path changes.
	key="$( {
		echo "$BASE_VERSION $HOST_PKGS $HOST_EXTRA"
		cat "$here/guest-init.sh"
		stat -c '%n %s %Y' "$BUSYBOX" /var/lib/dpkg/status
	} | sha256sum | cut -c1-16)"
	BASE="$CACHE/initramfs/base-$key.cpio.gz"
	CONSOLE_CPIO="$CACHE/initramfs/console.cpio"
	[ -f "$BASE" ] && [ -f "$CONSOLE_CPIO" ] && return 0

	log "building the base initramfs (busybox + host userland) — once per host package change"
	if ldd "$BUSYBOX" >/dev/null 2>&1; then
		env_fail "$BUSYBOX is dynamically linked; set TEGO_VM_BUSYBOX to a static busybox (Ubuntu: busybox-static)"
	fi
	mkdir -p "$CACHE/initramfs"
	base_dir="$(mktemp -d "$CACHE/tmp/base.XXXXXX")"
	STAGE="$base_dir/root"
	mkdir -p "$STAGE"
	INODE_OF=()

	# Merged /usr exactly as this host has it.
	local d
	for d in bin sbin lib lib64 lib32 libx32; do
		[ -L "/$d" ] && stage_path "/$d" >/dev/null || true
	done
	mkdir -p "$STAGE"/{dev,proc,sys,tmp,run,root,etc,vm,.vm,usr/local/bin,usr/lib/tego-vm/bin}

	install -m 0755 "$BUSYBOX" "$STAGE/usr/lib/tego-vm/busybox"
	local applet
	for applet in $("$BUSYBOX" --list); do
		ln -sf ../busybox "$STAGE/usr/lib/tego-vm/bin/$applet"
	done
	install -m 0755 "$here/guest-init.sh" "$STAGE/init"

	local pkg f n=0 skipped=""
	for pkg in $HOST_PKGS; do
		if ! installed "$pkg"; then
			skipped="$skipped $pkg"
			continue
		fi
		while read -r f; do
			case "$f" in
			/usr/share/* | /usr/lib/*/perl* | /etc/init.d/* | /etc/cron* | /etc/logrotate.d/* | /lib/systemd/* | /usr/lib/systemd/* | /.) continue ;;
			esac
			if [ -L "$f" ] || [ -f "$f" ]; then
				stage_path "$f" >/dev/null && n=$((n + 1)) || true
			fi
		done < <(dpkg -L "$pkg" 2>/dev/null)
	done
	for f in $HOST_EXTRA; do
		stage_path "$f" >/dev/null || true
	done
	[ -z "$skipped" ] || log "host packages not installed, not copied:$skipped"

	# The shared libraries every staged ELF file loads, resolved by the host's loader.
	local libs
	libs="$(find "$STAGE" -type f \( -perm -u+x -o -name '*.so*' \) -printf '/%P\n' | while read -r f; do
		if is_elf "$f"; then ldd "$f" 2>/dev/null || true; fi
	done | awk '/=> \// {print $3} /^[[:space:]]*\/[^ ]+ \(0x/ {print $1}' | sort -u)"
	for f in $libs; do
		stage_path "$f" >/dev/null || log "could not copy library $f"
	done

	# Directory modes as the host has them. mkdir -p made every staged directory with this script's
	# umask, and the guest's own mount points are not on the host at all: /root is 0700 there, /tmp
	# is 1777, and the archive's "." entry gives the guest's / the host's 0755 (an initramfs root is
	# otherwise the tmpfs default, 1777). Applied last so a read-only host mode cannot stop staging.
	local dmode
	while read -r d; do
		if [ -d "$d" ] && [ ! -L "$d" ] && dmode="$(stat -c %a "$d" 2>/dev/null)"; then
			chmod "$dmode" "$STAGE$d"
		fi
	done < <(find "$STAGE" -mindepth 1 -type d -printf '/%P\n')
	chmod 0755 "$STAGE"
	chmod 0700 "$STAGE/root"
	chmod 1777 "$STAGE/tmp"

	# Identity files a root shell expects; nothing from the host's own accounts.
	cat >"$STAGE/etc/passwd" <<-'EOF'
		root:x:0:0:root:/root:/bin/sh
		nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
	EOF
	cat >"$STAGE/etc/group" <<-'EOF'
		root:x:0:
		tty:x:5:
		nogroup:x:65534:
	EOF
	printf '127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\ttego-vm\n' >"$STAGE/etc/hosts"
	printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files\n' >"$STAGE/etc/nsswitch.conf"
	echo tego-vm >"$STAGE/etc/hostname"
	: >"$STAGE/etc/fstab"

	(cd "$STAGE" && find . | LC_ALL=C sort | cpio --quiet -o -H newc -R 0:0) | gzip -6 >"$BASE.part"
	mv "$BASE.part" "$BASE"
	find "$CACHE/initramfs" -maxdepth 1 -name 'base-*.cpio.gz' ! -name "$(basename "$BASE")" -delete
	write_console_cpio "$CONSOLE_CPIO"
	log "base initramfs: $BASE ($(du -h "$BASE" | cut -f1), $n package files plus $(echo "$libs" | wc -w) libraries)"
	chmod -R u+w "$base_dir" # the host's modes (a 0555 directory) would otherwise stop rm
	rm -rf "$base_dir"
}

# write_console_cpio writes a tiny uncompressed newc archive holding /dev and /dev/console, which
# cpio cannot take from the file system without root (mknod); the kernel opens /dev/console for
# /init's stdio before /init can mount devtmpfs. The kernel accepts concatenated archives.
write_console_cpio() {
	local final="$1" out="$1.part"
	cpio_entry() { # name mode(octal) rdevmajor rdevminor ino
		local name="$1" namesize=$((${#1} + 1)) hdr pad
		hdr="$(printf '070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X' \
			"$5" "$((8#$2))" 0 0 1 0 0 0 0 "$3" "$4" "$namesize" 0)"
		printf '%s%s\0' "$hdr" "$name"
		pad=$(((4 - (110 + namesize) % 4) % 4))
		head -c "$pad" /dev/zero
	}
	{
		cpio_entry dev 40755 0 0 1
		cpio_entry dev/console 20600 5 1 2
		cpio_entry 'TRAILER!!!' 0 0 0 0
	} >"$out"
	# Pad the archive to a multiple of 512 like cpio(1) does.
	local size
	size="$(stat -c %s "$out")"
	head -c $(((512 - size % 512) % 512)) /dev/zero >>"$out"
	# Renamed into place, so a run that reads the old file sees all of it, never a half-written one.
	mv "$out" "$final"
}

# ---- 3b. modules ----------------------------------------------------------------------------------

# find_ko DIR NAME prints the module file for NAME under DIR, whichever way the name and the file spell a
# separator: the kernel treats - and _ in a module name as one (modinfo's depends: field and lsmod print
# underscores), but the file keeps the hyphens of the object it was built from (snd-hda-intel.ko.zst).
find_ko() { find "$1" -name "${2//[-_]/[-_]}.ko*" -print -quit; }

# stage_modules decompresses each --module and its dependencies (modinfo's depends: field) into
# $1/.vm/modules and writes the load order, dependencies first.
stage_modules() {
	local dest="$1" m
	[ "${#modules[@]}" -gt 0 ] || return 0
	command -v modinfo >/dev/null 2>&1 || env_fail "--module needs modinfo (kmod) on the host"
	command -v zstd >/dev/null 2>&1 || env_fail "--module needs zstd on the host to decompress .ko.zst"
	fetch_module_tree
	local mroot="$KDIR/mods/lib/modules/$KVER"
	mkdir -p "$dest/.vm/modules"
	declare -A seen=()
	load() {
		local name="${1//-/_}" ko dep
		[ -z "${seen[$name]:-}" ] || return 0
		seen[$name]=1
		ko="$(find_ko "$mroot" "$name")"
		if [ -z "$ko" ]; then
			if grep -qE "/${name//_/[-_]}\.ko" "$mroot/modules.builtin" 2>/dev/null; then return 0; fi
			fetch_module_tree extra
			ko="$(find_ko "$mroot" "$name")"
		fi
		[ -n "$ko" ] || env_fail "module $name is neither built in nor in linux-modules(-extra)-$KVER"
		for dep in $(modinfo -F depends "$ko" | tr ',' ' '); do load "$dep"; done
		case "$ko" in
		*.zst) zstd -qdc "$ko" >"$dest/.vm/modules/$name.ko" ;;
		*.xz) xz -dc "$ko" >"$dest/.vm/modules/$name.ko" ;;
		*.gz) gzip -dc "$ko" >"$dest/.vm/modules/$name.ko" ;;
		*) cp "$ko" "$dest/.vm/modules/$name.ko" ;;
		esac
		echo "$name.ko" >>"$dest/.vm/modules.order"
	}
	for m in "${modules[@]}"; do load "${m//-/_}"; done
}

# ---- run ------------------------------------------------------------------------------------------

fetch_qemu
fetch_kernel
build_base

if [ "$prepare" = 1 ]; then
	echo "qemu:    $QEMU"
	echo "kernel:  $VMLINUZ"
	echo "base:    $BASE"
	exit 0
fi

run_dir="$(mktemp -d "$CACHE/tmp/run.XXXXXX")"
# shellcheck disable=SC2329 # the EXIT trap below calls it
cleanup() {
	guarded_kill
	# Copied source directories can be read-only. Restore only our staged directories, before
	# descending into them; leave symlink targets and potentially hardlinked file modes untouched.
	find "$run_dir" -type d -exec chmod u+rwx -- {} \;
	rm -rf -- "$run_dir"
}
# shellcheck source=test/vm/guarded-run.sh
. "$here/guarded-run.sh"
trap cleanup EXIT
# This run's own links to the base and the console archive, made while the lock is still held: a later run
# whose package set changed deletes the old base-*.cpio.gz and replaces console.cpio, and the link keeps
# this run's copy whole until the initrd is assembled. (cp when the cache and $CACHE/tmp are not one filesystem.)
for f in "$BASE" "$CONSOLE_CPIO"; do
	ln "$f" "$run_dir/${f##*/}" 2>/dev/null || cp "$f" "$run_dir/${f##*/}"
done
flock -u 9
P="$run_dir/payload"
mkdir -p "$P/.vm" "$P/vm"

sq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# The command's own argv0 comes along when it names a host file by a relative path (./x.test,
# bin/tego) or one under $HOME or /tmp; /bin/sh and friends stay the guest's own.
auto_copy=0
case "$1" in
/*) case "$1" in "$HOME"/* | /tmp/*) auto_copy=1 ;; esac ;;
*/*) auto_copy=1 ;;
esac
if [ "$auto_copy" = 1 ] && [ -f "$1" ]; then
	files+=("$1:/vm/$(basename "$1")")
	set -- "/vm/$(basename "$1")" "${@:2}"
fi

# Guest paths must not redirect a host write outside the private payload. Check every path a
# recursive copy will touch, before copying anything; .vm is reserved for the harness's metadata.
check_guest_destination() {
	local guest="$1" rest part current="$P"
	case "$guest" in
	/*) ;;
	*) echo "kvm-run: --file destination must be absolute: $guest" >&2; status usage; exit "$EXIT_USAGE" ;;
	esac
	rest="${guest#/}"
	while [ -n "$rest" ]; do
		part="${rest%%/*}"
		if [ "$part" = "$rest" ]; then rest=""; else rest="${rest#*/}"; fi
		case "$part" in
		"" | .) continue ;;
		..) echo "kvm-run: --file destination contains parent traversal: $guest" >&2; status usage; exit "$EXIT_USAGE" ;;
		esac
		if [ "$current" = "$P" ] && [ "$part" = .vm ]; then
			echo "kvm-run: --file cannot replace reserved .vm metadata: $guest" >&2
			status usage
			exit "$EXIT_USAGE"
		fi
		current="$current/$part"
		if [ -L "$current" ]; then
			echo "kvm-run: --file destination crosses a staged symlink: $guest" >&2
			status usage
			exit "$EXIT_USAGE"
		fi
	done
}

stage_guest_file() {
	local src="$1" dst="$2" copy_base entry
	[ -e "$src" ] || { echo "kvm-run: --file $src does not exist" >&2; status usage; exit "$EXIT_USAGE"; }
	check_guest_destination "$dst"
	copy_base="$dst"
	# cp appends the source basename when its destination already names a directory; /source/.
	# therefore still merges the source's contents, as VM_FIXTURE_ROOT's guest-root copy requires.
	[ ! -d "$P$dst" ] || copy_base="$dst/$(basename -- "$src")"
	check_guest_destination "$copy_base"
	if [ -d "$src" ] && [ ! -L "$src" ]; then
		if ! find "$src" -mindepth 1 -printf '%P\0' >"$run_dir/stage-paths"; then
			echo "kvm-run: cannot enumerate --file source $src" >&2
			status usage
			exit "$EXIT_USAGE"
		fi
		while IFS= read -r -d '' entry; do
			check_guest_destination "$copy_base/$entry"
		done <"$run_dir/stage-paths"
	fi
	mkdir -p -- "$P$(dirname -- "$dst")"
	cp -a -- "$src" "$P$dst"
}

for spec in "${files[@]+"${files[@]}"}"; do
	src="${spec%%:*}"
	if [ "$src" = "$spec" ]; then dst="/vm/$(basename -- "$src")"; else dst="${spec#*:}"; fi
	stage_guest_file "$src" "$dst"
done

nonce="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
echo "$nonce" >"$P/.vm/nonce"
cat "${TEGO_VM_CONTROLLERS_FILE:-/sys/fs/cgroup/cgroup.subtree_control}" >"$P/.vm/controllers" 2>/dev/null || true
[ "$delegate_user" = 0 ] || echo "cpu memory pids" >"$P/.vm/controllers"
[ "$dmesg" = 0 ] || : >"$P/.vm/dmesg"
{
	for e in "${envs[@]+"${envs[@]}"}"; do echo "export ${e%%=*}=$(sq "${e#*=}")"; done
} >"$P/.vm/env"
{
	echo "cd $(sq "$cwd") || exit 125"
	printf 'exec'
	for a in "$@"; do printf ' %s' "$(sq "$a")"; done
	echo
} >"$P/.vm/cmd"
stage_modules "$P"

# relative path | subtree_control | owner uid:gid. Most guests reproduce the caller's host chain;
# the matrix explicitly requests a user-manager fixture, independent of the runner's service ownership.
write_cgroup_chain() {
	local uid="$1" gid="$2" own d rest
	if [ "$delegate_user" = 1 ]; then
		printf '%s|cpu memory pids|0:0\n' user.slice "user.slice/user-$uid.slice"
		printf 'user.slice/user-%s.slice/user@%s.service|cpu memory pids|%s:%s\n' "$uid" "$uid" "$uid" "$gid"
		return
	fi
	own="$(sed -n 's/^0:://p' /proc/self/cgroup)"
	d=/sys/fs/cgroup
	rest="${own#/}"
	while [[ "$rest" == */* ]]; do
		d="$d/${rest%%/*}"
		rest="${rest#*/}"
		printf '%s|%s|%s\n' "${d#/sys/fs/cgroup/}" "$(cat "$d/cgroup.subtree_control" 2>/dev/null)" \
			"$(stat -c %u:%g "$d" 2>/dev/null || echo 0:0)"
	done
}
if [ "$sudo" = 1 ]; then
	echo "$(id -u) $(id -g) $(id -un)" >"$P/.vm/sudo"
	printf '%s' "$*" >"$P/.vm/sudo-command"
	write_cgroup_chain "$(id -u)" "$(id -g)" >"$P/.vm/cgroup-chain"
fi

# The host's hardening sysctls, which systemd-sysctl applies from /usr/lib/sysctl.d and /etc/sysctl.d at
# boot and a bare guest kernel does not: fs.protected_regular=2 alone changes what a root process may
# open with O_CREAT in /tmp. guest-init.sh writes each one back. AppArmor's userns restrictions are left
# at the kernel's default on purpose: the guest loads no AppArmor policy, and without the host's
# profiles (bwrap's among them) the restriction would refuse more than the host does.
if [ "${TEGO_VM_HOST_SYSCTL:-1}" = 1 ]; then
	for f in fs/protected_regular fs/protected_fifos fs/protected_symlinks fs/protected_hardlinks \
		fs/suid_dumpable kernel/kptr_restrict kernel/dmesg_restrict kernel/yama/ptrace_scope \
		kernel/unprivileged_bpf_disabled kernel/perf_event_paranoid kernel/unprivileged_userns_clone; do
		v="$(cat "/proc/sys/$f" 2>/dev/null)" && echo "$f $v"
	done >"$P/.vm/sysctl" || true
fi

(cd "$P" && find . -mindepth 1 | LC_ALL=C sort | cpio --quiet -o -H newc -R 0:0) | gzip -1 >"$run_dir/payload.cpio.gz"
cat "$run_dir/${CONSOLE_CPIO##*/}" "$run_dir/${BASE##*/}" "$run_dir/payload.cpio.gz" >"$run_dir/initrd"

if [ "${TEGO_VM_LSM:-}" = kernel ]; then
	# No lsm= at all: the kernel matrix boots each distro kernel the way a fresh install does, where the
	# active list is whatever that kernel was built with (CONFIG_LSM) and `bpf` is present only if the
	# distro put it there (docs/FEATURES.md R16, E38b).
	lsm=""
elif [ -n "${TEGO_VM_LSM:-}" ]; then
	lsm="$TEGO_VM_LSM"
else
	lsm="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
	[ -n "$lsm" ] || lsm="$(sed -n 's/^CONFIG_LSM="\(.*\)"$/\1/p' "/boot/config-$KVER" 2>/dev/null || true)"
	[ -n "$lsm" ] || lsm="landlock,lockdown,yama,integrity,apparmor"
	case ",$lsm," in *,bpf,*) ;; *) lsm="$lsm,bpf" ;; esac
fi
# Kernel lockdown as the host has it: a Secure Boot Ubuntu host runs in [integrity], which a guest
# booted without lockdown= would not (it restricts, among others, bpf_probe_write_user and debugfs).
lockdown="${TEGO_VM_LOCKDOWN:-$(sed -n 's/.*\[\([a-z]*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null || true)}"
case "${lockdown:-none}" in
none) lockdown_arg="" ;;
integrity | confidentiality) lockdown_arg="lockdown=$lockdown" ;;
*) echo "kvm-run: TEGO_VM_LOCKDOWN must be none, integrity or confidentiality, not $lockdown" >&2; status usage; exit "$EXIT_USAGE" ;;
esac
append="console=ttyS0 panic=-1 quiet ${lsm:+lsm=$lsm} $lockdown_arg ${TEGO_VM_APPEND:-}"

console="${logfile:-$run_dir/console.log}"
mkdir -p "$(dirname "$console")"
log "booting $KVER (${MEM} RAM, ${SMP} vCPUs, lsm=${lsm:-<the kernel default>}, lockdown=${lockdown:-none}): $*"
set +e
started=$SECONDS
guarded_run "$console" "$run_dir/qemu.status" \
	"$here/bounded-run.sh" "$TIMEOUT" env LD_LIBRARY_PATH="$QLIBS" "$QEMU" \
	-L "$QROOT/usr/share/seabios" -L "$QROOT/usr/share/qemu" \
	-enable-kvm -cpu host -m "$MEM" -smp "$SMP" -nographic -no-reboot -vga none -nic none \
	-fw_cfg name=etc/sercon-port,string=0 \
	-kernel "$VMLINUZ" -initrd "$run_dir/initrd" -append "$append" \
	</dev/null 2> >(grep -v 'externally provided fw_cfg item names' >&2)
qemu_status="$(cat "$run_dir/qemu.status" 2>/dev/null || echo 1)"
set -e

code="$(tr -d '\r' <"$console" | grep -ao "TEGO-VM-EXIT:$nonce:[0-9]*" | tail -1 | cut -d: -f3 || true)"
if [ -n "$code" ]; then
	status "guest $code"
	exit "$code"
fi
# Elapsed time, not only timeout(1)'s status: uutils' timeout (Ubuntu 25.10's default) exits 125, not
# 124, when the command it signalled (qemu catches SIGTERM) then exits on its own.
if [ "$qemu_status" = 124 ] || [ "$qemu_status" = 137 ] || [ $((SECONDS - started)) -ge "$TIMEOUT" ]; then
	log "the guest ran past ${TIMEOUT}s and was killed"
	status timeout
	exit "$EXIT_TIMEOUT"
fi
log "the guest ended (qemu exit $qemu_status) without reporting the command's exit code — kernel panic, init died, a guest setup step failed (tego-vm: FATAL), or qemu failed; see ${logfile:-the output above}"
status no-report
exit "$EXIT_NOREPORT"
