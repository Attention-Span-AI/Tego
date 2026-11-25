#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# tego-entrypoint.sh: the container image's entrypoint (docs/site/containers.md). Started as root, it does the two
# things only root can do in the container and then runs the command as the image's unprivileged user `tego`:
#
#   1. hands that user a cgroup v2 subtree of its own. Every tego run, at every tier, makes a cgroup per run (limits,
#      stop by cgroup.kill), and an unprivileged tego takes that subtree only where systemd would delegate it:
#      user.slice/user-<uid>.slice/user@<uid>.service, with the launcher inside it (internal/runtime/cgroup Detect and
#      CanPlace). A container has no user manager, so this script builds the same shape inside the container's own
#      cgroup namespace: every process moved out of the namespace root into init/, cpu, memory and pids enabled down
#      the path, the user@<uid>.service directory and its cgroup.procs, cgroup.subtree_control and cgroup.threads
#      chowned to the user (what systemd's Delegate= chowns), and this shell moved into its init.scope, so tego,
#      which this shell becomes, starts inside the subtree. Docker mounts /sys/fs/cgroup read-only in a container
#      that is not privileged, so it is remounted read-write first, which needs CAP_SYS_ADMIN and a mount the
#      AppArmor profile allows (compose.yaml says which settings give both).
#   2. makes sure the state directories (~tego/.tego, which holds the chain anchor, and the ledger root) and /work
#      belong to the user, for a bind mount of a host directory that does not.
#
#   3. hands tego the list of the kernel's active security modules, which a container usually cannot read itself: under
#      Docker's default profile lsm_list_modules(2) is refused (kernels before 6.8 lack it) and /sys/kernel/security is an
#      empty directory, and without the list tego refuses every file open it holds for the agent. Root reads it here,
#      from the kernel's own file (or by mounting securityfs read-only for the moment, which needs CAP_SYS_ADMIN and a
#      profile that allows `mount`) and writes /run/tego-lsm/lsm-list as root, mode 0644, in a root-only directory, with
#      this boot's id; /etc/tego/config.yaml names it (lsm.list_file) and tego believes it only while root alone can
#      change it (internal/platform/lsmlist, docs/user/container.md). The directory is /run/tego-lsm, its own: /run/tego
#      is tego's host state directory, which a root tego opens only as root's, mode 0700, and this step sets its
#      directory to 0755 at every start. A container that cannot read the list here says
#      why and starts anyway: held file opens are then refused, as they were.
#
# Then it drops to the user for good: setpriv with the user's uid, gid and groups, no inheritable, ambient or
# bounding capabilities, and no_new_privs, so neither tego nor the agent holds anything the container was given for
# step 1. Started as any other user (`--user`, compose's `user:`), it does nothing and runs the command as given:
# tego-control serve is started that way.
#
# TEGO_LSM_LIST: auto (default) writes the list when it can and otherwise says why and carries on; yes fails the
# container instead; no leaves /run/tego-lsm/lsm-list alone.
# TEGO_DELEGATE: auto (default) builds the subtree when it can and otherwise says why and carries on, so `tego machine check`
# can report the machine; yes fails the container instead; no never touches the cgroup tree.
# TEGO_LAUNCHER: user (default) as above; root, experimental, keeps tego root for the root tiers (cgroup, bpflsm) in a
# privileged container: the namespace root is emptied into init/ and given its controllers, tego is started as root
# with SUDO_UID naming the tego user, and nothing is dropped.
# A later process of the same container (`docker exec <container> tego-entrypoint tego run ...`) joins what the first
# start built.
#
# The cgroup steps refuse to touch a tree they cannot show is the container's own: only a private cgroup namespace,
# where /proc/self/cgroup reads "0::/", is changed. Under `--cgroupns=host` they would be editing the host's tree.
set -euo pipefail

prog=tego-entrypoint
user=tego
controllers=(cpu memory pids)

say() { printf '%s: %s\n' "$prog" "$*" >&2; }

# own_cgroup FILE: the unified (0::) path a /proc/<pid>/cgroup file names, empty when it names none.
own_cgroup() {
	sed -n 's/^0:://p' "$1" | head -n 1
}

# is_cgroup2 MOUNT: whether MOUNT holds a cgroup v2 hierarchy (its root has cgroup.controllers; v1 and hybrid
# hosts mount a tmpfs there with no such file).
is_cgroup2() {
	[ -f "$1/cgroup.controllers" ] && [ -f "$1/cgroup.subtree_control" ]
}

# make_writable MOUNT: the cgroup mount read-write. A runtime that already mounts it so (privileged, a userns-remapped
# daemon, sysbox) needs nothing; Docker's ro mount is remounted, which fails without CAP_SYS_ADMIN or under AppArmor's
# docker-default profile (`deny mount`). The bind remount changes this mount's read-only flag alone; the plain one,
# tried next, also asks the cgroup2 superblock (shared with the host's mount) to be read-write, which it already is.
# `test -w` answers for root too: access(2) refuses a write on a read-only mount whoever asks.
make_writable() {
	local mount=$1
	[ -w "$mount/cgroup.subtree_control" ] && return 0
	{ mount -o remount,bind,rw "$mount" 2>/dev/null || mount -o remount,rw "$mount" 2>/dev/null; } &&
		[ -w "$mount/cgroup.subtree_control" ]
}

# enable_controllers DIR: cpu, memory and pids in DIR's cgroup.subtree_control, each on its own so one the parent
# does not offer is named and the others still go in. tego machine check then reports what is missing.
enable_controllers() {
	local dir=$1 c ok=0
	for c in "${controllers[@]}"; do
		if grep -qw -- "$c" "$dir/cgroup.subtree_control" 2>/dev/null; then
			continue
		fi
		if ! printf '+%s\n' "$c" >"$dir/cgroup.subtree_control" 2>/dev/null; then
			say "could not enable the $c controller in $dir (is it in $dir/cgroup.controllers?)"
			ok=1
		fi
	done
	return "$ok"
}

# evacuate_root MOUNT: every process of the namespace root moved into MOUNT/init. cgroup v2 lets a cgroup that is not
# the system's root enable controllers for its children only while it holds no process itself, and the container's
# namespace root is such a cgroup. A process that exits between the read and the move is not an error; one that keeps
# appearing (nothing should be starting here yet) fails after a few passes.
evacuate_root() {
	local mount=$1 pass pid left
	mkdir -p "$mount/init"
	for pass in 1 2 3 4 5; do
		left=0
		while IFS= read -r pid; do
			[ -n "$pid" ] || continue
			left=1
			printf '%s\n' "$pid" >"$mount/init/cgroup.procs" 2>/dev/null || true
		done <"$mount/cgroup.procs"
		[ "$left" -eq 0 ] && return 0
		[ "$pass" -lt 5 ] && sleep 0.1
	done
	# A plain directory standing in for the mount (the tests) keeps what was written: report, do not loop forever.
	say "processes are still in the namespace root after 5 passes: $(tr '\n' ' ' <"$mount/cgroup.procs")"
	return 1
}

# delegate MOUNT UID GID SELF: builds user.slice/user-UID.slice/user@UID.service under MOUNT, delegated to UID:GID,
# and moves process SELF into its init.scope. Prints the service directory.
delegate() {
	local mount=$1 uid=$2 gid=$3 self=$4
	local slice="$mount/user.slice" uslice="$mount/user.slice/user-$uid.slice"
	local svc="$uslice/user@$uid.service"
	local rc=0
	# Called from a condition, where errexit does not apply: every step that must hold says so itself.
	evacuate_root "$mount" || return 1
	enable_controllers "$mount" || rc=1
	mkdir -p "$slice" "$uslice" "$svc/init.scope" || return 1
	enable_controllers "$slice" || rc=1
	enable_controllers "$uslice" || rc=1
	# SELF goes into the leaf before the service enables controllers below itself: a cgroup with a process of its own
	# could not.
	printf '%s\n' "$self" >"$svc/init.scope/cgroup.procs" || return 1
	enable_controllers "$svc" || rc=1
	# What systemd's Delegate= hands the user: the directory, its cgroup.procs (moving processes within the subtree),
	# cgroup.subtree_control and cgroup.threads. The interface files a parent sets for a child (memory.max, ...)
	# stay root's, so the user cannot raise the subtree's own limits.
	chown "$uid:$gid" "$svc" "$svc/cgroup.procs" "$svc/cgroup.subtree_control" "$svc/cgroup.threads" || return 1
	chown "$uid:$gid" "$svc/init.scope" "$svc/init.scope/cgroup.procs" || return 1
	printf '%s\n' "$svc"
	return "$rc"
}

# prepare_root MOUNT: for a launcher that stays root (TEGO_LAUNCHER=root): the namespace root emptied into init/ and
# offering cpu, memory and pids, which is where a root tego makes its runs' cgroups (tego.slice under the mount).
prepare_root() {
	local mount=$1
	evacuate_root "$mount" || return 1
	enable_controllers "$mount" || return 1
}

# setup_cgroup MOUNT PROCFILE UID GID SELF MODE [LAUNCHER]: step 1, with MODE auto|yes|no and LAUNCHER user (the
# default: the delegated subtree) or root (prepare_root). Returns non-zero only under yes.
setup_cgroup() {
	local mount=$1 procfile=$2 uid=$3 gid=$4 self=$5 mode=$6 launcher=${7:-user} own why=""
	case "$mode" in
	no) return 0 ;;
	auto | yes) ;;
	*)
		say "TEGO_DELEGATE=$mode: want auto, yes or no"
		return 2
		;;
	esac
	own=$(own_cgroup "$procfile")
	svc="$mount/user.slice/user-$uid.slice/user@$uid.service"
	if ! is_cgroup2 "$mount"; then
		why="$mount is not a cgroup v2 hierarchy (tego needs cgroup v2 on the host)"
	elif [ "$launcher" = root ] && [ "$own" = /init ]; then
		# A later root process of this container: root places a run's agent anywhere in the tree, so nothing to join.
		return 0
	elif [ "$own" = /init ] && [ -d "$svc/init.scope" ]; then
		# A later process of this container (docker exec tego-entrypoint ...): the container's first start built the
		# subtree and moved every process of the namespace root into /init, where the runtime starts an exec'd
		# process beside PID 1. Only this script makes /init at a namespace root, so this is the container's own tree.
		if printf '%s\n' "$self" >"$svc/init.scope/cgroup.procs" 2>/dev/null; then
			say "joined the cgroup subtree delegated to $user: $svc"
			return 0
		fi
		why="could not move this process into $svc/init.scope"
	elif [ "$own" != "/" ]; then
		why="this container shares a cgroup namespace (it sits at ${own:-an unnamed cgroup}); run it with a private one (compose cgroup: private, docker run --cgroupns=private), so the subtree is built in the container's own tree and never in the host's"
	elif ! make_writable "$mount"; then
		why="$mount is read-only and could not be remounted read-write: the container needs CAP_SYS_ADMIN and an AppArmor profile that allows the remount (compose.yaml's cap_add and security_opt), or a runtime that mounts it read-write"
	elif [ "$launcher" = root ]; then
		if prepare_root "$mount"; then
			say "cgroup namespace root emptied into $mount/init for a root launcher"
			return 0
		fi
		why="the namespace root could not be prepared for a root launcher (see the lines above)"
	elif ! svc=$(delegate "$mount" "$uid" "$gid" "$self"); then
		why="the subtree is only partly built${svc:+ at $svc} (see the lines above)"
	fi
	if [ -z "$why" ]; then
		say "cgroup subtree delegated to $user: $svc"
		return 0
	fi
	say "no delegated cgroup subtree: $why"
	say "tego run will refuse to start until there is one; tego doctor shows the cgroupv2 line (docs/site/containers.md)"
	[ "$mode" = yes ] && return 1
	return 0
}

# own_dir DIR UID GID: DIR exists and belongs to UID:GID. Only the directory itself: a ledger or a work tree that
# someone else's files sit in is theirs to fix, and a recursive chown on every start would cost a large ledger.
own_dir() {
	local dir=$1 uid=$2 gid=$3
	[ -d "$dir" ] || install -d -m 0700 -o "$uid" -g "$gid" "$dir"
	if [ "$(stat -c %u "$dir")" != "$uid" ]; then
		say "$dir belonged to uid $(stat -c %u "$dir"); handing it to $user ($uid)"
		chown "$uid:$gid" "$dir"
	fi
}

# read_lsm_list KERNEL_FILE SECFS_DIR: the kernel's active security-module list in LSM_LIST (as /sys/kernel/security/lsm
# prints it, without the newline) and the way it was read in LSM_LIST_WAY. First the kernel's file; where securityfs is not
# mounted (every container's own /sys), securityfs mounted read-only on SECFS_DIR for the moment. Fails, with the reason in
# LSM_LIST_WHY, when neither can be read.
read_lsm_list() {
	local kernel_file=$1 secfs=$2 list="" rc
	LSM_LIST="" LSM_LIST_WHY="" LSM_LIST_WAY=""
	if list=$(cat -- "$kernel_file" 2>/dev/null) && [ -n "$list" ]; then
		LSM_LIST_WAY=$kernel_file LSM_LIST=${list%$'\n'}
		return 0
	fi
	if ! mkdir -p -- "$secfs" 2>/dev/null; then
		LSM_LIST_WHY="$kernel_file is not readable and $secfs cannot be made for a securityfs mount"
		return 1
	fi
	# A new securityfs mount shows the same kernel instance the host has; read-only, and gone again as soon as it is read.
	if mount -t securityfs -o ro,nosuid,nodev,noexec securityfs "$secfs" 2>/dev/null; then
		list=$(cat -- "$secfs/lsm" 2>/dev/null) && rc=0 || rc=1
		umount -- "$secfs" 2>/dev/null || say "could not unmount the securityfs mount at $secfs"
		rmdir -- "$secfs" 2>/dev/null || true
		if [ "$rc" -eq 0 ] && [ -n "$list" ]; then
			LSM_LIST_WAY="securityfs mounted read-only at $secfs" LSM_LIST=${list%$'\n'}
			return 0
		fi
		LSM_LIST_WHY="securityfs mounted but its lsm file could not be read"
		return 1
	fi
	rmdir -- "$secfs" 2>/dev/null || true
	LSM_LIST_WHY="$kernel_file is not readable here and securityfs cannot be mounted (it needs CAP_SYS_ADMIN and a profile that allows mount: compose.yaml's cap_add and security_opt)"
	return 1
}

# lsm_list_ok LIST: whether LIST is a list the kernel could print: module names (lower case, digits, underscore) separated by
# commas, at most 64, with capability among them, which every kernel has active. tego checks the same on the file it reads.
lsm_list_ok() {
	local list=$1 n
	[[ $list =~ ^[a-z0-9_]+(,[a-z0-9_]+)*$ ]] || return 1
	[[ ",$list," == *,capability,* ]] || return 1
	n=$(printf '%s' "$list" | tr ',' '\n' | wc -l)
	[ "$n" -lt 64 ]
}

# hand_in_lsm_list FILE KERNEL_FILE SECFS_DIR BOOT_ID_FILE MODE: step 3, with MODE auto|yes|no. Writes FILE (root's, 0644, in
# a directory only root can write, written whole under another name and renamed into place) in the format lsmlist reads:
#   tego-lsm-list 1 / boot_id <this boot's id> / lsm <the list>
# and removes a FILE that is left from an earlier start when no list can be read now, so a stale one is never taken. Returns
# non-zero only under yes.
hand_in_lsm_list() {
	local out=$1 kernel_file=$2 secfs=$3 bootid_file=$4 mode=$5 dir list boot tmp=""
	case "$mode" in
	no) return 0 ;;
	auto | yes) ;;
	*)
		say "TEGO_LSM_LIST=$mode: want auto, yes or no"
		return 2
		;;
	esac
	dir=$(dirname -- "$out")
	if ! read_lsm_list "$kernel_file" "$secfs"; then
		rm -f -- "$out"
		say "no security-module list handed in: $LSM_LIST_WHY"
		say "held file opens are refused until it is: docker run --cap-add SYS_ADMIN with apparmor=unconfined (compose.yaml), or bind the host's /sys/kernel/security/lsm read-only and name it in /etc/tego/config.yaml lsm.list_file (docs/user/container.md)"
		[ "$mode" = yes ] && return 1
		return 0
	fi
	list=$LSM_LIST
	if ! lsm_list_ok "$list"; then
		rm -f -- "$out"
		say "no security-module list handed in: what was read ($LSM_LIST_WAY) is not a list the kernel prints"
		[ "$mode" = yes ] && return 1
		return 0
	fi
	if ! read -r boot <"$bootid_file" 2>/dev/null || [ -z "$boot" ]; then
		rm -f -- "$out"
		say "no security-module list handed in: $bootid_file cannot be read, so the list could not be tied to this boot"
		[ "$mode" = yes ] && return 1
		return 0
	fi
	# Root's, in a directory only root can write: tego refuses the file otherwise (and anything under a directory the user
	# can write), so the mode and owner are set on the directory every time, not only when it is made.
	if ! { mkdir -p -- "$dir" && chmod 0755 -- "$dir" && chown 0:0 -- "$dir" &&
		tmp=$(mktemp -- "$dir/.lsm-list.XXXXXX") &&
		printf 'tego-lsm-list 1\nboot_id %s\nlsm %s\n' "$boot" "$list" >"$tmp" &&
		chmod 0644 -- "$tmp" && chown 0:0 -- "$tmp" && mv -f -- "$tmp" "$out"; }; then
		[ -z "$tmp" ] || rm -f -- "$tmp"
		rm -f -- "$out"
		say "no security-module list handed in: $out could not be written"
		[ "$mode" = yes ] && return 1
		return 0
	fi
	say "security-module list handed in at $out (read from $LSM_LIST_WAY): $list"
	return 0
}

# has_cap BIT: whether this process's effective set has capability BIT (capabilities(7) numbering).
has_cap() {
	local eff
	eff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
	[ -n "$eff" ] && (((16#$eff >> $1) & 1))
}

main() {
	if [ "$#" -eq 0 ]; then
		set -- tego doctor
	fi
	if [ "$(id -u)" -ne 0 ]; then
		exec "$@"
	fi
	local uid gid home launcher=${TEGO_LAUNCHER:-user}
	uid=$(id -u "$user")
	gid=$(id -g "$user")
	home=$(getent passwd "$user" | cut -d: -f6)
	case "$launcher" in
	user | root) ;;
	*)
		say "TEGO_LAUNCHER=$launcher: want user or root"
		exit 2
		;;
	esac
	setup_cgroup /sys/fs/cgroup /proc/self/cgroup "$uid" "$gid" "$$" "${TEGO_DELEGATE:-auto}" "$launcher"
	own_dir "$home/.tego" "$uid" "$gid"
	own_dir /var/lib/tego/runs "$uid" "$gid"
	own_dir /work "$uid" "$gid"
	hand_in_lsm_list "${TEGO_LSM_LIST_FILE:-/run/tego-lsm/lsm-list}" /sys/kernel/security/lsm /run/tego-lsm/.securityfs /proc/sys/kernel/random/boot_id "${TEGO_LSM_LIST:-auto}"
	if [ "$launcher" = root ]; then
		# Experimental (docs/site/containers.md): tego stays root with the container's
		# capabilities, which the root tiers need, and runs the agent as the tego user, as `sudo tego run` runs it as
		# SUDO_UID's (identity-config R19). Nothing is dropped here: whatever the container was given, tego holds.
		say "TEGO_LAUNCHER=root: tego runs as root with the container's capabilities; the agent as $user ($uid)"
		export SUDO_UID="$uid" SUDO_GID="$gid" SUDO_USER="$user"
		exec "$@"
	fi
	# The runtime directory a login session would give the user (/run/user/<uid>): tego keeps a run's CODEX_HOME
	# there, and refuses a Codex run routed through its forwarder without one (internal/runtime, ErrNoRuntimeDir).
	install -d -m 0700 -o "$uid" -g "$gid" "/run/user/$uid"
	export HOME="$home" USER="$user" LOGNAME="$user" XDG_RUNTIME_DIR="/run/user/$uid"
	local drop=(--reuid="$uid" --regid="$gid" --init-groups --inh-caps=-all --no-new-privs)
	# Clearing the bounding set needs CAP_SETPCAP (8). Without it the set keeps what the container was given, which
	# no_new_privs leaves unreachable to the user (no setuid or file-capability gain after it), so say so and go on.
	if has_cap 8; then
		drop+=(--bounding-set=-all)
	else
		say "no CAP_SETPCAP: the bounding set is left as the container's (unreachable under no_new_privs)"
	fi
	exec setpriv "${drop[@]}" -- "$@"
}

if [ "${TEGO_ENTRYPOINT_LIB:-0}" != 1 ]; then
	main "$@"
fi
