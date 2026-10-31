#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# tego-entrypoint.sh: the container image's entrypoint (docs/user/container.md). Started as root, it does the two
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
# Then it drops to the user for good: setpriv with the user's uid, gid and groups, no inheritable, ambient or
# bounding capabilities, and no_new_privs, so neither tego nor the agent holds anything the container was given for
# step 1. Started as any other user (`--user`, compose's `user:`), it does nothing and runs the command as given:
# tego-control serve is started that way.
#
# TEGO_DELEGATE: auto (default) builds the subtree when it can and otherwise says why and carries on, so `tego doctor`
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
# does not offer is named and the others still go in. tego doctor then reports what is missing.
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
	say "tego run will refuse to start until there is one; tego doctor shows the cgroupv2 line (docs/user/container.md)"
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
	if [ "$launcher" = root ]; then
		# Experimental (docs/user/container.md, "Tiers that need root"): tego stays root with the container's
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
