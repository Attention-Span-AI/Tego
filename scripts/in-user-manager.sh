#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# in-user-manager.sh — runs a command inside the invoking user's systemd user manager, in a scope of its own
# under user@<uid>.service: the place an unprivileged tego run can put its agent in its run cgroup
# (docs/p0/runtime-launch.md case 41).
#
# Why it exists: a process outside that subtree finds it delegated, writable and usable for everything but
# placing a process in it. The kernel moves a process into a cgroup only for a writer of the cgroup.procs of
# the source's and the destination's common ancestor, and under systemd that ancestor is root's for a login
# over ssh (its session-<n>.scope) and for a service, such as the one a CI runner starts its steps from. So
# from there every unprivileged run is refused before it starts (cgroup's FS.CanPlace, doctor's D3), and the
# unit and integration suites cannot exercise one. `systemd-run --user --scope` has the user manager ask the
# system manager to move this process into a new scope of the user's subtree and then execs the command, so
# the command keeps this shell's environment, standard streams and exit status.
#
# A process already inside user@<uid>.service runs the command as it is, as does root, which places its runs
# from the cgroup2 root.
#
# Usage: scripts/in-user-manager.sh COMMAND [ARG...]
# Exit: the command's own status; 1 when there is no user manager to run it in; 2 on a usage error.
set -eu
[ $# -gt 0 ] || { echo "usage: scripts/in-user-manager.sh COMMAND [ARG...]" >&2; exit 2; }
uid="$(id -u)"
[ "$uid" != 0 ] || exec "$@"
case "$(sed -n 's/^0:://p' /proc/self/cgroup)" in
*/user@"$uid".service/*) exec "$@" ;;
esac
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$uid}"
if [ ! -S "$XDG_RUNTIME_DIR/systemd/private" ]; then
	echo "in-user-manager: uid $uid has no systemd user manager ($XDG_RUNTIME_DIR/systemd/private is not a socket);" \
		"start one with loginctl enable-linger $(id -un)" >&2
	exit 1
fi
exec systemd-run --user --scope --quiet -- "$@"
