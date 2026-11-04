#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced by tools which reuse a caller-selected output directory. Prints its
# physical path, or refuses before deletion. An empty/new directory can be claimed;
# a nonempty one needs the tool's own regular, nonsymlink marker.
# The BPF check may explicitly name its legacy empty lock as a fourth argument.
safe_output_dir() (
	sod_dir=$1 sod_marker=$2 sod_repo=$3
	sod_legacy_lock=${4:-}
	sod_lock_is_empty() {
		[ ! -L "$sod_dir/lock" ] && [ -f "$sod_dir/lock" ] && [ -O "$sod_dir/lock" ] &&
			[ "$(stat -c '%h:%s' -- "$sod_dir/lock")" = 1:0 ]
	}
	while [ "${sod_dir%/}" != "$sod_dir" ]; do sod_dir=${sod_dir%/}; done
	if [ -z "$sod_dir" ] || [ -L "$sod_dir" ]; then
		echo "refusing output directory: empty, root or symlink: $1" >&2; return 2
	fi
	mkdir -p -- "$sod_dir" || return 2
	[ -O "$sod_dir" ] || { echo "output directory is not owned by you: $sod_dir" >&2; return 2; }
	sod_dir=$(cd -- "$sod_dir" && pwd -P) || return 2
	case $sod_dir in /) echo "refusing root as output: $sod_dir" >&2; return 2 ;; esac
	sod_home_dir=$(cd -- "$HOME" && pwd -P) || return 2
	sod_repo=$(cd -- "$sod_repo" && pwd -P) || return 2
	case "$sod_home_dir/" in "$sod_dir/"*) echo "refusing home or its ancestor as output: $sod_dir" >&2; return 2 ;; esac
	case "$sod_repo/" in "$sod_dir/"*) echo "refusing checkout or its ancestor as output: $sod_dir" >&2; return 2 ;; esac
	if [ -L "$sod_dir/$sod_marker" ] || { [ -e "$sod_dir/$sod_marker" ] && [ ! -f "$sod_dir/$sod_marker" ]; }; then
		echo "refusing invalid ownership marker: $sod_dir/$sod_marker" >&2; return 2
	fi
	if [ ! -f "$sod_dir/$sod_marker" ]; then
		# Emit a nonnewline per entry: command substitution trims newline-only names.
		sod_entries=$(find "$sod_dir" -mindepth 1 -maxdepth 1 -printf x) || return 2
		if [ -n "$sod_entries" ] && [ "$sod_legacy_lock" = lock ] &&
			command -v flock >/dev/null && sod_lock_is_empty; then
			# Old BPF checks leave only this empty lock after cleanup. Wait for
			# its owner, then recheck both the lock and every other entry.
			exec 9<>"$sod_dir/lock" || return 2
			flock 9 || return 2
			sod_lock_is_empty || { echo "refusing changed legacy lock: $sod_dir/lock" >&2; return 2; }
			sod_entries=$(find "$sod_dir" -mindepth 1 -maxdepth 1 ! -name lock -printf x) || return 2
		fi
		[ -z "$sod_entries" ] || {
			echo "$sod_dir was not made by this tool (no $sod_marker); refusing nonempty output directory" >&2; return 2
		}
		(set -C; : >"$sod_dir/$sod_marker") || return 2
	fi
	printf '%s\n' "$sod_dir"
)
