# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# Helpers the action's scripts source. No side effects when sourced.

die() {
	printf '::error title=tego receipt::%s\n' "$*" >&2
	exit 1
}

warn() {
	printf '::warning title=tego receipt::%s\n' "$*" >&2
}

note() {
	printf 'tego-receipt: %s\n' "$*" >&2
}

# out NAME VALUE: one step output. Values here never hold a newline.
out() {
	case "$2" in *$'\n'* | *$'\r'*) die "internal: output $1 holds a newline" ;; esac
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
	else
		printf '%s=%s\n' "$1" "$2"
	fi
}

# words LIST: an input given one per line or comma separated, as one item per line, blanks and spaces dropped.
words() {
	printf '%s\n' "$1" | /usr/bin/tr ',' '\n' | /usr/bin/sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | /usr/bin/sed '/^$/d'
}

# in_user_manager CMD...: CMD inside the runner user's systemd user manager, where an unprivileged tego run can
# place its agent in a run cgroup. The same rule as Tego's scripts/in-user-manager.sh: root, or a process
# already under user@<uid>.service, runs CMD as it is.
in_user_manager() {
	local uid
	uid="$(/usr/bin/id -u)"
	if [ "$uid" = 0 ]; then
		"$@"
		return
	fi
	case "$(/usr/bin/sed -n 's/^0:://p' /proc/self/cgroup)" in
	*/user@"$uid".service/*)
		"$@"
		return
		;;
	esac
	XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$uid}" /usr/bin/systemd-run --user --scope --quiet -- "$@"
}

# The installer records one absolute path and checksum. Recheck before launch and collection.
verify_binary() {
	local got want
	want="$(/usr/bin/cat "${DIR:?}/state/binary-sha256")"
	got="$(/usr/bin/sha256sum "${TEGO:?}" | /usr/bin/cut -d' ' -f1)"
	[ "$got" = "$want" ] || { printf 'Tego executable changed\n' >&2; exit 125; }
}
