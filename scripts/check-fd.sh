#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-fd.sh — ADR 0023's descriptor rules that forbidigo cannot hold, run by tools/fdcheck on every package
# type-checked under each build the project ships (linux amd64 and arm64, with the lint's tags, the release tag
# and none; cgo and s390x for the files those miss): the birth rule (a fresh number becomes a sys.FD owner where it is created),
# leases and lent numbers (used only in the ways tools/fdcheck/lent.go admits), the listed Adopt, Abandon,
# Inherited and Stdio sites, close-on-exec, exported APIs that pass bare numbers, and the ratchet: every package
# not yet migrated is counted in tools/fdcheck/baseline.txt, exactly, and any other package has no raw close,
# dup, os.NewFile, Fd() or unowned producer at all. It also checks that the generated producer and edge lists are
# current and that no product binary links test code (F11). `make lint`, scripts/precommit.sh and CI's
# build-test run it; with --base, CI's bench-gate job and precommit also hold each kind's total, and the F4 lists', to
# the base's, and each package's count of each kind to the base's: it rises only by sites moved from another
# package (same kind and form, in a declaration that left the one package and arrived in the other).
#
# Usage: scripts/check-fd.sh [--base REV] [root]   (from anywhere; root is the checkout, this one by default)
# Exit: fdcheck's: 0 when every rule holds, 1 when one does not, 2 when the files could not be read or type-checked.
set -uo pipefail

base=()
if [ "${1:-}" = --base ]; then
	[ -n "${2:-}" ] || { echo "check-fd.sh: --base needs a revision" >&2; exit 2; }
	base=(-base "$2")
	shift 2
fi
root="${1:-}"
if [ -n "$root" ]; then
	root="$(cd "$root" && pwd)" || exit 2
fi
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
if [ -z "$root" ]; then
	root="$PWD"
fi
# Built, not `go run`: go run answers 1 for any failing exit, and the exit codes above are fdcheck's own.
bin="$(mktemp -d "${TMPDIR:-/tmp}/tego-fdcheck.XXXXXX")" || exit 2
trap 'rm -rf "$bin"' EXIT
"${GO:-go}" build -o "$bin/fdcheck" ./tools/fdcheck || exit 2
st=0
"$bin/fdcheck" "${base[@]}" "$root" || st=$?
exit "$st"
