#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests check-control-pin.sh with stand-in binaries: shell scripts that print what tego version and tego-control
# version print, the one pinning the other's hash in a comment the way the linker embeds the -X value.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
check=$here/check-control-pin.sh
dir=$(mktemp -d "${TMPDIR:-/tmp}/check-control-pin.XXXXXX")
trap 'rm -rf "$dir"' EXIT
fails=0
want() { # want <exit> <description> <args...>
	local code=$1 what=$2
	shift 2
	local got=0
	"$check" "$@" >"$dir/out" 2>&1 || got=$?
	if [ "$got" -ne "$code" ]; then
		echo "FAIL: $what: exit $got, want $code: $(cat "$dir/out")"
		fails=$((fails + 1))
	else
		echo "ok: $what"
	fi
}
# control prints its version; its own hash is computed after it is written, so its sha256 line reads a file.
write_control() { # write_control <version>
	cat >"$dir/tego-control" <<EOF
#!/bin/sh
printf 'tego-control=$1\ncommit=abc\ndate=d\ngo=go1\nsha256=%s\n' "\$(cat "$dir/control.sum")"
EOF
	chmod +x "$dir/tego-control"
	sha256sum "$dir/tego-control" | cut -d' ' -f1 >"$dir/control.sum"
}
write_tego() { # write_tego <version> <pin>
	cat >"$dir/tego" <<EOF
#!/bin/sh
# pin $2
printf 'tego=$1\ncommit=abc\ndate=d\ngo=go1\ncontrol_sha256=$2\n'
EOF
	chmod +x "$dir/tego"
}
write_control v1
sum=$(cat "$dir/control.sum")
write_tego v1 "$sum"
if [ "$(id -u)" -ne 0 ]; then
	want 0 "a matched pair" "$dir/tego" "$dir/tego-control"
	write_tego v2 "$sum"
	want 1 "a pair of two versions" "$dir/tego" "$dir/tego-control"
fi
want 0 "a matched pair, static" --static "$dir/tego" "$dir/tego-control"
write_tego v1 "$(printf '%064d' 0)"
want 1 "a tego that pins another hash" "$dir/tego" "$dir/tego-control"
want 1 "a tego that pins another hash, static" --static "$dir/tego" "$dir/tego-control"
want 1 "a missing tego-control" "$dir/tego" "$dir/none"
want 2 "no arguments"
[ "$fails" -eq 0 ] || exit 1
echo "check-control-pin_test: all passed"
