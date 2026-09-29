#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests python-pkgs.sh: the python packages the guest is built from follow the host's interpreter, not a version
# kvm-run.sh names (it named 3.13, and a host on 3.12 staged no stdlib, so the guest's python3 could not start),
# and kvm-run.sh takes its list from that function.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-pypkgs-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
# shellcheck source=test/vm/python-pkgs.sh
. "$here/python-pkgs.sh"

fail=0
want() { # want NAME LINK WANT: python_host_pkgs over a symlink to a file called LINK's target name
	local name=$1 target=$2 expect=$3 got
	mkdir -p "$tmp/$name"
	: >"$tmp/$name/$target"
	ln -sf "$target" "$tmp/$name/python3"
	got=$(python_host_pkgs "$tmp/$name/python3")
	if [ "$got" = "$expect" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: got \"$got\", want \"$expect\"" >&2
		fail=1
	fi
}
want 3.12 python3.12 "python3.12-minimal libpython3.12-minimal libpython3.12-stdlib"
want 3.13 python3.13 "python3.13-minimal libpython3.13-minimal libpython3.13-stdlib"
want 3.9 python3.9 "python3.9-minimal libpython3.9-minimal libpython3.9-stdlib"
want unrecognised pypy ""

if grep -q 'python3\.1[0-9]-minimal\|libpython3\.1[0-9]' "$here/kvm-run.sh"; then
	echo "FAIL kvm-run.sh names a python version" >&2
	fail=1
fi
grep -q 'python_host_pkgs' "$here/kvm-run.sh" || { echo "FAIL kvm-run.sh does not use python_host_pkgs" >&2; fail=1; }
[ "$fail" = 0 ] && echo "ok   python-pkgs_test.sh"
exit "$fail"
