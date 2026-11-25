#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-paths.py against planted names: one of each kind it must refuse, the names it must accept, an empty list,
# a tree walked with --root, and the checker's own run over this checkout.
set -euo pipefail
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-paths-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
fail=0
# run NAME WANT-EXIT PATH...: the paths go to the checker as one NUL-separated list.
run() {
	local name=$1 want=$2 rc=0
	shift 2
	printf '%s\0' "$@" | python3 -I "$here/check-paths.py" --list - >"$tmp/out" 2>&1 || rc=$?
	if [ "$rc" -eq "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $rc, want $want" >&2
		cat "$tmp/out" >&2
		fail=1
	fi
}
long=$(printf 'd%.0s' $(seq 1 241))
run "plain names pass" 0 a/b.go docs/x.md 'dir with space/file name.txt' 'unit@.service' 'a/%5C.conf' 'a/con-x.txt' 'a/console.go' 'a/com10.txt'
run "a backslash fails" 1 'a/b\x2dc.service'
run "a backslash in a folder fails" 1 'a\x2d.d/b.conf'
run "a colon fails" 1 'a/b:c'
run "an asterisk fails" 1 'a/b*c'
run "a question mark fails" 1 'a/b?c'
run "a double quote fails" 1 'a/b"c'
run "a less-than fails" 1 'a/b<c'
run "a greater-than fails" 1 'a/b>c'
run "a vertical bar fails" 1 'a/b|c'
run "a control character fails" 1 $'a/b\tc'
run "a name ending in a dot fails" 1 'a/b.'
run "a folder ending in a dot fails" 1 'a/b./c'
run "a name ending in a space fails" 1 'a/b '
for d in CON PRN AUX NUL COM1 COM9 LPT1 LPT9 con Nul lpt3 Com5; do
	run "device name $d fails" 1 "a/$d"
	run "device name $d with an extension fails" 1 "a/$d.txt"
done
run "a device name as a folder fails" 1 'aux/file.go'
run "two paths that differ only in case fail" 1 a/Readme.md a/README.md
run "two folders that differ only in case fail" 1 Docs/a.md docs/b.md
run "the same path twice is one path" 0 a/b a/b
run "a path of 240 characters passes" 0 "${long:0:240}"
run "a path of 241 characters fails" 1 "$long"
run "an empty list refuses" 2
# root NAME WANT-EXIT [ARGS...]: the checker over a folder.
root() {
	local name=$1 want=$2 rc=0
	shift 2
	python3 -I "$here/check-paths.py" "$@" >"$tmp/out" 2>&1 || rc=$?
	if [ "$rc" -eq "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $rc, want $want" >&2
		cat "$tmp/out" >&2
		fail=1
	fi
}
mkdir -p "$tmp/tree/sub"
: >"$tmp/tree/sub/ok.txt"
root "--root over a clean tree" 0 --root "$tmp/tree"
: >"$tmp/tree/sub/bad:name"
root "--root over a tree with a colon" 1 --root "$tmp/tree"
root "--root over a folder that is not there refuses" 2 --root "$tmp/missing"
# Line endings: the checker run inside a scratch repository that holds copies of itself. A script needs text=auto and
# eol=lf from .gitattributes and no CR in its bytes; a fixture marked -text may hold CRLF.
eolrepo() {
	local name=$1 want=$2 attrs=$3 script=$4 late=${5:-} rc=0 d="$tmp/eol"
	rm -rf "$d"
	mkdir -p "$d/scripts" "$d/fix"
	cp "$here/check-paths.py" "$here/tree-files.sh" "$d/scripts/"
	printf '%b' "$script" >"$d/scripts/run.sh"
	printf 'a\r\nb\r\n' >"$d/fix/data.yaml"
	git -C "$d" init -q
	# late: the CRLF script is committed before .gitattributes exists, so the rules cannot normalise it.
	[ -n "$late" ] || printf '%s' "$attrs" >"$d/.gitattributes"
	git -C "$d" -c core.autocrlf=false -c core.safecrlf=false add -A 2>/dev/null
	[ -z "$late" ] || { printf '%s' "$attrs" >"$d/.gitattributes"; git -C "$d" add .gitattributes; }
	python3 -I "$d/scripts/check-paths.py" >"$tmp/out" 2>&1 || rc=$?
	if [ "$rc" -eq "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $rc, want $want" >&2
		cat "$tmp/out" >&2
		fail=1
	fi
}
good=$'* text=auto eol=lf\nfix/*.yaml -text\n'
eolrepo "a script under text=auto eol=lf passes, a -text CRLF fixture too" 0 "$good" '#!/bin/sh\necho hi\n'
eolrepo "no .gitattributes fails" 1 '' '#!/bin/sh\necho hi\n'
eolrepo "text=auto without eol=lf fails" 1 $'* text=auto\nfix/*.yaml -text\n' '#!/bin/sh\necho hi\n'
eolrepo "eol=crlf on scripts fails" 1 $'* text=auto eol=lf\n*.sh text eol=crlf\nfix/*.yaml -text\n' '#!/bin/sh\necho hi\n'
eolrepo "a script marked -text fails" 1 $'* text=auto eol=lf\n*.sh -text\nfix/*.yaml -text\n' '#!/bin/sh\necho hi\n'
eolrepo "a script committed with CRLF fails even under the right attributes" 1 "$good" '#!/bin/sh\r\necho hi\r\n' late
# This checkout's own files.
root "this checkout's tracked paths" 0
exit "$fail"
