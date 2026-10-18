#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run_tests.sh -- the toy project's "test suite" (README.md): it fails while a source file still carries a FIXME marker,
# and names the file, as a failing test does. It is a program of its own, which the agent starts, and it uses bash
# builtins only, so a contract has to allow no program but bash for it.
fail=0 n=0
for f in src/*.py; do
	n=$((n + 1))
	line=0
	while IFS= read -r text; do
		line=$((line + 1))
		if [[ $text == *FIXME* ]]; then
			echo "FAIL $f:$line $text"
			fail=1
		fi
	done <"$f"
done
[ "$fail" = 0 ] && echo "OK $n files"
exit "$fail"
