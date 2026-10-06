#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# doctor-facts.sh — what the kernel matrix keeps per row and boot from the text of `tego doctor` as root, on stdin:
#
#   landlock_abi=<n>  the Landlock ABI (D4's line), 0 where the kernel has none;
#   cgroup_mode=<m>   the decision plane tier cgroup decides opens by on this boot (the "decision plane:" clause of
#                     D7's line): lsm, fmod_ret, or fanotify, the fallback; none where doctor offers neither tier
#                     cgroup nor tier bpflsm, since no plane is selected where no tier runs (Ubuntu 22.04's 5.15 prints
#                     a fanotify clause and has no tier); unknown where a tier cgroup is offered and the clause is not
#                     one of the three, so a change to doctor's words shows as "unknown" and not as a row that has none.
#
# ADR 0021 (7) ends the fanotify listener's enforcement role "when every matrix row, amd64 and arm64, selects a plane
# mode for one release". This is that sentence as a column, per row and per boot, in matrix.sh's summary.json: a row
# whose cgroup_mode is fanotify on any boot is one that keeps the listener alive. run-matrix-row.sh prints it after
# `MATRIX-FACTS `, test/vm/doctor-facts_test.sh holds the parser to lines doctor printed in guests.
#
# Usage: tego doctor | doctor-facts.sh
# Exit 0 with one line on stdout; 1, with nothing on stdout, when the input has no `tier:` line (it is not doctor's).
set -uo pipefail

text="$(cat)"
tier="$(sed -nE 's/^tier: ([a-z]+).*/\1/p' <<<"$text" | head -1)"
if [ -z "$tier" ]; then
	echo "doctor-facts: no tier line in doctor's output" >&2
	exit 1
fi
abi="$(sed -nE 's/^(ok|FAIL|skip) +landlock: ABI ([0-9]+).*/\2/p' <<<"$text" | head -1)"
mode=none
case "$tier" in
cgroup | bpflsm)
	mode="$(grep -oE '; decision plane: (lsm|fmod_ret|fanotify)( |;|$)' <<<"$text" | head -1 | sed -E 's/; decision plane: (lsm|fmod_ret|fanotify).*/\1/')"
	[ -n "$mode" ] || mode=unknown
	;;
esac
echo "landlock_abi=${abi:-0} cgroup_mode=$mode"
