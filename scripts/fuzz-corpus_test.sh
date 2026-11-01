#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run the actual workflow corpus-count blocks with GitHub's Linux bash flags.
# A cache miss starts from zero; failed directory setup or listing still fails.
set -euo pipefail
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
workflow="$here/../.github/workflows/fuzz.yml"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-fuzz-corpus-test.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
fail=0
extract() {
	awk -v name="$1" '
	$0 == "      - name: " name { found=1; next }
	found && /^        run:/ {
		command=$0; sub(/^        run: */, "", command)
		if (command == "|") { body=1; next }
		print command; emitted=1; exit
	}
	body && /^          / { sub(/^          /, ""); print; emitted=1; next }
	body { exit }
	END { if (!emitted) exit 2 }
	' "$workflow" >"$tmp/block"
}
check() {
	local name=$1 want=$2 count=$3 corpus=$4 rc=0
	shift 4
	CORPUS="$corpus" "$@" bash --noprofile --norc -e -o pipefail "$tmp/block" >"$tmp/out" 2>"$tmp/err" || rc=$?
	if [ "$rc" -eq "$want" ] && { [ "$count" = any ] || [ "$(tr -d '[:space:]' <"$tmp/out")" = "$count" ]; }; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $rc, want $want; count $(cat "$tmp/out"), want $count" >&2
		cat "$tmp/err" >&2
		fail=1
	fi
}
mkdir "$tmp/bin"
cat >"$tmp/bin/find" <<'EOF'
#!/bin/sh
exit 23
EOF
chmod +x "$tmp/bin/find"
for direction in in out; do
	extract "corpus carried $direction"
	corpus="$tmp/step-$direction/empty"
	check "$direction: fresh cache counts zero" 0 0 "$corpus" env
	[ -d "$corpus" ] || { echo "FAIL $direction: absent corpus was not initialized" >&2; fail=1; }
	# Keep the remaining controls independent of the fresh-cache verdict.
	mkdir -p "$corpus"
	printf x >"$corpus/first"
	printf x >"$corpus/second with spaces"
	check "$direction: restored corpus counts both entries" 0 2 "$corpus" env
	printf x >"$tmp/step-$direction/not-a-directory"
	check "$direction: invalid corpus path refuses" 1 any "$tmp/step-$direction/not-a-directory/child" env
	check "$direction: failed listing is not zero success" 23 any "$corpus" env PATH="$tmp/bin:$PATH"
done
exit "$fail"
