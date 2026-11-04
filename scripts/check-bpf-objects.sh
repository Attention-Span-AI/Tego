#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-bpf-objects.sh — the committed bpf2go output and its adoption metadata must be
# byte-for-byte what `make gen` makes of the committed tree. A build inside a .claude/worktrees checkout, or with
# any other clang, embeds different BTF bytes, and nothing else notices: this extracts the tree into a fresh
# directory, runs `make gen` there (pinned toolchain, scripts/bpf-toolchain.sh) and compares every generated file
# with the committed one.
#
# The scratch directory has a FIXED path (/tmp/tego-bpf-check/tree): clang's BTF output is not path-independent
# (the order of some type-name strings changes with the directory `make gen` runs in), so committed objects and this
# check must come from one path. --fix writes what make gen made there into internal/bpf; commit that.
#
# Usage: scripts/check-bpf-objects.sh [--worktree | --fix]
#   default     the tree is `git archive HEAD` (CI's bpf-gen job; what a commit already made)
#   --worktree  the tree is the working tree as it is now (tracked plus untracked, as scripts/tree-files.sh
#               lists it), so precommit checks what is about to be committed
#   --fix       as --worktree, then replaces internal/bpf's generated files with what make gen made (no check)
# Environment: BPF_CHECK_REPO (the repository; default this script's), BPF_TOOLCHAIN (the toolchain directory,
#   make gen's variable), BPF_CHECK_TMP (the scratch directory;
#   default /tmp/tego-bpf-check; set only by the self-test).
# Exit: 0 when identical, 1 when files differ (listed, with the fix command), 2 on a setup failure.
set -uo pipefail

mode="head"
case "${1:-}" in
'') ;;
--worktree) mode=worktree ;;
--fix) mode=fix ;;
*) echo "usage: $0 [--worktree | --fix]" >&2; exit 2 ;;
esac
repo="${BPF_CHECK_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
tmp="${BPF_CHECK_TMP:-/tmp/tego-bpf-check}"
# The path is fixed (clang's BTF depends on it) and /tmp is shared: refuse a directory another user pre-created or a
# symlink, and take it to 0700, so nobody else can swap the tree make gen runs in.
if [ -L "$tmp" ] || { [ -e "$tmp" ] && { [ ! -d "$tmp" ] || [ ! -O "$tmp" ]; }; }; then
	echo "check-bpf-objects: $tmp is not a directory owned by you (remove it, or set BPF_CHECK_TMP)" >&2
	exit 2
fi
# shellcheck source=scripts/safe-output-dir.sh
. "$(dirname -- "$0")/safe-output-dir.sh"
# Preserve the canonical BTF path when upgrading an old check's lock-only directory.
# Any unmarked generated state still refuses; the guard migrates only an empty lock.
tmp=$(safe_output_dir "$tmp" .tego-bpf-check "$repo" lock) || exit 2
chmod 700 "$tmp" || exit 2
# One run at a time: the path is fixed. The lock lives inside the verified directory.
if command -v flock >/dev/null; then
	exec 9>"$tmp/lock" && flock 9
fi
rm -rf "$tmp/tree" "$tmp/want"
trap 'rm -rf "$tmp/tree" "$tmp/want" "$tmp/gen.log"' EXIT
mkdir "$tmp/tree" "$tmp/want" || exit 2

cd "$repo" || exit 2
if [ "$mode" = head ]; then
	git archive HEAD | tar -x -C "$tmp/tree" || { echo "check-bpf-objects: git archive failed" >&2; exit 2; }
else
	"$repo/scripts/tree-files.sh" | tar --null -T - -c | tar -x -C "$tmp/tree" ||
		{ echo "check-bpf-objects: copying the working tree failed" >&2; exit 2; }
fi
# The committed side, before make gen removes it.
for f in "$tmp"/tree/internal/bpf/*_bpfe[lb].* "$tmp/tree/internal/bpf/adoption_specs_gen.go"; do
	[ -e "$f" ] && cp "$f" "$tmp/want/"
done

echo "check-bpf-objects: make gen in a clean copy of the tree ($mode)"
gen=(make -C "$tmp/tree" gen)
[ -z "${BPF_TOOLCHAIN:-}" ] || gen+=("BPF_TOOLCHAIN=$BPF_TOOLCHAIN")
if ! "${gen[@]}" >"$tmp/gen.log" 2>&1; then
	tail -40 "$tmp/gen.log" | sed 's/^/    /'
	echo "check-bpf-objects: make gen failed" >&2
	exit 2
fi

if [ "$mode" = fix ]; then
	rm -f "$repo"/internal/bpf/*_bpfe[lb].* "$repo/internal/bpf/adoption_specs_gen.go"
	for f in "$tmp"/tree/internal/bpf/*_bpfe[lb].* "$tmp/tree/internal/bpf/adoption_specs_gen.go"; do
		[ ! -e "$f" ] || cp "$f" "$repo/internal/bpf/" || exit 2
	done
	echo "check-bpf-objects: internal/bpf rewritten from the fixed-path make gen; commit it with explicit paths"
	exit 0
fi

bad=()
declare -A seen=()
for f in "$tmp"/want/*; do
	[ -e "$f" ] || continue
	n="$(basename "$f")"
	seen[$n]=1
	g="$tmp/tree/internal/bpf/$n"
	if [ ! -e "$g" ]; then
		bad+=("$n (committed, but make gen no longer makes it)")
	elif ! cmp -s "$f" "$g"; then
		bad+=("$n")
	fi
done
for g in "$tmp"/tree/internal/bpf/*_bpfe[lb].* "$tmp/tree/internal/bpf/adoption_specs_gen.go"; do
	[ -e "$g" ] || continue
	n="$(basename "$g")"
	[ -n "${seen[$n]:-}" ] || bad+=("$n (made by make gen, not committed)")
done

if [ "${#bad[@]}" -gt 0 ]; then
	echo "check-bpf-objects: internal/bpf differs from what make gen produces from a clean tree:"
	printf '    %s\n' "${bad[@]}"
	echo "fix: scripts/check-bpf-objects.sh --fix, then commit those files with explicit paths."
	echo "     (Not a plain \`make gen\` in the checkout: its bytes depend on the checkout's path.)"
	exit 1
fi
echo "check-bpf-objects: ok (${#seen[@]} files identical)"
