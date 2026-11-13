#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fails when a source file lacks an SPDX header. Exempt: bpf/include/vmlinux.h, bpf2go output, the site's generated
# files under web/, and internal/selftest/contract.yaml.tmpl, whose output is a contract in the user's hands.
# It also fails when git cannot list the files, or lists none: a check that read nothing would pass
# vacuously. Paths go through NUL-separated lists, so a name with a space is one file.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tmp="$(mktemp)"
listed="$(mktemp)"
trap 'rm -f "$tmp" "$listed"' EXIT
# The tree's own files (tracked or new, minus an unstaged deletion), plus the extensionless hook.
if ! ./scripts/tree-files.sh >"$listed"; then
  echo "check-spdx: listing the tree's files failed; is this a git checkout?" >&2
  exit 2
fi
# grep's no-match status is valid; an unreadable list or failed producer is not.
filtered=0
grep -zE '\.(go|rs|c|h|sh|py|css|js|cjs|tmpl)$' "$listed" >"$tmp" || filtered=$?
if [ "$filtered" -gt 1 ]; then
  echo "check-spdx: filtering the tree's files failed" >&2
  exit 2
fi
printf '.githooks/pre-commit\0' >>"$tmp"
if [ ! -s "$tmp" ]; then
  echo "check-spdx: the file list held no source file; nothing was checked" >&2
  exit 2
fi
status=0
n=0
while IFS= read -r -d '' f; do
  case "$f" in
    bpf/include/vmlinux.h|internal/bpf/*_bpfel.go|internal/bpf/*_bpfeb.go|internal/selftest/contract.yaml.tmpl|web/*) continue ;;
  esac
  n=$((n + 1))
  if ! head -3 -- "$f" | grep -q 'SPDX-License-Identifier'; then
    echo "missing SPDX header: $f"; status=1
  fi
done <"$tmp"
[ "$n" -gt 0 ] || { echo "check-spdx: every listed file was exempt; nothing was checked" >&2; exit 2; }
exit "$status"
