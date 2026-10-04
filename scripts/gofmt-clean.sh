#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# gofmt-clean.sh — fails, naming the files, when gofmt would reformat one. Shared by `make lint` and
# scripts/precommit.sh so neither swallows the list (a bare `test -z "$(gofmt -l .)"` prints nothing).
# Usage: scripts/gofmt-clean.sh [FILE...]   (no files: the Go files git tracks or would add)
# Exit: 0 when clean, 1 when a file would change.
set -uo pipefail
if [ $# -gt 0 ]; then
	files="$(gofmt -l "$@")" || exit 1
else
	cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
	files="$(./scripts/tree-files.sh | grep -zE '\.go$' | xargs -0 -r gofmt -l)" || exit 1
fi
[ -z "$files" ] || { echo "gofmt would reformat (run gofmt -w on them):"; echo "$files"; exit 1; }
