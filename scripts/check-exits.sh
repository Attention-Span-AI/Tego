#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-exits.sh — the two exit-code rules limits-check-doctor-cli.md states as CI checks, I6 (nothing but cmd/
# ends the process) and I9 (internal/cli returns no bare non-zero integer). The checks are tools/checkexits's,
# on the Go syntax tree: the grep this script held missed an aliased os.Exit and a call split across lines, and
# its exclude pathspec listed no file at all on git 2.51, so I9 checked nothing.
#
# Usage: scripts/check-exits.sh [root]   (from anywhere; root is the checkout to check, this one by default)
# Exit: 0 when both hold; non-zero when either does not or the files could not be read.
set -uo pipefail

root="${1:-}"
if [ -n "$root" ]; then
	root="$(cd "$root" && pwd)" || exit 2
fi
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
if [ -z "$root" ]; then
	root="$PWD"
fi
exec "${GO:-go}" run ./tools/checkexits "$root"
