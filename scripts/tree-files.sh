#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# tree-files.sh — prints, NUL-separated, the working tree's own files as they are now: tracked plus untracked and
# not ignored, minus a tracked file that has been deleted from the working tree but not yet from the index.
# `git ls-files -co` lists such a file, and `tar -T` then dies on it, so a copy of the tree for the KVM guest
# (test/vm/root-suites.sh, scripts/coverage.sh) takes this list instead. Run from inside the repository.
set -euo pipefail
git ls-files -z -co --exclude-standard --deduplicate | while IFS= read -r -d '' f; do
	if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
done
