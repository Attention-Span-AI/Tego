#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests tree-files.sh in a throwaway repository: a tracked file removed from the working tree (but not the index)
# is left out of the list and the tar copy of it succeeds; tracked, modified and untracked files, and one with a
# space in its name, are in it; an ignored one is not.
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-tree-files-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

git init -q "$tmp/work"
cd "$tmp/work"
git config user.email t@example.invalid
git config user.name t
git config commit.gpgsign false
echo kept >kept
echo gone >gone
echo ign >ignored
echo ignored >.gitignore
git add kept gone .gitignore
git commit -q -m one
rm gone
echo new >"un tracked"

mkdir "$tmp/copy"
"$here/tree-files.sh" | tar --null -T - -cf - | tar -xf - -C "$tmp/copy" ||
	{ echo "FAIL: copying the tree with a deleted tracked file failed"; exit 1; }
got=$(cd "$tmp/copy" && find . -type f | LC_ALL=C sort | tr '\n' ' ')
want="./.gitignore ./kept ./un tracked "
if [ "$got" != "$want" ]; then
	echo "FAIL: copied '${got}', want '${want}'"
	exit 1
fi
echo "ok   tree-files.sh skips a deleted tracked file and keeps the rest"
