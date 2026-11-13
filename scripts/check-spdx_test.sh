#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Exercise the actual checker and its actual tree-files producer in private
# repositories. Failed or partial enumeration must not become a hook-only PASS;
# a successful no-match filter still checks the extensionless hook.
set -euo pipefail
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-spdx-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
# A caller may place TMPDIR inside a Git checkout; these fixtures own their Git
# discovery boundary rather than accidentally enumerating the caller's tree.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
export GIT_CEILING_DIRECTORIES="$tmp"
fail=0
tree() {
	mkdir -p "$tmp/$1/scripts" "$tmp/$1/.githooks"
	cp "$here/check-spdx.sh" "$here/tree-files.sh" "$tmp/$1/scripts/"
	printf '#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\n' >"$tmp/$1/.githooks/pre-commit"
}
check() {
	local name=$1 want=$2 rc=0
	shift 2
	"$@" >"$tmp/out" 2>&1 || rc=$?
	if [ "$rc" -eq "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $rc, want $want" >&2
		cat "$tmp/out" >&2
		fail=1
	fi
}
tree no-git
check "Git enumeration failure refuses instead of checking only the hook" 2 "$tmp/no-git/scripts/check-spdx.sh"
tree valid
git init -q "$tmp/valid"
printf '// SPDX-License-Identifier: Apache-2.0\npackage x\n' >"$tmp/valid/source with space.go"
check "successful listing checks valid source with a space" 0 "$tmp/valid/scripts/check-spdx.sh"
printf 'package x\n' >"$tmp/valid/missing.go"
check "a listed source without a header fails" 1 "$tmp/valid/scripts/check-spdx.sh"
rm "$tmp/valid/missing.go"
for f in plain.css plain.js plain.cjs plain.tmpl plain.rs; do
	printf 'x\n' >"$tmp/valid/$f"
	check "$f without a header fails" 1 "$tmp/valid/scripts/check-spdx.sh"
	rm "$tmp/valid/$f"
done
mkdir -p "$tmp/valid/internal/selftest"
printf 'version: 0\n' >"$tmp/valid/internal/selftest/contract.yaml.tmpl"
check "the selftest's contract template, a user's text, is exempt" 0 "$tmp/valid/scripts/check-spdx.sh"
tree no-match
git init -q "$tmp/no-match"
printf 'scripts/\n' >"$tmp/no-match/.gitignore"
check "successful grep no-match still checks the hook" 0 "$tmp/no-match/scripts/check-spdx.sh"
printf '#!/bin/sh\n' >"$tmp/no-match/.githooks/pre-commit"
check "no-match never omits the hook header" 1 "$tmp/no-match/scripts/check-spdx.sh"
tree partial
mkdir "$tmp/bin"
cat >"$tmp/bin/git" <<'EOF'
#!/bin/sh
printf 'partial.go\0'
exit 7
EOF
chmod +x "$tmp/bin/git"
printf '// SPDX-License-Identifier: Apache-2.0\npackage x\n' >"$tmp/partial/partial.go"
check "partial producer output does not conceal its failure" 2 env PATH="$tmp/bin:$PATH" "$tmp/partial/scripts/check-spdx.sh"
exit "$fail"
