#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-fd_test.sh — .golangci.yml's ADR 0023 rules against their fixture, scripts/testdata/fdlint (ADR 0023 C3):
#   1. every primitive A4 forbids is reported once, on its marked line ("want ADR 0023"), and nothing else in the
#      fixture is (an alias, a value, a method expression and the amd64-only primitives included);
#   2. a non-test file that imports internal/testutil is denied (depguard testutil-never-in-binary, A7);
#   3. ADR 0021's exclusion is scoped to ADR 0021's messages: pointed at the fixture's proc package, it hides the
#      process start there and still lets ADR 0023's rule report; without its text: line it would hide both
#      (the negative control, which proves the scoping is what keeps proc under ADR 0023);
#   4. check-fd.sh hands fdcheck the root it is given (a directory git does not track exits 2) and refuses a
#      --base without a revision. Its run on this checkout is the gate's own step (make lint, precommit and CI
#      run check-fd.sh beside this test), and fdcheck_test.go's TestTreeRatchetAndPlantedSites holds the tree
#      to its baseline, so this test does not check the tree a third time.
# golangci-lint is GOLANGCI_LINT, else the one on PATH, else ci.yml's pinned version installed into a temporary
# directory.
# Exit: 0 when all hold, 1 otherwise.
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$here/.."
GO=${GO:-go}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-check-fd-test.XXXXXX")
variant=.golangci-fdtest.yml
trap 'rm -rf "$tmp" "$variant"' EXIT INT TERM
fixture=scripts/testdata/fdlint
fail=0

LINT=${GOLANGCI_LINT:-}
if [ -z "$LINT" ]; then
	if command -v golangci-lint >/dev/null; then
		LINT=golangci-lint
	else
		ver=$(sed -n 's/^ *version: \(v2\.[0-9.]*\)$/\1/p' .github/workflows/ci.yml | head -n 1)
		[ -n "$ver" ] || { echo "FAIL: no golangci-lint version in ci.yml"; exit 1; }
		GOBIN="$tmp/bin" "$GO" install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$ver"
		LINT="$tmp/bin/golangci-lint"
	fi
fi

# lint CONFIG PKG...: the forbidigo and depguard issues into $tmp/issues; fails on anything but "issues found"
# or "none", and on a type-check error, which would hide the fixture's lines.
lint() {
	local cfg=$1 st=0
	shift
	"$LINT" run --config "$cfg" --max-same-issues=0 --max-issues-per-linter=0 --enable-only forbidigo,depguard \
		--output.text.print-issued-lines=false --output.text.colors=false --show-stats=false "$@" \
		>"$tmp/issues" 2>"$tmp/err" || st=$?
	if [ "$st" -gt 1 ] || grep -q '(typecheck)' "$tmp/issues"; then
		echo "FAIL: golangci-lint $* exited $st:"
		sed 's/^/    /' "$tmp/issues" "$tmp/err"
		return 1
	fi
}

# 1. One report per forbidden primitive, on exactly the marked lines.
arch=$("$GO" env GOARCH)
: >"$tmp/want"
for f in "$fixture"/*.go; do
	case "$f" in *_amd64.go) [ "$arch" = amd64 ] || continue ;; esac
	grep -n '// want ADR 0023$' "$f" | cut -d: -f1 | sed "s#^#$f:#" >>"$tmp/want"
done
sort -o "$tmp/want" "$tmp/want"
if lint .golangci.yml "./$fixture/" "./$fixture/binary/"; then
	sed -n 's/^\([^:]*:[0-9]*\):[0-9]*: .*ADR 0023.*(forbidigo)$/\1/p' "$tmp/issues" | sort >"$tmp/got"
	if [ "$(wc -l <"$tmp/want")" -lt 30 ]; then
		echo "FAIL: the fixture marks only $(wc -l <"$tmp/want") lines; the marks were lost"
		fail=1
	elif ! diff -u "$tmp/want" "$tmp/got" >"$tmp/diff"; then
		echo "FAIL: ADR 0023's reports differ from the fixture's marked lines (- marked, + reported):"
		sed 's/^/    /' "$tmp/diff"
		fail=1
	else
		echo "ok   one ADR 0023 report on each of the $(wc -l <"$tmp/want") marked primitives, and none elsewhere"
	fi
	# 2. depguard.
	if grep -q "^$fixture/binary/binary.go:[0-9]*:[0-9]*: .*testutil-never-in-binary.*(depguard)$" "$tmp/issues"; then
		echo "ok   a non-test file importing internal/testutil is denied"
	else
		echo "FAIL: depguard did not deny $fixture/binary's import of internal/testutil:"
		sed 's/^/    /' "$tmp/issues"
		fail=1
	fi
else
	fail=1
fi

# 3. ADR 0021's exclusion, pointed at the fixture's proc package.
sed 's#^      - path: (_test\\.go\$|internal/platform/proc/|#      - path: (_test\\.go$|scripts/testdata/fdlint/proc/|internal/platform/proc/|#' \
	.golangci.yml >"$variant"
if ! grep -q 'scripts/testdata/fdlint/proc/' "$variant"; then
	echo "FAIL: ADR 0021's exclusion line changed; update this test's sed with it"
	fail=1
elif lint "$variant" "./$fixture/proc/"; then
	want="$fixture/proc/proc.go:$(grep -n '// want ADR 0023$' "$fixture/proc/proc.go" | cut -d: -f1)"
	if grep -q "^$want:[0-9]*: .*ADR 0023.*(forbidigo)$" "$tmp/issues" && ! grep -q 'ADR 0021' "$tmp/issues"; then
		echo "ok   ADR 0021's exclusion hides the process start and leaves ADR 0023's close reported"
	else
		echo "FAIL: under ADR 0021's exclusion, want $want reported for ADR 0023 and no ADR 0021 report, have:"
		sed 's/^/    /' "$tmp/issues"
		fail=1
	fi
	# The negative control: the same exclusion without its text: line hides the close too.
	sed -i '/^        text: ADR 0021$/d' "$variant"
	if lint "$variant" "./$fixture/proc/" && ! grep -q 'ADR 0023' "$tmp/issues"; then
		echo "ok   without its text: scope the exclusion would hide ADR 0023's report (the negative control)"
	else
		echo "FAIL: the unscoped exclusion did not hide the close; the positive case above proves nothing:"
		sed 's/^/    /' "$tmp/issues"
		fail=1
	fi
else
	fail=1
fi

# 4. The script itself: the root it is given, and its --base argument.
mkdir "$tmp/untracked"
st=0
GO="$GO" ./scripts/check-fd.sh "$tmp/untracked" >"$tmp/out" 2>&1 || st=$?
if [ "$st" = 2 ] && grep -q 'git ls-files' "$tmp/out"; then
	echo "ok   check-fd.sh checks the root it is given (an untracked directory exits 2)"
else
	echo "FAIL: check-fd.sh on an untracked directory exited $st, want 2 from git ls-files:"
	sed 's/^/    /' "$tmp/out"
	fail=1
fi
st=0
./scripts/check-fd.sh --base >"$tmp/out" 2>&1 || st=$?
if [ "$st" = 2 ]; then
	echo "ok   check-fd.sh --base without a revision exits 2"
else
	echo "FAIL: check-fd.sh --base without a revision exited $st, want 2"
	fail=1
fi

[ "$fail" -eq 0 ] && echo "check-fd_test: ok"
exit "$fail"
