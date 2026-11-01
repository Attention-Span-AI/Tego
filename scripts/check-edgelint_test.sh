#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-edgelint_test.sh — .golangci.yml's edge socket ban ("the edge opens no socket", ADR 0100 (1d)) against its
# fixture, internal/control/web/testdata/edgelint: every dial, listen, name lookup, HTTP client call and raw socket
# the fixture marks ("want the edge opens no socket") is reported once, on its line, and nothing else in the fixture
# is (the descriptors the edge is handed, its servers and the link's HTTP/2 connection stay allowed). The fixture
# sits inside the edge's packages, so the rule is run with its real path scope. This holds what golangci-lint
# reports. dialers.go imports the packages that dial or listen inside their own calls (the standard
# library's net/rpc, net/smtp, log/syslog and net/http/httptest, and golang.org/x/net's ctxhttp, dict, icmp, nettest,
# proxy and websocket), each of which the edge's depguard rule denies.
# golangci-lint is GOLANGCI_LINT, else the one on PATH, else ci.yml's pinned version installed into a temporary
# directory.
# Exit: 0 when all hold, 1 otherwise.
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$here/.."
GO=${GO:-go}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-check-edgelint-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
fixture=internal/control/web/testdata/edgelint
marker='the edge opens no socket'
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

st=0
"$LINT" run --config .golangci.yml --max-same-issues=0 --max-issues-per-linter=0 --enable-only forbidigo,depguard \
	--output.text.print-issued-lines=false --output.text.colors=false --show-stats=false "./$fixture/" \
	>"$tmp/issues" 2>"$tmp/err" || st=$?
if [ "$st" -gt 1 ] || grep -q '(typecheck)' "$tmp/issues"; then
	echo "FAIL: golangci-lint on $fixture exited $st:"
	sed 's/^/    /' "$tmp/issues" "$tmp/err"
	exit 1
fi

grep -n "// want $marker\$" "$fixture/edgelint.go" | cut -d: -f1 | sed "s#^#$fixture/edgelint.go:#" | sort >"$tmp/want"
sed -n "s/^\([^:]*:[0-9]*\):[0-9]*: .*$marker.*(forbidigo)\$/\1/p" "$tmp/issues" | sort >"$tmp/got"
if [ "$(wc -l <"$tmp/want")" -lt 100 ]; then
	echo "FAIL: the fixture marks only $(wc -l <"$tmp/want") lines; the marks were lost"
	fail=1
elif ! diff -u "$tmp/want" "$tmp/got" >"$tmp/diff"; then
	echo "FAIL: the edge rule's reports differ from the fixture's marked lines (- marked, + reported):"
	sed 's/^/    /' "$tmp/diff"
	fail=1
else
	echo "ok   one edge socket report on each of the $(wc -l <"$tmp/want") marked primitives, and none elsewhere"
fi

# The packages that dial or listen inside their own calls are denied whole by the edge's depguard rule.
grep -n '// want edge-holds-no-authority$' "$fixture/dialers.go" | cut -d: -f1 | sed "s#^#$fixture/dialers.go:#" | sort >"$tmp/want"
sed -n 's/^\([^:]*:[0-9]*\):[0-9]*: .*edge-holds-no-authority.*(depguard)$/\1/p' "$tmp/issues" | sort >"$tmp/got"
if [ "$(wc -l <"$tmp/want")" -lt 10 ]; then
	echo "FAIL: dialers.go marks only $(wc -l <"$tmp/want") imports; the marks were lost"
	fail=1
elif ! diff -u "$tmp/want" "$tmp/got" >"$tmp/diff"; then
	echo "FAIL: the edge's depguard reports differ from dialers.go's marked imports (- marked, + reported):"
	sed 's/^/    /' "$tmp/diff"
	fail=1
else
	echo "ok   the edge's depguard rule denies each of the $(wc -l <"$tmp/want") packages that dial inside their calls"
fi

[ "$fail" -eq 0 ] && echo "check-edgelint_test: ok"
exit "$fail"
