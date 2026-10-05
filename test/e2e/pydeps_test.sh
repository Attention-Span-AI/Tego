#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests the supply-chain pins of pydeps.sh (no network): pip's bootstrapper is refused unless it matches its
# pinned sha256, is fetched from a commit-pinned URL and never from the moving bootstrap.pypa.io copy, and the
# SDK requirement lists pin every package to a version and a hash and are installed with --require-hashes.
# Each case fails on the former unpinned `curl bootstrap.pypa.io/get-pip.py | python3` and `pip install pkg==ver`.
#
# Usage: test/e2e/pydeps_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-pydeps-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

# shellcheck source=test/e2e/get-pip.sh
. "$here/get-pip.sh"

# 1. The pin: a versioned (commit) URL, a 64-hex digest, and no use of the moving copy anywhere.
case "$GET_PIP_URL" in
https://raw.githubusercontent.com/pypa/get-pip/[0-9a-f]*/public/get-pip.py) ;;
*) fail "GET_PIP_URL is not a commit-pinned URL: $GET_PIP_URL" ;;
esac
[[ "$GET_PIP_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "GET_PIP_SHA256 is not a sha256"
if grep -n 'bootstrap.pypa.io' "$here/pydeps.sh" "$here/overhead/run.sh" | grep -v '^[^:]*:[0-9]*:[[:space:]]*#'; then
	fail "a script still fetches get-pip.py from the moving bootstrap.pypa.io copy"
fi

# 2. A download that does not match the digest is refused and removed; one that matches is kept.
printf 'print("pwned")\n' >"$tmp/evil.py"
TEGO_GET_PIP_URL="file://$tmp/evil.py" fetch_get_pip "$tmp/got.py"
[ $? = 2 ] || fail "a get-pip.py with the wrong digest was accepted"
[ ! -e "$tmp/got.py" ] || fail "the refused get-pip.py was left on disk"
GET_PIP_SHA256="$(sha256sum "$tmp/evil.py" | cut -d' ' -f1)"
TEGO_GET_PIP_URL="file://$tmp/evil.py" fetch_get_pip "$tmp/got.py" || fail "a get-pip.py with the right digest was refused"
TEGO_GET_PIP_URL="file://$tmp/absent.py" fetch_get_pip "$tmp/got2.py" 2>/dev/null
[ $? = 1 ] || fail "a failed download did not return 1"

# 3. Every requirement in the SDK lists is exact and hashed, and pydeps.sh installs them with --require-hashes.
for f in "$here"/pydeps/*.txt; do
	[ -s "$f" ] || fail "$f is empty"
	# Join continuation lines, then check each requirement.
	sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$f" | grep -v '^#' | grep -v '^$' >"$tmp/reqs"
	[ -s "$tmp/reqs" ] || fail "$f has no requirements"
	while IFS= read -r line; do
		[[ "$line" =~ ^[A-Za-z0-9_.-]+==[0-9][^[:space:]]*[[:space:]]+--hash=sha256:[0-9a-f]{64} ]] ||
			fail "$f: a requirement without an exact version and a sha256: $line"
	done <"$tmp/reqs"
done
# The wheelhouse list (kill test 4's pip kind and the benchmark) is held to the same rule and downloaded with it.
wl="$here/../workloads/build/python/requirements.txt"
sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$wl" | grep -v '^#' | grep -v '^$' >"$tmp/reqs"
[ -s "$tmp/reqs" ] || fail "$wl has no requirements"
while IFS= read -r line; do
	[[ "$line" =~ ^[A-Za-z0-9_.-]+==[0-9][^[:space:]]*[[:space:]]+--hash=sha256:[0-9a-f]{64} ]] ||
		fail "$wl: a requirement without an exact version and a sha256: $line"
done <"$tmp/reqs"
grep -Eq 'pip download .*--require-hashes' "$here/pydeps.sh" || fail "pydeps.sh downloads the wheelhouse without --require-hashes"
grep -Eq 'pip download .*--require-hashes' "$here/overhead/run.sh" || fail "overhead/run.sh downloads the wheelhouse without --require-hashes"
grep -q 'anthropic==' "$here/pydeps/anthropic.txt" || fail "pydeps/anthropic.txt does not pin anthropic"
grep -q 'claude-agent-sdk==' "$here/pydeps/claude-sdk.txt" || fail "pydeps/claude-sdk.txt does not pin claude-agent-sdk"
av="$(sed -n 's/^ANTHROPIC_VERSION="\(.*\)"/\1/p' "$here/pydeps.sh")"
cv="$(sed -n 's/^CLAUDE_SDK_VERSION="\(.*\)"/\1/p' "$here/pydeps.sh")"
grep -q "^anthropic==$av " "$here/pydeps/anthropic.txt" || fail "pydeps/anthropic.txt disagrees with ANTHROPIC_VERSION=$av"
grep -q "^claude-agent-sdk==$cv " "$here/pydeps/claude-sdk.txt" || fail "pydeps/claude-sdk.txt disagrees with CLAUDE_SDK_VERSION=$cv"
[ "$(grep -c -e '--require-hashes' "$here/pydeps.sh")" -ge 2 ] || fail "pydeps.sh does not install the SDKs with --require-hashes"
# 4. Each site's stamp covers its pin file: with a stand-in pip, editing a transitive pin without bumping the
# top-level version installs the site again, and an unchanged list is not installed twice.
mkdir -p "$tmp/r/test/e2e" "$tmp/r/test/workloads/build/python" "$tmp/c/pip-bootstrap/pip"
cp -r "$here/pydeps.sh" "$here/get-pip.sh" "$here/pydeps" "$tmp/r/test/e2e/"
cp "$here/../workloads/build/python/requirements.txt" "$tmp/r/test/workloads/build/python/"
: >"$tmp/c/pip-bootstrap/pip/__init__.py"
cat >"$tmp/c/pip-bootstrap/pip/__main__.py" <<'PY'
import os, sys
a = sys.argv[1:]
with open(os.environ["FAKE_PIP_LOG"], "a") as f:
    f.write(" ".join(a) + "\n")
for flag in ("--target", "-d"):
    if flag in a:
        os.makedirs(a[a.index(flag) + 1], exist_ok=True)
PY
export FAKE_PIP_LOG="$tmp/pip.log"
: >"$FAKE_PIP_LOG"
"$tmp/r/test/e2e/pydeps.sh" --claude-sdk "$tmp/c" >/dev/null || fail "pydeps.sh with a stand-in pip failed"
[ "$(grep -c 'pydeps/anthropic.txt' "$FAKE_PIP_LOG")" = 1 ] || fail "the first run did not install the anthropic site once"
: >"$FAKE_PIP_LOG"
"$tmp/r/test/e2e/pydeps.sh" --claude-sdk "$tmp/c" >/dev/null || fail "second pydeps.sh run failed"
[ ! -s "$FAKE_PIP_LOG" ] || fail "an unchanged cache was installed again: $(cat "$FAKE_PIP_LOG")"
echo "# a changed transitive pin" >>"$tmp/r/test/e2e/pydeps/anthropic.txt"
echo "# a changed transitive pin" >>"$tmp/r/test/e2e/pydeps/claude-sdk.txt"
"$tmp/r/test/e2e/pydeps.sh" --claude-sdk "$tmp/c" >/dev/null || fail "third pydeps.sh run failed"
grep -q 'pydeps/anthropic.txt' "$FAKE_PIP_LOG" || fail "an edited pydeps/anthropic.txt left the stale anthropic site in use"
grep -q 'pydeps/claude-sdk.txt' "$FAKE_PIP_LOG" || fail "an edited pydeps/claude-sdk.txt left the stale claude-sdk site in use"
echo "pydeps_test: ok"
