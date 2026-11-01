#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests install-maze.sh against a made-up release in a temporary folder (no network): it installs and the binary
# runs and the licence notices land beside it; an archive without them still installs and says where they are; a changed archive is refused with exit 7 before anything is installed; a missing release exits 5; every
# curl call is held to https and an https redirect.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; *) arch=arm64 ;; esac
v=9.9.9
rel="$tmp/base/v$v"
mkdir -p "$rel" "$tmp/src"
printf '#!/bin/sh\necho "maze %s (fake)"\n' "$v" >"$tmp/src/maze"
chmod 755 "$tmp/src/maze"
archive="maze_${v}_${os}_${arch}.tar.gz"
for f in LICENSE NOTICE THIRD_PARTY_NOTICES.txt; do echo "$f text" >"$tmp/src/$f"; done
tar -czf "$rel/$archive" -C "$tmp/src" maze LICENSE NOTICE THIRD_PARTY_NOTICES.txt
if command -v sha256sum >/dev/null 2>&1; then sum=$(sha256sum "$rel/$archive" | awk '{print $1}'); else sum=$(shasum -a 256 "$rel/$archive" | awk '{print $1}'); fi
echo "$sum  $archive" >"$rel/tego_${v}_checksums.txt"

fail() { echo "FAIL: $1" >&2; exit 1; }

MAZE_BASE_URL="file://$tmp/base" MAZE_VERSION="v$v" MAZE_PREFIX="$tmp/bin" sh "$here/install-maze.sh" >"$tmp/out" 2>&1 || fail "install failed: $(cat "$tmp/out")"
"$tmp/bin/maze" | grep -q "maze $v" || fail "installed binary doesn't run"
grep -q "Installed maze v$v" "$tmp/out" || fail "no success line: $(cat "$tmp/out")"
for f in LICENSE NOTICE THIRD_PARTY_NOTICES.txt; do
	[ -s "$tmp/share/doc/maze/$f" ] || fail "$f did not land beside the install: $(cat "$tmp/out")"
done

# An archive without the notices still installs, and the line says where they are.
mkdir -p "$tmp/bare/v$v"
tar -czf "$tmp/bare/v$v/$archive" -C "$tmp/src" maze
if command -v sha256sum >/dev/null 2>&1; then bare=$(sha256sum "$tmp/bare/v$v/$archive" | awk '{print $1}'); else bare=$(shasum -a 256 "$tmp/bare/v$v/$archive" | awk '{print $1}'); fi
echo "$bare  $archive" >"$tmp/bare/v$v/tego_${v}_checksums.txt"
MAZE_BASE_URL="file://$tmp/bare" MAZE_VERSION="v$v" MAZE_PREFIX="$tmp/nodoc/bin" sh "$here/install-maze.sh" >"$tmp/out" 2>&1 || fail "install without notices failed: $(cat "$tmp/out")"
grep -q "Licence notices: in file://$tmp/bare" "$tmp/out" || fail "no pointer to the notices: $(cat "$tmp/out")"

echo tampered >>"$rel/$archive"
rm "$tmp/bin/maze"
code=0
MAZE_BASE_URL="file://$tmp/base" MAZE_VERSION="v$v" MAZE_PREFIX="$tmp/bin" sh "$here/install-maze.sh" >"$tmp/out" 2>&1 || code=$?
[ "$code" -eq 7 ] || fail "a changed archive gave exit $code, want 7: $(cat "$tmp/out")"
[ ! -e "$tmp/bin/maze" ] || fail "a changed archive was installed"

code=0
MAZE_BASE_URL="file://$tmp/base" MAZE_VERSION="v0.0.1" MAZE_PREFIX="$tmp/bin" sh "$here/install-maze.sh" >"$tmp/out" 2>&1 || code=$?
[ "$code" -eq 5 ] || fail "a missing release gave exit $code, want 5: $(cat "$tmp/out")"

# Every curl call is held to https (file:// for this test) and an https redirect, as install.sh's are.
mkdir -p "$tmp/fake"
real_curl=$(command -v curl)
printf '#!/bin/sh\necho "$*" >>"%s/curl.args"\nexec "%s" "$@"\n' "$tmp" "$real_curl" >"$tmp/fake/curl"
chmod 755 "$tmp/fake/curl"
rm -f "$tmp/bin/maze"
PATH="$tmp/fake:$PATH" MAZE_BASE_URL="file://$tmp/base" MAZE_VERSION="v0.0.1" MAZE_PREFIX="$tmp/bin" sh "$here/install-maze.sh" >"$tmp/out" 2>&1 || true
PATH="$tmp/fake:$PATH" MAZE_BASE_URL="file://$tmp/base" MAZE_API_URL="file://$tmp/none" MAZE_PREFIX="$tmp/bin" sh "$here/install-maze.sh" >"$tmp/out" 2>&1 || true
[ -s "$tmp/curl.args" ] || fail "the fake curl was never run"
[ "$(grep -c . "$tmp/curl.args")" -ge 2 ] || fail "want the download and the latest-release lookup: $(cat "$tmp/curl.args")"
if grep -v -- "--proto =https,file --proto-redir =https" "$tmp/curl.args"; then fail "a curl call is not held to https"; fi

echo "install-maze: ok"
