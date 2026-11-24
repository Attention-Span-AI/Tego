#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests host-facts.sh, which prints the versions of the host packages a guest copies, with a dpkg-query that answers
# for the cases: an installed package, one removed with its configuration left (rc), one this host never had.
#
# Usage: test/vm/host-facts_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { echo "FAIL $*" >&2; exit 1; }
bin="$(mktemp -d)"
trap 'rm -rf "$bin"' EXIT
cat >"$bin/dpkg-query" <<'FAKE'
#!/usr/bin/env bash
case "${!#}" in
python3) printf 'ii  3.13.7-1' ;;
git) printf 'ii  1:2.51.0-1ubuntu1' ;;
nodejs) printf 'rc  20.19.2+dfsg-1' ;;
*) echo "dpkg-query: no packages found matching ${!#}" >&2; exit 1 ;;
esac
FAKE
chmod +x "$bin/dpkg-query"
got="$(PATH="$bin:$PATH" "$here/host-facts.sh" python3 git nodejs nosuch)"
want="python3 3.13.7-1
git 1:2.51.0-1ubuntu1
nodejs absent
nosuch absent"
[ "$got" = "$want" ] || fail "got:
$got
want:
$want"
grep -q 'host-facts.sh" python3 git nodejs' "$here/root-suites.sh" || fail "root-suites.sh does not record python3, git and nodejs"
echo "ok host-facts.sh"
