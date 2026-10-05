#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests that bench.py's measure_hyperfine leaves no --export-json file behind in TMPDIR, on a run that
# succeeds, one whose timed runs failed and one where hyperfine itself failed. A stand-in hyperfine on PATH
# writes the export the way the real one does.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "SKIP bench_test.sh: no python3"; exit 0; }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-bench-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

mkdir -p "$tmp/bin" "$tmp/t"
cat >"$tmp/bin/hyperfine" <<'EOF'
#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do
	[ "$1" = --export-json ] && out="$2"
	shift
done
case "${FAKE_HF:-ok}" in
fail) echo "boom" >&2; exit 3 ;;
badrun) code=1 ;;
*) code=0 ;;
esac
printf '{"results":[{"median":0.1,"stddev":0.01,"min":0.09,"max":0.11,"times":[0.1],"exit_codes":[%s]}]}\n' "$code" >"$out"
EOF
chmod +x "$tmp/bin/hyperfine"

leftovers() { find "$tmp/t" -type f | wc -l; }
run() {
	FAKE_HF="$1" PATH="$tmp/bin:$PATH" TMPDIR="$tmp/t" python3 - "$here" <<'PY' >/dev/null 2>&1
import sys
sys.path.insert(0, sys.argv[1])
import bench
bench.measure_hyperfine(None, "true", 0, 1)
PY
}

run ok || fail "measure_hyperfine failed against the stand-in hyperfine"
[ "$(leftovers)" = 0 ] || fail "a successful measurement left its export file in TMPDIR"
run badrun && fail "a failing timed run was not reported"
[ "$(leftovers)" = 0 ] || fail "a measurement with failing timed runs left its export file in TMPDIR"
run fail && fail "a failing hyperfine was not reported"
[ "$(leftovers)" = 0 ] || fail "a failing hyperfine left its export file in TMPDIR"
echo "ok bench_test.sh"
