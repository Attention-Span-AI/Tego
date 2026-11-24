#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# chrome-tests.sh — the browser tests (-tags chrome): every Test function of a file that says `//go:build chrome`, in the
# packages those files are in, each test driving a headless google-chrome ($TEGO_CHROME) over the DevTools pipe. Nothing
# else compiles them: no other step of the gate ran them (B22). Shared by scripts/precommit.sh and CI's chrome-tests job.
#
# Chosen by name, not by running each package whole: the untagged tests of the same packages run in the unit step, and
# chrome's tests are the ones that cost minutes. Why the whole suite took an hour: 142 tests, run one after another with
# one Chrome each, and eleven of them (the `matrix` list below) are matrices of every page at every width, theme and
# script setting, 100 to 423 s each; measured on 2026-11-22 (one run, a box with a load of 3): 51 minutes in all, 39.5
# of them in those eleven (2368 s), 12 in the other 131 (730 s). Without --full the eleven are left out, which leaves
# the gate about 12 minutes (one job, beside the integration tests); --full runs everything. The three operator tools in
# `operator` skip unless a person sets the variable that points them at a ledger or a gallery, and are left out by name.
# Held to an empty skip list by scripts/skipgate.sh (a skip is no pass), and a run that finds no test or no browser fails.
# One package at a time (-p 1): one Chrome runs at once (a run that held several once held 214 renderers and 18 GB).
#
# Usage: scripts/chrome-tests.sh [--full]
# Environment: GO (go), TEGO_CHROME (google-chrome), TEGO_CHROME_TIMEOUT (go test's alarm for the whole run, 45m: a hang
#   guard, never a per-test bound).
# Exit: 0 when every selected test passed; 1 when one failed, skipped, or none could run; 2 on a usage error.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
full=0
case "${1:-}" in
'') ;;
--full) full=1 ;;
*) echo "usage: scripts/chrome-tests.sh [--full]" >&2; exit 2 ;;
esac
GO="${GO:-go}"
matrix='TestInteriorsDisclosuresAndNoScriptInChrome|TestA1NativeRecoveryInChrome|TestFinishPackageNativeInChrome|TestFinishZoomAndSpacingInChrome|TestBuilderMatrixInChrome|TestInteriorsMatrixInChrome|TestA1PagesMatrixInChrome|TestPagePackageMatrixInChrome|TestTourNoScriptMatrixInChrome|TestFinishSupplementalMatrixInChrome|TestTourMatrixInChrome'
operator='TestFinishOwnerGalleryInChrome|TestLogsShotsInChrome|TestLiveShotsInChrome'
chrome="${TEGO_CHROME:-google-chrome}"
command -v "$chrome" >/dev/null || { echo "chrome-tests: no $chrome on PATH (TEGO_CHROME names another): the browser tests cannot run" >&2; exit 1; }
files="$(./scripts/tree-files.sh | tr '\0' '\n' | grep '_test\.go$' | xargs -r grep -l '^//go:build chrome$')"
[ -n "$files" ] || { echo "chrome-tests: no test file says //go:build chrome: a run that finds no test would pass over nothing" >&2; exit 1; }
# shellcheck disable=SC2086 # file names without spaces
dirs="$(dirname $files | sort -u | sed 's#^#./#')"
# shellcheck disable=SC2086
names="$(grep -h '^func Test' $files | sed -E 's/^func (Test[A-Za-z0-9_]*)\(.*/\1/' | sort -u | paste -sd'|')"
skip=$operator
[ "$full" = 1 ] || skip="$skip|$matrix"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-chrome-tests.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
printf '# no skip is allowed in the browser tests\n' >"$tmp/skips.txt"
st=0
# shellcheck disable=SC2086 # the packages are words
"$GO" test -count=1 -p 1 -json -timeout "${TEGO_CHROME_TIMEOUT:-45m}" -tags chrome -run "^($names)\$" -skip "^($skip)\$" $dirs >"$tmp/out.json" || st=1
./scripts/skipgate.sh "$tmp/skips.txt" "$tmp/out.json" || st=1
exit "$st"
