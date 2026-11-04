#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests release.sh's `push` against a throwaway repository with a local bare "origin": it pushes an annotated
# tag on main, and refuses (pushing nothing) from another branch, for a lightweight tag, and for an
# annotated tag on a commit main does not hold.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-release-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

git init -q --bare "$tmp/origin.git"
git init -q -b main "$tmp/work"
mkdir "$tmp/work/scripts"
cp "$here/release.sh" "$tmp/work/scripts/release.sh"
cd "$tmp/work"
git config user.email t@example.invalid
git config user.name t
git config commit.gpgsign false
git config tag.gpgsign false
git remote add origin "$tmp/origin.git"
git add -A
git commit -q -m one
git commit -q --allow-empty -m two

fail=0
check() { # check NAME WANT(0|1) TAGS-ON-ORIGIN-AFTER ARGS...
	name=$1 want=$2 tags=$3
	shift 3
	rc=0
	sh scripts/release.sh "$@" >"$tmp/out" 2>&1 || rc=$?
	got=$(git -C "$tmp/origin.git" tag | tr '\n' ' ')
	if { [ "$want" = 0 ] && [ "$rc" -ne 0 ]; } || { [ "$want" = 1 ] && [ "$rc" -eq 0 ]; } || [ "$got" != "$tags" ]; then
		echo "FAIL ${name}: exit ${rc}, origin tags '${got}', want '${tags}'"
		sed 's/^/    /' "$tmp/out"
		fail=1
	else
		echo "ok   ${name}"
	fi
}

git tag v1.0.0 # lightweight
check "lightweight tag refused" 1 "" push v1.0.0
git tag -d v1.0.0 >/dev/null

git checkout -q -b feature
git commit -q --allow-empty -m feature
git tag -a v1.1.0 -m "on the feature branch"
check "annotated tag off main's history refused" 1 "" push v1.1.0
git tag -a v1.2.0 -m "x" main
check "push from a feature branch refused" 1 "" push v1.2.0
git checkout -q main
check "annotated tag off main's history refused from main" 1 "" push v1.1.0
# The tag follows main only when ci is green for its commit: main goes first, the tag waits.
check "no gh: main pushed, tag held back" 1 "" push v1.2.0
[ "$(git -C "$tmp/origin.git" rev-parse main)" = "$(git rev-parse main)" ] || { echo "FAIL: main did not reach origin"; fail=1; }
printf '#!/bin/sh\necho 0\n' >"$tmp/gh0"
printf '#!/bin/sh\necho 1\n' >"$tmp/gh1"
chmod +x "$tmp/gh0" "$tmp/gh1"
TEGO_GH="$tmp/gh0" check "ci not green: tag held back" 1 "" push v1.2.0
# gh works only from inside the checkout (it picks the repository from the cwd) and its failure is reported as such.
printf '#!/bin/sh\ngit rev-parse --git-dir >/dev/null 2>&1 || { echo "not a git repository" >&2; exit 1; }\necho 1\n' >"$tmp/ghrepo"
printf '#!/bin/sh\necho "gh auth expired" >&2\nexit 4\n' >"$tmp/ghbad"
chmod +x "$tmp/ghrepo" "$tmp/ghbad"
TEGO_GH="$tmp/ghbad" check "gh failure: tag held back" 1 "" push v1.2.0
if ! grep -q "gh auth expired" "$tmp/out" || grep -q "no successful run" "$tmp/out"; then
	echo "FAIL: gh's error was not reported"; sed 's/^/    /' "$tmp/out"; fail=1
fi
(cd "$tmp" && TEGO_GH="$tmp/ghrepo" sh "$tmp/work/scripts/release.sh" push v1.2.0 >"$tmp/out" 2>&1) || { echo "FAIL: push from another cwd"; sed 's/^/    /' "$tmp/out"; fail=1; }
[ "$(git -C "$tmp/origin.git" tag | tr '\n' ' ')" = "v1.2.0 " ] || { echo "FAIL: tag not pushed from another cwd"; fail=1; }
git -C "$tmp/origin.git" tag -d v1.2.0 >/dev/null
TEGO_GH="$tmp/gh1" check "annotated tag on main pushed once ci is green" 0 "v1.2.0 " push v1.2.0
git -C "$tmp/origin.git" tag -d v1.2.0 >/dev/null
TEGO_RELEASE_SKIP_CI_CHECK=1 check "skip variable pushes the tag" 0 "v1.2.0 " push v1.2.0
[ -z "$(git -C "$tmp/origin.git" branch --list feature)" ] || { echo "FAIL: the feature branch reached origin"; fail=1; }

# `tag`'s changelog lookup, which refuses before the gate runs: the dated heading docs/CHANGELOG.md uses is found
# (the run then stops at the gate, which this throwaway repository has no Makefile for), and a section without
# the three required lines is refused.
git checkout -q main
mkdir -p docs
tagcheck() { # tagcheck NAME WANT-IN-OUTPUT WANT-ABSENT
	printf '%s' "$CHANGELOG" >docs/CHANGELOG.md
	git add -A
	git commit -q -m "changelog"
	rc=0
	sh scripts/release.sh tag v2.0.0 >"$tmp/out" 2>&1 || rc=$?
	if [ "$rc" -eq 0 ] || ! grep -q -- "$2" "$tmp/out" || { [ -n "$3" ] && grep -q -- "$3" "$tmp/out"; }; then
		echo "FAIL ${1}: exit ${rc}"
		sed 's/^/    /' "$tmp/out"
		fail=1
	else
		echo "ok   ${1}"
	fi
}
# shellcheck disable=SC2016 # Backticks are literal Markdown in the fixture.
CHANGELOG='# Changelog

## Unreleased

## v2.0.0 - 2026-01-01

Notes.

### Record `v`
1
### Contract schema
1
### Kernel minimums
6.1
'
tagcheck "dated changelog heading is found" "make" "has no '## v2.0.0' section"
# shellcheck disable=SC2016 # Backticks are literal Markdown in the fixture.
CHANGELOG='## v2.0.0 - 2026-01-01

Notes.

### Record `v`
1
'
tagcheck "section without the required lines refused" "has no 'Contract schema' line" "make"
CHANGELOG='## v2.0.0

Notes.
'
tagcheck "bare heading without the required lines refused" "has no 'Record" "make"

# A tag made from a section keeps its "###" headings (the default cleanup strips "#" lines); the gate is stubbed.
printf 'lint vuln test integration preset-freeze:\n\t@:\n' >Makefile
# shellcheck disable=SC2016 # Backticks are literal Markdown in the fixture.
printf '## v2.1.0\n\n### Record `v`\n1\n### Contract schema\n1\n### Kernel minimums\n6.1\n' >docs/CHANGELOG.md
git add -A
git commit -q -m "stub gate"
if sh scripts/release.sh tag v2.1.0 >"$tmp/out" 2>&1 &&
	[ "$(git cat-file -p v2.1.0 | grep -c '^### ')" -eq 3 ]; then
	echo "ok   tag message keeps the changelog headings"
else
	echo "FAIL tag message lost the changelog headings"
	sed 's/^/    /' "$tmp/out"
	git cat-file -p v2.1.0 2>&1 | sed 's/^/    /'
	fail=1
fi

# `notes` prints the section release.yml publishes as the release notes: its body, headings kept, without the
# version's own heading; a version with no section is refused.
if sh scripts/release.sh notes v2.1.0 >"$tmp/out" 2>&1 && [ "$(grep -c '^### ' "$tmp/out")" -eq 3 ] &&
	! grep -q '^## v2.1.0' "$tmp/out"; then
	echo "ok   notes prints the version's changelog section"
else
	echo "FAIL notes did not print the version's changelog section"; sed 's/^/    /' "$tmp/out"; fail=1
fi
if sh scripts/release.sh notes v9.9.9 >"$tmp/out" 2>&1 || ! grep -q "has no '## v9.9.9' section" "$tmp/out"; then
	echo "FAIL notes for a version with no section did not refuse"; sed 's/^/    /' "$tmp/out"; fail=1
else
	echo "ok   notes refuses a version with no section"
fi

# A version with shell syntax in it stops at release.sh's shape check, which is release.yml's gate's. A shape the gate
# takes gets past it, and on to the missing tag.
# shellcheck disable=SC2016 # Literal shell syntax: the versions are never expanded.
for bad in 'v1.2.3$(touch INJ)' 'v1.2.3";touch INJ;"' 'v1.2.3+build' 'v1.2' '1.2.3' 'v1.2.3-' 'v1.2.3
v1.2.3'; do
	if sh scripts/release.sh push "$bad" >"$tmp/out" 2>&1 || ! grep -q 'version must look like' "$tmp/out"; then
		echo "FAIL shape check let '$bad' past"; sed 's/^/    /' "$tmp/out"; fail=1
	else
		echo "ok   shape check refuses '$bad'"
	fi
done
for good in v9.9.9 v9.9.9-rc.1; do
	sh scripts/release.sh push "$good" >"$tmp/out" 2>&1 || :
	if grep -q 'version must look like' "$tmp/out"; then
		echo "FAIL shape check refused '$good'"; sed 's/^/    /' "$tmp/out"; fail=1
	else
		echo "ok   shape check takes '$good'"
	fi
done

# The real Makefile's preset-freeze passes a tag name as data, by both routes: release.yml's environment and release.sh's
# command line. A stand-in go records the value the test would read, and a name built to break out of the quoting (the
# release tag gate refuses these; the Makefile must not depend on that) runs nothing.
mkdir "$tmp/mk"
cat >"$tmp/gostub" <<'STUB'
#!/bin/sh
printf '%s\n' "$TEGO_RELEASE_VERSION" >"$FREEZE_OUT"
STUB
chmod +x "$tmp/gostub"
# shellcheck disable=SC2016 # Literal shell syntax: the point of the test is that nothing expands it.
for name in 'v0.1.0$(touch${IFS}INJ1)' 'v0.1.0";touch${IFS}INJ2;"' 'v0.1.0`touch${IFS}INJ3`' 'v0.1.0'; do
	rm -f "$tmp/mk/value"
	(cd "$tmp/mk" && VERSION=$name FREEZE_OUT="$tmp/mk/value" make -s -f "$here/../Makefile" GO="$tmp/gostub" preset-freeze) >"$tmp/out" 2>&1 || {
		echo "FAIL preset-freeze failed on the environment's '$name'"; sed 's/^/    /' "$tmp/out"; fail=1
	}
	if [ "$(cat "$tmp/mk/value" 2>/dev/null)" = "$name" ]; then
		echo "ok   preset-freeze passes '$name' through unchanged"
	else
		echo "FAIL preset-freeze passed '$(cat "$tmp/mk/value" 2>/dev/null)' for '$name'"; fail=1
	fi
done
# shellcheck disable=SC2016 # Literal make and shell syntax: a command line goes through make's own expansion once.
(cd "$tmp/mk" && FREEZE_OUT="$tmp/mk/value" make -s -f "$here/../Makefile" GO="$tmp/gostub" VERSION='v0.1.0$$(touch$${IFS}INJ4)' preset-freeze) >"$tmp/out" 2>&1 || {
	echo "FAIL preset-freeze failed on a command-line VERSION"; sed 's/^/    /' "$tmp/out"; fail=1
}
if [ -n "$(find "$tmp/mk" -name 'INJ*' -print -quit)" ]; then
	echo "FAIL a tag name ran as a command in preset-freeze: $(ls "$tmp/mk")"; fail=1
else
	echo "ok   no tag name ran as a command in preset-freeze"
fi

exit "$fail"
