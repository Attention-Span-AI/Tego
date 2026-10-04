#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The tag process (docs/VERSIONING.md §7): the mechanical, safe-to-automate half of cutting a tego release.
# `check` runs the release gate; `tag` cuts an annotated tag once the gate is green and docs/CHANGELOG.md has
# a section for it; `push` sends a cut tag to origin, which is what the tag-triggered release workflow
# actually builds and publishes from. Retracting a bad release is deliberately NOT automated — `undo` only
# prints the commands, and says why (docs/VERSIONING.md §7).
set -eu

prog=$(basename "$0")
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
changelog="${root}/docs/CHANGELOG.md"

die() {
	echo "${prog}: $1" >&2
	exit "${2:-1}"
}

usage() {
	cat <<EOF
usage: ${prog} check          run the release gate (build, test, integration, vet, lint, spdx, govulncheck)
       ${prog} tag vX.Y.Z     run the gate, then cut an annotated tag from CHANGELOG.md's section for it
       ${prog} push vX.Y.Z    push the branch, then the tag once ci is green for it
       ${prog} undo vX.Y.Z    print (do not run) the commands to retract a bad release
EOF
}

require_version() {
	# The shape release.yml's gate job requires, checked here so a tag it would refuse is never cut: catches "0.1.0"
	# (missing v), "latest" and a name with shell syntax in it early, with a message that says what's wrong, before
	# anything below spends five minutes on a doomed release gate. The case rejects a newline, which grep would split.
	case "$1" in
		*[!0-9A-Za-z.-]*) die "version must look like vX.Y.Z, got '$1'" 1 ;;
	esac
	printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' ||
		die "version must look like vX.Y.Z, got '$1'" 1
}

cmd_check() {
	# Reuses the Makefile's own targets rather than re-listing their flags here, so the gate is what those
	# targets are (`make lint` runs precommit's static steps). CI adds the race detector, the root suites and more:
	# a green check here is the local half, not a substitute for a green ci run. `make vuln` is here because a
	# tag is the last point a reachable vulnerability can be stopped before users install it.
	(cd "$root" && make lint)
	(cd "$root" && make vuln)
	(cd "$root" && make test)
	(cd "$root" && make integration)
	echo "${prog}: gate green"
}

changelog_section() {
	# Prints the body between "## v<version>" (optionally followed by " - <date>", the Keep a Changelog form
	# docs/CHANGELOG.md uses) and the next "## " heading (or nothing if there isn't one).
	awk -v want="## $1" '
		$0 == want || index($0, want " - ") == 1 { found = 1; next }
		found && /^## / { exit }
		found { print }
	' "$changelog"
}

cmd_tag() {
	version="${1:?usage: ${prog} tag vX.Y.Z}"
	require_version "$version"

	branch=$(git -C "$root" rev-parse --abbrev-ref HEAD)
	[ "$branch" = "master" ] || die "tag from master, not '${branch}' (docs/VERSIONING.md §7); merge first" 1
	[ -z "$(git -C "$root" status --porcelain)" ] || die "working tree is not clean; commit or stash first" 1
	if git -C "$root" rev-parse "$version" >/dev/null 2>&1; then
		die "tag ${version} already exists locally; see '${prog} undo' if it needs retracting, not a re-tag" 1
	fi

	section=$(changelog_section "$version")
	[ -n "$section" ] || die "docs/CHANGELOG.md has no '## ${version}' section (or it is empty); write the release notes before tagging" 1

	# docs/VERSIONING.md §7.1: the section ends in the three lines a reader uses to tell what a binary speaks.
	# shellcheck disable=SC2016 # These are literal changelog heading names.
	for need in 'Record `v`' 'Contract schema' 'Kernel minimums'; do
		printf '%s\n' "$section" | grep -qF -- "$need" ||
			die "the ${version} section of docs/CHANGELOG.md has no '${need}' line (docs/VERSIONING.md §7.1); add it before tagging" 1
	done

	# A preset revision this tag carries is released, so it is frozen from this tag on (ADR 0068 D3): the gate fails
	# until pkg/spec/presets' released table lists each with its sha256, and prints the lines to add.
	(cd "$root" && make preset-freeze VERSION="$version")
	cmd_check

	msg="tego ${version}
${section}"
	# verbatim: the default cleanup strips every "#" line, which drops the CHANGELOG's "### ..." headings.
	git -C "$root" tag -a --cleanup=verbatim "$version" -m "$msg"
	echo "${prog}: tagged ${version} on $(git -C "$root" rev-parse --short HEAD)."
	echo "${prog}: review with 'git show ${version}', then '${prog} push ${version}'."
}

cmd_push() {
	version="${1:?usage: ${prog} push vX.Y.Z}"
	require_version "$version"
	git -C "$root" rev-parse "$version" >/dev/null 2>&1 || die "no local tag ${version}; run '${prog} tag ${version}' first" 1
	# The same rules `tag` holds, checked again because a tag can be made by hand: release.yml builds and signs
	# whatever v* tag reaches origin, so only master's own history, under an annotated tag, is pushed.
	branch=$(git -C "$root" rev-parse --abbrev-ref HEAD)
	[ "$branch" = "master" ] || die "push from master, not '${branch}' (docs/VERSIONING.md §7); nothing was pushed" 1
	[ "$(git -C "$root" cat-file -t "refs/tags/${version}" 2>/dev/null)" = "tag" ] ||
		die "${version} is not an annotated tag (docs/VERSIONING.md §7.2); nothing was pushed" 1
	git -C "$root" merge-base --is-ancestor "${version}^{commit}" HEAD ||
		die "${version} does not point at master's history; nothing was pushed" 1
	git -C "$root" push origin "$branch"
	# release.yml's gate job refuses a commit with no successful ci run and does not wait for one, so a tag sent
	# with master (a commit ci has not seen) would fail its release at once. Master goes first; the tag follows
	# only when ci is green for the tagged commit, else nothing more is pushed and the rerun is one command.
	sha=$(git -C "$root" rev-parse "${version}^{commit}")
	if [ "${TEGO_RELEASE_SKIP_CI_CHECK:-}" != 1 ]; then
		gh=${TEGO_GH:-gh}
		command -v "$gh" >/dev/null 2>&1 ||
			die "master is pushed, the tag is not: no gh to check that ci is green for ${sha}; wait for ci, then run '${prog} push ${version}' again (TEGO_RELEASE_SKIP_CI_CHECK=1 pushes the tag without the check)" 1
		# From the checkout, whatever the caller's cwd (gh picks the repository from it); gh's own error is kept, so
		# a failed lookup (no auth, rate limit, network) is not reported as a ci that is not green yet.
		ghlog=$(mktemp "${TMPDIR:-/tmp}/release-gh.XXXXXX")
		if green=$(cd "$root" && "$gh" run list --workflow ci.yml --commit "$sha" --status success --json databaseId --jq length 2>"$ghlog"); then
			rm -f "$ghlog"
		else
			err=$(head -c 500 "$ghlog")
			rm -f "$ghlog"
			die "master is pushed, the tag is not: '${gh} run list' failed, so ci for ${sha} was not checked (${err:-no message}); fix that, then run '${prog} push ${version}' again" 1
		fi
		[ "${green:-0}" -ge 1 ] 2>/dev/null ||
			die "master is pushed, the tag is not: ci has no successful run for ${sha} yet; wait for it, then run '${prog} push ${version}' again" 1
	fi
	git -C "$root" push origin "$version"
	echo "${prog}: pushed ${branch} and ${version}"
}

cmd_undo() {
	version="${1:?usage: ${prog} undo vX.Y.Z}"
	require_version "$version"
	cat <<EOF
${prog}: undoing a release is not automated — read this, then run each step by hand:

1. Delete the GitHub release and its tag (assets stop being served, the tag stops resolving):
     gh release delete ${version} --cleanup-tag
   (no gh: delete the Release from the web UI, then delete the tag the same way.)

2. Do not push a fixed commit under ${version} again. The Go module proxy caches a tag's content
   the first time anyone fetches it, forever, for that exact tag string (docs/VERSIONING.md §7.4); a
   second push under ${version} then serves different bytes to different callers depending on
   whether they hit the cache. Cut the next patch tag instead.

3. In docs/CHANGELOG.md, do not delete the ${version} section: head it "### Yanked" (Keep a
   Changelog's own term for this), say why, and name the replacement tag. The record stays honest.

4. If anyone may already have fetched ${version}, deleting the release does not reach them — ship
   the fix as a new tag with its own note pointing back at this one, not a silent replacement.
EOF
}

case "${1:-}" in
	check) cmd_check ;;
	tag)
		shift
		cmd_tag "${1:-}"
		;;
	push)
		shift
		cmd_push "${1:-}"
		;;
	undo)
		shift
		cmd_undo "${1:-}"
		;;
	-h | --help | "") usage ;;
	*)
		usage >&2
		die "unknown subcommand '$1'" 1
		;;
esac
