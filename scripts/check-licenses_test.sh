#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Exercises check-licenses.sh in private copies of the tree's licence files, with a stand-in go: an empty module
# listing must fail rather than verify nothing (it once printed "verified"); a licence file on a linked package's
# directory chain below its module's root (klauspost/compress's zstd/internal/xxhash) must be in
# THIRD_PARTY_NOTICES.txt, as the module root's is; a package outside its module's directory, or an empty module
# directory, must end the script with a failure (a refusal inside a pipeline once went on to "verified"); and a
# release directory's archive must hold every licence file and be covered by the checksums, and each maze archive
# the notices; a file a binary embeds must carry an SPDX header or a line in the notices, each icon of a sprite by
# name; and the licence files the binaries embed must be exactly the licence files the script lists (docs/GAPS.md
# B12), none left out and none it does not list.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname -- "$here")
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-licenses-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
fail=0

# The module cache stand-in: example.com/m v1.0.0, with its root LICENSE and a sub-package's own LICENSE.txt.
mod="$tmp/modcache/example.com/m@v1.0.0"
mkdir -p "$mod/sub/internal/hash"
printf 'Copyright (c) 2020 Root Author\n\nPermission is granted, root terms.\n' >"$mod/LICENSE"
printf 'Copyright (c) 2016 Sub Author\n\nPermission is granted,\n  sub terms.\n' >"$mod/sub/internal/hash/LICENSE.txt"
printf 'Patent grant text.\n' >"$mod/PATENTS"

# A package directory outside its module's: its stand-in carries no licence; the check must stop there.
mkdir -p "$tmp/elsewhere/pkg"

# go list answers with the -f template's kind: the module lines, or the package and module directories. With
# LICTEST_EMPTY=1 it lists nothing and succeeds, as a module graph with no third-party module would. With
# LICTEST_STRAY=1 the first package lies outside its module's directory; with LICTEST_NOMODDIR=1 the module
# directory is empty, as go list -mod=vendor reports it. Both lead with that line and follow with the sub-package,
# whose licence the notices then lack: a refusal that only ends a pipeline stage would go on to "verified".
# The embedded files are the tree's own, under the working directory check-licenses.sh runs from: the files of its
# embed/ and, as the module root's notices.go embeds them, LICENSE, NOTICE, THIRD_PARTY_NOTICES.txt and LICENSES/*.txt,
# but for the one LICTEST_UNEMBED names. LICTEST_NOEMBED=1 lists none.
cat >"$tmp/go" <<EOF
#!/bin/sh
[ "\$1" = list ] || { echo "stand-in go: refusing \$*" >&2; exit 42; }
[ "\${LICTEST_EMPTY:-}" = 1 ] && exit 0
case "\$*" in
*EmbedFiles*)
	[ "\${LICTEST_NOEMBED:-}" = 1 ] && exit 0
	for f in \$PWD/embed/*; do echo "\$f"; done
	for f in LICENSE NOTICE THIRD_PARTY_NOTICES.txt LICENSES/*.txt; do
		[ "\$f" = "\${LICTEST_UNEMBED:-}" ] || echo "\$PWD/\$f"
	done
	;;
*.Module.Dir*)
	[ "\${LICTEST_STRAY:-}" = 1 ] && echo "$tmp/elsewhere/pkg|$mod"
	[ "\${LICTEST_NOMODDIR:-}" = 1 ] && echo "$mod/sub|"
	echo "$mod|$mod"
	echo "$mod/sub/internal/hash|$mod"
	;;
*) echo "example.com/m v1.0.0" ;;
esac
EOF
chmod +x "$tmp/go"

# tree NAME: a private root with the script and the licence files it requires, the notices holding both of the
# module's licence texts (one reflowed: the comparison ignores whitespace) but not its PATENTS.
tree() {
	t="$tmp/$1"
	mkdir -p "$t/scripts" "$t/LICENSES" "$t/embed"
	cp "$here/check-licenses.sh" "$t/scripts/"
	cp "$repo/LICENSE" "$repo/NOTICE" "$t/"
	cp "$repo/LICENSES/GPL-2.0-only.txt" "$repo/LICENSES/BSD-2-Clause.txt" "$repo/LICENSES/LGPL-2.1-only.txt" "$repo/LICENSES/Lucide.txt" "$t/LICENSES/"
	printf '/* SPDX-License-Identifier: Apache-2.0 */\n' >"$t/embed/own.css"
	printf '<svg><symbol id="logo"/><symbol id="i-kite"/></svg>\n' >"$t/embed/sprite.svg"
	{
		echo "===== example.com/m v1.0.0 ====="
		cat "$mod/LICENSE"
		echo "-----"
		echo "Copyright (c) 2016 Sub Author Permission is granted, sub terms."
		echo "Files: embed/sprite.svg"
		echo "Icons: kite, ship"
		cat "$repo/LICENSES/Lucide.txt"
	} >"$t/THIRD_PARTY_NOTICES.txt"
}
check() { # check NAME WANT CMD...: CMD exits WANT
	name=$1 want=$2
	shift 2
	rc=0
	GO="$tmp/go" "$@" >"$tmp/out" 2>&1 || rc=$?
	if [ "$rc" -eq "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $rc, want $want" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}

tree good
check "every module and licence file reproduced passes" 0 "$tmp/good/scripts/check-licenses.sh"

tree empty
LICTEST_EMPTY=1
export LICTEST_EMPTY
check "an empty module listing fails instead of verifying nothing" 1 "$tmp/empty/scripts/check-licenses.sh"
unset LICTEST_EMPTY

tree nosub
sed -i '/Sub Author/d' "$tmp/nosub/THIRD_PARTY_NOTICES.txt"
check "a sub-package's own licence missing from the notices fails" 1 "$tmp/nosub/scripts/check-licenses.sh"
grep -q 'sub/internal/hash/LICENSE.txt' "$tmp/out" || { echo "FAIL the refusal does not name the missing file" >&2; fail=1; }

# The stray and empty-module-directory refusals must end the script, so the sub-package's licence the notices
# lack is never reached; the timeout bounds a walk that would never reach an empty module directory.
tree stray
sed -i '/Sub Author/d' "$tmp/stray/THIRD_PARTY_NOTICES.txt"
LICTEST_STRAY=1
export LICTEST_STRAY
check "a package outside its module's directory fails" 1 timeout 60 "$tmp/stray/scripts/check-licenses.sh"
grep -q 'elsewhere/pkg is not under' "$tmp/out" || { echo "FAIL the refusal does not name the stray package" >&2; fail=1; }
grep -q 'verified' "$tmp/out" && { echo "FAIL the script went on to verify after the stray package" >&2; fail=1; }
unset LICTEST_STRAY

tree nomoddir
LICTEST_NOMODDIR=1
export LICTEST_NOMODDIR
check "an empty module directory fails" 1 timeout 60 "$tmp/nomoddir/scripts/check-licenses.sh"
grep -q 'no module directory' "$tmp/out" || { echo "FAIL the refusal does not name the empty module directory" >&2; fail=1; }
unset LICTEST_NOMODDIR

tree nohead
sed -i '/^===== example.com/d' "$tmp/nohead/THIRD_PARTY_NOTICES.txt"
check "a module without its heading fails" 1 "$tmp/nohead/scripts/check-licenses.sh"

tree nolicense
rm "$tmp/nolicense/LICENSES/LGPL-2.1-only.txt"
check "a missing licence text fails" 1 "$tmp/nolicense/scripts/check-licenses.sh"

tree nolucide
sed -i '/Permission to use, copy/d' "$tmp/nolucide/THIRD_PARTY_NOTICES.txt"
check "the icons' licence missing from the notices fails" 1 "$tmp/nolucide/scripts/check-licenses.sh"
grep -q 'Lucide.txt' "$tmp/out" || { echo "FAIL the refusal does not name the icons' licence" >&2; fail=1; }

tree noembed
LICTEST_NOEMBED=1
export LICTEST_NOEMBED
check "an empty embedded-file listing fails instead of checking nothing" 1 "$tmp/noembed/scripts/check-licenses.sh"
unset LICTEST_NOEMBED

tree stranger
printf 'body {}\n' >"$tmp/stranger/embed/stranger.css"
check "an embedded file with no header and no notice fails" 1 "$tmp/stranger/scripts/check-licenses.sh"
grep -q 'embed/stranger.css' "$tmp/out" || { echo "FAIL the refusal does not name the embedded file" >&2; fail=1; }

tree noted
printf 'font\n' >"$tmp/noted/embed/font.woff2"
echo "Files: embed/font.woff2" >>"$tmp/noted/THIRD_PARTY_NOTICES.txt"
check "an embedded file the notices name passes" 0 "$tmp/noted/scripts/check-licenses.sh"

tree newicon
printf '<svg><symbol id="logo"/><symbol id="i-kite"/><symbol id="i-whale"/></svg>\n' >"$tmp/newicon/embed/sprite.svg"
check "an icon the notices do not name fails, though they name its sprite" 1 "$tmp/newicon/scripts/check-licenses.sh"
grep -q 'i-whale' "$tmp/out" || { echo "FAIL the refusal does not name the icon" >&2; fail=1; }

# The binaries print the licence files they embed (tego licenses): one the build leaves out is a binary shipped
# without it, and a text under LICENSES/ the script does not list is one no release check asks for.
tree unembedded
LICTEST_UNEMBED=NOTICE
export LICTEST_UNEMBED
check "a licence file the binaries do not embed fails" 1 "$tmp/unembedded/scripts/check-licenses.sh"
grep -q 'do not embed NOTICE' "$tmp/out" || { echo "FAIL the refusal does not name the licence file left out" >&2; fail=1; }
unset LICTEST_UNEMBED

tree unlisted
printf 'Permission is granted, other terms.\n' >"$tmp/unlisted/LICENSES/Other.txt"
check "an embedded licence text the script does not list fails" 1 "$tmp/unlisted/scripts/check-licenses.sh"
grep -q 'embed LICENSES/Other.txt' "$tmp/out" || { echo "FAIL the refusal does not name the unlisted text" >&2; fail=1; }

# A release directory: the licence archive with every file, each maze archive, and checksums covering them.
dist() { # dist NAME [FILE-TO-LEAVE-OUT]
	d="$tmp/$1"
	mkdir -p "$d"
	(
		cd "$tmp/good"
		leave="${2:-none}"
		set --
		for f in LICENSE NOTICE THIRD_PARTY_NOTICES.txt LICENSES/GPL-2.0-only.txt LICENSES/BSD-2-Clause.txt LICENSES/LGPL-2.1-only.txt LICENSES/Lucide.txt; do
			[ "$f" = "$leave" ] || set -- "$@" "$f"
		done
		tar -czf "$d/tego_0.0.0_licenses.tar.gz" "$@"
		case "$leave" in
		maze-*) tar -czf "$d/maze_0.0.0_linux_amd64.tar.gz" LICENSE NOTICE ;;
		*) tar -czf "$d/maze_0.0.0_linux_amd64.tar.gz" LICENSE NOTICE THIRD_PARTY_NOTICES.txt ;;
		esac
	)
	(cd "$d" && sha256sum tego_0.0.0_licenses.tar.gz >tego_0.0.0_checksums.txt)
}
dist dist-good
check "a complete, checksummed licence archive passes" 0 "$tmp/good/scripts/check-licenses.sh" "$tmp/dist-good"
dist dist-nonotice NOTICE
check "an archive without NOTICE fails" 1 "$tmp/good/scripts/check-licenses.sh" "$tmp/dist-nonotice"
dist dist-badsum
echo "0000000000000000000000000000000000000000000000000000000000000000  tego_0.0.0_licenses.tar.gz" >"$tmp/dist-badsum/tego_0.0.0_checksums.txt"
check "an archive the checksums do not cover fails" 1 "$tmp/good/scripts/check-licenses.sh" "$tmp/dist-badsum"
dist dist-nolucide LICENSES/Lucide.txt
check "an archive without the icons' licence fails" 1 "$tmp/good/scripts/check-licenses.sh" "$tmp/dist-nolucide"
dist dist-mazebare maze-notices
check "a maze archive without the notices fails" 1 "$tmp/good/scripts/check-licenses.sh" "$tmp/dist-mazebare"
grep -q 'maze_0.0.0_linux_amd64.tar.gz lacks THIRD_PARTY_NOTICES.txt' "$tmp/out" || { echo "FAIL the refusal does not name the maze archive" >&2; fail=1; }
dist dist-nomaze
rm "$tmp/dist-nomaze"/maze_*.tar.gz
check "a release directory with no maze archive fails" 1 "$tmp/good/scripts/check-licenses.sh" "$tmp/dist-nomaze"
mkdir -p "$tmp/dist-empty"
check "a release directory with no archive fails" 1 "$tmp/good/scripts/check-licenses.sh" "$tmp/dist-empty"

exit "$fail"
