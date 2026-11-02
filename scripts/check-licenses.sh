#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Check source licensing material and, when given a dist directory, its release archives.
# shellcheck disable=SC2086 # $binaries is three package patterns, split on purpose
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
license_files="LICENSE NOTICE THIRD_PARTY_NOTICES.txt LICENSES/GPL-2.0-only.txt LICENSES/BSD-2-Clause.txt LICENSES/LGPL-2.1-only.txt LICENSES/Lucide.txt"
for file in $license_files; do
	[ -s "$file" ] || { echo "check-licenses: missing $file" >&2; exit 1; }
done
binaries="./cmd/tego ./cmd/tego-control ./cmd/maze"
modules=$("${GO:-go}" list -deps -tags tegobpf -f '{{if .Module}}{{if .Module.Version}}{{.Module.Path}} {{.Module.Version}}{{end}}{{end}}' $binaries)
modules=$(printf '%s\n' "$modules" | sort -u)
# An empty listing (a changed go list template, a stand-in go) would check nothing and pass: the binary links
# third-party modules, so none listed is an error.
[ -n "$modules" ] || { echo "check-licenses: go list named no linked module" >&2; exit 1; }
printf '%s\n' "$modules" | while IFS= read -r module; do
	[ -z "$module" ] && continue
	grep -qFx "===== $module =====" THIRD_PARTY_NOTICES.txt || {
		echo "check-licenses: update THIRD_PARTY_NOTICES.txt for $module" >&2
		exit 1
	}
done
# Every licence or notice file on a linked package's directory chain, from the package up to its module's root,
# must be reproduced, whitespace aside: a module can carry a sub-package's own licence (klauspost/compress's
# zstd/internal/xxhash is MIT, Caleb Spare) that its root LICENSE does not hold. PATENTS grants are not notices
# the licences require.
dirs=$("${GO:-go}" list -deps -tags tegobpf -f '{{if .Module}}{{if .Module.Version}}{{.Dir}}|{{.Module.Dir}}{{end}}{{end}}' $binaries)
[ -n "$dirs" ] || { echo "check-licenses: go list named no linked package directory" >&2; exit 1; }
# The walk runs in a command substitution, not as a pipeline's first stage: its refusals must end the script
# (set -e, no pipefail in sh), where they once only ended that stage and the script went on to "verified". An
# empty module directory (go list -mod=vendor) is refused: the walk up would never meet it.
notices=$(tr -s '[:space:]' ' ' <THIRD_PARTY_NOTICES.txt)
files=$(printf '%s\n' "$dirs" | while IFS='|' read -r dir moddir; do
	[ -n "$dir" ] || continue
	[ -n "$moddir" ] || { echo "check-licenses: $dir has no module directory" >&2; exit 1; }
	case "$dir/" in "$moddir"/*) ;; *) echo "check-licenses: $dir is not under its module's $moddir" >&2; exit 1 ;; esac
	d=$dir
	while :; do
		for f in "$d"/LICENSE* "$d"/LICENCE* "$d"/COPYING* "$d"/NOTICE*; do
			[ -f "$f" ] && echo "$moddir|$f"
		done
		[ "$d" = "$moddir" ] && break
		d=$(dirname "$d")
	done
done)
printf '%s\n' "$files" | sort -u | while IFS='|' read -r moddir f; do
	[ -n "$f" ] || continue
	text=$(tr -s '[:space:]' ' ' <"$f" | sed 's/^ //; s/ $//')
	case "$notices" in
	*"$text"*) ;;
	*) echo "check-licenses: THIRD_PARTY_NOTICES.txt lacks $(basename "$moddir")/${f#"$moddir"/}" >&2; exit 1 ;;
	esac
done
text=$(tr -s '[:space:]' ' ' <LICENSES/Lucide.txt | sed 's/^ //; s/ $//')
case "$notices" in
*"$text"*) ;;
*) echo "check-licenses: THIRD_PARTY_NOTICES.txt lacks LICENSES/Lucide.txt" >&2; exit 1 ;;
esac
# Every file a binary embeds must say what it is under: an SPDX header of ours, or a line in the notices. An asset
# copied in from elsewhere otherwise ships with no credit, which the walk above cannot see: it reads Go modules only.
# Exempt: BPF objects (NOTICE gives their terms), the project's own contracts and tables (a header would land in a
# user's copy, or in a pinned hash), the logo, and the licence files themselves. A sprite's symbols are each named
# too, so an icon added to a sprite already in the notices is not covered by the file's line.
# shellcheck disable=SC2016 # the braces and $d are go list's template, not the shell's
embeds=$("${GO:-go}" list -deps -tags tegobpf -f '{{if .Module}}{{if .Module.Main}}{{$d := .Dir}}{{range .EmbedFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{end}}{{end}}' $binaries)
[ -n "$embeds" ] || { echo "check-licenses: go list named no embedded file" >&2; exit 1; }
# The binaries carry the licence files themselves (docs/GAPS.md B12): the module root's package (notices.go) embeds
# them, and `tego licenses` and `tego-control licenses` print them. The licence files embedded, the ones at the root
# and under LICENSES/ (only the root's package reaches them), must be exactly the list the release archive is held to:
# one left out ships a binary without it, and one the list lacks is a text no archive check asks for.
embedded=$(for f in $embeds; do
	f=${f#"$root"/}
	case "$f" in LICENSES/*) echo "$f" ;; */*) ;; *) echo "$f" ;; esac
done)
for file in $license_files; do
	printf '%s\n' "$embedded" | grep -qFx "$file" || { echo "check-licenses: the binaries do not embed $file; embed it in notices.go" >&2; exit 1; }
done
for f in $embedded; do
	case " $license_files " in
	*" $f "*) ;;
	*) echo "check-licenses: the binaries embed $f, which license_files does not list; add it there" >&2; exit 1 ;;
	esac
done
icons=$(sed -n 's/^Icons: //p' THIRD_PARTY_NOTICES.txt | tr -d ',')
for f in $embeds; do
	f=${f#"$root"/}
	case " $license_files " in *" $f "*) continue ;; esac
	case "$f" in
	internal/bpf/*_bpf*.o | *.yaml | *.yaml.tmpl | internal/control/web/static/favicon.svg) continue ;;
	esac
	case "$f" in
	*.svg)
		# shellcheck disable=SC2013 # a symbol id holds no space, and exit must leave the script, not a pipeline's subshell
		for symbol in $(grep -o '<symbol id="[^"]*"' "$f" | sed 's/.*id="//; s/"$//'); do
			[ "$symbol" = logo ] && continue
			case " $icons " in
			*" ${symbol#i-} "*) ;;
			*) echo "check-licenses: THIRD_PARTY_NOTICES.txt names no icon for $symbol in $f" >&2; exit 1 ;;
			esac
		done
		;;
	esac
	head -3 "$f" | grep -q 'SPDX-License-Identifier' && continue
	grep -qF "$f" THIRD_PARTY_NOTICES.txt || { echo "check-licenses: $f is embedded with no SPDX header and no line in THIRD_PARTY_NOTICES.txt" >&2; exit 1; }
done
if [ "$#" -gt 0 ]; then
	[ "$#" -eq 1 ] || { echo "usage: check-licenses.sh [dist-directory]" >&2; exit 2; }
	set -- "$1"/*_licenses.tar.gz
	[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "check-licenses: expected one license archive" >&2; exit 1; }
	archive=$1
	entries=$(tar -tzf "$archive")
	for file in $license_files; do
		printf '%s\n' "$entries" | grep -qFx "$file" || { echo "check-licenses: archive lacks $file" >&2; exit 1; }
	done
	# maze ships in an archive of its own, which must hold the notices of what it links.
	dist=$(dirname "$archive")
	set -- "$dist"/maze_*.tar.gz
	[ -f "$1" ] || { echo "check-licenses: expected maze archives in $dist" >&2; exit 1; }
	for tarball in "$@"; do
		entries=$(tar -tzf "$tarball")
		for file in LICENSE NOTICE THIRD_PARTY_NOTICES.txt; do
			printf '%s\n' "$entries" | grep -qFx "$file" || { echo "check-licenses: $(basename "$tarball") lacks $file" >&2; exit 1; }
		done
	done
	set -- "$(dirname "$archive")"/*_checksums.txt
	[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "check-licenses: expected one checksums file" >&2; exit 1; }
	expected=$(awk -v file="$(basename "$archive")" '$2 == file { print $1 }' "$1")
	actual=$(sha256sum "$archive" | awk '{print $1}')
	[ "$expected" = "$actual" ] || { echo "check-licenses: license archive is not covered by checksums" >&2; exit 1; }
fi
echo "check-licenses: source notices and requested release contents verified"
