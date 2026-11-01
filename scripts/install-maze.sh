#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Installs the maze CLI on macOS or Linux, for people who don't use Homebrew:
#
#   curl -fsSL <release url>/install-maze.sh | sh
#
# It downloads the release archive goreleaser built for this OS and architecture plus the release's checksums
# file, checks the archive's sha256 before anything is unpacked, and moves the binary into place with a rename,
# so a maze that is running keeps its old file. It installs into your home folder by default: no sudo.
#
# The engine (tego, Linux only) installs separately with scripts/install.sh; on a Mac it will come with Maze's
# lightweight Linux layer. Folding both into one installer is a later step and needs the engine owner's
# review, since install.sh also verifies signatures.
#
# Settings are environment variables:
#   MAZE_VERSION    release to install, e.g. v0.1.0 (default: the latest)
#   MAZE_PREFIX     folder for the binary (default: $HOME/.local/bin)
#   MAZE_BASE_URL   where releases are downloaded from (default: GitHub releases); a file:// URL works for
#                   testing against a local build laid out as <base>/<version>/<files>
#   MAZE_API_URL    the GitHub API URL used only to find the latest release when MAZE_VERSION is unset
#
# Exit codes: 2 a needed tool is missing, 3 unsupported OS, 4 unsupported CPU, 5 no such release, 6 download
# failed, 7 checksum mismatch, 8 install step failed.
set -eu

prog=install-maze
die() {
	echo "$prog: $1" >&2
	exit "$2"
}

case "${1:-}" in
-h | --help)
	echo "usage: curl -fsSL <url>/install-maze.sh | sh"
	echo "       MAZE_VERSION=v0.1.0 MAZE_PREFIX=\$HOME/bin sh install-maze.sh"
	exit 0
	;;
esac

command -v curl >/dev/null 2>&1 || die "curl is needed to download maze; install it and run this again" 2
command -v tar >/dev/null 2>&1 || die "tar is needed to unpack maze; install it and run this again" 2
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	die "a sha256 tool is needed to check the download (sha256sum or shasum)" 2
fi

case "$(uname -s)" in
Darwin) os=darwin ;;
Linux) os=linux ;;
*) die "maze runs on macOS and Linux; this is $(uname -s)" 3 ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "maze is built for amd64 and arm64; this is $(uname -m)" 4 ;;
esac

# The repository releases are built in, as scripts/install.sh names it.
repo_owner="Attention-Span-AI"
repo_name="Tego"
# Every download is https (or a file:// test release), redirects included, as scripts/install.sh's are: a
# redirect to plain http would hand the checksums file and the archive to anyone on the path.
base="${MAZE_BASE_URL:-https://github.com/${repo_owner}/${repo_name}/releases/download}"
prefix="${MAZE_PREFIX:-$HOME/.local/bin}"
version="${MAZE_VERSION:-}"
if [ -z "$version" ]; then
	api="${MAZE_API_URL:-https://api.github.com/repos/${repo_owner}/${repo_name}/releases/latest}"
	version=$(curl -fsSL --proto '=https,file' --proto-redir '=https' --max-time 30 "$api" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1) || true
	[ -n "$version" ] || die "couldn't find the latest release; set MAZE_VERSION=v0.1.0 to pick one" 5
fi
case "$version" in v*) ;; *) version="v$version" ;; esac
v="${version#v}"
archive="maze_${v}_${os}_${arch}.tar.gz"
sums="tego_${v}_checksums.txt"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading maze $version for $os/${arch}…"
curl -fsSL --proto '=https,file' --proto-redir '=https' --max-time 300 "$base/$version/$sums" -o "$tmp/$sums" 2>/dev/null ||
	die "no release $version at $base (checksums file missing)" 5
curl -fsSL --proto '=https,file' --proto-redir '=https' --max-time 300 "$base/$version/$archive" -o "$tmp/$archive" 2>/dev/null ||
	die "couldn't download $archive from $base/$version" 6

want=$(awk -v f="$archive" '$2 == f {print $1}' "$tmp/$sums")
[ -n "$want" ] || die "the checksums file doesn't list $archive" 7
got=$(sha256 "$tmp/$archive")
[ "$got" = "$want" ] || die "$archive doesn't match its checksum: the download is damaged or was changed" 7

tar -xzf "$tmp/$archive" -C "$tmp" maze 2>/dev/null || die "$archive has no maze binary in it" 8
mkdir -p "$prefix" 2>/dev/null || die "can't create $prefix (try MAZE_PREFIX=\$HOME/bin)" 8
{ mv "$tmp/maze" "$prefix/.maze.new" && chmod 755 "$prefix/.maze.new" && mv -f "$prefix/.maze.new" "$prefix/maze"; } 2>/dev/null ||
	die "can't write to $prefix (try MAZE_PREFIX=\$HOME/bin)" 8

echo "✓ Installed maze $version to $prefix/maze"
# The licences of what the binary links travel with it. A prefix that has no writable share/doc still gets maze.
docs=$(dirname "$prefix")/share/doc/maze
if tar -xzf "$tmp/$archive" -C "$tmp" LICENSE NOTICE THIRD_PARTY_NOTICES.txt 2>/dev/null &&
	mkdir -p "$docs" 2>/dev/null && cp "$tmp/LICENSE" "$tmp/NOTICE" "$tmp/THIRD_PARTY_NOTICES.txt" "$docs/" 2>/dev/null; then
	echo "  Licence notices: $docs"
else
	echo "  Licence notices: in $base/$version/$archive"
fi
other=$(command -v maze 2>/dev/null || true)
if [ -n "$other" ] && [ "$other" != "$prefix/maze" ]; then
	echo
	echo "! Another maze comes first on your PATH: $other"
	echo "  Remove it, or put $prefix earlier on your PATH."
fi
case ":$PATH:" in
*":$prefix:"*) ;;
*)
	echo
	# The shell's startup file, relative to the home folder; the hint prints it as ~/<file> for the person to copy.
	rc=".bashrc"
	case "${SHELL:-}" in */zsh) rc=".zshrc" ;; */fish) rc=".config/fish/config.fish" ;; esac
	echo "$prefix isn't on your PATH yet. Add it, then open a new terminal:"
	if [ "$rc" = ".config/fish/config.fish" ]; then
		echo "  fish_add_path $prefix"
	else
		echo "  echo 'export PATH=\"$prefix:\$PATH\"' >> ~/$rc"
	fi
	;;
esac
echo
echo "Next: open a project and run  maze"
