#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Installs the tego binary for this host, and beside it tego-control, the binary tego hands `tego serve` and
# its other control commands to (ADR 0100 (1b): tego looks for it in its own directory only and runs it only when
# its SHA-256 is the one this tego was built with). Downloads the release archive goreleaser built for this OS/arch, the release's
# tego-control for the same target when its checksums file lists one, and the checksums file; checks who
# published the checksums when it can (below), verifies each binary against the published sha256 and tego's pin
# against tego-control's before anything is replaced, and moves the verified binaries into place with `mv` — not
# `cp` over the old file — because VERSIONING.md §5 is explicit that overwriting a live binary in place fails with
# ETXTBSY while a run holds it open, and a rename does not: a supervisor that opened the old inode keeps running it
# to completion. tego-control is moved first, so a failure between the two moves leaves the old tego working.
#
# A sha256 file fetched from the same place as the binary proves the download is intact, not who made it:
# whoever can replace the binary there can replace its checksum too. So the checksums file is also checked
# for authenticity, when a verifier is available: release.yml signs it with cosign, keyless, as the release
# workflow of this repository at this tag (the bundle is published beside it as <checksums>.sigstore.json),
# and attests each binary's build provenance, which `gh attestation verify` checks. A binary for a root-run
# enforcement tool is worth that step.
#
# Both verifiers are held to the requested tag, not merely to the release workflow: cosign to the certificate
# identity release.yml@refs/tags/<tag>, gh to that same identity and to the source ref refs/tags/<tag>.
# Whoever can replace release assets could otherwise serve an older release's genuine, signed binary under a
# newer tag, and the user would get an older build, perhaps one with a fixed vulnerability, believing it is
# the version they asked for. In gh mode the checksums file itself is not signature-checked, so that binding on
# the binary's own attestation is the whole of the tag check.
#
# The one-line install docs/INSTALL.md gives pipes this script into sh from the latest release, where it is an asset
# (.goreleaser.yaml), with no configuration: it installs that release into ~/.local/bin and ends with the next steps.
# Nothing checks a piped script before it runs (docs/GAPS.md B11); the binaries it downloads are checked as above, and
# docs/INSTALL.md shows how to check the script first.
#
# Configuration is env vars, not flags, to match the one already documented in VERSIONING.md §5:
#   TEGO_VERSION    tag to install, e.g. v0.1.0 (default: the latest published release)
#   TEGO_PREFIX     install directory (default: $HOME/.local/bin — no root needed)
#   TEGO_BASE_URL   release download base (default: the real GitHub releases URL; override to install from
#                    a mirror, or to point this script at a local goreleaser snapshot's dist/ output for testing)
#   TEGO_MAX_TIME   seconds one download may take before it is given up as a network failure (default: 300)
#   TEGO_API_URL    GitHub API URL used only to resolve "latest" when TEGO_VERSION is unset
#   TEGO_VERIFY     how the release's authenticity is checked (default: auto):
#                      auto    cosign when it is on PATH, else gh when it is on PATH and logged in, else the
#                              checksum alone, saying so; a verifier that is present and fails stops the install
#                      cosign  require cosign to verify the checksums file's signature bundle
#                      gh      require gh to verify the binary's build provenance attestation
#                      sha256  the checksum alone: integrity against the download's own origin, nothing more
set -eu

repo_owner="Attention-Span-AI"
repo_name="Tego"

# Everything below runs from main, called on the script's last line. Piped into sh (`curl -fsSL .../install.sh | sh`,
# the one-line install), the shell has then read the whole script before it runs any of it: a download cut short
# defines main partly or not at all and installs nothing, and no command the script starts can read the rest of the
# script from stdin, which is the pipe. The script reads nothing from stdin itself.
main() {
	prog=$(basename "$0")
	# Piped into sh, $0 is the shell's own name; the messages then name the script instead.
	case "$prog" in
		sh | dash | bash | ash | ksh | zsh | busybox) prog=install.sh ;;
	esac
	# A transfer that stalls after the connection is made ends at this many seconds (curl exit 28, which the
	# callers report as the network failure it is, exit 6) instead of hanging the install.
	max_time="${TEGO_MAX_TIME:-300}"

	version="${TEGO_VERSION:-}"
	prefix="${TEGO_PREFIX:-$HOME/.local/bin}"
	base_url="${TEGO_BASE_URL:-https://github.com/${repo_owner}/${repo_name}/releases/download}"
	api_url="${TEGO_API_URL:-https://api.github.com/repos/${repo_owner}/${repo_name}/releases/latest}"

	# die prints one line to stderr and exits with a code a caller can branch on: 2 missing dependency, 3
	# unsupported platform, 4 unsupported architecture, 5 no such release, 6 download failed, 7 checksum
	# mismatch, 8 local install step failed, 9 the release's signature or provenance did not verify.
	die() {
		echo "${prog}: $1" >&2
		exit "$2"
	}

	case "${1:-}" in
		-h | --help)
			echo "usage: TEGO_VERSION=v0.1.0 ${prog}    (installs the given tag; unset for latest)"
			echo "       TEGO_PREFIX=DIR ${prog}        (default: \$HOME/.local/bin)"
			exit 0
			;;
	esac

	# ---- required tools -----------------------------------------------------------------------------------
	# curl and a sha256 tool are not part of POSIX and some minimal images lack one or the other; everything
	# else below (uname, mktemp, awk, sed, mv, chmod) is base POSIX utilities present on any target this
	# script's own `os` check will accept.
	command -v curl >/dev/null 2>&1 || die "curl is required to download the release archive; install it and re-run" 2

	have_sha256sum=0
	have_shasum=0
	command -v sha256sum >/dev/null 2>&1 && have_sha256sum=1
	command -v shasum >/dev/null 2>&1 && have_shasum=1
	if [ "$have_sha256sum" -eq 0 ] && [ "$have_shasum" -eq 0 ]; then
		die "no sha256 tool found (need sha256sum or shasum); install one and re-run" 2
	fi

	sha256_of() {
		if [ "$have_sha256sum" -eq 1 ]; then
			sha256sum "$1" | awk '{print $1}'
		else
			shasum -a 256 "$1" | awk '{print $1}'
		fi
	}

	# ---- platform ------------------------------------------------------------------------------------------
	# Tego enforces from Landlock, cgroups and eBPF: kernel facilities a Darwin or NT kernel does not have.
	# README.md's own answer for those hosts is a Linux VM, so say that instead of half-installing a binary
	# that cannot run.
	os_raw=$(uname -s)
	case "$os_raw" in
		Linux) os=linux ;;
		Darwin)
			die "tego enforces from Landlock, cgroups and eBPF, none of which macOS's kernel has; there is no native macOS build. Run tego inside a Linux VM, the way Docker Desktop does (README.md), and install it there." 3
			;;
		*)
			die "unsupported operating system '${os_raw}': tego ships Linux binaries only. On Windows, install inside WSL2 (a real Linux kernel) and run this script there." 3
			;;
	esac

	arch_raw=$(uname -m)
	case "$arch_raw" in
		x86_64 | amd64) arch=amd64 ;;
		aarch64 | arm64) arch=arm64 ;;
		*) die "unsupported architecture '${arch_raw}': tego ships amd64 and arm64 only" 4 ;;
	esac

	# ---- version ---------------------------------------------------------------------------------------------
	workdir=$(mktemp -d "${TMPDIR:-/tmp}/tego-install.XXXXXX") || die "could not create a temporary directory" 8
	tmp_bin=""
	tmp_control=""
	cleanup() {
		rm -rf "$workdir"
		[ -n "$tmp_bin" ] && rm -f "$tmp_bin"
		[ -n "$tmp_control" ] && rm -f "$tmp_control"
		return 0
	}
	# INT and TERM end the install as well as clean up: a trap that only cleaned up let the shell carry on with the
	# next step after the temporary directory was gone. 130 and 143 are the shell's own codes
	# for a command ended by those signals.
	trap cleanup EXIT
	trap 'cleanup; exit 130' INT
	trap 'cleanup; exit 143' TERM

	# fetch downloads $1 to $2 and prints "<curl exit>:<HTTP status>". curl -f reports every HTTP error as exit
	# 22, so the status is read with -w, and the callers below judge the pair: a 404 or 410 (or a missing file
	# under a file:// mirror, exit 37) says the thing is not there, while any other status and any failure to
	# connect say nothing about the tag, and telling the user their tag is wrong on a 403, a 500 or a 503 sends
	# them looking in the wrong place.
	fetch() {
		set +e
		# --proto keeps a redirect (or a base URL) from leaving https; file is for the tests' local mirror.
		fetched_status=$(curl -fsSL --proto '=https,file' --proto-redir '=https' --connect-timeout 10 --max-time "$max_time" -o "$2" -w '%{http_code}' "$1")
		fetched_rc=$?
		set -e
		echo "${fetched_rc}:${fetched_status}"
	}
	# host_of is a URL's scheme and host, which is all a network failure's message needs.
	host_of() {
		echo "$1" | sed -E 's#(https?://[^/]+).*#\1#'
	}

	if [ -z "$version" ]; then
		meta="${workdir}/latest.json"
		# GitHub answers /releases/latest with 404 while a repository has no release, and with 403 or 429 when
		# its unauthenticated rate limit is spent, which is common on a shared CI address.
		got=$(fetch "$api_url" "$meta")
		case "$got" in
			0:*) ;;
			22:404 | 22:410 | 37:*)
				die "${repo_owner}/${repo_name} has no published release yet (${api_url} names none); set TEGO_VERSION=vX.Y.Z once one exists" 5
				;;
			22:*)
				die "${api_url} answered HTTP ${got#*:} when asked for the latest release (403 and 429 are GitHub's rate limit); try again later, or set TEGO_VERSION=vX.Y.Z to skip the lookup" 6
				;;
			*)
				die "could not reach $(host_of "$api_url") to find the latest release (curl exit ${got%%:*}); check the network, or set TEGO_VERSION=vX.Y.Z to skip the lookup" 6
				;;
		esac
		# No jq dependency: one field, pulled with the tools already required above.
		version=$(grep -m1 '"tag_name"' "$meta" | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')
		if [ -z "$version" ]; then
			die "${repo_owner}/${repo_name} has no published release yet (GitHub API returned no tag_name); set TEGO_VERSION=vX.Y.Z once one exists" 5
		fi
	fi
	case "$version" in
		v*) tag="$version" ;;
		*) tag="v${version}" ;;
	esac
	version_no_v="${tag#v}"

	# Matches the archives.name_template in .goreleaser.yaml exactly (one per binary of its tego archive): change one,
	# change the other.
	archive="tego_${version_no_v}_${os}_${arch}"
	control="tego-control_${version_no_v}_${os}_${arch}"
	checksums="tego_${version_no_v}_checksums.txt"
	archive_path="${workdir}/${archive}"
	control_path="${workdir}/${control}"
	checksums_path="${workdir}/${checksums}"

	# download fetches one release asset. Only an asset that is not there (fetch says which answers mean that)
	# is a question about the tag, exit 5; the server's own trouble, named by its status, and a network failure
	# are exit 6, which a retry may cure.
	download() {
		url="$1"
		dest="$2"
		label="$3"
		got=$(fetch "$url" "$dest")
		case "$got" in
			0:*) return 0 ;;
			22:404 | 22:410 | 37:*)
				die "no release found at ${url} — is '${tag}' a real tego release? Check TEGO_VERSION, or unset it to install the latest" 5
				;;
			22:*) die "the server answered HTTP ${got#*:} for ${label} at ${url}; try again later" 6 ;;
			6:* | 7:* | 28:*) die "could not reach $(host_of "$url") to download ${label}; check the network and try again" 6 ;;
			*) die "download of ${label} failed (curl exit ${got%%:*}): ${url}" 6 ;;
		esac
	}

	download "${base_url}/${tag}/${archive}" "$archive_path" "the ${os}/${arch} archive"
	download "${base_url}/${tag}/${checksums}" "$checksums_path" "the checksums file"

	# ---- who published it ------------------------------------------------------------------------------------
	# The checksums file is authenticated before anything below trusts it. A verifier that is present and says
	# no is a finding, never a reason to fall back to the checksum: a bundle stripped from a tampered release
	# must not be the thing that lets it install. Only its absence falls back, and only in auto mode.
	verify="${TEGO_VERIFY:-auto}"
	case "$verify" in
		auto)
			if command -v cosign >/dev/null 2>&1; then
				verify=cosign
			elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
				verify=gh
			else
				verify=none
			fi
			;;
		cosign | gh | sha256) ;;
		*) die "TEGO_VERIFY must be auto, cosign, gh or sha256, got '${verify}'" 2 ;;
	esac

	# The identity release.yml signs as: that workflow of this repository, run for this very tag.
	signer="https://github.com/${repo_owner}/${repo_name}/.github/workflows/release.yml@refs/tags/${tag}"
	# attested FILE NAME: in gh mode, the binary FILE (the asset NAME) must carry a build provenance attestation by the
	# release workflow at this tag. --cert-identity is the identity cosign mode checks, the workflow at this tag, and
	# --source-ref the ref the build ran from: with only the workflow's path, any tag's attested binary would pass as
	# this one.
	attested() {
		if ! gh attestation verify "$1" --repo "${repo_owner}/${repo_name}" \
			--cert-identity "$signer" --source-ref "refs/tags/${tag}" >"$verifier_out" 2>&1; then
			show_verifier gh
			die "gh could not verify a build provenance attestation for $2 by ${signer} from refs/tags/${tag} (its output is above). An attestation for another tag, or none, means this is not the ${tag} tego's release workflow published; a gh without network or not logged in fails here too. Not installing it." 9
		fi
	}
	verifier_out="${workdir}/verifier.out"
	# show_verifier prints what the verifier itself said, indented under its name: exit 9 below says only that
	# verification failed, and the verifier's own words are what tell a forged release from an outdated tool or
	# an unreachable trust root.
	show_verifier() {
		sed "s/^/  $1: /" "$verifier_out" >&2
	}
	case "$verify" in
		cosign)
			command -v cosign >/dev/null 2>&1 || die "TEGO_VERIFY=cosign but cosign is not on PATH; install it or choose another TEGO_VERIFY" 2
			bundle_path="${checksums_path}.sigstore.json"
			bundle_url="${base_url}/${tag}/${checksums}.sigstore.json"
			# A bundle the server says is not there is told apart from one that could not be fetched: the first is
			# what a stripped release looks like and stops the install as unverifiable (9), the second is the
			# server's or the network's failure (6) that a retry may cure. Neither falls back to the checksum.
			got=$(fetch "$bundle_url" "$bundle_path")
			case "$got" in
				0:*) ;;
				22:404 | 22:410 | 37:*)
					die "${tag} has no signature bundle (${checksums}.sigstore.json) where its release is; every release tego's release workflow publishes carries one, and a release stripped of it cannot be told from one altered after signing. Not installing it." 9
					;;
				22:*) die "the server answered HTTP ${got#*:} for the signature bundle ${bundle_url}; try again later" 6 ;;
				*) die "could not download the signature bundle ${bundle_url} (curl exit ${got%%:*}); check the network and try again" 6 ;;
			esac
			if ! cosign verify-blob --bundle "$bundle_path" --certificate-identity "$signer" \
				--certificate-oidc-issuer https://token.actions.githubusercontent.com "$checksums_path" >"$verifier_out" 2>&1; then
				show_verifier cosign
				die "cosign could not verify ${checksums} as signed by ${signer} (its output is above). A signature by another identity, or a file changed after signing, means this is not what tego's release workflow published; a cosign too old to read the bundle, or no network to fetch Sigstore's trust root, fails here too. Not installing it." 9
			fi
			;;
		gh)
			command -v gh >/dev/null 2>&1 || die "TEGO_VERIFY=gh but gh is not on PATH; install it or choose another TEGO_VERIFY" 2
			attested "$archive_path" "$archive"
			;;
		none)
			echo "${prog}: note: neither cosign nor a logged-in gh is on PATH, so only the checksum is checked. It proves the download is intact, not who published it: install cosign (how: https://docs.sigstore.dev/cosign/system_config/installation/) or log gh in (gh auth login) and run this again, or set TEGO_VERIFY=sha256 to silence this." >&2
			;;
	esac

	# ---- verify before unpacking ------------------------------------------------------------------------------
	# The whole reason a release ships checksums is so this step happens; an installer that skips it is worse
	# than none, because it looks safe.
	expected=$(awk -v f="$archive" '$2==f {print $1}' "$checksums_path")
	if [ -z "$expected" ]; then
		die "${checksums} has no entry for ${archive}; the release for ${tag} looks incomplete" 7
	fi
	actual=$(sha256_of "$archive_path")
	if [ "$expected" != "$actual" ]; then
		die "checksum mismatch for ${archive}: expected ${expected}, got ${actual}. The download is corrupt or was tampered with — not installing it. Try again, and report it if it repeats." 7
	fi

	# tego-control, when the release has one: the checksums file, authenticated above, says whether it does (a release
	# from before tego-control lists none). It is held to the same checks as tego: its provenance in gh mode, and its
	# checksum.
	control_expected=$(awk -v f="$control" '$2==f {print $1}' "$checksums_path")
	if [ -n "$control_expected" ]; then
		download "${base_url}/${tag}/${control}" "$control_path" "the ${os}/${arch} tego-control"
		[ "$verify" = gh ] && attested "$control_path" "$control"
		control_actual=$(sha256_of "$control_path")
		if [ "$control_expected" != "$control_actual" ]; then
			die "checksum mismatch for ${control}: expected ${control_expected}, got ${control_actual}. The download is corrupt or was tampered with — not installing it. Try again, and report it if it repeats." 7
		fi
	fi

	# ---- install --------------------------------------------------------------------------------------------
	mkdir -p "$prefix" || die "could not create install directory ${prefix}" 8
	# archives.formats is [binary] in .goreleaser.yaml: the verified download already is the executable, nothing
	# to extract. Land it in $prefix under a temp name first so the final `mv` below is a same-filesystem rename.
	tmp_bin="${prefix}/.tego.tmp.$$"
	cp "$archive_path" "$tmp_bin" || die "could not write to ${prefix}" 8
	chmod 755 "$tmp_bin" || die "could not make ${tmp_bin} executable (existing install untouched)" 8
	# Run the new binary where it sits (same directory, same mount options as its final place) before it replaces
	# anything: one that will not run must not cost the user the install that works. Its version names the
	# tego-control SHA-256 it was built with (control_sha256, or none).
	if ! version_out=$("$tmp_bin" version 2>/dev/null); then
		die "the downloaded tego would not run (an Exec format error here usually means an architecture mismatch); any existing install is untouched; please report this" 8
	fi
	pin=$(echo "$version_out" | sed -n 's/^control_sha256=//p')
	# tego runs only the tego-control its pin names: a pair that does not match is refused at every handed-off command
	# ([control-mismatch]), so it is not installed. tego-control itself is not run here: it refuses euid 0, and an
	# install under sudo is one.
	if [ -n "$control_expected" ]; then
		if [ "$pin" != "$control_actual" ]; then
			die "the release's tego is built for tego-control ${pin:-(no pin)}, but its ${control} has SHA-256 ${control_actual}; the release looks inconsistent — not installing it" 7
		fi
		tmp_control="${prefix}/.tego-control.tmp.$$"
		cp "$control_path" "$tmp_control" || die "could not write to ${prefix}" 8
		# 755: tego's handoff refuses a tego-control its group or others can write, or that the user may not execute.
		chmod 755 "$tmp_control" || die "could not make ${tmp_control} executable (existing install untouched)" 8
	elif [ -n "$pin" ] && [ "$pin" != none ]; then
		die "the release's tego is built for tego-control ${pin}, but ${checksums} lists no ${control}; the release for ${tag} looks incomplete" 7
	fi
	# mv into a directory named tego would move the binary inside it and report success with nothing installed.
	for name in tego tego-control; do
		if [ -d "${prefix}/${name}" ]; then
			die "${prefix}/${name} is a directory, not a ${name} binary; move it away or choose another TEGO_PREFIX (nothing installed)" 8
		fi
	done
	control_moved=""
	if [ -n "$tmp_control" ]; then
		mv -f "$tmp_control" "${prefix}/tego-control" || die "could not install ${prefix}/tego-control (existing install untouched)" 8
		tmp_control=""
		control_moved=1
	fi
	# The failure names what this install already replaced: tego-control, when it moved one, else nothing.
	if ! mv -f "$tmp_bin" "${prefix}/tego"; then
		[ -n "$control_moved" ] ||
			die "could not install ${prefix}/tego (existing install untouched)" 8
		die "could not install ${prefix}/tego; ${prefix}/tego-control is already ${tag}'s, so the old tego refuses its control commands ([control-mismatch]) until this install is run again" 8
	fi
	tmp_bin="" # moved: nothing left for cleanup to remove under that name

	installed="${prefix}/tego"

	if [ -n "$control_moved" ]; then
		echo "installed tego ${tag} (${os}/${arch}) to ${installed}, and tego-control beside it"
	else
		echo "installed tego ${tag} (${os}/${arch}) to ${installed}"
		echo "note: ${tag} has no tego-control, which serve and the other commands tego hands to it need: they say [control-not-installed]"
	fi
	echo "licence notices: ${base_url}/${tag}/tego_${version_no_v}_licenses.tar.gz"

	# What comes next, short: the PATH block only when it is needed (with the line for this shell's profile), the
	# scope line only over SSH (tier 1 needs a cgroup the user can place a process in, and an SSH login starts outside
	# one; docs/INSTALL.md "Check the machine"), then the one next command in tego's own hint format (a line starting
	# "next: ", the command on the line after it, indented two spaces).
	echo "Quickstart: https://github.com/${repo_owner}/${repo_name}/blob/main/docs/QUICKSTART.md"
	case ":${PATH}:" in
		*":${prefix}:"*) ;;
		*)
			echo ""
			case "${SHELL:-}" in
				*/fish)
					echo "${prefix} is not on your PATH. Run this line; fish keeps it for later shells too:"
					echo "  fish_add_path \"${prefix}\""
					;;
				*)
					# shellcheck disable=SC2088 # the profile is named for a person to read, not expanded
					case "${SHELL:-}" in
						*/zsh) profile="~/.zshrc" ;;
						*/bash) profile="~/.bashrc" ;;
						*) profile="your shell's profile (~/.profile)" ;;
					esac
					echo "${prefix} is not on your PATH. Run this line, and add it to ${profile} too:"
					echo "  export PATH=\"${prefix}:\$PATH\""
					;;
			esac
			;;
	esac
	if [ -n "${SSH_CONNECTION:-}" ]; then
		echo ""
		echo "over SSH, tego starts no run, not even tego watch, until you open a shell in your user manager's cgroup:"
		echo "  systemd-run --user --scope bash"
	fi
	echo ""
	# tego setup checks the machine and says which step it is on and what to type next (ADR 0142). A
	# release made before it has no setup command, and this script installs any tag, so the installed tego's own
	# command list decides: the line never names a command that tego lacks. Its stdin is not the script's (see the
	# version check above).
	if "$installed" help </dev/null 2>/dev/null | grep -q '^  setup '; then
		echo "next: see where this machine is, step by step, and what to type next:"
		echo "  tego setup"
	else
		echo "next: check this machine:"
		echo "  tego doctor"
	fi
}

main "$@"
