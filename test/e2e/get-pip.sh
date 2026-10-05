# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# Sourced by pydeps.sh and overhead/run.sh: fetch pip's bootstrapper at a pinned commit and refuse it unless its
# sha256 matches. bootstrap.pypa.io/get-pip.py serves whatever is current, and the script runs as the user on the
# developer's or the CI runner's host, so a changed upstream would run unreviewed code. To bump: take a commit of
# github.com/pypa/get-pip, download public/get-pip.py at it, and update both values below.
GET_PIP_URL="https://raw.githubusercontent.com/pypa/get-pip/f6f644156f23dfe9acc06e7b9ca75eee311f2e37/public/get-pip.py"
GET_PIP_SHA256="fb24e693bab954209a063d90953621412ccad4a500905a726286e038f508ddf6"

# fetch_get_pip DEST [TIMEOUT] downloads the pinned get-pip.py to DEST. It returns 1 when the download failed
# (no network) and 2 when the file does not match the digest, removing it. TEGO_GET_PIP_URL replaces the URL for
# tests only; the digest is checked either way.
fetch_get_pip() {
	local dest="$1" max="${2:-60}"
	curl -fsSL --max-time "$max" -o "$dest" "${TEGO_GET_PIP_URL:-$GET_PIP_URL}" || return 1
	if ! echo "$GET_PIP_SHA256  $dest" | sha256sum -c --status 2>/dev/null; then
		rm -f "$dest"
		return 2
	fi
}
