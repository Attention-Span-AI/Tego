#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# pydeps.sh — the Python packages the kill tests install from, fetched once into a local cache.
#
# Why it exists: kill test 4's `pip install` + `pytest` (docs/FEATURES.md R18) and kill test 7 (a Claude
# Agent SDK agent, and a system-Python agent on the Anthropic SDK) need packages this box's system Python
# does not ship, and none may depend on a package index while it is being judged: R18 times each run against
# the median of five runs outside tego, which a registry's latency would swamp, and the kernel-matrix guest
# has no network at all. So the packages are fetched here once, with the network, and the tests install
# from the cache offline:
#   pip-bootstrap/    pip itself (get-pip.py at a pinned commit and sha256, --target), since Ubuntu's python3 ships no pip module;
#   wheelhouse/       test/workloads/build/python/requirements.txt, the §9 build workload's pinned, hashed wheels;
#   anthropic-site/   the Anthropic Python SDK and its dependencies, installed with --target, for PYTHONPATH;
#   claude-sdk-site/  with --claude-sdk only: the Claude Agent SDK for Python and its dependencies, the same
#                     way. Its wheel bundles the Claude Code binary, about 270 MB installed, so only the kill
#                     test that runs it asks for it.
# The wheelhouse list, the SDKs and every package they pull in are pinned to exact versions and wheel sha256s (pydeps/*.txt, installed
# with --require-hashes; the wheelhouse download too), so a kill-test result names the client it exercised and a changed release cannot run.
#
# Usage: test/e2e/pydeps.sh [--claude-sdk] [DIR]   (default: $KT_PYDEPS, else ~/.cache/tego-kt/python)
# Prints DIR on success. Exit 97, with the reason on stderr, when the cache is incomplete and cannot be
# filled here: no network, or get-pip.py or pip failing (the same "this box cannot" code test/vm uses).
set -euo pipefail

ANTHROPIC_VERSION="1.8.0"
CLAUDE_SDK_VERSION="0.2.158"

claude_sdk=no
if [ "${1:-}" = --claude-sdk ]; then
	claude_sdk=yes
	shift
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
dir="${1:-${KT_PYDEPS:-$HOME/.cache/tego-kt/python}}"
mkdir -p "$dir"
# shellcheck source=test/e2e/get-pip.sh
. "$here/get-pip.sh"
env_fail() { echo "pydeps: $*" >&2; exit 97; }
command -v python3 >/dev/null 2>&1 || env_fail "no python3 on PATH"

pip() { PYTHONPATH="$dir/pip-bootstrap" python3 -m pip --disable-pip-version-check -q "$@"; }

if [ ! -d "$dir/pip-bootstrap/pip" ]; then
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	rc=0
	fetch_get_pip "$tmp/get-pip.py" || rc=$?
	[ "$rc" != 2 ] || env_fail "get-pip.py does not match the pinned sha256 (test/e2e/get-pip.sh); not running it"
	[ "$rc" = 0 ] || env_fail "cannot download get-pip.py (no network?) and $dir/pip-bootstrap is not primed"
	rm -rf "$dir/pip-bootstrap.part"
	python3 "$tmp/get-pip.py" --target="$dir/pip-bootstrap.part" --no-warn-script-location -q ||
		env_fail "get-pip.py could not install pip into $dir/pip-bootstrap.part"
	rm -rf "$dir/pip-bootstrap"
	mv "$dir/pip-bootstrap.part" "$dir/pip-bootstrap"
fi

req="$repo/test/workloads/build/python/requirements.txt"
stamp_w="$(sha256sum "$req" | cut -c1-16)"
if [ "$(cat "$dir/wheelhouse/.stamp" 2>/dev/null)" != "$stamp_w" ]; then
	rm -rf "$dir/wheelhouse.part"
	pip download --only-binary=:all: --require-hashes -d "$dir/wheelhouse.part" -r "$req" ||
		env_fail "pip download of $req failed (no network?)"
	echo "$stamp_w" >"$dir/wheelhouse.part/.stamp"
	rm -rf "$dir/wheelhouse"
	mv "$dir/wheelhouse.part" "$dir/wheelhouse"
fi

# A site's stamp names its top-level version and the sha256 of the pinned, hashed list it was installed from, so
# editing a transitive pin or hash without bumping the version installs again (the wheelhouse stamp does the same).
stamp_a="anthropic==$ANTHROPIC_VERSION $(sha256sum "$here/pydeps/anthropic.txt" | cut -c1-16)"
stamp_c="claude-agent-sdk==$CLAUDE_SDK_VERSION $(sha256sum "$here/pydeps/claude-sdk.txt" | cut -c1-16)"
if [ "$(cat "$dir/anthropic-site/.stamp" 2>/dev/null)" != "$stamp_a" ]; then
	rm -rf "$dir/anthropic-site.part"
	pip install --only-binary=:all: --require-hashes --target "$dir/anthropic-site.part" -r "$here/pydeps/anthropic.txt" ||
		env_fail "pip install anthropic==$ANTHROPIC_VERSION failed (no network?)"
	echo "$stamp_a" >"$dir/anthropic-site.part/.stamp"
	rm -rf "$dir/anthropic-site"
	mv "$dir/anthropic-site.part" "$dir/anthropic-site"
fi

if [ "$claude_sdk" = yes ] && [ "$(cat "$dir/claude-sdk-site/.stamp" 2>/dev/null)" != "$stamp_c" ]; then
	rm -rf "$dir/claude-sdk-site.part"
	pip install --only-binary=:all: --require-hashes --target "$dir/claude-sdk-site.part" -r "$here/pydeps/claude-sdk.txt" ||
		env_fail "pip install claude-agent-sdk==$CLAUDE_SDK_VERSION failed (no network?)"
	echo "$stamp_c" >"$dir/claude-sdk-site.part/.stamp"
	rm -rf "$dir/claude-sdk-site"
	mv "$dir/claude-sdk-site.part" "$dir/claude-sdk-site"
fi

echo "$dir"
