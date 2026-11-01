#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks a project's saved Maze rules with the real engine, from a Mac: runs `tego compile <contract> --test
# <verdicts>` in a Linux container (Colima/Docker), the way `maze` does by itself on Linux. Stand-in programs
# are put on PATH for every program the contract allows, because compile refuses a program it can't find and
# the container has none of the project's toolchain; nothing is run, only checked.
#
# Usage: scripts/maze-verify.sh [project]   (default: the current folder; run `maze` there and Start first)
# Needs: docker with Colima (or Docker Desktop) sharing the home folder; Go to build the engine for Linux.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="$(cd "${1:-.}" && pwd)"
id="$(printf %s "$project" | shasum -a 256 | cut -c1-16)"
contract="$HOME/.maze/projects/$id/claude.yaml"
verdicts="$HOME/.maze/projects/$id/claude.verdicts.yaml"
[ -f "$contract" ] || { echo "maze-verify: no $contract; run maze in $project and choose Start first" >&2; exit 2; }
command -v docker >/dev/null || { echo "maze-verify: docker is not on PATH" >&2; exit 2; }

arch=arm64; [ "$(uname -m)" = x86_64 ] && arch=amd64
tego="$repo/bin/linux-$arch/tego.testhooks"
if [ ! -x "$tego" ]; then
	echo "maze-verify: building the engine for Linux ($arch)…"
	(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -tags tegobpf,tegotesthooks -trimpath -o "$tego" ./cmd/tego)
fi
# A test build, so the chain anchor and own log land in a throwaway folder, never in the user's ~/.tego.
iso="$repo/bin/verify-iso"
rm -rf "$iso" && mkdir -p "$iso"

stubs="$repo/bin/verify-bin"   # outside the project, so the agent could not overwrite them
rm -rf "$stubs" && mkdir -p "$stubs"
# The programs the contract allows (exec.allow), plus claude, the contract's command.
python3 - "$contract" "$stubs" <<'PY'
import json, re, sys, os
text = open(sys.argv[1]).read()
m = re.search(r'^exec:\n  allow: (\[.*\])', text, re.M)
names = json.loads(m.group(1)) if m else []
for n in names + ["claude"]:
    if n in ("bash", "sh"):
        continue
    p = os.path.join(sys.argv[2], os.path.basename(n))
    with open(p, "w") as f:
        f.write("#!/bin/sh\n# stand-in for maze-verify; never run\nexit 0\n")
    os.chmod(p, 0o755)
PY

docker run --rm -v "$HOME:$HOME" -v "$project:$project" -v "$repo:$repo" -w "$project" -e HOME="$HOME" -e TEGO_TEST_CHAIN_ANCHOR="$iso/chain.log" -e TEGO_TEST_OWN_LOG_HOME="$iso" -e PATH="$stubs:/usr/local/bin:/usr/bin:/bin" \
	debian:stable-slim "$tego" compile "$contract" --offline --test "$verdicts"
