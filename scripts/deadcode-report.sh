#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ADR 0029 (4): report production reachability for the four tag sets on both architectures and apply the
# classification ratchet (tools/deadcodereport -gate): an unclassified unreachable function, a stale
# classification or an unavailable profile fails; the number of classified findings is not gated.
set -euo pipefail

if [ "$#" -ne 2 ] || [ "$1" != -o ] || [ -z "$2" ]; then
    echo 'usage: scripts/deadcode-report.sh -o NEW_OUTPUT_DIRECTORY' >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$repo"
out=$2
if [ -e "$out" ] || [ -L "$out" ]; then
    echo "deadcode report: output must be new: $out" >&2
    exit 2
fi
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd)
go_cmd=${TEGO_DEADCODE_GO:-go}
tool=golang.org/x/tools/cmd/deadcode@v0.50.0
# The analyzer executes on the host. GOARCH below selects packages to analyze,
# not the analyzer's own executable (cross-compiled `go run` cannot execute).
host_os=$("$go_cmd" env GOHOSTOS)
host_arch=$("$go_cmd" env GOHOSTARCH)
install_status=0
GOOS=$host_os GOARCH=$host_arch CGO_ENABLED=0 GOBIN="$out/.tool" timeout 300s \
    "$go_cmd" install "$tool" >"$out/tool-install.stdout" 2>"$out/tool-install.stderr" || install_status=$?
printf '%s\n' "$install_status" >"$out/tool-install.status"
if [ "$install_status" -eq 0 ]; then
    sha256sum "$out/.tool/deadcode" >"$out/tool.sha256"
fi
failed=0
for arch in amd64 arm64; do
    for mode in plain integration tegobpf integration-tegobpf; do
        name=linux-$arch-$mode
        args=(-json)
        if [ "$mode" != plain ]; then args+=(-tags "${mode/-/,}"); fi
        args+=(./cmd/tego)
        # A tool/download/type-check failure remains unavailable, with stderr and
        # status retained. It must never turn into an empty successful report.
        status=$install_status
        if [ "$install_status" -eq 0 ]; then
            GOOS=linux GOARCH=$arch CGO_ENABLED=0 timeout 300s \
                "$out/.tool/deadcode" "${args[@]}" >"$out/$name.json" 2>"$out/$name.stderr" || status=$?
        else
            : >"$out/$name.json"
            cp -- "$out/tool-install.stderr" "$out/$name.stderr"
        fi
        printf '%s\n' "$status" >"$out/$name.status"
        if [ "$status" -ne 0 ]; then failed=1; fi
    done
done
GOOS=$host_os GOARCH=$host_arch CGO_ENABLED=0 \
    "$go_cmd" run ./tools/deadcodereport -dir "$out" -allow tools/deadcode-allow.txt -gate || failed=1
if [ -f "$out/report.md" ]; then cat -- "$out/report.md"; fi
exit "$failed"
