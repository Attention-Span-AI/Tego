#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# control-pin.sh OUT GOOS GOARCH VERSION COMMIT DATE: builds tego-control for one release target exactly as
# .goreleaser.yaml's tego-control build does (same flags, ldflags and environment, so the same bytes: the build is
# reproducible), to OUT/tego-control, and writes its SHA-256 to OUT/tego-control.sha256. .goreleaser.yaml's tego
# build runs it as a pre hook and links that hash into tego (internal/handoff.controlSHA256, ADR 0100 (1b));
# release.yml and CI's reproducible job then check that the tego-control goreleaser built is the pinned one
# (check-control-pin.sh --static). Keep the flags here and in .goreleaser.yaml's tego-control build the same.
set -euo pipefail
if [ "$#" -ne 6 ]; then
	echo "usage: $0 OUT GOOS GOARCH VERSION COMMIT DATE" >&2
	exit 2
fi
out=$1 goos=$2 goarch=$3 version=$4 commit=$5 date=$6
mkdir -p "$out"
pkg=github.com/attention-span-ai/tego/internal/buildinfo
CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch "${GO:-go}" build -trimpath -buildmode=exe \
	-ldflags "-s -w -X $pkg.version=$version -X $pkg.commit=$commit -X $pkg.date=$date" \
	-o "$out/tego-control" ./cmd/tego-control
sha256sum "$out/tego-control" | cut -d' ' -f1 | tr -d '\n' >"$out/tego-control.sha256"
