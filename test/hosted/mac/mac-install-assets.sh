#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# CI-only unsigned release fixture, never run its Linux binaries on the build host.
# Match .goreleaser.yaml: static exe, trimpath, tegobpf engine, shared buildinfo,
# commit date, and the release's own control-pin pre-hook. Only Intel is booted.
# GitHub documents these runner facts (no workflow override is needed):
# https://docs.github.com/en/actions/reference/workflows-and-actions/variables
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  echo 'this script installs the real product and is only for GitHub-hosted machines' >&2
  exit 2
fi
set -euo pipefail
out=$1
version=v0.2.0-macci
commit=$(git rev-parse HEAD)
date=$(git show -s --format=%cI HEAD)
module=$(go list -m)
mkdir -p "$out/$version"
echo "CHECK build release-shaped linux/amd64 pair at $commit ($version)"
scripts/control-pin.sh "$out/pin" linux amd64 "$version" "$commit" "$date"
pin=$(cat "$out/pin/tego-control.sha256")
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags tegobpf -buildmode=exe \
  -ldflags "-s -w -X $module/internal/buildinfo.version=$version -X $module/internal/buildinfo.commit=$commit -X $module/internal/buildinfo.date=$date -X $module/internal/handoff.controlSHA256=$pin" \
  -o "$out/$version/tego_${version#v}_linux_amd64" ./cmd/tego
cp "$out/pin/tego-control" "$out/$version/tego-control_${version#v}_linux_amd64"
scripts/check-control-pin.sh --static "$out/$version/tego_${version#v}_linux_amd64" "$out/$version/tego-control_${version#v}_linux_amd64"
cp scripts/install.sh examples/lima/tego.yaml "$out/$version/"
(cd "$out/$version" && sha256sum -- install.sh tego.yaml *linux_amd64 >"tego_${version#v}_checksums.txt")
rm -rf "$out/pin"
echo "CHECK real checksums for every served file (no signature or attestation is claimed)"
(cd "$out/$version" && sha256sum -c "tego_${version#v}_checksums.txt")
