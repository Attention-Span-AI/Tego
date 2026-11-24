#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build a release-shaped integration fixture. Invoke through the resource wrapper;
# these normal binaries are only executed inside the guest, never on the host.
# scripts/windows-release-fixture.sh (the Windows install workflow) builds on it.
set -euo pipefail
if [ "$#" -ne 1 ]; then printf 'usage: %s NEW_ASSETS_DIRECTORY\n' "$0" >&2; exit 2; fi
root=$(cd "$(dirname "$0")/../.." && pwd)
out=$1
if [ -e "$out" ]; then printf 'refusing existing fixture directory: %s\n' "$out" >&2; exit 2; fi
export GOMAXPROCS=${GOMAXPROCS:-4} GOMEMLIMIT=${GOMEMLIMIT:-2GiB} CGO_ENABLED=0
version=${TEGO_FIXTURE_VERSION:-v0.1.1}
# This is the public tree-equivalent source identity, not the private checkout's VCS identity.
public_commit=${TEGO_FIXTURE_PUBLIC_COMMIT:-f01b19dd6c962cf85a447859591e15ae090fe9b4}
if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || ! $public_commit =~ ^[0-9a-f]{40}$ ]]; then
    printf 'fixture version and public commit must be a release tag and full public SHA\n' >&2; exit 2
fi
mkdir -p "$out/$version"
out=$(cd "$out/$version" && pwd)
cd "$root"
date=${TEGO_FIXTURE_DATE:-$(git show -s --format=%cI HEAD)}
flags="-s -w -X github.com/attention-span-ai/tego/internal/buildinfo.version=$version -X github.com/attention-span-ai/tego/internal/buildinfo.commit=$public_commit -X github.com/attention-span-ai/tego/internal/buildinfo.date=$date"
ver=${version#v}
go build -p 2 -buildvcs=false -buildmode=exe -trimpath -ldflags "$flags" -o "$out/tego-control_${ver}_linux_amd64" ./cmd/tego-control
pin=$(sha256sum "$out/tego-control_${ver}_linux_amd64" | cut -d' ' -f1)
go build -p 2 -buildvcs=false -buildmode=exe -trimpath -tags tegobpf -ldflags "$flags -X github.com/attention-span-ai/tego/internal/handoff.controlSHA256=$pin" -o "$out/tego_${ver}_linux_amd64" ./cmd/tego
cp scripts/install.sh examples/systemd/tego-agent@.service "$out/"
printf '{"fixture":true,"public_source_commit":"%s","version":"%s","signature_verified":false}\n' "$public_commit" "$version" > "$out/fixture.json"
cd "$out"
sha256sum "tego_${ver}_linux_amd64" "tego-control_${ver}_linux_amd64" install.sh tego-agent@.service > "tego_${ver}_checksums.txt"
printf 'fixture only, not a published release: %s\n' "$out"
