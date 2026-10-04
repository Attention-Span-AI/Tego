#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# gated-test.sh — go test -json ARGS in the user's systemd manager (scripts/in-user-manager.sh), held to a skip
# list by scripts/skipgate.sh, as CI's unit and integration steps run them. Shared by `make test`,
# `make integration` (so release.sh check runs the gate CI does) and scripts/precommit.sh. Fails on go test's
# status or the gate's.
# -count=1: go test's result cache rechecks only the files the test process itself opens, so a test whose verdict
# rests on a go list, go build or go run subprocess (the link gates, the binary-closure tests) replayed a stale
# "ok (cached)" after a tree change that fails it. It comes first, so a
# caller's own -count still wins.
# Usage: scripts/gated-test.sh LIST CGO_ENABLED ARGS...     Environment: GO (go)
set -uo pipefail
[ $# -ge 3 ] || { echo "usage: scripts/gated-test.sh LIST CGO_ENABLED ARGS..." >&2; exit 2; }
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
list=$1 cgo=$2
shift 2
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-gated.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
st=0
CGO_ENABLED=$cgo ./scripts/in-user-manager.sh "${GO:-go}" test -count=1 -json "$@" >"$tmp/out.json" || st=1
./scripts/skipgate.sh "$list" "$tmp/out.json" || st=1
exit "$st"
