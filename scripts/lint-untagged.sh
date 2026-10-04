#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# lint-untagged.sh — golangci-lint over the files the build tags leave out: .golangci.yml with its build-tags
# line emptied and unused off, as CI's second lint run. `make lint` and scripts/precommit.sh both run it.
# Usage: scripts/lint-untagged.sh [PACKAGE...]   (default ./...; precommit-affected passes the changed packages)
# Environment: GOLANGCI_LINT (golangci-lint). Exit: golangci-lint's status; 1 when the build-tags line changed.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
LINT="${GOLANGCI_LINT:-golangci-lint}"
untagged=.golangci-untagged.yml
trap 'rm -f "$untagged"' EXIT
sed 's/^  build-tags: \[integration, tegobpf, tegotesthooks\]$/  build-tags: []/' .golangci.yml >"$untagged"
grep -qx '  build-tags: \[\]' "$untagged" ||
	{ echo ".golangci.yml's build-tags line changed; update this script and ci.yml's with it"; exit 1; }
"$LINT" run --config "$untagged" --disable unused "${@:-./...}"
