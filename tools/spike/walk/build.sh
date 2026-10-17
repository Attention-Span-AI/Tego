#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build.sh — SPIKE (TIER3-PLAN T0), not part of tego's build: compiles bpf/spike/walk.bpf.c in its eight walk forms and
# the static loader into OUT (default bin/spike-walk). clang is test/vm/fetch-clang.sh's unless CLANG is set.
# Usage: tools/spike/walk/build.sh [OUT]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
out="${1:-$root/bin/spike-walk}"
mkdir -p "$out"
clang="${CLANG:-$("$root/test/vm/fetch-clang.sh")}"
go="${GO:-go}"
for f in "a-rd 1 1 0" "a-pr 1 0 0" "b-rd 0 1 0" "b-pr 0 0 0" "c-rd 0 1 1" "c-pr 0 0 1" "d-rd 1 1 1" "d-pr 1 0 1"; do
	# shellcheck disable=SC2086 # one form: name, WALK_GLOBAL, READ_RDONLY, WALK_LOOP
	set -- $f
	"$clang" -O2 -g -Wall -Werror -target bpfel -D__TARGET_ARCH_x86 -DWALK_GLOBAL="$2" -DREAD_RDONLY="$3" -DWALK_LOOP="$4" \
		-I"$root/bpf/include" -c "$root/bpf/spike/walk.bpf.c" -o "$out/walk-$1.o"
done
(cd "$root" && CGO_ENABLED=0 "$go" build -tags tegospike -trimpath -o "$out/spike" ./tools/spike/walk)
cp "$here/run.sh" "$out/run.sh"
echo "$out"
