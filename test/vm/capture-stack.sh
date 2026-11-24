#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Usage: test/vm/capture-stack.sh ROW OUT
# Every full kernel row must load and read back the capture programs and offer
# uprobes. VM_RUNNER optionally wraps the guest boot with a site's slot allocator.
set -euo pipefail
row=${1:?kernel matrix row}
out=${2:?output directory}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
body=$(python3 "$here/fetch-kernel.py" --body "$row")
[ "$body" = full ] || { echo "capture-stack: $row is not a full kernel matrix row" >&2; exit 2; }
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$repo"
CGO_ENABLED=0 "${GO:-go}" test -p 1 -c -tags integration,tegobpf -o "$out/doctor.test" ./internal/doctor
runner=()
[ -z "${VM_RUNNER:-}" ] || runner=("$VM_RUNNER")
rm -f "$out/guest.status" "$out/guest.console"
TEGO_VM_MEM=${TEGO_VM_MEM:-1536M} "${runner[@]}" "$here/run-in-vm.sh" "$row" \
 --sudo --timeout 300 --status "$out/guest.status" --log "$out/guest.console" \
 --env TEGO_CAPTURE_STACK_DUMP=1 -- "$out/doctor.test" -test.v -test.timeout=240s \
 -test.run '^TestCaptureStackInvariantOnThisKernel$'
grep -qx 'guest 0' "$out/guest.status"
# A zero exit after a skip or an empty test selection proves no acceptance.
if grep -Eq -- '^[[:space:]]*--- SKIP:' "$out/guest.console"; then
 echo "capture-stack: a required kernel invariant skipped on $row" >&2
 exit 1
fi
grep -q -- '^--- PASS: TestCaptureStackInvariantOnThisKernel (' "$out/guest.console" || {
 echo "capture-stack: the loaded capture invariant did not pass on $row" >&2
 exit 1
}
