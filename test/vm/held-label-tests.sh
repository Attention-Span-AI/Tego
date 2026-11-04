#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Usage: test/vm/held-label-tests.sh selinux|smack OUT
# Builds the exact tree, loads a disposable policy, requires every live proof.
# VM_RUNNER optionally wraps the boot (e.g. the shared machine's vmslot).
set -euo pipefail
mode=${1:?selinux or smack}
out=${2:?output directory}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
mkdir -p "$out/prebuilt"
out=$(cd "$out" && pwd)
cd "$repo"
export CGO_ENABLED=0
case "$mode" in
selinux)
 row=fedora-7.0
 export TEGO_VM_LSM=capability,selinux,landlock,yama,bpf,ima,evm TEGO_VM_APPEND=enforcing=1
 "${SECILC:-secilc}" -M false -c 33 -o "$out/policy.bin" -f "$out/file-contexts" internal/runtime/supervisor/testdata/labels/selinux.cil
 go test -p 2 -c -tags integration,tegobpf -o "$out/runtime.test" ./internal/runtime
 go build -p 2 -tags tegobpf,tegotesthooks -o "$out/prebuilt/tego.tegobpf.testhooks" ./cmd/tego
 cp "$out/prebuilt/tego.tegobpf.testhooks" "$out/prebuilt/tego.testhooks"
 ;;
smack)
 row=ubuntu-25.10
 export TEGO_VM_LSM=capability,smack,landlock,yama,bpf
 ;;
*) echo 'choose selinux or smack' >&2; exit 2 ;;
esac
go test -p 2 -c -tags integration -o "$out/supervisor.test" ./internal/runtime/supervisor
files=(--file "$out/supervisor.test:/vm/supervisor.test" --file "$out/prebuilt:/vm/prebuilt"
 --file "$here/go-shim.sh:/usr/local/bin/go" --file "$here/held-label-policy.sh:/vm/held-label-policy.sh"
 --file "$here/held-label-guest.sh:/vm/held-label-guest.sh" --file "$here/held-label-required.sh:/vm/held-label-required.sh")
if [ "$mode" = selinux ]; then
 files+=(--file "$out/runtime.test:/vm/runtime.test" --file "$out/policy.bin:/vm/policy.bin")
fi
runner=()
[ -z "${VM_RUNNER:-}" ] || runner=("$VM_RUNNER")
TEGO_VM_MEM=${TEGO_VM_MEM:-3G} "${runner[@]}" "$here/run-in-vm.sh" "$row" --sudo --timeout 600 \
 --status "$out/guest.status" --log "$out/guest.console" --dmesg "${files[@]}" \
 --env TEGO_VM_PREBUILT=/vm/prebuilt -- /bin/bash /vm/held-label-guest.sh "$mode"
grep -qx 'guest 0' "$out/guest.status"
