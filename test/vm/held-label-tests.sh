#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Usage: test/vm/held-label-tests.sh selinux|smack|apparmor|tomoyo OUT
# Builds the exact tree, loads a disposable policy, requires every live proof.
# VM_RUNNER optionally wraps the boot (e.g. the shared machine's vmslot).
set -euo pipefail
mode=${1:?policy mode}
out=${2:?output directory}
export CGO_ENABLED=0
case "$mode" in
selinux)
 row=fedora-7.0
 export TEGO_VM_LSM=capability,selinux,landlock,yama,bpf,ima,evm TEGO_VM_APPEND=enforcing=1
 ;;
smack)
 row=ubuntu-25.10
 export TEGO_VM_LSM=capability,smack,landlock,yama,bpf
 ;;
apparmor)
 row=ubuntu-25.10
 export TEGO_VM_LSM=capability,landlock,yama,apparmor,bpf,ima,evm
 ;;
tomoyo)
 row=${TEGO_VM_HELD_LABEL_KERNEL:-ubuntu-25.10}
 case "$row" in
 ubuntu-25.10) export TEGO_VM_LSM=capability,landlock,yama,apparmor,tomoyo,bpf,ima,evm ;;
 debian-13) export TEGO_VM_LSM=kernel ;;
 *) echo 'TOMOYO kernel must be ubuntu-25.10 or debian-13' >&2; exit 2 ;;
 esac
 export TEGO_VM_APPEND='TOMOYO_trigger=/vm/tomoyo-trigger TOMOYO_loader=/vm/tomoyo-loader'
 ;;
*) echo 'choose selinux, smack, apparmor or tomoyo'  >&2; exit 2 ;;
esac
# Check the build/boot prerequisites before compiling any fixture. QEMU and its
# firmware are fetched by kvm-run.sh unless TEGO_VM_QEMU names a local executable.
missing=0
for tool in go python3 apt-get apt-cache dpkg-deb dpkg-query cpio gzip ldd flock timeout gpg gpgv xz zstd \
 awk basename cat chmod cp cut date dirname find grep head id install ln mkdir mktemp mv readlink realpath rm sed sha256sum sort stat tar touch tr uname; do
 if ! command -v "$tool" >/dev/null 2>&1; then
  echo "held-label-tests: missing prerequisite: $tool" >&2
  missing=1
 fi
done
if [ "$mode" = selinux ] && ! command -v "${SECILC:-secilc}" >/dev/null 2>&1; then
 echo "held-label-tests: missing prerequisite: ${SECILC:-secilc}" >&2
 missing=1
fi
busybox=${TEGO_VM_BUSYBOX:-/usr/bin/busybox}
if [ ! -x "$busybox" ]; then
 echo "held-label-tests: missing prerequisite: static busybox ($busybox)" >&2
 missing=1
elif ldd "$busybox" >/dev/null 2>&1; then
 echo "held-label-tests: prerequisite busybox ($busybox) must be static (install busybox-static)" >&2
 missing=1
fi
[ "$missing" = 0 ] || exit 97
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
mkdir -p "$out/prebuilt"
out=$(cd "$out" && pwd)
cd "$repo"
if [ "$mode" = selinux ]; then
 "${SECILC:-secilc}" -M false -c 33 -o "$out/policy.bin" -f "$out/file-contexts" internal/runtime/supervisor/testdata/labels/selinux.cil
fi
if [ "$mode" != smack ]; then
 go test -p 2 -c -tags integration,tegobpf,tegotesthooks -o "$out/runtime.test" ./internal/runtime
 go build -p 2 -tags tegobpf,tegotesthooks -o "$out/prebuilt/tego.tegobpf.testhooks" ./cmd/tego
 cp "$out/prebuilt/tego.tegobpf.testhooks" "$out/prebuilt/tego.testhooks"
fi
go test -p 2 -c -tags integration,tegotesthooks -o "$out/supervisor.test" ./internal/runtime/supervisor
files=(--file "$out/supervisor.test:/vm/supervisor.test" --file "$out/prebuilt:/vm/prebuilt"
 --file "$here/go-shim.sh:/usr/local/bin/go" --file "$here/held-label-policy.sh:/vm/held-label-policy.sh"
 --file "$here/held-label-guest.sh:/vm/held-label-guest.sh" --file "$here/held-label-required.sh:/vm/held-label-required.sh")
if [ "$mode" != smack ]; then
 files+=(--file "$out/runtime.test:/vm/runtime.test")
fi
if [ "$mode" = selinux ]; then
 files+=(--file "$out/policy.bin:/vm/policy.bin")
fi
if [ "$mode" = tomoyo ]; then
 files+=(--file "$here/held-label-tomoyo-loader.sh:/vm/tomoyo-loader.fixture")
fi
runner=()
[ -z "${VM_RUNNER:-}" ] || runner=("$VM_RUNNER")
TEGO_VM_MEM=${TEGO_VM_MEM:-3G} "${runner[@]}" "$here/run-in-vm.sh" "$row" --sudo --timeout 600 \
 --status "$out/guest.status" --log "$out/guest.console" --dmesg "${files[@]}" \
 --env TEGO_VM_PREBUILT=/vm/prebuilt -- /bin/bash /vm/held-label-guest.sh "$mode"
grep -qx 'guest 0' "$out/guest.status"

# A fresh second boot proves that a counted update alone refuses: no loader runs.
if [ "$mode" = tomoyo ]; then
 TEGO_VM_MEM=${TEGO_VM_MEM:-3G} "${runner[@]}" "$here/run-in-vm.sh" "$row" --sudo --timeout 600 \
  --status "$out/counter.status" --log "$out/counter.console" --dmesg "${files[@]}" \
  --env TEGO_VM_PREBUILT=/vm/prebuilt --env TEGO_VM_TOMOYO_COUNTER_ONLY=1 \
  -- /bin/bash /vm/held-label-guest.sh "$mode"
 grep -qx 'guest 0' "$out/counter.status"
fi
