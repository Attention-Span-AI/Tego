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
 # Debian 12's 6.1.0-50-amd64, cached by hand under ~/.cache/tego-vm/kernel (bpf/README.md): TOMOYO is built in and off in
 # its default lsm=, so the list names it. It is no matrix row, so it boots through kvm-run.sh itself.
 debian-12-6.1) export TEGO_VM_LSM=capability,landlock,yama,tomoyo,bpf TEGO_VM_KERNEL=6.1.0-50-amd64 TEGO_VM_LOCKDOWN=${TEGO_VM_LOCKDOWN:-none} ;;
 *) echo 'TOMOYO kernel must be ubuntu-25.10, debian-13 or debian-12-6.1' >&2; exit 2 ;;
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
# boot NAME [env...]: one fresh boot of the row's kernel running the guest script, its status in $out/NAME.status.
boot() {
 local name=$1; shift
 local envs=(--env TEGO_VM_PREBUILT=/vm/prebuilt)
 for e in "$@"; do envs+=(--env "$e"); done
 if [ "$row" = debian-12-6.1 ]; then
  TEGO_VM_MEM=${TEGO_VM_MEM:-3G} "${runner[@]}" "$here/kvm-run.sh" --sudo --timeout 600 \
   --status "$out/$name.status" --log "$out/$name.console" --dmesg "${files[@]}" "${envs[@]}" -- /bin/bash /vm/held-label-guest.sh "$mode"
 else
  TEGO_VM_MEM=${TEGO_VM_MEM:-3G} "${runner[@]}" "$here/run-in-vm.sh" "$row" --sudo --timeout 600 \
   --status "$out/$name.status" --log "$out/$name.console" --dmesg "${files[@]}" "${envs[@]}" -- /bin/bash /vm/held-label-guest.sh "$mode"
 fi
 grep -qx 'guest 0' "$out/$name.status"
}
# TEGO_VM_TOMOYO_BOOTS names the TOMOYO boots to make, in order: main (activation), counter (a counted write, no loader),
# enforcing (a profile that enforces), initializer (an unprivileged process moves the counter), flip (a profile mode
# toggled while the proof reads it) and differential (the proof against what the kernel enforces).
boots=${TEGO_VM_TOMOYO_BOOTS:-main counter enforcing initializer flip differential}
has() { case " $boots " in *" $1 "*) return 0 ;; esac; return 1; }
if [ "$mode" != tomoyo ]; then
 boot guest
fi

if [ "$mode" = tomoyo ]; then
 # The first boot activates the policy loader; each other boot is fresh.
 if has main; then boot guest; fi
 # A fresh boot proves that a counted update alone no longer refuses a root tier: no loader runs.
 if has counter; then boot counter TEGO_VM_TOMOYO_COUNTER_ONLY=1; fi
 # SEC08b: a boot whose loader also defines a profile in mode enforcing: every tier refuses, the root tiers' included,
 # which can otherwise prove nothing enforces.
 if has enforcing; then boot enforcing TEGO_VM_TOMOYO_HALF=enforcing_profile; fi
 # SEC08b / C75: an unprivileged process in a user and mount namespace of its own moves the counter by starting
 # /sbin/modprobe; no loader runs. The root tiers admit, tier landlock (the invoking user) refuses with the new sentence.
 if has initializer; then boot initializer TEGO_VM_TOMOYO_HALF=initializer_counter; fi
 # A registered manager toggles a profile category between permissive and enforcing while the proof reads it.
 if has flip; then boot flip TEGO_VM_TOMOYO_HALF=profile_flip_race; fi
 # The proof against what the kernel enforces, random profile states, in a domain whose profile the states set.
 if has differential; then boot differential TEGO_VM_TOMOYO_HALF=differential; fi
fi
