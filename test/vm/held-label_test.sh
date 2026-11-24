#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Stand-ins cover dispatch, required-pass judging and the guest-only guards.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s\n' '--- PASS: TestRequired (0.01s)' > "$work/pass"
"$here/held-label-required.sh" "$work/pass" TestRequired
if "$here/held-label-required.sh" "$work/pass" TestMissing; then exit 1; fi
printf '%s\n' '    --- SKIP: TestRequired/leaf (0.00s)' >> "$work/pass"
if "$here/held-label-required.sh" "$work/pass" TestRequired; then exit 1; fi
if [ ! -f /.vm/nonce ]; then
 for script in held-label-policy.sh held-label-tomoyo-loader.sh; do
  if "$here/$script" tomoyo; then echo "guest guard failed: $script" >&2; exit 1; fi
 done
fi
mkdir -p "$work/repo/test/vm" "$work/bin"
cp "$here"/held-label*.sh "$here/go-shim.sh" "$work/repo/test/vm/"
cat > "$work/bin/go" <<'STUB'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
 if [ "$1" = -o ]; then touch "$2"; exit 0; fi
 shift
done
exit 1
STUB
cp "$work/bin/go" "$work/bin/secilc"
cat > "$work/repo/test/vm/run-in-vm.sh" <<'STUB'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$HELD_TEST_ARGS"
printf '%s\n' "$TEGO_VM_LSM" "${TEGO_VM_APPEND:-}" > "$HELD_TEST_ENV"
while [ "$#" -gt 0 ]; do
 if [ "$1" = --status ]; then printf 'guest 0\n' > "$2"; exit 0; fi
 shift
done
exit 1
STUB
# Dispatch uses stand-ins only, including VM prerequisites absent on a CI runner.
# A script is sufficient here: the harness's ldd check rejects the real dynamic
# executable below, and no VM ever consumes this BusyBox stand-in.
printf '#!/bin/sh\nexit 0\n' > "$work/busybox"
chmod +x "$work/busybox"
for tool in apt-get apt-cache dpkg-deb dpkg-query cpio flock timeout gpg gpgv xz zstd; do
 if ! command -v "$tool" >/dev/null 2>&1; then ln -s /bin/true "$work/bin/$tool"; fi
done
cp "$work/repo/test/vm/run-in-vm.sh" "$work/repo/test/vm/kvm-run.sh"
chmod +x "$work/bin/"* "$work/repo/test/vm/run-in-vm.sh" "$work/repo/test/vm/kvm-run.sh"
for mode in selinux smack apparmor tomoyo; do
 export HELD_TEST_ARGS="$work/$mode.args" HELD_TEST_ENV="$work/$mode.env"
 : > "$HELD_TEST_ARGS"
 PATH="$work/bin:$PATH" SECILC="$work/bin/secilc" TEGO_VM_BUSYBOX="$work/busybox" VM_RUNNER='' \
  "$work/repo/test/vm/held-label-tests.sh" "$mode" "$work/$mode"
 grep -q -- '--status' "$HELD_TEST_ARGS"
 test -f "$work/$mode/supervisor.test"
 if [ "$mode" != smack ]; then test -f "$work/$mode/runtime.test"; fi
done
grep -q 'tomoyo' "$work/tomoyo.env"
grep -q 'TOMOYO_trigger=/vm/tomoyo-trigger TOMOYO_loader=/vm/tomoyo-loader' "$work/tomoyo.env"
test -f "$work/tomoyo/counter.status"
test -f "$work/tomoyo/enforcing.status"
for boot in initializer flip differential; do test -f "$work/tomoyo/$boot.status"; done
grep -q -- '--env TEGO_VM_TOMOYO_COUNTER_ONLY=1' "$work/tomoyo.args"
grep -q -- '--env TEGO_VM_TOMOYO_HALF=enforcing_profile' "$work/tomoyo.args"
grep -q -- '--env TEGO_VM_TOMOYO_HALF=initializer_counter' "$work/tomoyo.args"
grep -q -- '--env TEGO_VM_TOMOYO_HALF=profile_flip_race' "$work/tomoyo.args"
grep -q -- '--env TEGO_VM_TOMOYO_HALF=differential' "$work/tomoyo.args"
# TEGO_VM_TOMOYO_BOOTS picks the boots, and Debian 12's 6.1 boots through kvm-run.sh itself.
export HELD_TEST_ARGS="$work/tomoyo-only.args" HELD_TEST_ENV="$work/tomoyo-only.env"
: > "$HELD_TEST_ARGS"
PATH="$work/bin:$PATH" TEGO_VM_BUSYBOX="$work/busybox" TEGO_VM_TOMOYO_BOOTS='flip' VM_RUNNER='' \
 "$work/repo/test/vm/held-label-tests.sh" tomoyo "$work/tomoyo-only"
test "$(wc -l < "$HELD_TEST_ARGS")" = 1
grep -q -- '--env TEGO_VM_TOMOYO_HALF=profile_flip_race' "$HELD_TEST_ARGS"
test ! -e "$work/tomoyo-only/guest.status"
grep -q 'tomoyo-loader.fixture' "$work/tomoyo.args"
grep -q '^fedora-7.0 ' "$work/selinux.args"
export HELD_TEST_ARGS="$work/tomoyo-debian.args" HELD_TEST_ENV="$work/tomoyo-debian.env"
: > "$HELD_TEST_ARGS"
PATH="$work/bin:$PATH" TEGO_VM_BUSYBOX="$work/busybox" TEGO_VM_HELD_LABEL_KERNEL=debian-13 VM_RUNNER='' \
 "$work/repo/test/vm/held-label-tests.sh" tomoyo "$work/tomoyo-debian"
grep -q '^debian-13 ' "$HELD_TEST_ARGS"
grep -qx kernel "$HELD_TEST_ENV"
test -f "$work/tomoyo-debian/guest.status"
test -f "$work/tomoyo-debian/counter.status"
test -f "$work/tomoyo-debian/enforcing.status"
export HELD_TEST_ARGS="$work/tomoyo-61.args" HELD_TEST_ENV="$work/tomoyo-61.env"
: > "$HELD_TEST_ARGS"
PATH="$work/bin:$PATH" TEGO_VM_BUSYBOX="$work/busybox" TEGO_VM_HELD_LABEL_KERNEL=debian-12-6.1 TEGO_VM_TOMOYO_BOOTS='main' VM_RUNNER='' \
 "$work/repo/test/vm/held-label-tests.sh" tomoyo "$work/tomoyo-61"
if grep -q '^debian-12-6.1 ' "$HELD_TEST_ARGS"; then exit 1; fi
grep -q -- '--status' "$HELD_TEST_ARGS"
test -f "$work/tomoyo-61/guest.status"
grep -qx 'capability,landlock,yama,tomoyo,bpf' "$HELD_TEST_ENV"
if VM_RUNNER='' "$work/repo/test/vm/held-label-tests.sh" invalid "$work/invalid"; then exit 1; fi

# Missing prerequisites must be named before any fixture compilation or boot.
mkdir "$work/missing-bin"
for tool in dirname mkdir; do ln -s "$(command -v "$tool")" "$work/missing-bin/$tool"; done
if PATH="$work/missing-bin" /bin/bash "$work/repo/test/vm/held-label-tests.sh" tomoyo "$work/no-tools" > "$work/no-tools.log" 2>&1; then
 echo 'missing build tools accepted' >&2; exit 1
fi
for tool in go python3 cpio; do grep -q "missing prerequisite: $tool$" "$work/no-tools.log"; done
test ! -e "$work/no-tools/runtime.test"
if PATH="$work/bin:$PATH" TEGO_VM_BUSYBOX="$work/absent-busybox" /bin/bash "$work/repo/test/vm/held-label-tests.sh" tomoyo "$work/no-busybox" > "$work/no-busybox.log" 2>&1; then
 echo 'missing BusyBox accepted' >&2; exit 1
fi
grep -q 'missing prerequisite: static busybox' "$work/no-busybox.log"
if PATH="$work/bin:$PATH" TEGO_VM_BUSYBOX=/bin/bash /bin/bash "$work/repo/test/vm/held-label-tests.sh" tomoyo "$work/dynamic-busybox" > "$work/dynamic-busybox.log" 2>&1; then
 echo 'dynamic BusyBox accepted' >&2; exit 1
fi
grep -q 'must be static' "$work/dynamic-busybox.log"

# The guest script's paths are relocated only in this stand-in copy.
mkdir "$work/guest"
sed "s@/vm/@$work/guest/@g" "$here/held-label-guest.sh" > "$work/guest/check.sh"
cp "$here/held-label-required.sh" "$work/guest/"
printf '#!/bin/sh\nexit 0\n' > "$work/guest/held-label-policy.sh"
cat > "$work/guest/supervisor.test" <<'STUB'
#!/bin/sh
for name in TestOpenLabelSELinuxCreation TestOpenLabelSmackProcessRules TestOpenLabelAppArmorHiddenAncestors; do
 printf '%s\n' "--- PASS: $name (0.01s)"
done
STUB
cat > "$work/guest/runtime.test" <<'STUB'
#!/bin/sh
if [ "${HELD_TEST_SKIP:-0}" = 1 ]; then printf '%s\n' '--- SKIP: required/leaf (0.01s)'; fi
for name in TestIntegrationHeldOpenTOMOYO TestIntegrationTOMOYOProfileProofDifferential TestIntegrationHeldCreateRespectsSELinux TestIntegrationHeldOpenRespectsAppArmor TestIntegrationHeldOpenRespectsAppArmorWithoutLSMList TestIntegrationHeldOpenSameAppArmorProfileWithoutLSMList; do
 printf '%s\n' "--- PASS: $name (0.01s)"
done
half=positive
if [ "${TEGO_VM_TOMOYO_COUNTER_ONLY:-0}" = 1 ]; then half=counter_without_activation; fi
if [ "${TEGO_VM_TOMOYO_HALF:-}" = enforcing_profile ]; then half=enforcing_profile; fi
if [ "${TEGO_VM_TOMOYO_HALF:-}" = initializer_counter ]; then half=initializer_counter; fi
if [ "${TEGO_VM_TOMOYO_HALF:-}" = profile_flip_race ]; then
 printf '%s\n' "    --- PASS: TestIntegrationHeldOpenTOMOYO/profile_flip_race (0.01s)"
 exit 0
fi
half=${HELD_TEST_HALF:-$half}
for tier in landlock cgroup bpflsm; do
 [ "$tier" != "${HELD_TEST_MISSING_TIER:-}" ] || continue
 printf '%s\n' "    --- PASS: TestIntegrationHeldOpenTOMOYO/$half/$tier (0.01s)"
done
STUB
chmod +x "$work/guest/"*
for mode in selinux smack apparmor tomoyo; do
 bash "$work/guest/check.sh" "$mode" > "$work/$mode-guest.log"
done
if HELD_TEST_SKIP=1 bash "$work/guest/check.sh" tomoyo > "$work/skip.log"; then
 echo 'TOMOYO required guest accepted a skip' >&2; exit 1
fi
TEGO_VM_TOMOYO_COUNTER_ONLY=1 bash "$work/guest/check.sh" tomoyo > "$work/counter-guest.log"
TEGO_VM_TOMOYO_HALF=enforcing_profile bash "$work/guest/check.sh" tomoyo > "$work/enforcing-guest.log"
for half in initializer_counter profile_flip_race differential; do
 TEGO_VM_TOMOYO_HALF=$half bash "$work/guest/check.sh" tomoyo > "$work/$half-guest.log"
done
if TEGO_VM_TOMOYO_HALF=initializer_counter HELD_TEST_HALF=positive bash "$work/guest/check.sh" tomoyo > "$work/wrong-init.log"; then
 echo 'TOMOYO initializer_counter boot accepted the wrong half' >&2; exit 1
fi
if TEGO_VM_TOMOYO_HALF=enforcing_profile HELD_TEST_HALF=positive bash "$work/guest/check.sh" tomoyo > "$work/wrong-enforcing.log"; then
 echo 'TOMOYO enforcing_profile boot accepted the wrong half' >&2; exit 1
fi
for counter in 0 1; do
 wrong=counter_without_activation
 [ "$counter" != 1 ] || wrong=positive
 if TEGO_VM_TOMOYO_COUNTER_ONLY=$counter HELD_TEST_HALF=$wrong bash "$work/guest/check.sh" tomoyo > "$work/wrong-half-$counter.log"; then
  echo "TOMOYO boot counter=$counter accepted the wrong half" >&2; exit 1
 fi
 for tier in landlock cgroup bpflsm; do
  if TEGO_VM_TOMOYO_COUNTER_ONLY=$counter HELD_TEST_MISSING_TIER=$tier bash "$work/guest/check.sh" tomoyo > "$work/missing-$counter-$tier.log"; then
   echo "TOMOYO boot counter=$counter accepted a missing $tier leaf" >&2; exit 1
  fi
 done
done
printf 'held-label self-tests passed\n'
