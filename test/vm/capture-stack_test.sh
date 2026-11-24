#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Stand-ins test the acceptance gate; no BPF program or guest is run.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/test/vm" "$work/bin"
cp "$here/capture-stack.sh" "$work/test/vm/"
cat >"$work/test/vm/fetch-kernel.py" <<'PY'
import sys
print("doctor-only" if sys.argv[-1] == "ubuntu-22.04" else "full")
PY
cat >"$work/bin/go" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >"$TRACE/build"
SH
cat >"$work/test/vm/run-in-vm.sh" <<'SH'
#!/bin/bash
set -eu
printf '%s\n' "$*" >"$TRACE/boot"
while [ "$#" -gt 0 ]; do
 case "$1" in
 --status) status=$2; shift ;;
 --log) log=$2; shift ;;
 esac
 shift
done
if [ "${NO_EVIDENCE:-0}" != 1 ]; then
 printf '%s\n' "${STATUS:-guest 0}" >"$status"
 printf '%s\n' "${CONSOLE:---- PASS: TestCaptureStackInvariantOnThisKernel (0.01s)}" >"$log"
fi
exit "${BOOT_RC:-0}"
SH
chmod +x "$work/bin/go" "$work/test/vm/run-in-vm.sh"
export PATH="$work/bin:$PATH" TRACE="$work" GO="$work/bin/go"
unset VM_RUNNER
run() { "$work/test/vm/capture-stack.sh" "$1" "$work/out"; }
for row in rhel-9 al2023 ubuntu-24.04 debian-13 al2023-6.12 ubuntu-25.10 fedora-7.0 fedora-7.2; do
 run "$row"
 grep -q '^test -p 1 -c -tags integration,tegobpf ' "$work/build"
 grep -q -- "^$row --sudo --timeout 300 " "$work/boot"
 grep -q -- '--env TEGO_CAPTURE_STACK_DUMP=1' "$work/boot"
done
for mode in skip nested-skip empty lost fail missing-evidence; do
 case "$mode" in
 skip) CONSOLE='--- SKIP: TestCaptureStackInvariantOnThisKernel (0.01s)' ;;
 nested-skip) CONSOLE=$'    --- SKIP: TestCaptureStackInvariantOnThisKernel/program (0.01s)\n--- PASS: TestCaptureStackInvariantOnThisKernel (0.01s)' ;;
 empty) CONSOLE='testing: warning: no tests to run' ;;
 lost) CONSOLE='--- PASS: TestCaptureStackInvariantOnThisKernel (0.01s)'; STATUS='lost signal 9' ;;
 fail) CONSOLE='--- FAIL: TestCaptureStackInvariantOnThisKernel (0.01s)'; BOOT_RC=1 ;;
 missing-evidence) NO_EVIDENCE=1 ;;
 esac
 export CONSOLE STATUS BOOT_RC NO_EVIDENCE
 if run rhel-9 >"$work/$mode.log" 2>&1; then
  echo "capture-stack_test: $mode was accepted" >&2
  exit 1
 fi
 unset CONSOLE STATUS BOOT_RC NO_EVIDENCE
done
if run ubuntu-22.04 >"$work/doctor-only.log" 2>&1; then
 echo 'capture-stack_test: doctor-only row was accepted' >&2
 exit 1
fi
echo 'capture-stack harness: PASS'
