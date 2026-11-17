#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Only disposable guests: policy installation refuses every other machine.
set -euo pipefail
mode=$1
/vm/held-label-policy.sh "$mode" /vm/policy.bin
uname -r
cat /sys/kernel/security/lsm
case "$mode" in
selinux) name=TestOpenLabelSELinuxCreation ;;
smack) name=TestOpenLabelSmackProcessRules ;;
apparmor) name=TestOpenLabelAppArmorHiddenAncestors ;;
tomoyo)
 export TEGO_VM_TOMOYO_COUNTER_ONLY=${TEGO_VM_TOMOYO_COUNTER_ONLY:-0}
 /vm/runtime.test -test.v -test.run '^TestIntegrationHeldOpenTOMOYO$' -test.timeout=300s | tee /vm/runtime.log
 /vm/held-label-required.sh /vm/runtime.log TestIntegrationHeldOpenTOMOYO
 half=positive
 if [ "$TEGO_VM_TOMOYO_COUNTER_ONLY" = 1 ]; then half=counter_without_activation; fi
 for tier in landlock cgroup bpflsm; do
  /vm/held-label-required.sh /vm/runtime.log "TestIntegrationHeldOpenTOMOYO/$half/$tier"
 done
 exit 0
 ;;
*) exit 2 ;;
esac
/vm/supervisor.test -test.v -test.run "^$name$" -test.timeout=120s | tee /vm/supervisor.log
/vm/held-label-required.sh /vm/supervisor.log "$name"
if [ "$mode" = selinux ]; then
 /vm/runtime.test -test.v -test.run '^TestIntegrationHeldCreateRespectsSELinux$' -test.timeout=300s | tee /vm/runtime.log
 /vm/held-label-required.sh /vm/runtime.log TestIntegrationHeldCreateRespectsSELinux
fi

if [ "$mode" = apparmor ]; then
 /vm/runtime.test -test.v -test.run '^TestIntegrationHeldOpen(RespectsAppArmor|RespectsAppArmorWithoutLSMList|SameAppArmorProfileWithoutLSMList)$' -test.timeout=300s | tee /vm/runtime.log
 /vm/held-label-required.sh /vm/runtime.log TestIntegrationHeldOpenRespectsAppArmor TestIntegrationHeldOpenRespectsAppArmorWithoutLSMList TestIntegrationHeldOpenSameAppArmorProfileWithoutLSMList
fi
