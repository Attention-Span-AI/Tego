#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The tiers scene (README.md, "Tiers"), sourced by demo.sh: it uses demo.sh's say, show, piped, plant, sink_up,
# damage, last_run and need_tego. Tier 1 runs here; tier 2 needs sudo (the presenter types the password);
# tier 3 runs only when BPF LSM is active, otherwise the one-time enable steps are printed, never run.

cmd_tiers() {
  need_tego
  say "Tiers: what this machine can enforce (tego doctor, short)"
  # whole lines, folded at a space: a cut in the middle of a word hid the lsm fix
  show "'$TEGO' doctor 2>&1 | grep -E '^(ok|FAIL|skip) +(landlock|seccomp|cgroupv2|lsm|fanotify)|^tier:|^missing for' | fold -s -w 150 || true"

  # Each run goes to the screen, without tego's notes, and to stage/run.out. Whether a tier ran is its command's own
  # exit status (piped), not grep's: a sudo or a tego that refused the run is said to be one, never followed by an
  # untouched machine or an earlier run's tier as if this run had been made.
  filter="tee '$STAGE/run.out' | grep -v -E '^(warning|note|  fix:)|no price table'"
  plant; sink_up; : >"$STAGE/sink.log"
  say "Tier 1 (landlock): no root. Landlock + the seccomp supervisor"
  if piped "cd '$PROJECT' && '$TEGO' run --tier landlock agent.yaml </dev/null 2>&1" "$filter"; then
    run=$(run_id_in "$STAGE/run.out")
    [ -n "$run" ] || run=$(last_run demo-guarded)
    [ -n "$run" ] && echo "$run" >"$STAGE/last-run"
    [ -n "$run" ] && show "'$TEGO' events '$run' --kind run_start 2>&1 | grep -o -E 'tier[^,]{0,30}' | head -n 3"
  else
    echo "(tier 1 did not run: exit $?, see the message above)"
  fi

  say "Tier 2 (cgroup): root. cgroup BPF + fanotify; every process of the run sits in one cgroup"
  echo "(needs a tego built with the BPF objects: make build. The ledger goes to the invoking user's"
  echo " ~/.tego/runs (sudo's SUDO_UID), so 'tego events', './demo.sh why' and the dashboard read it as you.)"
  plant; : >"$STAGE/sink.log"
  t2="cd '$PROJECT' && sudo --preserve-env=SECRETS,SINK,HOMEISH,PROJECT,PYTHON3,PATH,TEGO_CONFIG,XDG_RUNTIME_DIR '$(command -v "$TEGO")' run --tier cgroup agent.yaml </dev/null 2>&1"
  if [ "${DEMO_SUDO:-ask}" = no ]; then
    printf '$ %s | %s\n(DEMO_SUDO=no: not run)\n' "$t2" "$filter"
  elif piped "$t2" "$filter"; then
    damage
    run=$(run_id_in "$STAGE/run.out")
    [ -n "$run" ] || run=$(last_run demo-guarded)
    [ -n "$run" ] && echo "$run" >"$STAGE/last-run"
    [ -n "$run" ] && show "'$TEGO' events '$run' --kind run_start 2>&1 | grep -o -E 'tier[^,]{0,30}|cgroup[^,]{0,80}' | head -n 4"
  else
    echo "(tier 2 did not run: exit $?, see the message above)"
  fi

  say "Tier 3 (bpflsm): root + BPF LSM in the kernel's lsm= list"
  lsm=$(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)
  echo "active LSMs: $lsm"
  case ",$lsm," in
    *,bpf,*)
      plant; : >"$STAGE/sink.log"
      if piped "cd '$PROJECT' && sudo --preserve-env=SECRETS,SINK,HOMEISH,PROJECT,PYTHON3,PATH,TEGO_CONFIG,XDG_RUNTIME_DIR '$(command -v "$TEGO")' run --tier bpflsm agent.yaml </dev/null 2>&1" \
        "grep -v -E '^(warning|note|  fix:)|no price table'"; then
        damage
      else
        echo "(tier 3 did not run: exit $?, see the message above)"
      fi ;;
    *)
      echo "BPF LSM is not active on this machine's kernel, so tier 3 is not run here. One-time steps to enable it (NOT run by this demo):"
      echo "  1. sudoedit /etc/default/grub and add to  GRUB_CMDLINE_LINUX_DEFAULT  (the variable tego doctor names):  lsm=$lsm,bpf"
      echo "  2. sudo update-grub"
      echo "  3. reboot"
      echo "  4. cat /sys/kernel/security/lsm     # must now end in ,bpf; then: ./demo.sh tiers" ;;
  esac
}
