# Decision record: cross-check SSH suite completion with the system manager

Date: 2026-11-12. Status: implemented; acceptance owed in a guest.
This record is kept under `test/vm/`, beside the harness it describes.
This is an unnumbered test-harness record. ADR numbers belong to `docs/adr/`; 0149 is already allocated there.

The old driver accepted a nonce-bearing result when the recorded supervisor disappeared. COMMAND shared its
identity and could read the actual nonce, forge exit 0 and kill the supervisor. A separate working directory
prevented accidental collisions but did not authenticate completion. The wrong-nonce test did not cover this.

The driver now requires root and the guest's system systemd manager. PID 1 runs the supervisor as a transient
service with `RemainAfterExit=yes`; failed units are also retained (no `--collect`). The supervisor writes the
result and exits with the command's wait code, or 124 for its watchdog. The host pins `InvocationID` from the
start reply. Polls require that identity, a terminal service state, normal `ExecMainCode=1`, and agreement of
`ExecMainStatus` with the file. Killing the supervisor yields a signal wait status, not a normal exit 0.
Missing, replaced or disagreeing authority cannot pass. All SSH calls remain bounded. Starts remain idempotent.
Every path passed through ExecStart (supervisor script, state and work directory) doubles dollars before remote
shell quoting. The manager interprets `$$` as a literal dollar. Shell quoting alone cannot stop its later
`${NAME}` expansion. This uses the longstanding `systemd.service(5)` syntax, not a newer `systemd-run` option.

This uses PID 1's own wait, returned through SSH, rather than treating a command-accessible file as authority.
The nonce identifies the run; it is not secret from root. Only the root account is required. The three SSH image
rows are systemd distributions; the service-image provisioner creates an administrator with sudo on each.
A non-root SSH account must use `--sudo`. No user-manager fallback is allowed. This deliberately refuses older
non-root invocations that have no access to the system manager, instead of retaining the weak file-only path.

COMMAND runs as root for root suites. Root can modify the supervisor, manager, units, utilities or SSH and thus
forge evidence even with these checks. The driver trusts that guest authority. Host qemu liveness cannot attest
the outcome. A separate unprivileged workload account would be needed for a stronger guest integrity boundary;
root suites cannot use that boundary without losing the privileges their tests need.

The real-nonce supervisor-kill regression returns guest 0 on the base script and lost suite-gone on the revised
protocol with stand-ins. Other tests retain the earlier closures and cover a mismatching normal wait code and
changed invocation. The manager-path test models one-pass dollar expansion and checks a literal `${TEGO_UNSET}`
and `$$` directory. The checksum test requires evidence that the injected checksum command ran and refused the
read-back. Reboot records change only while polling is acknowledged down. Dropped connections and short logs
hold commands on release files until fault injection. These are protocol tests, not real systemd or guest proof.
The four AlmaLinux acceptance checks below are owed in a guest. No guest, private gate or product binary ran in
this round. Host tests use unprivileged manager stand-ins.
Units and state are retained for diagnosis until the operator stops/resets them or discards the guest.

## AlmaLinux 9.8 acceptance: owed in a guest

All four checks are **owed in a guest**. Do not treat the stand-in test results as real systemd acceptance.
Use a disposable AlmaLinux 9.8 guest with at most 3 GiB RAM.
Run these host commands from the repository root after its starter supplies `SSH` (an executable administrator
SSH wrapper accepting one shell command argument), `QEMU_PID` and `QEMU_STATUS` (the starter's exit/signal file).
The administrator must have passwordless sudo, as the provisioned `tego-admin` does. Do not run these against
the host. No guest is started by the commands below. Keep the starter's console and qemu exit status with the
evidence; an externally killed guest is loss, never an acceptance result.

```sh
set -eu
: "${SSH:?administrator SSH wrapper}" "${QEMU_PID:?guest qemu pid}" "${QEMU_STATUS:?starter status file}"
S="${XDG_CACHE_HOME:-$HOME/.cache}/tego-ssh-suite"
mkdir -p "$S/tmp"
OUT=$(mktemp -d "$S/tmp/guest-checks.XXXXXX")
export TMPDIR="$S/tmp" GOTMPDIR="$S/tmp" GOMAXPROCS=2 GOMEMLIMIT=2GiB GOFLAGS=-p=1
DRIVER="$PWD/test/vm/ssh-suite.sh"
GUEST_DIR='/var/tmp/tego-ssh-suite-${TEGO_UNSET}'
"$SSH" 'cat /etc/almalinux-release; systemd --version | head -n 1; sudo -n id -u'
"$SSH" "sudo -n test ! -e '$GUEST_DIR'"

run_case() {
    case_name=$1 want_rc=$2 want_status=$3
    shift 3
    rc=0
    "$DRIVER" --ssh "$SSH" --sudo \
        --qemu-pid "$QEMU_PID" --qemu-status "$QEMU_STATUS" \
        --dir "$GUEST_DIR" --name "$case_name" --poll 1 --call-timeout 30 --unreachable 90 \
        --status "$OUT/$case_name.status" --log "$OUT/$case_name.log" \
        "$@" >"$OUT/$case_name.out" 2>"$OUT/$case_name.err" || rc=$?
    actual_status=$(cat "$OUT/$case_name.status")
    printf '%s exit=%s status=%s\n' "$case_name" "$rc" "$actual_status"
    test "$rc" = "$want_rc"
    test "$actual_status" = "$want_status"
}
inspect() {
    "$SSH" "sudo -n sh -c 'n=\$(cat \"\$1/\$2/nonce\"); systemctl show \
        \"tego-ssh-suite-\$n.service\" --property=InvocationID --property=ExecMainCode \
        --property=ExecMainStatus --property=ActiveState --property=SubState' inspect '$GUEST_DIR' '$1'" >"$OUT/$1.manager"
    cat "$OUT/$1.manager"
}
```

The first command must report AlmaLinux 9.8, the installed systemd version, and uid `0`. The directory check
must succeed; use a fresh guest if earlier fixtures remain. The literal `${TEGO_UNSET}` path also exercises the
manager-expansion fix against the real service manager.

1. **Ordinary success, owed in a guest.** Expected summary: `success exit=0 status=guest 0`. The log must contain
   `ordinary success` and the literal directory ending in `success.work`. Manager: `ExecMainCode=1`,
   `ExecMainStatus=0`, `ActiveState=active`, `SubState=exited`.

   ```sh
   run_case success 0 'guest 0' --timeout 30 --grace 2 -- sh -c 'echo "ordinary success"; printf "%s\n" "$PWD"'
   grep -Fx 'ordinary success' "$OUT/success.log"
   grep -Fx "$GUEST_DIR/success.work" "$OUT/success.log"
   inspect success
   ```

2. **Nonzero completion, owed in a guest.** Expected summary: `nonzero exit=23 status=guest 23`. The log must
   contain `ordinary failure`. Manager: `ExecMainCode=1`, `ExecMainStatus=23`, `ActiveState=failed`, `SubState=failed`.

   ```sh
   run_case nonzero 23 'guest 23' --timeout 30 --grace 2 -- sh -c 'echo "ordinary failure"; exit 23'
   grep -Fx 'ordinary failure' "$OUT/nonzero.log"
   inspect nonzero
   ```

3. **Timeout cleanup, owed in a guest.** Expected summary: `timeout exit=124 status=timeout`, without
   `group-left`. Manager: `ExecMainCode=1`, `ExecMainStatus=124`, `ActiveState=failed`, `SubState=failed`.
   The final check must print `timeout group empty` with exit 0, confirming no process remains in the recorded
   command group. It does not claim cleanup of descendants that escape the group.

   ```sh
   run_case timeout 124 timeout --timeout 5 --grace 2 -- sh -c '
   echo "$$" >../timeout/pgid
   trap "" TERM
   (trap "" TERM; sleep 600) &
   while :; do sleep 1; done'
   inspect timeout
   "$SSH" "sudo -n sh -c 'g=\$(cat \"\$1/timeout/pgid\") || exit 1; \
       case \"\$g\" in \"\" | *[!0-9]*) exit 1 ;; esac; test \"\$g\" -gt 1 || exit 1; \
       rc=0; pgrep -a -g \"\$g\" || rc=\$?; test \"\$rc\" = 1 || exit 1; \
       echo \"timeout group empty\"' timeout '$GUEST_DIR'"
   ```

4. **Supervisor ended mid-run, owed in a guest.** The command uses the real nonce, forges a zero result and
   kills its actual supervisor. Expected summary: `forged exit=98 status=lost suite-gone`. Both stderr and log
   must have `GUEST-LOST:`; neither may authenticate `guest 0`. Manager: the original invocation,
   `ExecMainCode=2`, `ExecMainStatus=9`, `ActiveState=failed`, `SubState=failed` after cleanup.

   ```sh
   run_case forged 98 'lost suite-gone' --timeout 30 --grace 2 -- sh -c '
   read -r n <../forged/nonce
   printf "%s exit 0 ended\n" "$n" >../forged/result
   kill -KILL "$PPID"
   sleep 30
   exit 1'
   grep '^GUEST-LOST:' "$OUT/forged.err"
   grep '^GUEST-LOST:' "$OUT/forged.log"
   inspect forged
   ```

For each manager capture, `InvocationID` must be the 32-hex identity pinned by startup. Retain the output files,
console and starter status, then discard the disposable guest. Compatibility and cleanup on this real image
remain unmeasured until all four checks run.
