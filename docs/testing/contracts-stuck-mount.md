# Recorded paths on a stopped FUSE server

**MERGE BLOCKER: owed in a guest.** No execution of this recipe is claimed. Host
ptrace tests stop before syscall execution; they do not prove command exit while
the kernel waits for FUSE. A passing syntax check does not lift this blocker.
The maintainer runs the recipe on this branch's final commit. No guest run from
an earlier commit satisfies this acceptance check.

This recipe is self-contained in `docs/testing`. It uses a real read-only FUSE
filesystem which first answers normally. Its server is then stopped with SIGSTOP,
so uncached requests wait in the kernel. It is subsequently killed with SIGKILL,
or released through the FUSE connection's abort file. The mount has zero entry and
attribute cache lifetimes. No fake timeout, ptrace stop, FIFO, network timeout or
external staged server stands in for the mount.

Use a fresh disposable KVM guest on an authorized machine after the release has
released its guest slots. Required guest tools are Python 3 with its standard
library, `setpriv`, `fusermount`, `mount`, and kernel FUSE support. No fusepy or
libfuse development package is needed. The host needs the repository's VM kit
prerequisites (`test/vm/README.md`), installed QEMU, `fusermount`, the installed
sudo-rs and `pam_permit.so` to stage into the guest. The host staging script reads
their trusted ELF images and recursive `ldd` dependencies; it never executes sudo.
It hashes the copied files and leaves the host unchanged. Guest root installs
them, enables the sudo setuid bit, and writes a fixture-only NOPASSWD policy and
PAM permit stack. Only a disposable guest may run that installation. The guest
must have a non-root invoking uid with cpu/memory/pids delegation. The kit's
`--sudo --delegate-user` supplies that uid, but its synthetic SUDO metadata is not
used as proof: each sudo cell actually starts as that user and invokes the staged
`/usr/bin/sudo -n -u root`. Do not run the guest entry point or a product binary on
the host. The versioned staging script deliberately refuses a different sudo
implementation; use a full disposable distro guest with sudo-rs installed for it.

From the repository root, the following is the complete build and launch recipe.
Set CONTRACTS_CHECK to a host command wrapper that caps memory and CPU, and
CONTRACTS_VM_SLOT to a wrapper that serializes guest launches. All Go commands
and the guest launch run sequentially through these wrappers, with GOMAXPROCS=2
and `-p 1`. Choose a disk-backed CONTRACTS_SCRATCH directory. Run only when guest execution is authorized; this fix round
does not authorize it.

```bash
set -eu
test -z "$(git status --porcelain)"  # Build only the clean final commit recorded below.
S=${CONTRACTS_SCRATCH:?set CONTRACTS_SCRATCH to a disk-backed scratch directory}
: "${CONTRACTS_CHECK:?set CONTRACTS_CHECK to a memory-capped command wrapper}"
: "${CONTRACTS_VM_SLOT:?set CONTRACTS_VM_SLOT to a serial guest launcher wrapper}"
check() {
  "$CONTRACTS_CHECK" "$@"
}
O="$S/fuse-guest-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$O/tmp"
export TMPDIR="$O/tmp" GOTMPDIR="$O/tmp" GOMAXPROCS=2 GOMEMLIMIT=2GiB GOFLAGS=-p=1
export PATH="/usr/bin:$HOME/.local/go/bin:$HOME/go/bin:$PATH"
check env CGO_ENABLED=0 go build -tags tegotesthooks -o "$O/tego" ./cmd/tego
check env CGO_ENABLED=0 go build -tags tegotesthooks -o "$O/tego-control" ./cmd/tego-control
sha256sum "$O/tego" "$O/tego-control" > "$O/binaries.sha256"
git rev-parse HEAD > "$O/head"
python3 -I docs/testing/contracts-stage-sudo.py "$O/sudo-support" > "$O/sudo-files.json"
python3 test/vm/fetch-kernel.py --modules ubuntu-25.10 > "$O/module-tree"
export CONTRACTS_QEMU_REAL
CONTRACTS_QEMU_REAL=$(command -v qemu-system-x86_64)
test -x "$CONTRACTS_QEMU_REAL"
export CONTRACTS_QEMU_STATUS="$O/qemu.status"
export TEGO_VM_QEMU="$(pwd)/docs/testing/contracts-qemu-status.sh"
export TEGO_VM_MEM=3G TEGO_VM_LOCKDOWN=none
set +e
check "$CONTRACTS_VM_SLOT" \
  test/vm/run-in-vm.sh ubuntu-25.10 --sudo --delegate-user \
  --module fuse --module unix_diag --module inet_diag --module tcp_diag \
  --timeout 1800 --log "$O/console.log" --status "$O/harness.status" \
  --file "$O/tego:/vm/tego" --file "$O/tego-control:/vm/tego-control" \
  --file "$(pwd)/docs/testing:/vm/recipes" \
  --file "$O/sudo-support:/vm/sudo-support" \
  --file "$(readlink -f /usr/bin/fusermount):/usr/bin/fusermount" \
  --env TEGO_DISPOSABLE_HOST=kvm \
  -- /bin/sh /vm/recipes/contracts-stalled-mount.sh > "$O/launch.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" > "$O/wrapper.status"
cat "$O/wrapper.status" "$O/harness.status" "$O/qemu.status"
python3 -I docs/testing/contracts-stalled-mount.py --host-status "$O"
```

The launch loads the socket diagnostic modules needed by the supervisor and the
dashboard sign-in guard, as well as FUSE. The resolved fusermount image is copied
as a regular file because the host command may be a symlink to fusermount3, which
the minimal guest does not otherwise contain. All fixture source and entry points
are staged from this checkout. The executable
`contracts-qemu-status.sh` records the actual QEMU child's raw exit status, ignores
the harness's preliminary `--version` call, and forwards signals only to its own
child. Keep the three statuses, HEAD, binary hashes, module provenance and complete
console/launch logs. A lost guest, absent status, timeout or memory-guard kill is
incomplete evidence. Inspect the host memory-guard log before assigning a verdict.
Do not retry a failed assertion into a passing claim. The fresh evidence directory
and fresh guest keep each run separate.

The driver performs these assertions, in this order:

| Step | Operation | Required result |
| --- | --- | --- |
| 1 | Install the hashed staged sudo-rs/PAM files inside the guest. Probe all four phases with their actual command wrapper. The sudo phase starts as the delegated uid and executes `/usr/bin/sudo -n -u root -- /usr/bin/env ...`. Record healthy and future-mounted projects with `tego run agent.yaml`, from each actual working folder, as the delegated uid. | Each phase's four `/proc/self/status` uid and gid fields match its real identity. Only actual sudo reports SUDO metadata, matching the invoking uid/gid/name; real root has none. Both recordings exit 0. Config, ledger, hook paths, cwd used for later commands, and command output files are outside the mount. Source ownership is the delegated uid. |
| 2 | Start `tego-control serve --addr 127.0.0.1:0 --ledger LEDGER` as the delegated uid and uid 54320; obtain real sessions with the printed token link. | Each prints a link within 15 seconds. HTTP clients actually run as the service uid, so normal peer-uid checks apply. Healthy user Rules and Change rules pages return HTTP 200. |
| 3 | Attempt the direct control service as real root and with valid SUDO ids. | Exit 125 with `never as root`. The dashboard has always refused a root service. Root CLI behavior is checked separately below; the fixture does not pretend a root dashboard exists. |
| 4 | For each of delegated user, real root without SUDO variables, the delegated user invoking actual sudo-rs, and another uid, mount a fresh normally answering filesystem. Explicitly show its user-owned source and request `contracts --json` under that phase's actual identity, from that identity's own healthy project. Assert the mount still reports the source's delegated owner. | Explicit source show compiles only for its effective owner (user); root, sudo and other uid exit 125 with the existing `rulefile: refused` ownership reason. The listing enforces the separate registry/record ownership table below. These answered results prove the fixture works before the stall. The sudo cells use sudo's own metadata after its normal environment sanitization; selected config/hook inputs are arguments to `/usr/bin/env` after sudo. |
| 5 | SIGSTOP that server, confirm state T using `/proc/PID/status`, then run `contracts`, `contracts --json`, `contracts show deadproj`, `contracts show ABSOLUTE_SOURCE`, and `contracts show PROJECT/../project/agent.yaml` under the selected identity. Explicitly show a separate source owned by that phase's effective uid under that same phase identity before recovery. | Every dead-path command is reaped by `Popen.poll()`/`waitpid(WNOHANG)` within 70 seconds, exits 125, and contains `cannot tell: this location does not answer (a disconnected or stuck mount?)`, except that name selection requires `discovery is incomplete, so that name cannot be proven unambiguous; give the contract's path`, and subject to the foreign-owner exception below. JSON retains the dead entry as incomplete; the user's JSON still shows the recorded healthy source as compiles. The phase's own explicit healthy source exits 0. The server is still alive and stopped at every successful exit assertion. Output without actual reaping fails. |
| 6 | Request `/rules?c=REF`, `/rules/change`, and `/rules/change?c=REF` against the recorded path while the server remains stopped. | Each HTTP 200 within 20 seconds including sign-in and the complete page body, entry retained with the same cannot-tell sentence. Rules has a disabled change button and no enabled edit link for this ref; Change rules has no write form for this unavailable source. The other-uid service checks the owner's recorded source too. Root/SUDO CLI phases use the unprivileged owner's dashboard because of step 3. |
| 7 | Capture helper counts, argv, all task states, uid/gid fields and `/proc/PID/task/TID/wchan`, while commands are already reaped. | At least one helper remains in a real FUSE kernel wait. Counts stay at or below the 32 reservations per effective uid/network namespace; each CLI helper has its caller's four uid fields. No particular D/S state is assumed across kernels: retain both state and FUSE wait channel. Nothing touches the dead path to monitor it. |
| 8 | Only after all command-exit and page assertions, SIGKILL the saved FUSE server pid. While the disconnected mount remains attached, repeat explicit source show (plain and JSON) and all three dashboard pages; then detach with `fusermount -u -z`. | Every retained helper pid disappears from `/proc` within 15 seconds, including zombies, and its reservation is released. New CLI checks exit 125 within their bound with the cannot-tell sentence; pages retain that unavailable state and disabled actions within their 20-second total bound after ENOTCONN/EIO too. The server is reaped with status -9. Recovered `contracts --json` uses the phase's actual identity and asserts the ownership table below. Explicit show checks the user-owned source with the expected ownership result, then compiles that phase's own healthy source. |
| 9 | For each identity, on a separate fresh mount, repeatedly run explicit dead-source show from fresh commands until all 32 reservations are held; start one more command. For user and other uid, request all three dashboard pages at that service's actual uid while the same 32 reservations are held. Root/sudo repeat the root service refusal at capacity. | Commands are reaped within 70 seconds and complete dashboard responses within 20 seconds, except an exhausted page: it may wait for a slot that other commands' stuck helpers hold (a command for the start-up budget, 30 s, ADR 0144 amendment 2026-11-20; only a pool of helpers the same process knows to be stuck refuses at once), and a dashboard page for at most its request bound, 25 s (the server's 30 s write deadline less a 5 s margin, ADR 0144 "A page is answered before its write deadline"). The recipe's page command makes two requests, the sign-in, which lands on the overview and waits its own 25 s at capacity, and the page, so its bound is 60 seconds there (two bounds and a margin), and each answer must come before the server's write deadline, not as a closed connection. At exhaustion, CLI exits 125 and pages return HTTP 200 with `32 filesystem helpers are still alive in this uid and network namespace` (the product continues `, and Tego cannot tell whether they are busy or stuck`) and the unavailable entry/actions. While the youngest holder is younger than the maximum helper lifetime (115 s: the 30 s start-up budget, the 20 s location cap, the 55 s paused compile allowance and a 10 s margin, ADR 0144 "A full pool of helpers older than any check can live is stuck") the wait is kept; so a later page, made when every holder has aged past it, may already carry the stuck words (`32 earlier checks are still stuck on a location that does not answer`) instead of the capacity words, and both are accepted. After the pool has aged (5 s past the maximum lifetime from when the 32nd reservation was held) one more command exits 125 within 10 seconds, and one dashboard page (sign-in landing and page) is answered within 20 seconds, both naming `32 earlier checks are still stuck on a location that does not answer` and not the capacity words, with the same 32 helpers and no replacement. Compare pid sets before and after every extra command/page: exactly the same 32 helpers must remain, with no replacement. Root service still refuses before dispatch. |
| 10 | Detach that mount with `fusermount -u -z`, then write `1` to its `/sys/fs/fuse/connections/ID/abort` if it remains. Resume the server so it can exit. | Every retained helper disappears, the FUSE server exits 0, and the next listing under the actual phase identity satisfies the ownership table. Explicit show restores the user-owned source's ownership result and the phase's own source compiles. Lazy unmount alone need not abort open FUSE requests; the explicit abort prevents a false cleanup claim. |
| 11 | For each identity, on another fresh stopped mount, repeat exit/page assertions and write `1` directly to that connection's abort file before detaching. | Same helper disappearance, server status 0 and listing/source recovery under the phase's actual identity. Only this fixture's connection is aborted, identified from the mountinfo device minor. |
| 12 | Terminate only the two service pids this fixture started, wait and validate their statuses and `/proc` disappearance, then check no helper remains. | A service that exited before cleanup, needed SIGKILL, returned an unexpected status, or remains in `/proc` fails. Status 0 or requested SIGTERM (-15) is accepted. Each FUSE server has already been reaped and checked absent. Print PASS only after all cleanup succeeds. The host separately requires wrapper 0, `guest 0`, QEMU 0 and the final sentinel. |
| 13 | A loaded guest (ADR 0144, "A starved checker is not a stuck location", 2026-11-20). On a fresh normally answering mount start eight runnable busy loops per CPU. Run explicit show of the user's source three times; then SIGSTOP the server and run it once more, with the loops still running. | The three healthy commands exit 0, say `compiles`, and never say the mount words or the busy words (`was too slow to finish`, `was still working when its time ran out`, `did not finish in time`, `did not start in time`). The stuck one exits 125 with the mount words and none of the busy words, between 4.5 and 20 seconds. The loops are ended by pid, the connection is aborted, the server exits and every helper disappears. |

The healthy mounted and recovered listing boundaries are:

| Actual phase identity | Exit | Recorded source and healthy entry |
| --- | --- | --- |
| Delegated user | 0 | Both `compiles`; catalogue is complete. |
| Real root with no SUDO metadata | 125 | Both `unsafe`, with `source-unreadable` and the registry's `untrusted` owner refusal. Catalogue is incomplete because those registry reads were refused. |
| Actual sudo from delegated user | 0 | Both `compiles`; catalogue is complete because registry reads select the invoking owner and pass their checked bytes to the compiler. |
| Other uid | 125 | Both paths omitted; catalogue is incomplete with `other-owner`. |

The explicit-path check uses the stricter `rulefile.Read` guard, which requires
the effective uid to own its source. Thus explicit show of the user-owned source
refuses root, actual sudo and the other uid even when a sudo catalogue can read
it through the invoking user's registry. The fixture asserts this existing
boundary instead of changing policy. Each phase also has a separate normally
answering contract and directory owned by its effective uid, which it explicitly
checks before the stall, while stalled when below capacity, and after recovery
from its own healthy cwd.
User and other-uid phases also repeat all three pages as that service's actual
uid after detach: HTTP 200, retained ref and no stale cannot-tell sentence.

Step 5 distinguishes name selection from inspecting a source. As the user and operator
pages state, incomplete discovery cannot prove a name unique. `contracts show deadproj`
therefore refuses with the name-selection reason above, rather than choosing an entry
to display its source diagnostic. List, explicit-path and dashboard availability
checks retain the cannot-tell requirement. ADR 0144 requires ambiguous names never
be chosen by order; this recipe correction changes no product wording or policy.

Step 5 has one required owner-policy exception: another uid's CLI listing and
name selector exclude the owner's recorded sources before any source lookup.
Those three commands still exit 125, with the existing owner/selection refusal;
JSON has an `other-owner` issue and omits the owner's source. They must not start
a blocked source helper or promise cannot-tell words for a path they refuse to
inspect. Explicit absolute-path and path-walk checks under that uid still have
the bounded cannot-tell expectation, as do that uid's dashboard pages viewing
the shared ledger. This preserves the existing owner boundary.

The driver creates uid 54320 only after proving it is unused. Its selected config
and hook paths belong to that uid. All identities see the same selected ledger;
the fixture makes only this guest's ledger readable, without changing source
ownership. No host passwd, source, selected config, ledger or owner log is touched.
CLI commands have a 70-second reaping allowance for the 60-second command deadline.
Each dashboard client has a separate 20-second monotonic budget covering sign-in
and the complete page, and each HTTP open uses the remaining budget. Its client
process must also be reaped within 20 seconds. When any command misses its bound, the fixture kills it without waiting, aborts
the mount, then reaps it as failed evidence. It does not call `subprocess.run`
with a timeout around a potentially kernel-blocked Tego command.

Host-safe assertion checks import the recipe without entering `main`, starting a
product binary or mounting anything:

```bash
python3 -I docs/testing/contracts-stalled-mount-selfcheck.py docs/testing/contracts-stalled-mount.py
check go test -p 1 -race -count=1 -run '^TestStalledMountRecipeRejectsWrongEvidence$' ./docs/testing
```

The 132 checks accept valid synthetic observations and reject deliberately wrong
observations. These checks validate the recipe's judgement and call wiring;
the stopped-mount results remain owed in a guest.

Disposable-guest/root entry checks, non-root delegate and unused fixture uid,
required tools/device/binaries, fresh directories, and staged-file hashes are
prerequisite guards. The host self-check table covers the guest acceptance
judgements below; it does not claim to execute those prerequisite guards on a
real guest or to prove guest results.

| Assertion self-checks | Deliberately wrong evidence rejected |
| --- | --- |
| Actual identity and sudo provenance | Wrong real/effective/saved/fs uid or gid for each of the four actual identities; sudo names root as its delegate, or real root has SUDO metadata. |
| Root dashboard refusal | Root starts serving instead of refusing. |
| Command reaping, elapsed bound and status | Unreaped pid, 71-second command, or unexpected exit 125. |
| HTTP status and complete-body bound | HTTP 500, or a 21-second complete response. |
| Host wrapper, harness, QEMU and sentinel | Each status changed to failed, or sentinel missing. |
| Healthy/recovered owner boundary for each of four identities | Wrong source state; other uid exposes a foreign record. |
| Catalogue completeness for each identity | Each identity's `incomplete` value is inverted while its other fields stay correct. |
| Catalogue entry retention and states | Source and healthy entries are removed separately for user, root and sudo; each healthy entry's state is changed separately from the source state. |
| Catalogue root refusal diagnostic | Wrong `source-unreadable` code or missing `untrusted` message, separately for source and healthy entries. |
| Catalogue foreign-owner boundaries and reason | Source exposed, healthy entry exposed, or `other-owner` issue missing, with the other fields correct. |
| Stalled CLI JSON for user, root and sudo | Complete catalogue, missing dead entry, or dead entry marked compiles, independently for each identity. |
| Stalled CLI JSON healthy entry for user | Healthy entry omitted or marked incomplete while the dead entry is retained correctly. |
| Stalled CLI JSON foreign-owner exception | Complete catalogue, source exposed, healthy entry exposed, or missing `other-owner`, separately. |
| Mounted source owner | Observed st_uid 0 replaces the expected delegated owner's uid. |
| FUSE server before abort | Server already exited, running state S, or missing State field instead of an alive stopped server. The real driver rechecks after CLI and page responses and immediately before abort. |
| Explicit source owner and three foreign identities | Owner refused, or foreign uid allowed to compile the user-owned source. |
| Explicit source refusal details and availability | Ownership and guard refusal words are removed separately for each foreign identity; a healthy answer falsely includes cannot-tell, or a CLI failure omits cannot-tell. |
| Name-selector refusal and call wiring | Literal recorded name refusal is accepted; permission denial, source-availability wording, compiles, and removal of the incomplete/uniqueness/path-advice reason each fail. A path check rejects the name refusal. Removing the selector-specific argument fails wiring checks. |
| Unavailable page reason, retained entry, disabled control, edit link and write form | Missing reason/ref/disabled control, enabled edit link, or POST form. |
| Recovered page availability and retained entry | Stale cannot-tell sentence, or missing recorded ref. |
| Capacity page reason, full bound and no replacement | Missing capacity reason, fewer than 32 helpers, or a replaced pid. |
| Worker FUSE wait, credentials and bound | No retained worker, `ptrace_stop`, uid 0 for the user, or 33 workers. |
| Service status, disappearance and lifetime | Exit 7, surviving `/proc` pid, or a service that exited before cleanup. |
| Helper and zombie disappearance | A remaining worker or retained `/proc` pid. |
| FUSE server status and disappearance | Exit 1 instead of SIGKILL, surviving server pid, or SIGKILL instead of clean exit on connection/lazy-unmount abort, separately. |
| Seven phase-control identities | Mounted source/list/own-source, healthy source, recovery list/source/own-source control each changed back to user. |
| Actual identity through acceptance validators and pages | Catalogue, stalled JSON and source validators, plus capacity and recovery pages, each changed back to user. |
| Actual identity at phase dispatch | Normal, exhaustion and connection-abort phase calls each changed back to user before the phase receives its context. |
| Shared-capacity page wiring and cleanup order | Capacity flag removed, or PASS moved ahead of cleanup. |
| FUSE protocol reply errors | ENOENT (cancelled unique), ENODEV and ECONNABORTED finish cleanly; unexpected EIO must still fail. The device and mount syscalls are stand-ins for these host checks. |

The version probe for the separate AlmaLinux guest is
`sh docs/testing/alma-systemd-version.sh`. It captures and checks the absolute
`/usr/lib/systemd/systemd --version` command before printing the first line.
Missing systemd and a nonzero version exit both fail the recipe. Its real Alma
execution is also owed in a guest.

Fix round 5 also rejects an unavailable Rules page that drops the recorded rule, YAML panel, copy text
or copy positions. Capacity refusal pages cannot start a worker and do not promise a recorded projection.
