<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0154: local OS roles for rule publication and exact-call approval

Status: **accepted 2026-11-12** for Slice 1, root-only once answers. The remaining local roles, publication and business routes below are planned work. Host unit proof is retained privately; kernel and root proof is owed in a guest.

Amends ADR 0123 for enrolled local managed runs; leaves personal-mode behavior unchanged. Adds local authority/provenance requirements to the later approval slice of business-rules ADR 0151. Does not alter frozen bizrule/v1 predicates or canonical bytes. The approval protocol proposed by the bizrelay design is not yet frozen. This is a limited local subset of earlier private proposals, not their implementation.

## Context

The owner wants customized roles and access for anyone operating an agent, including approval requests and a dashboard available from other devices. A role schema without file, handler and broker checks does not meet that request.

Today the dashboard identifies the serving OS account and a session held by its browser. It checks local socket ownership, same-origin form tokens and governed socket scope. The approval socket accepts the invoking UID or root outside every governed scope, with authenticated packets and a single winning answer. Those are process identities, not individually authenticated people. Rulefile rejects unsafe ownership and writes through pinned descriptors, but its journal is appended after replacement, is not hash chained and has no role. Baseline is parsed but not applied at the inspected HEAD. Access and governance codecs exist; role commands remain stubs.

Tego holds AI agents of every kind to rules the Linux kernel enforces and records each run. People who operate Tego need a separate, deterministic authorization boundary. There is no language model in identity, authorization, approval or rule decisions.

## Decision

1. **Ship a restriction first.** Add a fixed-system-only owner-only approval mode for root-launched, non-root-child managed runs. UID 0 in the initial user namespace, outside all governed scopes, is Owner. The child's UID cannot answer from a terminal or dashboard. Existing nonce, packet credentials, pidfd and cgroup checks stay. Approve/Deny are once-only; always and alternate are unavailable in this mode. No cross-user socket widening, root browser or central service is required. Positive answers receive a typed OS actor/Owner role and a synchronous durable chained record before release. Business amount approval remains unavailable.

2. **Use four local roles.** Owner publishes enrolled contract/business revisions and shared general profiles, changes roles, and with OS root changes the fixed system baseline input. Rule author writes drafts and proposes publication. Approver answers only explicitly granted ask kinds/scopes, with business routes capped per currency/profile. Viewer reads authorized record/receipt/rules only. Root is operationally trusted. Owner has no implicit business amount cap or separation-of-duties exemption. Draft-only authorship is a deliberate v0.2 scope decision. Unlisted managed mutations refuse. Existing personal-mode files and runs have no managed-role claim.

3. **Bind to facts the product can authenticate.** Later local bindings name host, initial-namespace numeric UID and root-issued account/binding generation. No invented person account. Direct UID bindings precede optional root-controlled group expansion into exact UID members. Unknown membership refuses; a group change invalidates pending authority. A local dashboard session always acts as its serving UID. Two tabs, one SSH tunnel or two humans sharing an OS account do not establish two people. Root elevation is attributed as root; environment identity strings do not identify a person.

4. **Protect effective rules through publication.** Roles, published objects, registry/index, shared profiles, transitive dependencies and managed run records live under root-owned placement with no agent/author write authority. Rule drafts use existing guarded writers; effective bytes change only through a root terminal publication transaction. Do not loosen rulefile's refusal of shared writable groups. Publication durably records author and publisher/roles plus exact old/new digests before effective use, then records its result. An uncommitted index state or drift blocks managed activation. Baseline application remains separately gated and disclosed.

5. **Check authority at every effect.** The dashboard preserves all existing authentication and same-origin checks and adds route/target authorization. Shared CLI/services also check. The broker, including direct ask.sock access, checks the actual packet principal against the immutable request and current root grants. Final consumer rechecks at admission, serialized with role revocation. Hiding a button has no authorization meaning. A governed peer is never authorized even with a role.

6. **Exact business asks need exact authority.** A versioned route sidecar on the enclosing compiled contract references the complete asking-rule set and names role/profile, currency and integer minor-unit ranges. Root grants form an additional ceiling. Require one identity to cover every barrier, or refuse unsupported combined routing. Unknown/missing route or provenance refuses. Keep evaluator v1 unchanged. A separate approval protocol binds one call digest, nonce, host/boot/run, adapter/worker/bundle, complete asks, route, authors, grant/restriction revisions and expiry. It permits one use and no partial, standing, delegated or batch approval. Reevaluate fresh state and all restrictions before forwarding. A person never overrides hard deny, kernel restrictions or durable run caps.

7. **Hard-code independent exception approval.** The answerer differs from the actual agent UID and every author of the relevant rule/route/grant revisions. A publisher cannot erase authorship. One independent approver suffices; the author cannot approve alone and the initial design refuses author votes altogether. Owner obeys the same check. Unknown authors must be republished with provenance before business exceptions activate. No quorum/delegation subsystem is needed. This authenticates different OS identities, not distinct physical people or human presence.

8. **Fail closed on authority loss.** No approver means refusal at the original deadline, never yes by silence or implicit owner escalation. Only one valid answer wins. Any authority revision change invalidates pending asks and accepted but unused answers. Revocation and final admission have one bounded root-domain lock: revocation first means no effect; admission first cannot be undone by later revocation. Missing/unreadable/replaced policy, stale identity, expiry or record durability failure refuses. Do not keep a permissive last-good role cache.

9. **Record actors honestly.** Add minor-gated OS actor/role/grant/revision fields to run approvals and a shared receipt projection. Preserve historical bytes and label absent identity not recorded. Later publications/role changes use the existing governance hash framing with a deliberately versioned local OS principal extension, not fabricated person IDs. Implement the bounded root writer; the codec is not that writer. Run receipts carry verifiable references to rule authors and publication. Each no-run change has a change receipt. Root can rewrite local evidence; a local hash chain is not a truthful-host guarantee.

10. **Separate local and remote claims.** Another device needs authenticated paired-device/person binding, protected transport, device-bound sign-in and an assertion bound to each answer, as planned in October. A URL or session alone never names a separate person. Remote people, central routing/offboarding, directory/SSO, external anchors and team deployment authority wait. Some can be implemented host-locally later, but none exists merely because this ADR refers to it.

## Alternatives rejected

- Roles only in the dashboard: direct CLI, socket and file writes would bypass them.
- Binding a role to a session chosen by its holder: shared account software could choose a stronger identity.
- Making Rule author group-write published files: bypasses publication attribution and existing guarded-writer trust.
- Reusing owner/root's current ask path unchanged for business caps: it does not bind exact call/role/cap/current authority.
- Owner bypass or silence approval: defeats independence and fail-closed operation.
- Implementing remote accounts, quorum, delegation and team services as the first slice: too large to prove before the release target.
- Changing business evaluator v1: role policy is outside its frozen supplied-fact predicate contract.

## Consequences and acceptance

Slice 1 is independently releasable after tests/review/guest proof. Business amount approval also depends on relay/durable-accounting/exclusive-route work; it is not available after slice 1. Personal runs remain compatible and visibly distinct. Administrators must perform root publication; same-UID approvals stop working in managed mode; a lone rule author cannot approve exceptions. Root-owned evidence and required durable records cost implementation and can reduce availability on disk errors.

Slice 1 acceptance covers trusted source and launch qualification, direct-socket and dashboard bypass attempts, single winner, exact source digest, lifecycle, durable records and receipt parity. Later slices require separate acceptance for publication, author exclusion, role revocation and business amount ranges. Every kernel/root claim requires a guest witness and a failing witness with the protection removed. Guest checks are owed, not claimed by host tests.

## Later decisions before further slices

The maintainer accepted initial-namespace root as the sole Owner and the same-user refusal for Slice 1. The mode is a system-only floor under the existing system trust checks. Missing identity diagnostics, private user namespaces and unknown cgroups refuse without consuming a pending request. There is no socket mode change, role editor or shared dashboard. Publication, non-root role bindings, protected completed records, business caps and author exclusion need later implementation and qualification.


## Slice 1 profile and compatibility

`local_roles: owner_only` is the sole enabling value, read only from the system
config layer. `off` or absence is personal mode. Only the exact strings `off` and `owner_only`
are accepted. Empty, `auto`, differently cased, unknown and non-string values
make the system layer invalid and refuse every launch until corrected. An
unreadable system layer cannot fall back to personal approval. User and explicit environment
layers are ignored for this field. A managed run pins exact system bytes and
placement identity; disappearance, changed bytes or inode replacement refuses further answers.
A same-byte in-place write retains the pin. Restoring the original bytes on the
original trusted inode restores that byte check; replacing it again does not.
Root launch, the initial user namespace, an acknowledged non-root credential drop,
enforcement and recording are required. Observe, adopt and setuid opt-out refuse.

The floor binds only runs launched after it is set. It is fixed per run at launch: a run already live, whatever its
version, keeps same-user approvals until it ends, because the broker of a personal run never reads the system file
again. Stop every live run before relying on the floor, then start them again. `tego doctor` lists the live runs of the
selected ledger root that started without the floor.

Beyond that, the mount-identity refusal (v0.1.3) is assumed for every run: each live run must have been started by
v0.1.3 or later. Stop and restart older runs first. Activation does not check live-run versions.
A known run records its launcher version in `run_start.tego_version`, but there
is no complete host-wide inventory across configurable per-user and
`TEGO_CONFIG` ledger roots. Inspecting the selected root cannot establish that
no older run remains. A mount made by host root after the run-start compile snapshot is outside
this claim; backend preparation does not independently recheck mounts. Host
root is the owner.

The merged v0.1.3 release refuses `fs.write` and `fs.ask` grants reaching cgroup
filesystems by mount identity, including bind aliases, submounts and v1
controllers (`pkg/spec/agent/kernelfs.go`, `mountTable.controlFS`,
`fsBuilder.writes` and `compiler.fsAsk`). `tego run` compiles before selecting
or starting the backend. The earlier path-only R10 check did not establish this
premise. `TestLocalRolesCgroupAliasesRefuseGrants` covers these spellings and a
symlink route using synthetic mount tables; kernel proof is owed in a guest.

Record minor 33 is occupied by secrets/vault declarations, 34 and 35 are declared,
and 36 reserves team `answer.principal`. This slice uses the next free minor 37,
`MinorLocalRoles`. Personal launch and adoption keep the revision of the payload they write; a
managed launch writes `MinorLocalRoles` only when its launch would write less (2026-11-20 integration: the fields'
minimum revision is 37 and they are valid at every supported revision from there, so a run that also records a machine
baseline writes the baseline revision, and a later revision that declares a superset of the earlier ones is never
lowered to 37 to write them: `localRolesMinor`). Since ADR 0157 every launch and adoption writes revision 41, so a run under
the floor carries 41 and the roles fields validate there; the reader supports 37 and 41 (and 39, 40). Readers support 37; 36 and 38 stay reserved and
unsupported. Revisions 32 to 36 introduce no mandatory field
for this profile. The reserved team principal is never asserted. New answer
fields are `actor` or `system_cause`; run_start carries `local_approval_authority`
with mode, system digest and actual dropped UID. Missing actor/role means not
recorded, never an inferred Owner from `by`. Root actor records UID 0, PID, start
time, initial user namespace, `kernel-local-uid` and role `owner`.

Managed run_start and answers use required file and directory durability barriers
before release. A write, validation or sync failure grants nothing. Source and
the sender snapshot are checked again after recording under the delivery lock.
The snapshot uses the packet's send-time PID, UID and GID and its sender pidfd.
Linux 6.5 and later supplies SCM_PIDFD with SO_PASSPIDFD; older kernels use a
receipt-time pidfd_open bound to the packet PID and the compared process start.
The retained process directory supplies the user namespace, cgroup namespace and
membership and current real UID from `status`; the governed-scope decision runs
inside these reads. A second fact reading must agree. Process start and pidfd liveness are validated after all
sender reads. The second policy check follows those reads. A final nonblocking
pidfd poll also rejects exit during that policy check; no sender proc read
escapes the policy bracket. Each policy reading must match the
activation pin's trusted inode and exact bytes, so both readings are equal.
Restoration on the original trusted inode retains the O5 behavior above; this
does not detect every transient change restored between readings.

The send-time identity is the packet credentials and process handle. Namespace,
scope and current real UID are decision-time facts, read again through that
binding. A process that is root on the host and outside every governed scope
when the answer is decided is the host's root; where it stood for the moment it
sent is not known to the broker and is not judged. A sender inside a governed
scope or private user/cgroup namespace, or without real UID 0 at the decision,
is refused, whatever it was earlier. PID reuse, relaying, exit or exec between
reads cannot make the broker read another process. Exec keeps the process
identity; both fact passes re-read namespace inodes, cgroup membership and real
UID, and a changed fact refuses. Changes after the completed final snapshot do
not revoke the decision. The normal approval client remains alive waiting for
the broker reply (`internal/askclient/client.go`, Call).

After the snapshot returns, the broker checks cancellation, shutdown, the
original monotonic deadline and pending state, then commits without I/O.
An unreadable, incoherent or exited sender refuses without releasing the held
operation. Before append the same ask remains pending. After an immutable
selection was appended, the operation is published with a fresh ask ID and the
original deadline, preserving one answer per ask. The earlier selection has no
completion evidence from this retry. Policy drift after append remains a
terminal refusal with the stop/relaunch remedy.
Expiry returns a timeout refusal even when a root denial was in flight. Cancellation, shutdown
and expiry can still refuse the operation after a recorded answer; an answer
is not proof of an effect. The existing hand-back of personal ledgers after
Close remains a limit of this slice. Root can rewrite local evidence.

Refusal words on terminal, dashboard and receipt name the authority and action:
only root may answer once; run the approval as root from a terminal outside any
governed run. Deny requires the same authority as Approve. Always and alternate
answers refuse without consuming the ask. No language model participates.

Acceptance groups: trusted system configuration and launch qualification; broker
identity and non-consumption; one winner, lifecycle and required durability;
terminal/dashboard/receipt parity and unchanged personal record/protocol bytes.
Kernel and root operation proof is owed in a guest, including a negative witness
with the UID floor removed. Slice 2 must add protected publication, authorship,
role manifests and permanently root-owned managed evidence.


## Fix round 1 amendment (2026-11-12)

Policy drift has its own `approval-policy-changed` refusal: "the approval policy
file changed since this run started". Root, CLI and dashboard receive the same
cause and stop/relaunch remedy once the broker is contacted. A strict Approve
CLI load can instead refuse an unreadable system file before contacting it;
repair a mode-only mistake on the original inode and bytes first. Deny uses a
warning load and can reach the broker's distinct refusal. Before selection, both Approve and Deny refuse without consuming a
pending ask. Broker-authorized dashboard clients receive policy drift before
the identity remedy. Fix round 2 replaces the former one-sided peer-refresh /
policy-read ordering with the bracketed sender snapshot described above.
Drift after recording instead refuses delivery terminally;
pending wording is conditional. Drift after selection retains this recovery
cause whether it is found before or after recording. The immutable-machine
rule in identity-config I3 concerns merged settings; it does not disable the
live approval-source check. [The user guide](../site/approvals.md) gives exact commands
with the same ledger selection and a five-method edit outcome table.

All answer decision fields at minor 37 or later use exact case-sensitive names. Duplicate and
folded-duplicate fields are invalid. Actor approval has no nonempty
`answer_reason`; actor denial requires `ask-denied`. Shared invalid fixtures
hold the schema and Go validator to both rules. The authority display
requires the complete run_start payload to validate at its exact revision too.
Accepted fixture mutations must remain valid after canonical encoding. Receipt, CLI and dashboard present an
actor only when the run minor carries it and the complete answer validates.
A legacy actor-shaped field supplies no authenticated identity.

An appended root approval followed by a refused held operation is a valid
recorded outcome when cancellation, expiry, shutdown or policy drift overtakes
recording. The immutable answer describes the selection. The subsequent
operation/refusal line describes the result. UI labels say "approval recorded"
and distinguish operation completion; no completion is inferred from an answer.
An absent operation line leaves the effect unproven. A system cause is recorded
on the answer only when it overtakes selection before append, not by rewriting
an appended actor line.

The dashboard host witness uses the real handler, broker socket and test-process
credentials for its non-root refusal. It proves no root/kernel effect. The
guest recipe (retained separately) includes the buildable
fault adapter and exact expected effects. Its execution is **owed in a guest**
and remains a merge blocker; no guest ran in this fix round.

## Fix round 3 amendment (2026-11-12)

A5 replaces A1's send-time authority wording with send-time identity and
revalidated decision-time authority. Equal later readings make no claim about
namespace or scope at the send. Reading real UID through the retained process
directory also refuses a sender that dropped real root before the decision;
packet UID remains unchanged for attribution. Malformed or missing UID facts
refuse. The exec tests use a real exec and modeled mutable root facts on the
host. Actual namespace send/restore and mirror sequences are owed in a guest.
The reviewer sequence is admitted when the same host-root sender returns to the
initial cgroup namespace outside every governed scope before the decision.
Its outside-send/inside-at-decision mirrors refuse and leave the ask pending.

## Integration amendment (2026-11-20)

The slice-1 work was replayed onto the pass-14 line. Record revision 37 is a supported reader revision
(`record.SupportsMinor`, schema `minor` set, `MinorLocalRoles`); 36 and 38 remain reserved and unsupported. The
chain vector of the refused-effect case is 133, after the baseline vectors 130 to 132. The row for this slice in
GAPS is C83.

**Attribution follows the run's floor (2026-11-20 review, finding 2).** The record rule is per run, not only per line:
in a run whose `run_start` carries `local_approval_authority` every answer carries an `actor` or a `system_cause`; in a
run whose `run_start` does not, none does. `record.Event.ValidateFloor` states it; the writer (and its resume) and
`chaincheck.LineCheck` (`tego events --verify`) apply it. Readers project attribution through `record.AnswerAuthorityOf`,
which returns none unless the run's validated `run_start` carries the floor, so a line rewritten to claim root in a run
that never had the floor is refused by the verifier and never shown as root's. Completed user-owned records stay
not tamper resistant (the guide says so): this is consistency, not a defence against the record's own user.

**Where the floor refuses.** The launcher's user and user namespace, the contract's record mode and its `setuid`
are configuration and caller facts. `runtime.Preflight` refuses them (`preflightLocalRoles`) before the CLI selects a
backend, so a launch the floor cannot admit costs no kernel probe: guest row 16 (setuid contract) measured 124
instead of 125 because the refusal waited behind a cold bpf probe and teardown of 19.9 to 38.3 seconds. Whether the
selected tier enforces still waits for the backend and is checked in `newRunner` (`validateLocalRoles`), which repeats
the whole floor with the same words. Host tests: `TestPreflightRefusesTheLocalRolesFloorWithoutABackend` and
`TestLocalRolesSetuidFloorRefusesBeforeProbing` (no probe and no run start). The guest row is to be rerun.
