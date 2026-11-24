# ADR 0143: The CI receipt signature is made in a separate job

Status: **proposed**, 2026-11-11. Every acceptance measurement below must pass before a recorded acceptance
decision. This is a design record.
The original design amendment was based on source inspection. The implementation notes below describe the
later unsigned slice and its limits; no GitHub acceptance row is closed by that implementation.

## Decision and trust

The signature is made in a separate job that never ran the agent. With `id-token: write`, every `run:`
step receives GitHub's OIDC request interface, including installers before Tego. Environment scrubbing
cannot protect against those steps. The agent job has **no** `id-token: write`.
The signer uses a fresh GitHub-hosted runner and executes only pinned Tego code and verified tools.
The receipt jobs ship in `attention-span-ai/tego/.github/workflows/ci-receipt.yml`. The signing job ships
in the separate `ci-receipt-sign.yml`; both are exported with the product. `action/` holds implementation and trust files. A standalone step cannot offer this signing claim.

After full verification: **These exact receipt and manifest bytes were emitted and signed by Tego's
signer workflow at this pinned version, for this repository, source commit, run and attempt. The agent
never shared a runner with the signing credential.** This is workflow provenance, not Tego endorsing
the record's truth. Root on the agent runner can still feed fabricated evidence to the signer.
A maintainer can still change which workflow runs; pin both caller and signer digests.
On a pull request, the caller workflow file is the pull request's own.

The signer checks consistency, not honest kernel execution, complete observation, authorship of
agent-supplied traffic, remote effects or artifact availability. Work delegated through an allowed
endpoint or an unconfined daemon (A8) can outlive the governed scope.

## The user writes one job, and a second one only for a signature

“One line” became “one job, and a second one only for a signature”. The unsigned caller delegates only
contents/actions read to `ci-receipt.yml`, which has no signing job and never requests OIDC:

```yaml
jobs:
  agent_receipt:
    uses: attention-span-ai/tego/.github/workflows/ci-receipt.yml@<TEGO_RELEASE_COMMIT>
    permissions: {contents: read, actions: read}
    with:
      contract: agent.yaml
      run: ./agent/run.sh
      sign: 'false'
```

`<TEGO_RELEASE_COMMIT>` is the full implementing release commit, not yet available. Do not invent a pin.
The contract and command already belong to the user's repository. For a signature, change the first call's
`sign` to `'true'` and add its `sign-consent` with the exact sentence below. Then add this second caller job:

```yaml
  agent_signature:
    needs: agent_receipt
    if: ${{ !cancelled() && needs.agent_receipt.outputs.should-sign == 'true' }}
    uses: attention-span-ai/tego/.github/workflows/ci-receipt-sign.yml@<TEGO_RELEASE_COMMIT>
    permissions: {contents: read, actions: read, id-token: write}
    with:
      handoff: ${{ needs.agent_receipt.outputs.handoff }}
      sign: 'true'
      sign-consent: I consent to publish repository and workflow names in the permanent public Sigstore log
```

Signing permanently publishes organisation, repository and workflow names, identities, source/ref/run/attempt
and visibility in the public Sigstore log, including for private repositories. Deleting artifacts cannot undo
that disclosure. Both calls require the exact consent for eligible signing. Use matching release pins and
`sign`, `sign-consent`, `matrix-key`, `use-sudo` and `on-refusal` inputs across the calls.

GitHub validates delegated permissions before runtime job conditions. A signing job inside the receipt
workflow would force even unsigned callers to delegate OIDC. Separate reusable workflows avoid that grant.
Inside the receipt workflow, `agent` explicitly has contents read and `report` contents/actions read.
Only `sign` in the separately called signer has contents/actions read and id-token write. No caller extras
are inherited. Summary/artifact are default; comments/check writes need separately specified permissions.
No `secrets: inherit`; named agent secrets go only to `agent`.

Receipt inputs: `contract` and `run` required; string `sign: auto|true|false`, default `false`; boolean
`use-sudo`, false; `runner: ubuntu-24.04|ubuntu-24.04-arm`, first by default; `matrix-key`, `single`;
`on-refusal: warn|fail`, `warn`. The signer requires `handoff` and `sign-consent`; its `sign` defaults to
`auto`. Matrix callers pass `${{ toJSON(matrix) }}` as `matrix-key`, canonicalized and hashed for paths/markers.
Pin all actions and tools by full commit or verified release digest. The signer always uses fresh
`ubuntu-24.04`, without services, caches or caller setup hooks.

## Evidence and binary identity

Sign two exact byte strings with public Sigstore keyless cosign: `receipt.json` and `manifest.json`, each
with its own `<name>.sigstore.json`. All receipt totals, lists, notes and binding are **inside the signed
bytes**. The digest of `events.jsonl` is signed; `blobs/` is not. Comments and Markdown are displays;
show the signed filenames and full receipt SHA-256. Retain files before the stated artifact expiry.
The public log stores metadata, not a retrievable record archive.

Require binding 2, retaining receipt version 1 and old binding-1 readability. Add `binding.contract_hash`,
`binding.capabilities` (from `run_start`) and `binding.binary_sha256`. The producer executable hash sits
**outside `MadeBy`**. `receipt_by` equality remains release version/commit, excluding dirty/unknown builds.
`facts` holds the well-formed producer hash constant when recomputing, lists `binding.binary_sha256` in
`not_compared`, and compares every other field as before. Release verification supplies binary trust.

Each job installs its own binary: verify the release checksums bundle against the exact Tego release
workflow identity, source commit and GitHub issuer, then match the executable to its named Linux asset
in those checksums. Record both hashes. Keep the absolute executable path; rehash before launch and
collection rather than resolving workspace PATH. The agent uses one verified executable for both.
Signer and reader may use another architecture's asset from the same release/commit;
never require their hashes to equal the producer's. Verify each against the signed release checksums.
Totals checking requires Linux and that release. Another release can check chain bytes but cannot
establish `facts`. B1-4 must measure amd64/arm64 compatibility before promising it.

Keep `no-signature`: “This JSON carries no signature. A CI signature is a detached bundle checked
separately.” Keep local rewrite/crash-tail limits. Never rewrite receipt JSON after signing.

Manifest `tego.ci-receipt/1` has this complete required shape; angle brackets describe values:

```json
{
  "schema": "tego.ci-receipt/1",
  "receipt": {"file": "receipt.json", "bytes": 1234, "sha256": "<hash>"},
  "record": {"file": "run/events.jsonl", "run": "<Tego run id>", "bytes": 5678,
    "sha256": "<hash>", "lines": 12, "head": "<hash>", "ended": true},
  "anchor": {"file": "anchor-line.txt", "sha256": "<hash>"},
  "contract": {"file": "contract.yaml", "file_sha256": "<hash>", "compiled_hash": "<hash>"},
  "teardown": {"file": "run-status.json", "sha256": "<hash>"},
  "signer_check": {"file": "signer-check.json", "sha256": "<hash>"},
  "tego": {"version": "<release>", "commit": "<commit>", "checksums_sha256": "<hash>",
    "producer": {"asset": "<release filename>", "binary_sha256": "<hash>"},
    "signer": {"asset": "<release filename>", "binary_sha256": "<hash>"}},
  "artifact": {"agent_id": "<id>", "inventory_sha256": "<hash>"},
  "github": {
    "server_url": "https://github.com", "repository": "<owner/repository>",
    "repository_id": "<id>", "repository_owner_id": "<id>", "visibility": "<visibility>",
    "source_sha": "<commit>", "source_ref": "<ref>",
    "workflow_ref": "<caller path@ref>", "workflow_sha": "<commit>",
    "job_workflow_ref": "<Tego reusable path@ref>", "job_workflow_sha": "<commit>",
    "event": "<trigger>", "run_id": "<id>", "run_attempt": "<attempt>",
    "agent_job": "agent", "signing_job": "sign", "step": "collect",
    "matrix_key": "<canonical key>", "action_sha": "<commit>",
    "checkout_sha": "<commit>", "pull_request_head_sha": null,
    "agent_runner": {"environment": "github-hosted", "image": "<ImageOS>", "version": "<ImageVersion>", "arch": "<arch>"},
    "signer_runner": {"environment": "github-hosted", "image": "<ImageOS>", "version": "<ImageVersion>", "arch": "X64"}
  }
}
```

Hashes are 64 lowercase SHA-256 hex characters. IDs/attempts are positive decimal strings; counts exact
nonnegative integers. Commits use full repository object IDs. PR head is required on PR events, null
otherwise. Reject unknown/duplicate keys, wrong types, trailing values, unsupported schemas and manifests
over 64 KiB. Require exact relative filenames; extract regular files only, refusing links/traversal.
No manifest/bundle self-digests.

Match receipt size/hash and record bytes/hash/lines/head/run/end with `binding.chain`; require no binding
error, zero torn bytes/newer lines. Anchor is exactly `<run> <head>\n`. Match compiled contract hash and
whole capability map to `run_start`. The YAML hash is separate; it does not reproduce compilation with
merged defaults and runtime grants. Read tier, `best_effort`, `reads_notified`, `runtime_grants` and
`run_command_grant` too.
Require `binding.binary_sha256` equals `tego.producer.binary_sha256`, and receipt/run version/commit
equal `tego.version/commit`. Both named assets must belong to the verified release checksums.

## The receipt and signing jobs

`agent` checks out the event commit with credentials unpersisted. Metadata comes from GitHub contexts
and authenticated API responses, never stdout. `github.sha` is the event commit; PR head is separate.
`workflow_ref/sha` name the caller; `job_workflow_ref/sha` name the reusable workflow. Job/step IDs are
fixed there; `action_sha` is its implementation pin. Image/version/architecture come from runner values,
workflow assertions rather than certificate claims about a particular image. The API identifies
artifacts and exact-attempt jobs.

Probe and require the tier: `landlock` by default, `cgroup` with sudo. Never silently fall back or infer
tier from labels. No hosted tier was measured here. Refuse record-only mode, `setuid:true`,
`keep_descendants:true`, persisted checkout credentials and overlapping protected write grants.
Require the compiled `tego/ci` denials. Protect ledger, anchor, evidence/status/output paths, runner
installation, all `_actions`, tools, `$RUNNER_TEMP`, `.github/` and token files against direct paths,
broad parents and resolved aliases. Refuse write grants overlapping any original job PATH entry,
including relative and missing entries, the system collection tools, tool cache, action tree or HOME
shell startup files. Each refusal names the grant and protected path. CI treats compile's `path-shadow`
diagnostic as an error. A warning cannot keep a later unconfined step from running a planted tool.

Deny OIDC request variables, `ACTIONS_RUNTIME_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, preissued
`SIGSTORE_ID_TOKEN` and token-bearing inputs; reject attempts to pass them. Scrub the launcher's
environment too. Pass permitted secrets without values in argv. No signing request authority exists
in this job, including installers. Other credentials still need protection.

Landlock's **ptrace domain rule** refuses access to processes outside the caller's domain or descendant
domains. `/proc/<pid>/environ` uses a ptrace check; this names the mechanism, not a new PID blacklist.
T10 measures it, root/fd aliases, memory, inherited descriptors, new processes and token files/sockets.
An allowed service or daemon can still perform A8 work.

Stop workflow-command processing with an unpredictable marker before agent output. Protect file-command
files too. Never parse stdout for paths, IDs or outputs. Drain output before restoring commands.
Collection uses absolute system tool paths, a fixed `/usr/bin:/bin` PATH, and a private empty HOME.
Every shell entrypoint uses absolute `/bin/bash -p` with `set -euo pipefail`; shell startup variables,
exported functions and Python user configuration cannot supply collector code. The launcher alone
receives the original HOME for the agent. The original job PATH and HOME are recorded before changing
the collector environment so protection checks cover what later action post steps may resolve.
The action writes fixed PATH, private HOME and disabled startup settings to `GITHUB_ENV` for subsequent
steps. The runner may still prepend directories retained through `GITHUB_PATH`. The collector itself
enforces its fixed PATH and absolute tools; other actions' post steps rely on refusing writes over the
original job PATH, tool and configuration paths. Hosted runner prepend behavior remains unmeasured.
Steps a caller adds after the agent in that job consume the workspace the agent left behind. Keep the
agent's job to the agent; later work belongs in a separate job with a fresh checkout and reviewed inputs.
Fixed PATH/HOME settings do not make workspace content safe to execute. T11 names the owed measurement
of later actions and checkout post steps on the actual runner.

The product owns the checks in `receipt --check --json`. Both jobs require command
exit 0, `check_v:1`, `result:"match"` and `ended:true`. The workflow requires a
minimum set of `receipt`, `made_by`, `run`, `chain`, `head`, `bytes` and `facts`
for `binding_v:1`; `binding_v:2` additionally requires `binding`. Missing,
non-integer or unknown binding versions are refused. The check file must be one strict JSON document,
with no duplicate object keys at any depth, including escaped spellings of the
same key. Validation reads the bytes once and rejects duplicates before jq can
keep a last value. Check names must be nonempty and unique. Every returned check
must explicitly have `result:"pass"`, including any name the workflow does not know. An unknown,
missing or non-pass result never counts as a pass. Additional product checks do
not require a workflow allowlist change, but a new binding version requires an
explicit minimum set before the workflow accepts it. Offline fixtures produced
by the product cover binding 1 and 2 through collection and fresh-job comparison. The original B1-2 unsigned slice used this generic ended
comparison without status or `--require-ended`/`complete:true`. The B1-3b amendment below records the
later implemented status and complete-comparison path; its guest acceptance remains open.

### B1-2 evidence custody amendment (2026-11-11)

These are source-level design facts and offline test boundaries. Actual hosted ownership, tiers,
PATH contents and post-step behavior remain owed in a guest and on GitHub as applicable.

Before launch, the action makes a fresh `$DIR` at
`$RUNNER_TEMP/tego-ci/<run-id>/<agent-attempt>/<matrix-sha256>`. It is owned by the runner account,
mode 0700. Before launch, `state/`, `ledger/`, `evidence/`, `bin/`, `home/` and the frozen
`collector/` copy are also runner-owned 0700 directories. Collection creates `evidence/run/` only
after the agent returns, with the same owner and mode. Output JSON/text files are runner-owned, mode 0600. The original action under
`_actions` or the pinned implementation checkout and the copied collector are hashed before launch;
both trees must still match those digests immediately after the agent returns, before receipt
collection. After system `sha256sum` checks the recorded bytes, the checked collector also requires
exact path, type and permission inventories for both trees; added files are refused. The collector
executes the pre-run copy. Its parent exports the private TEGO_CONFIG for preparation, launch and
collection; exporting it only inside the preparation child would make collection read another ledger. The contract refuses writes over either tree, the containing runner paths,
every original PATH entry, tool cache, `.github/`, original HOME's startup files and `.tego`, the
resolved passwd-home state and collection state. It also refuses grants overlapping the caller's
`.git` path and both checkouts' resolved Git and common directories. Those Git refusals defend consumers
of repository configuration. They include environment/passwd HOME `.gitconfig`, default and explicit
XDG Git configuration, system and override paths, worktree configuration and include files read before
launch. The system path comes from the installed Git, even when system reads are disabled. Missing
default paths are protected too. Configurations selected only by a future caller step remain outside
this discovery. An agent cannot commit in this workflow because Git metadata writes are refused.
No checkout post-step exploit was measured. Runner `_diag` is also read-denied because its
logs may expose the workflow-command resume marker. Installed system runtimes remain readable.

Tego writes `$DIR/ledger/<run>/events.jsonl` and its run metadata, with run directories 0700 and
regular files 0600. At `landlock`, Tego and the agent share the runner uid. At `cgroup`, the launcher
is root and the agent drops to the invoking runner uid; the new live run directory and its contents
stay root-owned until `Writer.Close`. Because `ledger/` belongs to the runner, Close hands the run
tree to that account. A root-owned live child of a runner-writable parent does not prevent that
runner from replacing the child's directory entry. This is not a root-owned evidence store.
`internal/ledger/handover.go` and `writer.go` define these permissions and handover rules.

The chain anchor is `<passwd-home>/.tego/chain.log` for the invoking account, independent of collector
HOME and `ledger_root` (`internal/runtime/anchor.go`). Its directory is created 0700 and its file
0600; a root launcher hands newly created anchor entries to the owning runner account immediately.
Existing entries retain their ownership and mode. Preparation resolves the passwd home separately from
the original environment HOME and protects both state locations. After return, the runner collector reads the ledger
and anchor through Tego, produces `receipt.json`, `verify.json`, `run_start.json`, `agent-check.json`
and `tego-ci.json`, and copies `run/events.jsonl` and `anchor-line.txt` into `evidence/`. It also keeps
the prepared `contract.yaml`, `compile.json`, `compile.txt`, `doctor.json` and `eligibility.json` there.
The generated Markdown display is not a receipt authority. Inventory checks bind these copied
files for transport. The fresh job creates its own runner-owned 0700 extraction directory and 0600
files, then saves a separate `signer-check.json` from its fresh comparison.

At the no-root tier, 0700 and 0600 do not separate the agent from the collector: they have the same
uid. The protection is the contract's kernel and supervisor restrictions, including refusing the
grants that could replace post-run tools, startup files or action code. If CI allowed a write grant
over those job tool folders, the agent could arrange unconfined runner execution and forge evidence;
CI therefore refuses that contract before launch. The hash chain, the separately copied anchor and
fresh `receipt --check` detect partial or inconsistent edits, truncation relative to a retained head,
and changed receipt totals. They cannot detect a fully fabricated matching chain, anchor, receipt
and job outputs supplied by an unconfined runner user or root. Digests recorded by that same runner
are consistency checks, not an external trust anchor. Permissions, a frozen copy and a fresh job
do not change that residual. No immutable seal or scope-removal assertion exists in B1-2; the owned
teardown interface remains B1-3. Runtime aliases, descriptors, allowed daemons and lingering processes
still require the stated acceptance measurements.

Preparation saves its complete refusal list in `$DIR/state/protected-paths.json`, outside agent writes.
Before producing a receipt, collection reads `run_start.runtime_grants` and checks `fs.codex_home` and
`fs.harness-state` write paths against that same list, resolving aliases and parent/child overlaps.
An overlap, unknown filesystem grant form, missing saved list or record older than minor 11 (which lacks
complete runtime-grant disclosure) fails collection with 125. Other command/network grants do not add
filesystem writes. This check occurs after launch; it refuses the receipt and does not undo earlier
effects. It is no substitute for T11 or the kernel checks owed in a guest.

The fresh job derives refusal totals, run id, verified status and agent exit code from the receipt
and sidecars it has checked against the copied record. It derives the pull request number from its
own event file. It uses first-job outputs only to locate and bind transport, including the explicit
agent attempt and artifact name. Re-running only a failed fresh job continues to select the original
agent artifact rather than substituting the fresh job's newer attempt. Every display names the event
commit. A failed comparison replaces the matching earlier Bot comment with a no-checked-receipt
message naming that commit, subject to comment permission; failure to post is reported.

### Teardown interface

Add `tego run --status-file <absolute-path>`. CI uses
`$RUNNER_TEMP/tego-ci/<github.run_id>/<github.run_attempt>/<matrix-key-sha256>/run-status.json`, in a
fresh 0700 directory outside grants. The copied name is `run-status.json`. `pkg/spec/runstatus` owns
versioned types/strict codec; `internal/runtime` owns lifecycle facts; `internal/cli/run.go` wires the
flag and secure writer. This interface does not exist today.

```json
{"schema":"tego.run-status/1","run":"<Tego run id>","scope":"/sys/fs/cgroup/<exact scope>","cgroup_id":"<positive decimal id>","removed":true,"deferred":false}
```

Require every key, reject duplicates/unknowns/wrong types, limit to 4 KiB. Once run/scope are acquired,
write initial `removed:false,deferred:false` before exec. Before normal return, write final status after
grace/kill, drain, record close, backend release and removal attempt. Atomically rename a new 0600
regular file without following links. Bind run/kernel cgroup ID to runtime state and record `cgroup`,
never a guessed path. `removed:true` means removal succeeded and the known scope was confirmed absent.
Deferred cleanup writes `removed:false,deferred:true` before return, even if it later completes;
no background success rewrite. Pre-scope refusal writes no status. Missing/stale/partial status cannot
allow signing.

The collector requires matching run/ID, `removed:true`, `deferred:false` and its own confirmed absence
of that exact scope. Uncertainty/timeout/unreadable/remaining scope means no signature and exit 125.
The signer checks the copied status/digest; it cannot inspect the previous runner's cgroup filesystem.
Absence remains the collector's assertion.

After teardown, produce `receipt.json` with `tego receipt <run> --verify --json`, then check frozen copies:
`tego receipt --check receipt.json ./run --require-ended --json`. Add `--require-ended`: an unended
match exits 1. Preserve existing behavior without it. Require `match`, `ended:true` and all required
checks `pass`, including `facts`; today's generic exit 0 also includes `match-unended`.

Step `collect` writes trusted single-line outputs only after teardown/checking: `run-id`, `matrix-key`,
`agent-exit-code`, `inventory-sha256`, and `{receipt,record,anchor,contract,status}-{sha256,bytes}`.
Inventory is sorted filename order, one ASCII `<sha256> <bytes> <path>\n` per frozen receipt, record,
anchor, contract and status file. A pinned upload action adds `artifact-id`. Map these through GitHub
job outputs. Artifact names include run/agent-attempt/matrix digest; pass that attempt and name
explicitly so a rerun of `sign` alone can use the retained artifact. `sign` downloads **by ID**, requires all
output digests and rehashes every file; never trust a digest file inside the artifact. Root on the
agent runner can still forge both channel and files.

`sign` never checks out/executes caller code, installs an agent, runs services, restores caches or
accepts shell hooks. A successful bounded download and inventory check precede the fresh trust state below; then
it verifies its own Tego executable, checks the bounded artifact/inventory and
reruns `--check --require-ended --json`. Save exact output as `signer-check.json`; require full ended
match and hash it into the manifest. Assemble trusted metadata and rehash inputs before signing/upload.
The final artifact adds manifest, signer check and both bundles.

After the teardown output passes, create fresh 0700 `HOME` and `TUF_ROOT` directories before any
cosign operation. Scrub inherited Sigstore/proxy/shell/XDG configuration; import no agent HOME or
`.sigstore`. The pinned workflow supplies hash-pinned bootstrap `root.json`, `trusted_root.json`
and public service configuration. Initialize only the pinned mirror from that bootstrap, checking
TUF signatures/expiry and refusing unexpected root/config changes. Cosign uses absolute verified paths
and this isolated environment. No key enters Tego; cosign discards its ephemeral key. Never upload
credentials or HOME. Signing operations are:

```sh
cosign sign-blob --yes --bundle receipt.sigstore.json receipt.json || exit 125
cosign sign-blob --yes --bundle manifest.sigstore.json manifest.json || exit 125
```

Capture agent failure in outputs so `agent` can retain evidence before reporting.
After comparison upload, the receipt gate always preserves the checked agent exit, or returns 1 for
`on-refusal:fail` when the agent succeeded, independently of signing selection or a later signing call.
The optional signer may sign checked, ended failure or refusal receipts too; after signed upload,
its own gate independently preserves the same outcome. Evidence/signing failure
takes 125, naming the checked agent result when available; before a successful comparison the agent
result stays unknown. Doctor refusal launches nothing: preserve 211, upload `doctor.json`,
summary “No receipt: this runner cannot provide tier X. The agent did not start.”

## Eligibility and private repositories

Eligible: `push`, `schedule`, `workflow_dispatch`, same-repository `pull_request`. Detect forks by API
repository IDs, not association. Forks stay unsigned even with write-token settings. Refuse
`pull_request_target` before launch. Other triggers, including `issue_comment` and `workflow_run`, get
unsigned reports only. This excludes a common agent trigger; `sign:true` cannot lift restrictions.
Check triggers in the verifier too, including multi-trigger workflows.

In the optional signing path, `auto` requires signing for eligible public runs with exact consent;
missing delegated OIDC permission fails before execution or token issuance. The receipt call defaults to
`false`. Private/internal auto defaults to unsigned. Determine visibility from authenticated repository API **before any OIDC request**,
never the event payload. Recheck token visibility when signing. Unknown visibility sends nothing to
Sigstore; auto remains unsigned, while an eligible explicit true request refuses. API transport/process failures count as
unknown. Disabled signing makes no eligibility API request. Disagreement stops before Fulcio/Rekor.
Explicit `true` still requires the separate exact consent to public repository/workflow/ref/run/visibility
disclosure for known private/internal repositories. State disclosure beside that input before launch. `false` is unsigned; requested signing failure never becomes successful
unsigned output. Keep distinct unsigned reasons: fork, trigger, private, unknown, disabled.

## Complete verifier

B1-3 ships this command in the independently installed release:

```sh
tego receipt --verify-ci ./evidence --expect ./expected-ci.json \
  --trusted-root ./trusted_root.json --cosign /verified/bin/cosign --json
```

`internal/check/cireceipt` owns verification: Go standard-library JSON/SHA-256/X.509/ASN.1 and existing
receipt/ledger packages, no new dependency. `internal/cli/receipt.go` owns flags/wiring.
Strict expectation schema `tego.ci-expect/1` has `schema`, `github` (the manifest's provenance/job fields,
excluding the two runner-image objects), `tego` (`version`,`commit`), and `attempt`
(`started_at`,`completed_at`, RFC3339 UTC). Require those exact keys. Obtain values from trusted
configuration and GitHub's exact-attempt metadata, never evidence; retain API metadata for offline use.
Missing expectations fail closed. Use independently verified release checksums/roots, never archive binaries.

Freeze bounded regular-file copies privately. Invoke pinned cosign v3.1.3 on both blobs with these
arguments; every `EXPECTED_*` comes from the independent expectation:

```sh
for blob in receipt manifest; do
  cosign verify-blob "$blob.json" --bundle "$blob.sigstore.json" \
    --trusted-root "$TRUSTED_ROOT" \
    --certificate-identity "$EXPECTED_SIGNER_URI" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository "$EXPECTED_REPOSITORY" \
    --certificate-github-workflow-sha "$EXPECTED_SOURCE_SHA" \
    --certificate-github-workflow-ref "$EXPECTED_SOURCE_REF" \
    --certificate-github-workflow-trigger "$EXPECTED_TRIGGER" || exit 1
done
```

**These calls show these bytes, this workflow, some run.** They do not complete verification.
Require validity at signing time, trusted roots and verified transparency inclusion/time. Bundle plus
`--trusted-root` supports offline verification; no deprecated `--offline`, skip flags, wildcard
identities or artifact-supplied trust authority.

Parse leaf DER from the exact immutable bundle cosign verified, using `crypto/x509`; decode Fulcio
extensions with `encoding/asn1`. Reject missing/duplicate/malformed/conflicting required extensions.
Require both certificates and manifest to match:

| Fulcio field (OID suffix after `1.3.6.1.4.1.57264.1`) | Required comparison |
|---|---|
| Issuer `.8`; signer URI/digest `.9/.10` | GitHub issuer; exact reusable workflow URI/commit |
| Runner `.11` | Exactly `github-hosted` for signer |
| Source URI/digest/ref `.12/.13/.14`; IDs `.15/.17` | Expected repository, source SHA/ref, immutable repository/owner IDs |
| Config URI/digest `.18/.19` | Expected caller workflow and `workflow_sha`, separately from source SHA |
| Trigger `.20`; invocation `.21` | Expected event; exact `https://github.com/<repo>/actions/runs/<id>/attempts/<attempt>` |
| Visibility `.22` | Expected/API visibility |

Require SAN equals signer URI; compare legacy GitHub extensions against modern equivalents when present.
Job/matrix/step/checkout/image are assertions checked against pinned configuration/API, not certified
step identities. The signer extension does not certify the agent runner; require that job's
GitHub-hosted metadata separately. Check image fields for well-formed runner metadata, without claiming
certified image versions. Both Rekor integrated times must fall in the independent attempt window,
allowing 60 seconds clock skew, and each certificate's validity. Ephemeral keys may differ; provenance
must agree. Missing deployed extensions block acceptance, never weaken checks.

Then check the full manifest, all hashes, signed release checksums, status, saved signer check and fresh
local `--check --require-ended --json`. Require mandatory checks pass; allow only documented
`not_compared` entries (producer hash and existing price-table inputs). Those prices are not reproduced.
Saved check is the signer's signed assertion; fresh check is the reader's comparison. Neither
independently authenticates the earlier scope absence.

Output `tego.ci-verify/1` prints result, signer/caller URI/digests, repository IDs, source SHA,
run/attempt, trigger, runner environment, integrated times, receipt hash, ended status, individual
checks, `not_compared` and residual limits. Human output prints “full ended match”
only on success. On every other result the identity block is labeled
"Expected (not established):". Root/maintainer/coverage limits follow. Exit 0 requires full ended match; 1 means
mismatch/refused provenance/unended; 125 means could not check; 2 means bad usage.

## Threats and public words

| Actor or attack | Required handling and residual |
|---|---|
| Agent, installer, earlier step | No OIDC authority in `agent`; protected output/file paths, teardown and trusted collector. Root or A8 can still compromise evidence. |
| Signer dependency | Pinned code/verified tools, fresh runner/HOME/TUF state; never execute evidence. Compromised pinned signer code remains trusted. |
| Maintainer or agent-runner root | Can select another workflow or fabricate consistent inputs. Pin both digests; signatures cannot make false evidence true. |
| Fork or privileged trigger | Repository IDs/trigger allowlist before launch/signing and in verifier; write tokens cannot override. Same-repository PR controls its caller. |
| Replay/mixed pair/matrix substitution | Certificate invocation, exact attempt window, both signatures, inventory/artifact IDs and matrix key. Old signatures belong to old statements. |
| Forged comment | Hash workflow/job/step/matrix tuple. Update only authenticated configured author/app's comments; escape bidi/control characters, never adopt human markers. |
| Private disclosure | API visibility before token request, unsigned default, explicit disclosure consent. |
| Deletion | State retention; retain complete evidence independently. Public log cannot recover artifacts. |

No signing claim ships until every acceptance row passes. Every user-facing “signed” claim must have
its residual beside it, in README, summary, comment and check:

| Claim | Required words/condition |
|---|---|
| Signed | “Signed by Tego's pinned signer workflow in your repository's run. Anyone who can change which workflow runs could have supplied different evidence; root on the agent runner could have fabricated it.” Name both JSON files/bundles and receipt hash. |
| Unsigned | “Unsigned (reason): a report, not evidence.” Keep `no-signature` in JSON. |
| Checkable later | “Checkable later, off the runner, by anyone who pins both workflows and retains files, trusted roots and expected metadata.” Include the same maintainer/root residual. |
| Tamper-evident | Changes to retained bytes are detected after signing, with pinned provenance and the same residual. Never “tamper-proof”. |
| Refusals/reads | “No refusals recorded”, never every action/everything it did, or proof it could not read secrets. Use receipt notes, capabilities, caps and lower bounds. |
| Kernel enforcement | Name rule/tier; general words name kernel and supervisor. Landlock host/port admission uses the supervisor; root recording can miss callbacks (C53). |

Show **Incomplete** first when `coverage.complete:false`, then tier/read limits before lists. True coverage
does not mean every action observed. CI defaults `reason.reads:on`; contracts may override it, withdrawing
refused-read-recording claims. Reason reads record refused opens, not all reads. Preserve visible sample
labels, notes, truncation/lower bounds and plain capability names. Signing repairs no crash tail,
allowed-host exfiltration or missing remote effects.

## Acceptance measurements

Every row is **unmeasured**: require real GitHub run/attempt links, downloadable artifacts, image/version,
expected metadata, verifier output and exit code. Green jobs alone are insufficient. Use private lab,
public twin and second-account fork. Branch-build lab inputs require trusted commit/digests; repeat
the completed set on the published release candidate.

| Run | What must be shown |
|---|---|
| C0, before implementation | Public twin signs a fixed blob on push, dispatch, same-repository PR, attempt 2 and reusable workflow call. Dump every certificate extension: actual SAN, signer/config digests, invocation/attempt, runner and time mappings. |
| T1 | Same-repository amd64 PR, no sudo: two distinct runners, no OIDC interface in any agent-job step, tier landlock, known read/write/connect refusals, ended match, summary/artifact and authorized optional comment. |
| T2 | Repeat on arm64; both assets match signed release checksums. Each architecture checks the other's same-release receipt through `made_by`/`facts`, with producer hash in `not_compared`. |
| T3 | Update PR, two matrix legs, rerun one: distinct artifacts/markers, correct comment update, forged human marker untouched. |
| T4 | Sudo: tier cgroup, agent unprivileged, named env values arrive without argv disclosure, truthful root read note and C53 incompleteness. |
| T5 | Fork with write tokens enabled: unsigned fork reason, no secrets/signing calls, summary/artifact survive comment denial. PR head cannot substitute for merge SHA. |
| T6 | Public auto fully verifies. After download, edit one total and one whitespace byte separately: both fail signatures. Mix two runs' receipt/manifest/bundles: full verification fails. |
| T7 | Refusal gate uploads/reports before failure 1. Separate doctor refusal: no launch/signature, diagnostic artifact/summary, exit 211. |
| T8 | Agent exits 3: ended failure receipt retained/checked/signed, final exit 3. Evidence/signing failure takes 125; name the checked agent result when available, otherwise unknown. |
| T9 | Descendants, keep-descendants, stalled drain, failed/deferred removal, crash/stale status: only confirmed removal allows signing. Truncated/unended record fails ended-only mode even if generic check exits 0. |
| T10 | Both agent architectures/tiers: ptrace/proc, new PIDs/fd aliases, inherited fds, token file/socket canaries, broad protected grants; log no secrets. Workflow-command/output/resume injection changes no outputs/PATH. Hostile agent `.sigstore` cannot reach fresh signer state. |
| T11, later-action PATH and HOME | Owed on the lab repository, on both architectures and tiers. In a disposable unsigned agent job, run pinned checkout before the agent and another checkout plus a diagnostic step after it; retain the earlier checkout's post-step logs. Seed harmless tool/config canaries in original PATH, retained GITHUB_PATH, HOME and XDG paths. Record effective PATH/HOME, resolved git/bash paths and Git configuration origins (no values), runner image/version and run/attempt links. Show whether GITHUB_ENV PATH/HOME settings actually reach later steps and checkout post steps, which GITHUB_PATH entries are prepended, and that every consumed tool/config canary path is protected from declared and runtime-added writes. No planted executable/config canary may run or change the retained evidence/outputs. If a later consumer reaches an agent-writable path, record the failure and keep this row open. A green collector-only offline test cannot close it. |
| R1 | Attempt-1 evidence against attempt-2 expectations, then old run against new: invocation/time/provenance refusal. |
| R2 | Multi-trigger `pull_request_target`: refused before launch; genuine target-event blob cannot pass push expectations. Issue-comment/workflow-run remain unsigned. |
| R3 | Self-hosted signer certificate refused. On GitHub, exercise missing/wrong extension fixtures with isolated test trust, plus genuine controlled certificates against wrong production expectations: each fails closed. |
| R4 | Private/internal auto and unknown API visibility: no OIDC/Fulcio/Rekor request. Explicit private true documents disclosure; API/token disagreement stops before Fulcio. |
| R5 | Real long/3,000-file workloads and read modes on/off/full: limits first, comments fit, truthful counts/notes. Replaced executable fails release checksums; YAML hash never substitutes for compiled hash. |

## Build slices

These are the build slices of this decision.

| Slice | Builds | Closing proof |
|---|---|---|
| B1-2 | Move/export `action/`; reusable workflow, explicit permissions/two fresh jobs, fixed metadata/outputs. Original ACTION-REVIEW corrections plus the custody, gate-source, stale-comment, export, interpolation, ended-only and rerun corrections in the follow-up review. Signing disabled pending later slices. | Original C0-before-implementation dependency remains unmet. Offline negative cases for each review boundary and permissions; shellcheck/actionlint clean. C0 and hosted acceptance stay open. No signing claim. |
| B1-3 | Binding 2 without hash in MadeBy; release checksums; owned status interface; ended-only check; artifact-ID/digest handoff; isolated signer trust state, manifest/two bundles and complete verifier. Replace caller repository-variable implementation and binary pins with workflow literals, or verify source reachability from a trusted Tego tag and binary membership in that release. Depends on B1-1/B1-2. | Focused schema/lifecycle/verifier checks and gate: edits, mixed pairs, unended, deferred cleanup, every missing/wrong extension and cross-architecture fixtures. Local-key verification proves byte handling only; GitHub acceptance remains open. |
| B1-4 | C0/T1-T10/R1-R5, fixes in owning slices, retained evidence, candidate repeat. | Every row has run/attempt links and required results, none unknown/red. Then record acceptance and enable public signing words. |

## Second reading

Separate jobs replace same-step signing because every script step in an OIDC-enabled job can sign.
Status stays proposed until measurements exist, rather than accepted merely after amendments.
“Signed by your workflow, not by Tego” now names the reusable signer and caller control accurately.
The producer hash is excluded from build equality; signed release checksums establish binary membership.

## B1-2 implementation note (2026-11-11, historical slice)

This section records the original unsigned slice. The B1-3b and permission-split amendments below
supersede its installer, status, job-name, comment-permission and signing descriptions.

The unsigned implementation lived in `action/` and `.github/workflows/ci-receipt.yml`.
The agent has contents read only. The fresh `sign` job has contents/actions read and pull-request write
for the optional comment. Neither job has OIDC authority. `sign:true` retains the unsigned report and
fails 125; other values never enable signing. Canonical merged contracts refuse setuid, kept descendants
and record off; compiled CI environment denials are mandatory. The custody amendment above specifies the
fixed collector environment, frozen action copy, pre-run digests and mandatory grant refusals. Tool and
startup and known Git configuration paths are write-protected; token/evidence paths and runner diagnostics are also read-denied, so
installed runtimes remain readable. Overlapping parent/child writes and resolved symlinks or direct
file grants to hardlink aliases are refused. Existing hardlinks inside a granted tree and runtime aliases
remain open; file modes do not isolate the same-uid agent or establish immutable evidence.

Until a compatible release is published, callers supply independently reviewed repository-variable pins
for the exported implementation commit, release version and per-architecture binary SHA-256. Both jobs
use those exact pins. No pin or compatible release is invented. These variables are trusted caller
configuration and must be reviewed alongside the caller and reusable workflow commits. A fork-network
checkout SHA does not establish membership in a Tego release. Before signing, B1-3 must make these pins
literals in the trusted workflow or check source reachability from a trusted Tego tag and binary
membership in its verified release checksums. The B1-2 installer checked only the configured digest.

The agent uploads a bounded unsigned artifact with ID, archive SHA-256 and sorted inventory SHA-256
passed through job outputs. The fresh job downloads by ID, checks API run metadata, refuses special,
duplicate or unexpected archive names, rehashes every regular file and compares the inventory. It installs
its own pinned binary and requires generic receipt --check to return match, ended true, the minimum
seven checks including facts (plus binding for version 2), and every returned check passing.
The check file must have no duplicate object keys at any depth. This requires an ended record; the
workflow still does not request --require-ended or establish complete teardown. Display sidecars are checked against copied bytes before rerendering. Additional command/runtime grants
are shown from run_start, separately from the compiled hash, which does not include them. The
collector also checks runtime-added filesystem writes against the saved pre-launch refusal list before
issuing a receipt; this retrospective check does not prevent or undo earlier effects. The fresh
comparison is retained separately. Refusal/exit gates use checked files, and PR targets use the fresh
job's event. Failed checks attempt to replace a previous matching Bot comment; every display names its
event commit. Artifact selection carries the producing attempt explicitly for fresh-job-only reruns.
The B1-2 workflow retains no teardown assertion, final signing manifest or bundle.

The original review regression cases cover comment author checks, reads/notes/caps, escaping, matrix
identity and doctor 211. The independent follow-up found gaps in collector trust, gate inputs, stale
comments, export leaks, interpolation coverage, the ended test and rerun selection. The fix round adds
separate negative cases for those boundaries; the earlier suite was not evidence that they held.
Offline tests use a fake CLI and labelled historical guest
fixtures; they do not establish actual hosted execution or a real comparison by a published release.
The exact C0 lab files are under action/testdata/c0. The lab repository is still owed, so C0 was not
performed before this implementation. This is an explicit acceptance dependency, not a passing measurement.
The ADR remains proposed; no signing claim or acceptance row is closed by these offline results.

## B1-3a product interface amendment (2026-11-11)

This first half of B1-3 adds product interfaces. Fix round 1 also updates the
workflow comparison contract in "The receipt and signing jobs" for both supported binding
versions. No bundle operation or GitHub acceptance run is included. This ADR
remains proposed and every hosted acceptance row remains open.

Binding 2 also adds `binding.receipt_sha256`: SHA-256 of the compact canonical
receipt JSON after removing only that field. Objects are sorted recursively and
JSON number spellings are retained. The earlier design relied on a later bundle
to cover receipt totals, while its binding covered only record bytes. The owner's
B1-3a requirement makes the binding itself commit to totals, lists and notes.
An edited total without a recomputed checksum now fails the binding check before
`facts`. This is a consistency check: anyone editing the receipt alone can
recompute the checksum. It adds no identity or authenticity claim.

`binding.binary_sha256` remains outside `MadeBy`. The checking executable is not
compared to this field. `facts` validates its shape, holds it constant and lists it
in `not_compared`. The CI verifier instead checks producer and fresh-job asset
hashes against caller-supplied release checksums, which the caller must
authenticate separately. This avoids making an
amd64 receipt impossible to compare with an arm64 asset of the same release.
Fixture coverage does not close the real cross-architecture acceptance row.

The receipt stays at `receipt_v:1`. Binding 1 is read and compared in its original
shape, with the checked version reported as `binding_v`. Unknown binding versions
return `cannot-check`, exit 125, never a match. Receipt-only additions and the
separate status file change no record line, so they need no record minor.

The status codec retains the six-key `tego.run-status/1` shape but also accepts an
empty scope or cgroup ID to mean unknown. This is a deliberate extension of the
original positive-ID example: a tier unable to establish identity must be able to
report that uncertainty without inventing one. Such a status can never set
`removed:true` and cannot complete an ended-only check. The runtime's synchronous
launch/shutdown path supplies facts; deferred cleanup never rewrites success from
the background. Pre-scope refusal writes no status. Launcher loss leaves the
initial assertion or no file, even if a later sweep closes the record.

`--require-ended` additionally checks the launcher's copied status. Supply it with
`--status-file`, or use `run-status.json` in the record folder or its parent. The
checker requires the record's run/kernel cgroup ID, `removed:true` and
`deferred:false`. It cannot confirm absence on an earlier runner's filesystem;
the collector's independent absence check remains owed. A missing or malformed
status or unreadable record is `cannot-check`/125 unless a separate check failed.
A readable unended run or explicit removal refusal is `mismatch`/1. Coverage false yields `incomplete`/1 when no other check failed.
The generic comparison retains `match-unended`/0. Both outputs distinguish coverage
from completion: `coverage_complete` describes the receipt and `complete` is true
only after the ended-only requirements pass.

This slice exposes `tego receipt --verify-ci <evidence> --expect <expected.json>
--checksums <trusted-checksums> [--json]`. The `--trusted-root` and `--cosign`
integration in the complete-verifier design remains in the later half of B1-3.
The current command accepts independent expectations and checksums, performs local
consistency comparisons and names the statement each check supports. It does not
establish checksum trust, fetch GitHub metadata, validate a bundle or parse an
actual certificate. `BundleVerifier` owns that future boundary. Every mandatory
bundle/certificate field is reported as `not checked: no bundle` when the interface
has no implementation; an absent check can never count as a pass. Its output
states that this command did not authenticate the release checksums file. A checking executable with an unavailable exact release identity or a hash
outside the supplied checksums yields `not-checked`, rather than an evidence
mismatch. Producer and signer asset mismatches still fail. On any result except
`match`, the text labels the identity block "Expected (not established):".
Local consistency therefore returns `cannot-check`/125, while a known mismatch
returns 1. Missing or wrong certificate fields and real time/provenance mappings remain acceptance work.
All real lifecycle checks remain owed in a guest.

Generic `--check` uses the same nonblocking, no-leaf-symlink regular-file opener
as the retained CI inputs. This applies the existing evidence-file invariant to
receipt input too: a FIFO cannot hold the open waiting for a writer, and a leaf
symlink cannot redirect the receipt read. Unreadable input returns 125 unless
a separate check failed. The receipt checker uses the reader directly:
a receipt-supplied head is no independent anchor proving that a missing or
substituted file previously existed. The ledger command retains its separate
trusted-anchor loss finding. End and teardown remain unchecked until both chain
and head pass. Facts compares receipt values before the derived checksum so a
resealed edit names the edited field. An unreadable receipt prints neither a
coverage claim nor binding version 0; binding 1 says it has no receipt checksum
and totals are compared only by facts.

`run --status-file` refuses `--observe` with usage exit 2. Record-only execution
cannot protect the status assertion from the agent sharing the launcher uid.
The status file does not cover work that left the scope through an allowed
daemon. Existing-file refusal also prevents `--service` restarts from reusing
one status destination.

Fix round 1 also aligns strict provenance decoding with the published schemas:
`source_ref` requires a nonempty suffix after `refs/`, and a workflow reference
requires exactly one `@` separator. Both manifest and expectation decoding reject
these malformed shapes. This narrows input validation without adding a trust claim.

## Check-file validation amendment (2026-11-12, fix round 2)

The workflow minimum now depends on the receipt binding version: seven checks
for version 1, plus `binding` for version 2. Missing, non-integer or unknown
binding versions are refused. The entire check file is parsed as one strict JSON document before
comparison; duplicate keys at every object depth are refused, including equal
values, container keys and escaped spellings. Ordinary jq object parsing alone
cannot establish that contract because it keeps the last duplicate value.
This narrows check-file acceptance; it adds no signing or teardown claim.

## B1-3b signing implementation amendment (2026-11-12)

The receipt workflow has two fresh jobs: `agent` and `report`. The separately called signing workflow
has one fresh job, `sign`. `agent` has contents read; `report` has contents/actions read and resolves
eligibility without OIDC. Only the optional second caller delegates id-token write to `sign`. The extra reporting job preserves unsigned diagnostics and checks without exposing
signing authority. It never executes caller code. Comments have no write permission in these jobs.
An independently authorized integration can use the retained comment implementation separately.

Every signing request, including eligible public `auto`, requires the exact `sign-consent` string:
`I consent to publish repository and workflow names in the permanent public Sigstore log`.
The input description explicitly names organisation, repository and workflow disclosure to a public,
permanent log. The reporting job refuses eligible requests without this consent after retaining reports;
the signing script independently refuses before installers or token requests. Private/internal auto,
forks and unsupported triggers remain unsigned. Unknown visibility remains unsigned for auto; an eligible
explicit true request refuses. This intentionally narrows the earlier
public-auto rule: public repository names do not imply consent to permanent publication of workflow/run metadata.

Each job's installer authenticates the release-checksums bundle and requires the implementation SHA equal the
independently configured release source SHA certified by the official release workflow. This replaces
repository-variable binary trust alone. No compatible release pin is invented. The lab adapter is explicitly
lab only and verifies artifact transport; it does not claim release authentication. Cosign v3.1.3 and
bootstrap root16, trusted root and signing-config v0.2 bytes are pinned by SHA-256. Fresh private HOME/TUF
state verifies the pinned mirror's metadata signatures/expiry and refuses unexpected root/config changes.
An ordinary trust rotation needs a reviewed pin update. No credential or trust HOME is uploaded.

The launcher receives --status-file. When status exists, collection requires matching successful teardown
and independently confirms the exact scope absent before copying it. Unsigned diagnostics may have no
status; the signer never accepts that case. It downloads the original artifact by ID, repeats the complete
binding-2 ended comparison with copied status and rechecks release assets. It requires all mandatory product
checks and every returned check to pass. Manifest assembly compares agent metadata with independent contexts,
checks the producing attempt's paginated job API for one completed GitHub-hosted agent, and compares OIDC claims
received directly from GitHub HTTPS with repository API visibility and independent contexts before Fulcio/Rekor.
Runner image versions remain assertions. Agent runner name is only an API lookup key, not an image attestation.
The exact receipt and manifest get separate detached bundles; the manifest includes the record digest.
Inputs are rehashed before signing and before the seven-day final artifact is exposed. Each workflow
uploads before its own checked agent/refusal gate. The receipt gate always runs independently of signing.
Root on the earlier runner can still fabricate consistent inputs.

Complete verification now takes `--checksums`, `--trusted-root`, `--cosign` and `--cosign-sha256` with
independent `--expect`; the checksums must be authenticated separately. `--check --bundle` verifies only the
receipt signature plus its ordinary record comparison, while `--verify-ci` verifies both blobs and the complete
manifest/provenance. Cosign verifies immutable copies, then Go parses those exact bundles' leaf certificates,
mandatory modern extensions, SAN, validity and verified Rekor time. Exactly one Rekor entry with signed entry
timestamp and inclusion proof is required so the integrated time is authenticated. Missing deployed extensions
or unsupported bundle shapes refuse acceptance. Isolated certificate/stub-cosign fixtures prove handling,
not production GitHub identity mapping. Every C0/T/R acceptance row remains open; no public signing claim
is accepted by this implementation. Guest lifecycle measurements remain owed in a guest.

The launcher status parent is a dedicated `$DIR/status` directory, 0700 and owned by the actual launcher.
At sudo this is root-owned; a pinned stdout-only reader checks its ownership, modes, no-link components,
regular singly-linked leaf and 4 KiB bound through sudo. The runner collector creates its own 0600 copy
exclusively, then validates successful teardown and independently checks scope absence. Product parent
ownership checks are unchanged. Historical unsigned fixtures without status remain reports; they cannot
schedule the OIDC job. The report also verifies every out-of-band core file digest/size and complete status
before setting should-sign. Hosted ownership and lifecycle behavior remain owed in a guest and on GitHub.

For agent-runner API classification, the signer requires completed status, a unique runner-name match,
runner group ID integer 0/name GitHub Actions and no self-hosted label. Six ordinary jobs in the public
v0.1.2 release attempt matched this shape; new receipt/ARM runner mappings remain owed. This strengthens
lookup against a self-hosted runner merely named GitHub Actions. Runner images remain workflow assertions.

An explicit sign:true request with unknown authenticated visibility or same-repository PR identity fails
125 after retaining the report; it cannot become a successful unsigned result. Auto preserves the unknown
unsigned reason, including repository or PR API transport/process failures. Disabled signing short-circuits before either API
request, so unavailable eligibility metadata cannot fail an unsigned report. Fork and unsupported-trigger exclusions remain unsigned as specified. The 216-case policy
matrix covers these uncertainty refusals; ordinary known visibility/identity selections are unchanged.


## Reusable permission split amendment (2026-11-12, signing fix round 1)

The permission split above replaces the earlier single-workflow design. `ci-receipt.yml` exports a compact
`handoff` of artifact/core-file digests and `should-sign`; it contains no signing job or OIDC permission.
The optional caller passes both policy inputs and this handoff to `ci-receipt-sign.yml`. The signer refuses
malformed handoffs and independently repeats policy, complete evidence comparison and token claim checks.
The certified reusable identity is now `attention-span-ai/tego/.github/workflows/ci-receipt-sign.yml@<exact-commit>`.
Hosted acceptance must retain an unsigned caller with only contents/actions read, and a signed caller whose
second job alone delegates id-token write. Local workflow checks cannot close either hosted row.

The committed Go public-release fixture parses certificate and bundle shape. Successful real pinned-cosign
verification of downloaded public release bytes was a separate scratch measurement, not a committed Go
integration regression. The committed boundary tests use a stub cryptographic operation; the test plan
distinguishes those checks. All guest and GitHub acceptance rows remain open.

## Receipt outcome amendment (2026-11-12, signing fix round 2)

The receipt workflow always runs its checked outcome gate after the comparison upload. Signing
selection and an optional downstream signer cannot change the receipt job conclusion. Checked agent
exit 3 remains failure 3; a successful agent with refusals returns 1 under `on-refusal:fail` and 0 under
`warn`. An optional signer can process and sign a checked failure or refusal receipt even when the
receipt call failed; caller examples use `!cancelled()` to allow that call.

The handoff formatter emits original transport hints before pin validation, download or comparison.
Only `should-sign` follows the required policy and complete evidence checks. A handoff alone grants
no signing eligibility; the signer independently validates it. Offline receipt-only regressions cover
both reported failures and all 12 sign/outcome combinations. Hosted job conclusions remain unmeasured.
