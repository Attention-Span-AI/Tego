# A CI job with a receipt

The reusable workflow runs any AI agent under a Tego contract, retains its record and checks its receipt
on a fresh runner. A second, separately called workflow signs the exact receipt and manifest with public
Sigstore keyless cosign when requested. The signer never runs caller code. The implementation has offline tests; real GitHub acceptance,
beginning with C0 certificate dumps, remains open. This is ready for lab review, not an accepted signing service.

A receipt on a pull request is only as honest as the workflow file that made it. On `pull_request` that file
comes from the pull request. Trust only a reviewed caller and reusable workflow pinned by full commits.
Root on the agent runner can fabricate matching evidence. A signature establishes workflow provenance,
not honest execution, complete observation, authorship or remote effects. Allowed daemons can outlive the scope.

For an unsigned run, add this beneath `jobs:` in an existing eligible workflow:

```yaml
agent_receipt:
  uses: Attention-Span-AI/Tego/.github/workflows/ci-receipt.yml@<TEGO_RELEASE_COMMIT>
  permissions: {contents: read, actions: read}
  with:
    contract: agent.yaml
    run: ./agent/run.sh
    sign: 'false'
```

No compatible published release pin is assumed. Replace the placeholder only with a reviewed release commit
containing these interfaces. Configure independent repository variables:

| Variable | Required value |
|---|---|
| `TEGO_CI_ACTION_SHA` | Full published implementation commit; must equal `TEGO_CI_RELEASE_SHA` |
| `TEGO_CI_RELEASE_SHA` | Exact source commit in the release checksum certificate |
| `TEGO_CI_VERSION` | Exact release tag containing `tego/ci@1`, binding 2 and teardown status |
| `TEGO_CI_SHA256_AMD64` | Independent SHA-256 of that release's named amd64 executable |
| `TEGO_CI_SHA256_ARM64` | Same for arm64 when requested |

The installer verifies the checksum bundle against GitHub's issuer, exact official release workflow URI,
release tag, source commit and push trigger. It then matches the named asset against those checksums and the
independent pin. Each job rehashes its own absolute executable before use. Unknown pins or a different
implementation commit refuse execution. Caller and repository-variable changes remain trusted configuration.

For a signature, use these two calling jobs instead. The receipt workflow has no signing job and requests
no OIDC permission. GitHub validates a reusable workflow's requested permissions before runtime conditions,
so a caller that wants only a receipt never needs to delegate `id-token: write`.

```yaml
agent_receipt:
  uses: Attention-Span-AI/Tego/.github/workflows/ci-receipt.yml@<TEGO_RELEASE_COMMIT>
  permissions: {contents: read, actions: read}
  with:
    contract: agent.yaml
    run: ./agent/run.sh
    sign: 'true'
    sign-consent: I consent to publish repository and workflow names in the permanent public Sigstore log
agent_signature:
  needs: agent_receipt
  if: ${{ !cancelled() && needs.agent_receipt.outputs.should-sign == 'true' }}
  uses: Attention-Span-AI/Tego/.github/workflows/ci-receipt-sign.yml@<TEGO_RELEASE_COMMIT>
  permissions: {contents: read, actions: read, id-token: write}
  with:
    handoff: ${{ needs.agent_receipt.outputs.handoff }}
    sign: 'true'
    sign-consent: I consent to publish repository and workflow names in the permanent public Sigstore log
```

Use the same release pin, signing selection, consent, `matrix-key`, `use-sudo` and `on-refusal` values
for both calls when overriding their defaults. The second call alone delegates signing authority.
It repeats policy and evidence checks; receipt outputs select work and bind transport, not honest execution.

Signing publishes your organisation, repository and workflow names, identities, source/ref/run/attempt and
visibility to a **public, permanent** log, even for a private repository. Deleting artifacts or the repository
cannot remove that disclosure. Consent is an exact string, checked inside the signing script as well as its
workflow. Absent or incorrect consent refuses an otherwise eligible signing request with 125. No signature
is attempted without it. The optional `auto` selection also requires consent for an eligible public run; private/internal `auto` remains unsigned.

Authenticated API visibility and PR repository IDs decide eligibility before the first OIDC request.
Forks and unsupported triggers remain unsigned even with `sign:true`. `pull_request_target` is refused
before launch. Unknown visibility or an API transport/process failure sends nothing to Sigstore; `auto` remains unsigned,
while an explicit eligible true request fails 125. Malformed or contradictory authenticated replies still refuse reporting. Disabled signing performs no eligibility API requests. The signer rechecks API visibility against
the GitHub token claims before Fulcio/Rekor calls. Only `push`, `schedule`, `workflow_dispatch` and same-repository
`pull_request` are eligible. A same-repository PR still controls its caller workflow.

The `agent` job has contents read only and no OIDC interface. The fresh `report` job has contents/actions
read only. It retains a checked unsigned report and resolves signing policy without OIDC. The `sign` job in `ci-receipt-sign.yml`
alone has contents/actions read and id-token write. It uses a fresh `ubuntu-24.04` runner, no caller checkout,
services, caches, setup hooks or inherited secrets. Comments are disabled in this reusable workflow; the
comment implementation is retained for separately authorized integrations. A read-only fork token cannot
prevent retention of summaries and artifacts.

A small contract:

```yaml
version: 0
name: ci-agent
extends: [tego/ci@1, tego/no-secrets, tego/no-prod]
fs:
  write: [./out/]
```

Create `out/` before the run. The preset defaults to refused-read recording and denies named CI token variables.
It cannot locate runner temp, tools or token files by itself. The action adds concrete protections. Write grants
must avoid `.github/`, state/evidence, all original job PATH entries, tools, actions, both checkouts' Git/common
directories and HOME startup and Git configuration, including default/explicit XDG, system/override/worktree
configuration and pre-launch include files. It refuses broad parents, known resolved aliases and path-shadow
diagnostics. The agent cannot commit because Git metadata is protected. The error names the grant and path.
`setuid:true`, `keep_descendants:true` and `record:off` are refused after merging. Runtime-added filesystem grants
are checked against the same list before collection; this check happens after launch and cannot undo effects.
The no-prod preset restricts destinations; tego/ci alone does not. An allowed host is a data path out.

| Input | Default | Meaning |
|---|---|---|
| `contract`, `run` | required | Repository contract and intentional shell command |
| `runner` | `ubuntu-24.04` | This image or `ubuntu-24.04-arm` |
| `use-sudo` | `false` | Require landlock; true requires cgroup with an unprivileged agent; no fallback |
| `matrix-key` | `single` | Pass `${{ toJSON(matrix) }}`; canonicalized and hashed |
| `on-refusal` | `warn` | `fail` returns 1 for recorded refusals after reporting if the agent succeeded |
| `sign` | `false` in receipt; `auto` in signer | Eligible public auto or explicit true requests signing; false disables it |
| `sign-consent` | empty in receipt; required in signer | Exact public-log disclosure consent required for signing |
| `handoff` | required in signer only | Exact receipt-workflow output binding artifact and core file digests |
| `comment` | `false` | Reserved for separately authorized comment integrations |

The launcher writes protected `run-status.json`. The collector independently checks the exact known scope
is absent before copying successful status. Missing status can remain in an unsigned diagnostic; signing
requires binding 2, `--require-ended`, `removed:true,deferred:false`, full coverage and every product check
passing, including facts, ended, teardown and coverage. The fresh signer checks the copied status and record;
it cannot inspect the earlier runner. Uncertainty, stale status or failed/deferred removal refuses signing.
An incomplete unsigned report still starts with **Incomplete**. True coverage does not mean every action observed.
The product keeps binding 1 readable for ordinary unsigned comparisons.

The final artifact retains exact `receipt.json`, `manifest.json`, `receipt.sigstore.json` and
`manifest.sigstore.json`, copied record, anchor, contract, teardown assertion and fresh `signer-check.json`.
The manifest signs the record digest, bytes, lines, head and run; contract file and compiled hashes; teardown
and fresh-check hashes; both release asset identities; artifact inventory and exact GitHub provenance.
Blobs are not signed. Markdown is a display. The JSON keeps its no-signature note because bundles are detached.
The public log stores metadata, not a recoverable record archive. Retain complete artifacts, independent
expectations and roots **before seven-day expiry**. The summary names the full receipt SHA-256.

Cosign v3.1.3 and bootstrap root, trusted root and public signing configuration are pinned by SHA-256. Every
cosign call uses a fresh private HOME/TUF state and an empty inherited configuration environment. TUF verifies
signatures and expiry; unexpected root/config bytes refuse signing. Neither HOME nor a credential is uploaded.
A future legitimate trust rotation requires review and updated pins rather than silently accepting new roots.

The signed summary says: "Signed by Tego's pinned signer workflow in your repository's run. Anyone who can change
which workflow runs could have supplied different evidence; root on the agent runner could have fabricated it."
These limits apply to checking retained bytes too. See the [verification recipe](ci-verification.md),
[manifest schema](../../spec/ci-receipt/v1/manifest.schema.json) and
[independent expectation schema](../../spec/ci-receipt/v1/expect.schema.json). The reader must authenticate
its release checksums separately; a matching file hash alone is not checksum trust.

Unsigned comparison on the same verified Linux release:

```sh
tego receipt --check receipt.json run --json
tego receipt --check receipt.json run --require-ended --status-file run-status.json --json
```

The generic comparison accepts binding 1/2 with all checks passing. Signing requires the complete binding-2
check. An unreadable required input returns 125; an established mismatch returns 1; bad usage returns 2.
Doctor refusal launches nothing, retains diagnostics and preserves 211. Ended agent failure receipts can be
signed. The receipt outcome gate always runs after its comparison upload, independently of `sign` or
a downstream signing call. It preserves the checked agent exit, including 3, or returns 1 for
`on-refusal:fail` when the agent succeeded. The optional signer may sign these failed or refused runs,
then applies its own outcome gate after signed upload. A signing/evidence failure takes 125 and names
the agent result only after comparison. The handoff is emitted before checks as transport hints;
`should-sign` is emitted only after the required signing checks.

The compiled contract hash is separate from its YAML SHA-256; merged defaults and runtime grants are not
reconstructed from YAML alone. Runtime/command grants and best-effort notes remain record assertions.
Cross-architecture facts comparison, hosted image/tier behavior, certificate mappings, process/token/socket
canaries and T11 later-action PATH/HOME behavior remain unmeasured on GitHub. Lifecycle checks are
[owed in a guest](../../spec/run-status/v1/README.md#guest-lifecycle-checks-owed).

At landlock the agent and collector share a uid; 0700/0600 modes do not separate them. The collector checks
pre-launch copies and exact action inventories, uses absolute system tools, `/bin/bash -p`, fixed PATH/private
HOME, and requests those settings for later steps via GITHUB_ENV. The runner may prepend GITHUB_PATH entries.
Other actions' post steps rely on declared/runtime grant protections. Keep the agent's job to the agent.
Later work belongs in a separate job with a fresh checkout and reviewed inputs. Inherited descriptors,
runtime aliases, allowed daemons and configuration selected only by future steps remain limits.

See [fixture provenance](../../action/testdata/README.md), [the test plan](../../action/TEST-PLAN.md),
[ADR 0143](../adr/0143-signed-ci-receipt.md) and [known gaps](../GAPS.md).
