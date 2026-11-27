---
title: CI
description: "Run an AI agent under Tego in GitHub Actions with the tego/ci preset and reusable workflows, keep a signed receipt, and check it later with tego session show."
summary: "Run an agent in GitHub Actions and keep a receipt you can check."
section: Production
order: 3
---

A CI job can run your agent under a rules file and keep a receipt: a JSON report of one session, bound to that session's record. The reusable GitHub Actions workflows run your agent under Tego, check the receipt on a fresh runner and, if you ask, sign it with Sigstore. You can check a kept receipt later with `tego session show`.

> **Note:** The reusable workflows have offline tests. They have not yet been accepted on hosted GitHub runners.

## Check the runner first

In any CI system, make the job's first step a level check:

```sh
tego machine check --require landlock
```

It exits 0 when the runner can enforce at Basic and 211 when it cannot, so the job stops before the agent starts. Use `--require cgroup` to require Plus. [Self-check](/docs/self-check/) explains the rest of the output.

## Write a rules file for CI

Extend the `tego/ci` preset. It keeps the CI token variables out of the agent's environment and refuses writes to `./.github/`. [Presets](/docs/presets/) lists exactly what it sets.

```yaml
version: 0
name: ci-agent
extends: [tego/ci@1, tego/no-secrets, tego/no-prod]
fs:
  write: [./out/]
```

Create `out/` before the session starts. With `tego/no-prod` and `tego/no-secrets` beside `tego/ci`, the agent reaches no host and gets only plain variables, so add the hosts and variables it needs. An allowed host is a way for data to leave the runner ([Security and limits](/docs/security-and-limits/)).

## Use the reusable workflow

Set these repository variables first:

| Variable | Value |
|---|---|
| `TEGO_CI_VERSION` | The Tego release tag to install. |
| `TEGO_CI_RELEASE_SHA` | The release's source commit. |
| `TEGO_CI_ACTION_SHA` | The same commit as `TEGO_CI_RELEASE_SHA`. |
| `TEGO_CI_SHA256_AMD64` | The SHA-256 of that release's amd64 `tego`. |
| `TEGO_CI_SHA256_ARM64` | The same for arm64, when you use the arm runner. |

Then add a job under `jobs:` in a workflow. Pin the workflow to a full commit you reviewed:

```yaml
agent_receipt:
  uses: Attention-Span-AI/Tego/.github/workflows/ci-receipt.yml@<TEGO_RELEASE_COMMIT>
  permissions: {contents: read, actions: read}
  with:
    contract: agent.yaml
    run: ./agent/run.sh
    sign: 'false'
```

`contract` is the path of your rules file and `run` is the command that starts your agent.

| Input | Default | Meaning |
|---|---|---|
| `runner` | `ubuntu-24.04` | `ubuntu-24.04` or `ubuntu-24.04-arm`. |
| `use-sudo` | `false` | `false` requires Basic (`landlock`). `true` requires Plus (`cgroup`), with Tego started through `sudo` and the agent as an ordinary user. Neither falls back. |
| `on-refusal` | `warn` | `fail` makes the job fail when the session recorded a refusal and the agent itself succeeded. |
| `matrix-key` | `single` | Pass `${{ toJSON(matrix) }}` from a matrix job. |
| `sign` | `false` | `true` or `auto` asks for a signature (below). |
| `sign-consent` | empty | The exact consent sentence, required to sign. |

The job keeps the receipt, the record and the rules file as a workflow artifact. GitHub deletes artifacts after their retention period, so download the ones you need to keep.

## Sign the receipt

Signing publishes your organisation, repository and workflow names to Sigstore's public log, permanently, even for a private repository. The signing job runs only with this exact consent sentence:

```
I consent to publish repository and workflow names in the permanent public Sigstore log
```

Signing is a second job that calls `ci-receipt-sign.yml`. It alone gets `id-token: write`:

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

Use the same pin, `sign`, `sign-consent`, `matrix-key`, `use-sudo` and `on-refusal` values in both jobs. Only `push`, `schedule`, `workflow_dispatch` and `pull_request` from the same repository are signed. Forks stay unsigned, and `pull_request_target` is refused.

## What a receipt proves

A receipt is only as honest as the workflow file that made it. On `pull_request`, that file comes from the pull request, so trust only a reviewed caller pinned by full commit. Root on the agent's runner can forge matching evidence. A signature shows which workflow produced the receipt. It does not show that the runner reported honestly or that every action was observed.

## Check a receipt

Compare a receipt with the session record it came from:

```sh
tego session show --check receipt.json <run folder> --json
```

Add `--require-ended --status-file run-status.json` to also require that the session ended and its processes were cleaned up. It uses the standard exit codes ([Exit codes](/docs/exit-codes/#other-commands)): 1 means a mismatch.

To check a signed artifact, keep these outside the artifact folder:

- the release checksums you verified yourself
- an expectation file in the `tego.ci-expect/1` shape, with the repository, commit and run you expect
- Sigstore's trusted root
- cosign v3.1.3 and its SHA-256

```sh
tego session show --verify-ci ./evidence --expect ./expected-ci.json \
  --checksums ./verified-release-checksums.txt \
  --trusted-root ./trusted_root.json --cosign /verified/bin/cosign \
  --cosign-sha256 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 \
  --json
```

It uses the standard exit codes ([Exit codes](/docs/exit-codes/#other-commands)): 1 means a mismatch or a refused identity. A missing signature bundle never passes. The hash above is cosign v3.1.3 for Linux amd64.

## Next steps

- [Presets](/docs/presets/): what `tego/ci`, `tego/no-secrets` and `tego/no-prod` set.
- [Sessions and records](/docs/sessions-and-records/): what a record holds and how its hash chain is checked.
- [Servers and CI runners](/docs/servers-and-ci-runners/): self-hosted runners and service accounts.
- [Exit codes](/docs/exit-codes/): every code Tego returns.
