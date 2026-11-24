# CI receipt implementation

The reusable workflow checks out pinned Tego implementation code separately from the caller checkout.
The agent job has no signing permission. It requires the selected tier, checks the merged contract,
scrubs the launcher's environment, stops workflow commands around agent output, then collects and compares copies.
It uploads an unsigned artifact and exports the artifact ID, archive digest, sorted inventory digest and status.

Before launch it snapshots its collector and hashes both original and copied code. After return it verifies
both before using the copied collector. System `sha256sum` checks bytes first; the checked collector then
requires exact path, type and permission inventories, refusing added files. Shells start through `/bin/bash -p`, use `set -euo pipefail`, absolute
system tools, fixed `/usr/bin:/bin` and a private empty HOME. Exported functions and shell startup files are
not loaded. The original PATH is retained for grant checks, and original HOME goes only to the agent launcher.
Declared writes overlapping original PATH entries, collector tools, tool cache, action code, `.github/`, HOME startup
files, both environment-HOME and resolved passwd-home state, repository Git/common directories or evidence
are refused before launch, with the grant and protected path in the error. Git protection includes environment/passwd
HOME `.gitconfig`, default/explicit XDG configuration, system/override/worktree files and pre-launch include
paths, including empty or absent targets. It defends later consumers; no checkout exploit was measured.
`GITHUB_ENV` requests fixed PATH and private
HOME for later steps, but the runner may prepend retained `GITHUB_PATH` directories. The collector enforces
its own fixed PATH and absolute tools. Other actions' post steps rely on the original PATH/tool/configuration
grant refusals; hosted later-action PATH/HOME behavior remains the owed ADR 0143 T11 measurement.
Later caller steps consume the workspace left by the agent. Keep the agent's job to the agent.
Compile's `path-shadow` diagnostic is an error. Runner `_diag` is read-denied to hide command-resume markers.
Before producing a receipt, collection checks runtime-added filesystem writes against the saved pre-launch
refusal list. Overlaps, unknown filesystem grant forms or unavailable disclosure fail collection with 125.
This happens after launch and does not undo earlier effects.

The second job uses a fresh ubuntu-24.04 runner and checks out only pinned Tego code. It downloads by ID,
checks the authenticated artifact's run ID, refuses oversized archives, links, traversal, duplicate and unexpected
names, hashes every regular file and compares the inventory against the job output. It independently installs
checksum-pinned Tego and reruns receipt --check. Only an ended match with every required check, including facts,
passing is accepted. Binding 1 requires seven baseline checks; binding 2 also requires `binding`.
Missing, non-integer or unknown binding versions and duplicate object keys at any depth are refused.
Every additional check must pass too. Rendered text is rebuilt after comparison; nothing in the artifact is executed. Gate values
come from checked files and the PR number from the fresh job's event. In separately authorized comment
integrations, a failed check attempts to replace the matching Bot comment with a no-checked-receipt message
naming the event commit. The reusable workflows disable comments and request no comment write permission.
Successful displays name the event commit too.
Artifact name and producing attempt are explicit outputs, so rerunning only the failed fresh job selects the
original artifact rather than an artifact for its own attempt.

The receipt workflow contains only agent and report jobs, without OIDC permission. It defaults to unsigned
reporting and accepts binding 1 and 2 comparisons. Collection copies successful launcher teardown status
when available; an unsigned diagnostic can lack it. Requested signing requires a complete binding-2
ended-only comparison with status before exporting `should-sign`. The compact handoff of artifact,
inventory and core-file digests is emitted first as unchecked transport hints, before pin and evidence checks.
After the comparison upload, the receipt outcome gate always runs, independently of signing selection
or a later signing call. Checked agent failures and `on-refusal:fail` remain failures. The optional
signer can still sign checked failure or refusal receipts. Disabled signing performs no eligibility API
requests. With API uncertainty, `auto` remains unsigned; eligible explicit `true` refuses.
Consent is exact and required for eligible signing.

A caller wanting a signature adds a second call to `ci-receipt-sign.yml`, passing the handoff and matching
policy inputs, with contents/actions read and id-token write. GitHub validates delegated permissions before
runtime conditions, so no signing job may live in the receipt workflow. The separate signer checks out only
pinned implementation code and independently repeats policy, transport, complete ended comparison, token
claims and release checks before signing exact receipt and manifest bytes with detached bundles.

Root on the agent runner can fabricate consistent evidence and outputs. The launching user and anyone who
changes the workflow remain trusted. No completeness claim follows from a match. Runner-owned 0700 directories
and 0600 files do not separate a same-uid no-root agent. Preventing post-run tool takeover requires the grant
refusals above, in addition to the collector environment. Root-tier live ledger files are handed to the runner
at close; a runner-owned parent also permits directory replacement. Hash chains, copied anchors and fresh
comparisons detect inconsistent edits, not a fully fabricated matching chain, anchor, receipt and outputs.
There is no immutable evidence seal. ADR 0143 records the files, owners and permissions at each tier.

The executable version, per-architecture SHA-256 and implementation commit are independent repository
configuration. Installation also authenticates the official release checksum bundle, exact source/workflow
identity and named binary membership; implementation and release source pins must match. Empty or malformed
pins fail closed. Publishing a compatible release and freezing reviewed pins is required before use.
Hosted permission, certificate and lifecycle acceptance remain open. The committed Go public-release test
parses certificate/bundle shape and the boundary fixtures stub successful cryptography; the real successful
pinned-cosign release check was a separate manual scratch measurement.
