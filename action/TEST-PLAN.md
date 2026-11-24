# CI receipt test plan

`WORK=/disk/scratch action/test/run-tests.sh` runs the original checks, review regressions, permissions and
injection cases, and boundary tests. No network, Tego executable, guest or service is needed. The fake CLI
answers from labelled
fixtures and models check outcomes; it does not perform a real receipt comparison.

The earlier review suite did not establish every trust boundary: independent review found missing tool/startup,
gate-source, stale-comment, export, interpolation, ended-only and rerun checks. The fix round requires each new
regression to fail against the unfixed code in a scratch copy; retain logs outside the public tree.
Boundary tests mutate archive bytes, digests, names, types and check results. In particular, `result:match`
with `ended:false` must fail on its own. Binding 2 without a binding check, unknown or non-integer
binding versions, and duplicate object keys at every depth must fail; valid product v1/v2 fixtures must pass. Step interpolation checks cover every action YAML, including examples
and C0, and shell and working-directory fields. Planted PATH tools, shell startup hooks, exported functions,
original/frozen action bytes, additions, types and permissions, and failed collector tools must refuse or remain unused. Grant checks cover
job PATH, tool cache, action tree, `.github/`, Git/common directories, passwd-home state and HOME startup files.
Git cases cover both HOME locations, default/explicit XDG configuration, system/override paths, worktree
configuration and includes. Collection cases check runtime-added filesystem writes, disjoint grants, aliases,
unknown forms, missing disclosure and missing pre-launch state before issuing a receipt. Fresh-job gate tests disagree with first-job
outputs; failure-comment tests replace a prior marker, and rerun tests retain the producing attempt's artifact.
Fixtures labelled Sample are displays, never acceptance evidence. shellcheck and actionlint must pass with
explicit shellcheck integration. Lint tools are test arguments or SHELLCHECK/ACTIONLINT environment variables.
Run the same suite in a git worktree, a normal clone and an exported tree with no `.git`.
Lint the C0 lab as its own project. Tests that need a caller HEAD create their own repository under WORK;
the source tree needs no git metadata. No layout-dependent skips are permitted.

The signing suites cover 216 eligibility combinations, exact consent, complete binding-2 checks,
per-file out-of-band handoff digests, manifest provenance/release substitutions and launcher-owned status.
Tool/root/config pins, clean cosign environment and exact release certificate constraints have separate
fixtures. The signer fixture runs the production signing loop against a fake token service and fake cosign,
checking both exact blob inputs, bundles, published inventory, each claim/consent mismatch and signing failures.
These fixture signatures do not establish cryptographic validity. Root ownership is modeled by stand-ins only; real lifecycle checks remain owed in a guest.
The Go verifier tests freeze bytes and compare required certificate fields and authenticated integration
times. `TestPublicReleaseBundleShape` parses the committed public release certificate and transparency
shape; boundary fixtures substitute a successful cosign operation. The committed suite does not perform
successful cryptographic verification of public release bytes with real cosign. The earlier pinned-cosign
verification was a separate manual scratch measurement requiring downloaded release bytes, the pinned
executable, trusted root and independent release/attempt expectations.
Neither these fixtures nor that manual release check accepts the new signer.

Permission regressions require the unsigned caller to use only `ci-receipt.yml` with contents/actions read,
including when signing is disabled by default. No job in that workflow may request OIDC. The signed caller
adds `ci-receipt-sign.yml` as a second job, passes the exact handoff and consent, and delegates OIDC only there.
Retain hosted copies of both callers: local YAML checks do not prove GitHub's permission delegation behavior.

Hosted acceptance is owed. Use a separately approved lab repository and the fixed-blob workflows in
[testdata/c0](testdata/c0/README.md) to dump actual certificate extensions first. C0 was required before
implementation and was not measured; its chronology cannot be repaired by local tests. A prepared lab
kit does not close that dependency. The fixed-blob workflow does not run the agent or establish receipt
signing acceptance. Consented receipt rows must assert both exact detached signatures and retained digests;
missing consent must show the actual consent refusal, not count a build/doctor failure as success.

Then measure two distinct runners; amd64 and arm64 tier availability; refused reads, writes and connects;
matrix comments, a forged human marker, check-failure comment replacement and fresh-job-only reruns;
cgroup recording gaps; fork and privileged triggers;
private visibility; agent failure 3; doctor refusal 211; evidence failure 125; output/file-command injection;
proc/fd/token/socket aliases; hosted PATH/tool/startup grant refusal, persistent `GITHUB_PATH` prepending and
post-step configuration consumption (ADR 0143 T11); descendants and
actual scope removal; long workloads; and cross-architecture facts. Kernel and ownership checks are owed in a guest.
Retain exact run/attempt URLs, runner image/version, expected metadata, artifact IDs/digests, stdout and exit codes.
A green job alone closes no acceptance row. Repeat on the published release candidate before acceptance.

Receipt-only outcome regressions execute the shipped gate with checked-output fixtures and the parsed
workflow condition, after a modeled successful comparison upload. No downstream signer is called.
They cover agent exit 3 and `on-refusal:fail` with signing selected, plus sign true/false/auto against
exit 0, exit 3, refusal fail and refusal warn. These local conclusions do not prove hosted execution.
