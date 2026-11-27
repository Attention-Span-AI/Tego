# Tego CI receipt

The receipt workflow runs any AI agent under a Tego contract and compares its receipt on a fresh runner.
A second reusable workflow optionally signs exact receipt and manifest bytes. Only its job has OIDC authority;
unsigned callers delegate contents/actions read only.
Signing requires explicit consent to publishing organisation, repository and workflow names in the public,
permanent Sigstore log. No hosted acceptance row is closed by the offline tests.

See the [CI guide](../docs/site/ci.md) for pins, inputs, permissions, retention, restrictions and
limits, and for the commands that check a receipt.
This composite action collects an unsigned report, not evidence; it cannot supply the separate-job signing claim alone.

Trust a reviewed workflow on a protected branch. A receipt on a pull request is only as honest as the workflow file that made it. Root on the agent runner
can fabricate matching evidence. At landlock the agent and collector share a uid; private modes do not separate
them. Tiers, read recording, protected paths, process/token/socket canaries and later-action behavior still
need the guest and GitHub measurements listed in ADR 0143. Keep the agent's job to the agent; later work belongs
in a separate job with a fresh checkout and reviewed inputs.

`WORK=/your/disk/scratch action/test/run-tests.sh` runs the offline script fixtures with Python 3, PyYAML, jq,
bash, pinned shellcheck and actionlint. The Go verifier fixtures run separately. No sample is a real GitHub
acceptance run. The receipt JSON's no-signature note remains true: cryptographic checks use detached bundles.

The launcher passes base variables under the contract. Use no-prod to restrict destinations; tego/ci alone
does not. Landlock records are advisory against a hostile process. Root tracing can miss lines.
The no-root runner may require enable-linger setup. Named agent secrets remain deferred.
