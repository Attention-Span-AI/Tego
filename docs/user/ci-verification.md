# Check a retained CI signature

Keep the exact uploaded artifact before it expires. The receipt and manifest
have separate detached Sigstore bundles. The manifest signs the record digest,
anchor, contract, teardown status, fresh comparison, release identity and GitHub
run metadata. It does not sign `blobs/` or establish that a privileged runner
reported honest evidence.

Install the expected Tego release independently. Authenticate its release
checksums against the release workflow before using them. Obtain the exact
repository IDs, source commit/ref, caller workflow commit, reusable signer
workflow commit, run ID, attempt and attempt time window from trusted configuration
and GitHub's authenticated exact-attempt metadata. Save those values in the
strict `tego.ci-expect/1` shape specified by ADR 0143, outside the artifact.
An expectation copied from the artifact cannot establish its provenance.

Use the pinned cosign v3.1.3 executable and independently trusted Sigstore root.
The published Linux amd64 cosign SHA-256 is
`4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`.
Keep the executable and trust file outside the artifact directory. Full verification
requires both bundles and the same exact Tego release as the receipt:

```sh
tego receipt --verify-ci ./evidence --expect ./expected-ci.json \
  --checksums ./verified-release-checksums.txt \
  --trusted-root ./trusted_root.json --cosign /verified/bin/cosign \
  --cosign-sha256 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 \
  --json
```

Exit 0 requires a full ended match. Exit 1 means a mismatch or refused identity.
Exit 125 means verification could not finish. A missing bundle never passes.
The product verifies immutable copies of both bundles and parses their exact
certificates. Missing modern Fulcio fields, wrong attempt/invocation, self-hosted
signer claims, duplicate fields or conflicting legacy fields fail closed.
Its supported v0.3 bundle requires one transparency entry with an inclusion proof
and a signed entry timestamp authenticating `integratedTime`. Missing deployed
fields remain an acceptance blocker. Real GitHub compatibility is still owed.

To compare just a signed receipt with its retained record, use:

```sh
tego receipt --check ./evidence/receipt.json ./evidence/run \
  --bundle ./evidence/receipt.sigstore.json --expect ./expected-ci.json \
  --trusted-root ./trusted_root.json --cosign /verified/bin/cosign \
  --cosign-sha256 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 \
  --require-ended --status-file ./evidence/run-status.json --json
```

This checks the receipt signature, certified provenance and ordinary receipt/record
comparison. Use `--verify-ci` to also authenticate the manifest and its full file
inventory and release membership. Totals checking needs the same release/commit.
The signer and reader may use different architecture assets from that release.

A plain cosign check authenticates each blob and a workflow identity. Supply exact
independently expected values, never wildcard identities:

```sh
EXPECTED_SIGNER_URI='https://github.com/Attention-Span-AI/Tego/.github/workflows/ci-receipt-sign.yml@<exact-implementing-commit>'
EXPECTED_REPOSITORY='owner/repository'
EXPECTED_SOURCE_SHA='<exact-source-commit>'
EXPECTED_SOURCE_REF='refs/heads/main'
EXPECTED_TRIGGER='workflow_dispatch'
for blob in receipt manifest; do
  /verified/bin/cosign verify-blob "./evidence/$blob.json" \
    --bundle "./evidence/$blob.sigstore.json" --trusted-root ./trusted_root.json \
    --certificate-identity "$EXPECTED_SIGNER_URI" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository "$EXPECTED_REPOSITORY" \
    --certificate-github-workflow-sha "$EXPECTED_SOURCE_SHA" \
    --certificate-github-workflow-ref "$EXPECTED_SOURCE_REF" \
    --certificate-github-workflow-trigger "$EXPECTED_TRIGGER" || exit 1
done
```

Replace every placeholder with reviewed values. Plain cosign alone does not
compare the modern caller/config digest, immutable repository and owner IDs,
exact invocation/attempt, visibility, full manifest or retained record totals.
The product adds those checks. Both recipes retain the root and maintainer
residual: a privileged agent runner can fabricate matching evidence, and a
maintainer can choose another workflow. Signed bytes do not prove complete
observation or actions performed through allowed external services.
