#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LAB ONLY. Runs after explicit owner setup; no agent or caller command is run.
set -euo pipefail
: "${COSIGN_SHA256:?configure the independently checked v3.1.3 amd64 binary hash}"
[[ "$COSIGN_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 125
[ "${GITHUB_SERVER_URL:?}" = https://github.com ] || exit 125
cosign_bin="$(command -v cosign)"
[ "$(sha256sum "$cosign_bin" | cut -d' ' -f1)" = "$COSIGN_SHA256" ] || exit 125
mkdir -m 700 c0-output
gh api "repos/$GITHUB_REPOSITORY" >c0-output/repository.json
jq -e '.visibility == "public"' c0-output/repository.json >/dev/null || exit 125
case "$GITHUB_EVENT_NAME" in
  push | workflow_dispatch) ;;
  pull_request)
    pr="$(jq -r .number "$GITHUB_EVENT_PATH")"
    [[ "$pr" =~ ^[1-9][0-9]*$ ]] || exit 125
    gh api "repos/$GITHUB_REPOSITORY/pulls/$pr" >c0-output/pull.json
    jq -e '.head.repo.id == .base.repo.id' c0-output/pull.json >/dev/null || exit 125
    ;;
  *) exit 125 ;;
esac
gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" >c0-output/attempt.json
gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs" >c0-output/jobs.json
jq -n '{repository:env.GITHUB_REPOSITORY,source_sha:env.GITHUB_SHA,source_ref:env.GITHUB_REF,
  caller_ref:env.GITHUB_WORKFLOW_REF,caller_sha:env.CALLER_SHA,expected_signer:env.EXPECTED_WORKFLOW,
  run:env.GITHUB_RUN_ID,attempt:env.GITHUB_RUN_ATTEMPT,event:env.GITHUB_EVENT_NAME,
  image:env.ImageOS,image_version:env.ImageVersion,arch:env.RUNNER_ARCH,leg:env.C0_LEG}' >c0-output/expected.json
printf 'Tego C0 fixed blob version 1\n' >c0-output/blob.txt
"$cosign_bin" sign-blob --yes --bundle c0-output/blob.sigstore.json c0-output/blob.txt
verify_rc=0
"$cosign_bin" verify-blob --bundle c0-output/blob.sigstore.json \
  --certificate-identity "https://github.com/$EXPECTED_WORKFLOW" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com c0-output/blob.txt >c0-output/verify.txt 2>&1 || verify_rc=$?
printf '%s\n' "$verify_rc" >c0-output/verify-exit.txt
python3 -I - <<'PY'
import base64
import json
from pathlib import Path
m = json.loads(Path('c0-output/blob.sigstore.json').read_text())['verificationMaterial']
if 'certificate' in m:
    cert = m['certificate']['rawBytes']
else:
    cert = m['x509CertificateChain']['certificates'][0]['rawBytes']
Path('c0-output/leaf.der').write_bytes(base64.b64decode(cert, validate=True))
PY
openssl x509 -inform DER -in c0-output/leaf.der -noout -text >c0-output/certificate.txt
openssl asn1parse -inform DER -in c0-output/leaf.der -i -dump >c0-output/certificate-asn1.txt
sha256sum c0-output/blob.txt c0-output/blob.sigstore.json c0-output/leaf.der >c0-output/digests.txt

exit "$verify_rc"
