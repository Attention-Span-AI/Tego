#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi
set -euo pipefail
trap 'exit 125' ERR
umask 077
here="$(cd "$(/usr/bin/dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
# This check is inside the reusable signing boundary. A caller condition alone
# cannot provide consent to permanent publication.
[ "${IN_SIGN_CONSENT:-}" = 'I consent to publish repository and workflow names in the permanent public Sigstore log' ] || { echo 'explicit permanent public-log signing consent is required' >&2; exit 125; }
/usr/bin/python3 -I "$here/signing.py" decision >"${RUNNER_TEMP:?}/tego-sign-decision.json"
/usr/bin/jq -e '.sign == true' "$RUNNER_TEMP/tego-sign-decision.json" >/dev/null || die 'this run is ineligible for signing'
export SIGNING_JOB=true DEFER_GATE=true DO_COMMENT=false
"$here/verify.sh"
export DIR="$RUNNER_TEMP/tego-verifier"
export HOME="$DIR/home"
export TEGO="$DIR/bin/tego"
export CANONICAL_MATRIX_KEY
CANONICAL_MATRIX_KEY="$(/usr/bin/python3 -I "$here/identity.py" | /usr/bin/jq -er .matrix_key)"
# shellcheck source-path=SCRIPTDIR source=trust.sh
. "$here/trust.sh"
trust_load
# Freeze the pre-sign inventory. Rehash after identity/manifest assembly and each
# signature, before publishing. No evidence file is executed.
/usr/bin/python3 -I "$here/signing.py" snapshot "$DIR/evidence" >"$DIR/state/before-sign"
/usr/bin/python3 -I "$here/signing.py" sign-inputs "$DIR/evidence"
/usr/bin/python3 -I "$here/signing.py" unchanged "$DIR/evidence" "$DIR/state/before-sign"
/usr/bin/python3 -I "$here/signing.py" snapshot "$DIR/evidence" >"$DIR/state/before-sign"
token="$(/usr/bin/cat "$DIR/state/identity-token")"
trap '/usr/bin/rm -f "$DIR/state/identity-token"; unset token' EXIT
for blob in receipt manifest; do
  cosign_clean --identity-token "$token" sign-blob --yes --signing-config "$SIGNING_CONFIG" --trusted-root "$TRUSTED_ROOT" --bundle "$DIR/$blob.sigstore.json" "$DIR/evidence/$blob.json"
done
/usr/bin/rm -f "$DIR/state/identity-token"
unset token
# manifest and signer-check were newly assembled and are outside the incoming
# transport allowlist. Check the original evidence still has its frozen bytes.
/usr/bin/python3 -I "$here/signing.py" unchanged "$DIR/evidence" "$DIR/state/before-sign"
/usr/bin/mkdir -m 700 "$DIR/signed"
/usr/bin/cp -R "$DIR/evidence/." "$DIR/signed/"
/usr/bin/install -m 0600 "$DIR/receipt.sigstore.json" "$DIR/manifest.sigstore.json" "$DIR/signed/"
out signed-dir "$DIR/signed"
receipt_hash="$(/usr/bin/sha256sum "$DIR/signed/receipt.json" | /usr/bin/cut -d' ' -f1)"
{
  printf 'Signed by Tego\047s pinned signer workflow in your repository\047s run. Anyone who can change which workflow runs could have supplied different evidence; root on the agent runner could have fabricated it.\n\n'
  # shellcheck disable=SC2016
  printf 'Exact files: receipt.json, manifest.json, receipt.sigstore.json, manifest.sigstore.json. Receipt SHA-256: `%s`. Artifact retention: seven days. Retain the complete artifact, independent expectations and trusted roots before expiry.\n' "$receipt_hash"
  printf '\nreceipt.md retains the unsigned reporting phase. Check the detached bundles for the final cryptographic result; this Markdown is a display.\n'
} >"$DIR/signed/SIGNATURE.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  /usr/bin/cat "$DIR/signed/SIGNATURE.md" >>"$GITHUB_STEP_SUMMARY"
fi
