#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


# Authenticate checksums before admitting either architecture's named executable.
set -euo pipefail
here="$(cd "$(/usr/bin/dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
# shellcheck source-path=SCRIPTDIR source=trust.sh
. "$here/trust.sh"
: "${DIR:?}" "${IN_VERSION:?}" "${IN_SHA256:?}" "${IN_RELEASE_COMMIT:?}" "${TEGO_CODE_SHA:?}"
[[ "$IN_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || exit 125
[[ "$IN_SHA256" =~ ^[0-9a-f]{64}$ && "$IN_RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || exit 125
[ "$TEGO_CODE_SHA" = "$IN_RELEASE_COMMIT" ] || { printf 'implementation must be the authenticated release commit\n' >&2; exit 125; }
case "$(/usr/bin/uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) exit 125 ;; esac
asset="tego_${IN_VERSION#v}_linux_$arch"
sums="tego_${IN_VERSION#v}_checksums.txt"
setup_trust || exit 125
for file in "$sums" "$sums.sigstore.json" "$asset"; do
  /usr/bin/curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 120 \
    -o "$DIR/download/$file" "https://github.com/Attention-Span-AI/Tego/releases/download/$IN_VERSION/$file" || exit 125
done
cosign_clean verify-blob "$DIR/download/$sums" --bundle "$DIR/download/$sums.sigstore.json" \
  --trusted-root "$TRUSTED_ROOT" \
  --certificate-identity "https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/$IN_VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository Attention-Span-AI/Tego \
  --certificate-github-workflow-sha "$IN_RELEASE_COMMIT" \
  --certificate-github-workflow-ref "refs/tags/$IN_VERSION" \
  --certificate-github-workflow-trigger push || exit 125
/usr/bin/python3 -I "$here/release-checksums.py" "$DIR/download/$sums" "$asset" "$DIR/download/$asset" "$IN_SHA256" || exit 125
/usr/bin/install -m 0755 "$DIR/download/$asset" "$DIR/bin/tego"
/usr/bin/install -m 0600 "$DIR/download/$sums" "$DIR/state/release-checksums.txt"
/usr/bin/install -m 0600 "$DIR/download/$sums.sigstore.json" "$DIR/state/release-checksums.sigstore.json"
printf '%s\n' "$IN_SHA256" >"$DIR/state/binary-sha256"
printf '%s\n' "$asset" >"$DIR/state/binary-asset"
/usr/bin/sha256sum "$DIR/state/release-checksums.txt" | /usr/bin/cut -d' ' -f1 >"$DIR/state/checksums-sha256"
out tego "$DIR/bin/tego"
out version "$IN_VERSION"
