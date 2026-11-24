#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# Sourced only by the cleaned collector. No inherited configuration is authority.
TRUST_MIRROR=https://tuf-repo-cdn.sigstore.dev
TRUST_ROOT_SHA256=27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f
TRUSTED_ROOT_SHA256=6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66
SIGNING_CONFIG_SHA256=9711a6d5375706957a4859af31c5866a4474f81f0544f9f4b76c9c4f4c8a539c

trust_hash() {
  local got
  [ -f "$1" ] && [ ! -L "$1" ] || return 125
  got="$(/usr/bin/sha256sum "$1" | /usr/bin/cut -d' ' -f1)"
  [ "$got" = "$2" ] || { printf 'unreviewed Sigstore tool or trust bytes: %s\n' "$1" >&2; return 125; }
}

trust_load() {
  : "${DIR:?}"
  export COSIGN="$DIR/bin/cosign" TRUSTED_ROOT="$DIR/sigstore/trusted_root.json"
  export SIGNING_CONFIG="$DIR/sigstore/signing_config.v0.2.json"
  case "$(/usr/bin/uname -m)" in
    x86_64) COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    aarch64) COSIGN_SHA256=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    *) printf 'unsupported cosign architecture\n' >&2; return 125 ;;
  esac
  export COSIGN_SHA256
}

trust_assert() {
  trust_hash "$COSIGN" "$COSIGN_SHA256" || return 125
  trust_hash "$DIR/sigstore/root.json" "$TRUST_ROOT_SHA256" || return 125
  trust_hash "$TRUSTED_ROOT" "$TRUSTED_ROOT_SHA256" || return 125
  trust_hash "$SIGNING_CONFIG" "$SIGNING_CONFIG_SHA256" || return 125
  trust_hash "$DIR/sigstore/tuf/tuf-repo-cdn.sigstore.dev/root.json" "$TRUST_ROOT_SHA256" || return 125
  trust_hash "$DIR/sigstore/tuf/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json" "$TRUSTED_ROOT_SHA256" || return 125
  trust_hash "$DIR/sigstore/tuf/tuf-repo-cdn.sigstore.dev/targets/signing_config.v0.2.json" "$SIGNING_CONFIG_SHA256" || return 125
  trust_hash "$DIR/sigstore/tuf/remote.json" 26fde894c9d27975a70cb0fa4171d2380dd2962409e61385f75a0489c327fca6 || return 125
}

# The optional token is supplied explicitly by the consent-checking caller. Never
# copy inherited SIGSTORE_ID_TOKEN, OIDC request variables, proxies or XDG/HOME.
cosign_clean() {
  local token='' rc=0
  if [ "${1:-}" = --identity-token ]; then token="${2:?}"; shift 2; fi
  trust_assert || return 125
  local helper
  helper="$(/usr/bin/dirname "${BASH_SOURCE[0]}")/cosign-env.py"
  if [ -n "$token" ]; then
    SIGSTORE_ID_TOKEN="$token" /usr/bin/python3 -I "$helper" --identity-token "$COSIGN" "$@" || rc=$?
  else
    /usr/bin/python3 -I "$helper" "$COSIGN" "$@" || rc=$?
  fi
  trust_assert || return 125
  return "$rc"
}

setup_trust() {
  local here arch
  here="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/../trust" && pwd)"
  trust_load || return 125
  case "$(/usr/bin/uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) return 125 ;; esac
  # mkdir without -p refuses reuse, including a pre-existing link or stale state.
  /usr/bin/mkdir -m 700 "$DIR/sigstore" || return 125
  /usr/bin/mkdir -m 700 "$DIR/sigstore/home" "$DIR/sigstore/tuf" || return 125
  trust_hash "$here/root.json" "$TRUST_ROOT_SHA256" || return 125
  trust_hash "$here/trusted_root.json" "$TRUSTED_ROOT_SHA256" || return 125
  trust_hash "$here/signing_config.v0.2.json" "$SIGNING_CONFIG_SHA256" || return 125
  /usr/bin/install -m 600 "$here/root.json" "$here/trusted_root.json" "$here/signing_config.v0.2.json" "$DIR/sigstore/"
  /usr/bin/mkdir -p "$DIR/download" "$DIR/bin" "$DIR/state"
  /usr/bin/curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 120 \
    -o "$DIR/download/cosign" "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$arch" || return 125
  trust_hash "$DIR/download/cosign" "$COSIGN_SHA256" || return 125
  /usr/bin/install -m 755 "$DIR/download/cosign" "$COSIGN"
  /usr/bin/python3 -I "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/cosign-env.py" "$COSIGN" initialize --root "$DIR/sigstore/root.json" --root-checksum "$TRUST_ROOT_SHA256" \
    --mirror "$TRUST_MIRROR" || return 125
  trust_assert || return 125
  printf '%s\n' "$COSIGN_SHA256" >"$DIR/state/cosign-sha256"
}
