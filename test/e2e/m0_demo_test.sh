#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks on m0-demo.sh. The demo itself needs a built binary and Landlock, so the checks read the script and run it
# with a stub tego. It must not write to the developer's own ~/.tego, so it builds with tegotesthooks and points
# the chain anchor into its work directory, the way lib.sh's kt_ensure_tego and kt_config do; and a relative --work
# still gives tego an absolute $TEGO_CONFIG.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { echo "FAIL $*" >&2; exit 1; }
grep -Eq 'go build .*-tags[= ]tegotesthooks' "$here/m0-demo.sh" || fail "m0-demo.sh builds without tegotesthooks"
# shellcheck disable=SC2016 # Match literal variables in the script being checked.
grep -Eq '^export TEGO_TEST_CHAIN_ANCHOR="\$work/' "$here/m0-demo.sh" || fail "m0-demo.sh does not point the chain anchor into its work directory"
# shellcheck disable=SC2016 # Match literal variables in the script being checked.
grep -q 'rm -f "\$out/summary.md"' "$here/m0-demo.sh" || fail "m0-demo.sh does not clear a stale summary.md before run 1"
bash -n "$here/m0-demo.sh" || fail "m0-demo.sh does not parse"

# A relative --work still hands tego an absolute $TEGO_CONFIG: the machine config refuses a relative layer
# (identity-config R14), so the demo ran nothing with `--work demo`. A stub tego records what it was
# given and fails the compile, which ends the demo before any run.
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-m0-test.XXXXXX")" || fail "no scratch directory"
tmp="$(cd "$tmp" && pwd)"
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/tego" <<'EOF'
#!/usr/bin/env bash
# A stub that passes m0-demo's TEGO_TEST_CHAIN_ANCHOR check.
printf '%s\n' "$TEGO_CONFIG" "${XDG_RUNTIME_DIR:-unset}" "$(stat -c %a "${XDG_RUNTIME_DIR:-/nonexistent}" 2>/dev/null)" >"$STUB_SEEN"
exit 1
EOF
chmod 755 "$tmp/tego"
(cd "$tmp" && umask 002 && XDG_RUNTIME_DIR=/run/user/12345 STUB_SEEN="$tmp/seen" TEGO_TEST_OUT="$tmp/out" "$here/m0-demo.sh" --work demo --tego "$tmp/tego" >/dev/null 2>&1)
[ "$(sed -n 1p "$tmp/seen" 2>/dev/null)" = "$tmp/demo/config.yaml" ] ||
	fail "m0-demo.sh --work demo gave tego the config layer $(sed -n 1p "$tmp/seen" 2>/dev/null), want $tmp/demo/config.yaml"
# The demo's runs keep their runtime directory in the work directory, 0700 whatever the umask, never the invoking
# user's /run/user/<uid>/tego, which a launch makes and sweeps (identity-config.md R27 clause b4).
seen="$(sed -n 2,3p "$tmp/seen" 2>/dev/null | paste -sd' ')"
[ "$seen" = "$tmp/demo/run 700" ] || fail "m0-demo.sh gave tego XDG_RUNTIME_DIR and mode \"$seen\", want \"$tmp/demo/run 700\""
echo "ok m0_demo_test.sh"
