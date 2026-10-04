#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Report orchestration only: no Go download, compilation or workload execution.
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cat >"$work/go" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "$*" = 'env GOHOSTOS' ]; then echo linux; exit 0; fi
if [ "$*" = 'env GOHOSTARCH' ]; then echo amd64; exit 0; fi
if [ "$*" = 'install golang.org/x/tools/cmd/deadcode@v0.50.0' ]; then
    [ "$GOOS" = linux ] && [ "$GOARCH" = amd64 ] && [ "$CGO_ENABLED" = 0 ]
    if [ "${DEADCODE_TEST_INSTALL_FAIL:-}" = 1 ]; then echo 'install failed' >&2; exit 31; fi
    mkdir -p "$GOBIN"
    cp "$DEADCODE_TEST_ANALYZER" "$GOBIN/deadcode"
    exit 0
fi
if [ "$*" = 'run ./tools/deadcodereport -dir '"$DEADCODE_TEST_OUT"' -allow tools/deadcode-allow.txt -gate' ]; then
    printf '%s %s %s\n' "${GOOS:-unset}" "${GOARCH:-unset}" "${CGO_ENABLED:-unset}" >"$DEADCODE_TEST_OUT/formatter.environment"
    if [ "${GOOS:-}" != linux ] || [ "${GOARCH:-}" != amd64 ] || [ "${CGO_ENABLED:-}" != 0 ]; then
        echo 'formatter must execute on the host, independent of analyzed target' >&2
        exit 37
    fi
    printf 'Report fixture\n' >"$DEADCODE_TEST_OUT/report.md"
    if [ "${DEADCODE_TEST_RATCHET_FAIL:-}" = 1 ]; then echo 'deadcode ratchet: unclassified fixture' >&2; exit 1; fi
    exit 0
fi
echo "unexpected go argv: $*" >&2
exit 99
STUB
cat >"$work/analyzer" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != -json ] || [ "${!#}" != ./cmd/tego ] ||
   [ "$GOOS" != linux ] || [ "$CGO_ENABLED" != 0 ]; then
    echo "unexpected tool argv/environment: $*" >&2
    exit 99
fi
mode=plain
if [ "$#" -eq 4 ] && [ "$2" = -tags ]; then
    case $3 in
    integration | tegobpf) mode=$3 ;;
    integration,tegobpf) mode=integration-tegobpf ;;
    *) exit 99 ;;
    esac
elif [ "$#" -ne 2 ]; then exit 99
fi
printf '%s %s\n' "$GOARCH" "$mode" >>"$DEADCODE_TEST_CALLS"
if [ "${DEADCODE_TEST_FAIL:-}" = "$GOARCH-$mode" ]; then
    echo 'fixture type-check failed' >&2
    exit 23
fi
# Many unreachable functions still succeed: findings are not a gate.
printf '[{"Path":"fixture","Funcs":[{"Name":"Unreachable"}]}]\n'
STUB
chmod +x "$work/go" "$work/analyzer"
export TEGO_DEADCODE_GO="$work/go" DEADCODE_TEST_CALLS="$work/calls" DEADCODE_TEST_ANALYZER="$work/analyzer"
for test in cross-environment success failure install-failure ratchet-failure; do
    export DEADCODE_TEST_OUT="$work/$test"
    : >"$DEADCODE_TEST_CALLS"
    unset DEADCODE_TEST_FAIL DEADCODE_TEST_INSTALL_FAIL DEADCODE_TEST_RATCHET_FAIL
    if [ "$test" = failure ]; then export DEADCODE_TEST_FAIL=arm64-integration-tegobpf; fi
    if [ "$test" = ratchet-failure ]; then export DEADCODE_TEST_RATCHET_FAIL=1; fi
    if [ "$test" = install-failure ]; then export DEADCODE_TEST_INSTALL_FAIL=1; fi
    status=0
    if [ "$test" = cross-environment ]; then
        GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 "$repo/scripts/deadcode-report.sh" -o "$DEADCODE_TEST_OUT" >"$work/$test.log" 2>&1 || status=$?
    else
        "$repo/scripts/deadcode-report.sh" -o "$DEADCODE_TEST_OUT" >"$work/$test.log" 2>&1 || status=$?
    fi
    if [ "$test" = success ] || [ "$test" = cross-environment ]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
    printf 'linux amd64 0\n' >"$work/formatter-want"
    cmp "$work/formatter-want" "$DEADCODE_TEST_OUT/formatter.environment"
    if [ "$test" = install-failure ]; then : >"$work/want"
    else
        for arch in amd64 arm64; do
            for mode in plain integration tegobpf integration-tegobpf; do printf '%s %s\n' "$arch" "$mode"; done
        done >"$work/want"
    fi
    cmp "$work/want" "$DEADCODE_TEST_CALLS"
    [ -s "$DEADCODE_TEST_OUT/report.md" ]
    for profile in linux-{amd64,arm64}-{plain,integration,tegobpf,integration-tegobpf}; do
        [ -f "$DEADCODE_TEST_OUT/$profile.json" ]
        [ -f "$DEADCODE_TEST_OUT/$profile.stderr" ]
        [ -f "$DEADCODE_TEST_OUT/$profile.status" ]
        if [ "$test" = install-failure ]; then
            [ "$(cat "$DEADCODE_TEST_OUT/$profile.status")" = 31 ]
            [ -s "$DEADCODE_TEST_OUT/$profile.stderr" ]
        fi
    done
    if [ "$test" = failure ]; then
        [ "$(cat "$DEADCODE_TEST_OUT/linux-arm64-integration-tegobpf.status")" = 23 ]
        [ -s "$DEADCODE_TEST_OUT/linux-arm64-integration-tegobpf.stderr" ]
        [ ! -s "$DEADCODE_TEST_OUT/linux-arm64-integration-tegobpf.json" ]
    fi
    # Existing evidence must survive a refused rerun unchanged.
    cp "$DEADCODE_TEST_OUT/report.md" "$work/report-before"
    status=0
    "$repo/scripts/deadcode-report.sh" -o "$DEADCODE_TEST_OUT" >"$work/existing.log" 2>&1 || status=$?
    [ "$status" -eq 2 ]
    cmp "$work/report-before" "$DEADCODE_TEST_OUT/report.md"
done
echo 'deadcode report orchestration: PASS'
