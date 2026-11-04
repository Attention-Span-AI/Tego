#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Caller-selected cleanup paths, reproduced only in a scratch tree with stand-ins.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d "${TMPDIR:-/tmp}/cleanup-guards.XXXXXX")
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/checkout/examples" "$t/bin" "$t/home" "$t/base" "$t/head"
cp -R "$here/../examples/live-modes-demo" "$t/checkout/examples/"
cp -R "$here/../examples/supply-chain-demo" "$t/checkout/examples/"
for tool in systemctl systemd-run claude curl zstd make; do
	printf '#!/bin/sh\nexit 66\n' >"$t/bin/$tool"
done
cat >"$t/bin/go" <<'EOF'
#!/bin/sh
case $1 in list) echo example.com/test ;; test|tool) exit 0 ;; *) exit 66 ;; esac
EOF
chmod +x "$t/bin/"*
fail=0
kept() {
	if [ "$rc" = 0 ] || [ ! -f "$1" ]; then
		echo "FAIL: $2 must refuse the path and keep its contents"; fail=1
	else echo "ok: $2 refuses the path and keeps its contents"; fi
}
mkdir -p "$t/agent-project/src"
echo precious >"$t/agent-project/src/keep"
rc=0
PROJECT="$t/agent-project" sh "$here/../examples/demo/agents/mini.sh" command >"$t/out" 2>&1 || rc=$?
kept "$t/agent-project/src/keep" 'stand-in agent with an unmarked project'
mkdir -p "$t/live-ledger" "$t/checkout/examples/live-modes-demo/vault-data"
echo precious >"$t/live-ledger/keep"
echo precious >"$t/checkout/examples/live-modes-demo/vault-data/keep"
rc=0
env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "DEMO_LEDGER=$t/live-ledger" \
	sh "$t/checkout/examples/live-modes-demo/demo.sh" reset >"$t/out" 2>&1 || rc=$?
kept "$t/live-ledger/keep" 'live-modes reset with an unmarked ledger'
kept "$t/checkout/examples/live-modes-demo/vault-data/keep" 'live-modes reset preflight'

mkdir -p "$t/supply/without/proj" "$t/supply/without/claude-home" "$t/supply/with/proj" "$t/supply/with/claude-home"
echo precious >"$t/supply/without/proj/keep"
rc=0
env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/go" DEMO_AGENT=claude \
	"DEMO_STAGE=$t/supply" "DEMO_LEDGER=$t/supply-ledger" "DEMO_CONFIG=$t/config" \
	sh "$t/checkout/examples/supply-chain-demo/demo.sh" setup >"$t/out" 2>&1 || rc=$?
kept "$t/supply/without/proj/keep" 'supply-chain setup with lookalike sides'

# Even a marked stage must not let reset rotate an unrelated ledger. Validate
# before deleting either side or stopping a user unit.
printf '%s\n' "$t/supply" >"$t/supply/.tego-supply-chain-stage"
mkdir -p "$t/supply/without/proj" "$t/unrelated-ledger"
echo precious >"$t/supply/without/proj/keep"
echo precious >"$t/unrelated-ledger/keep"
rc=0
env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/go" DEMO_AGENT=claude \
	"DEMO_STAGE=$t/supply" "DEMO_LEDGER=$t/unrelated-ledger" "DEMO_CONFIG=$t/config" \
	sh "$t/checkout/examples/supply-chain-demo/demo.sh" reset --stop >"$t/out" 2>&1 || rc=$?
kept "$t/unrelated-ledger/keep" 'supply-chain reset with an unmarked ledger'
kept "$t/supply/without/proj/keep" 'supply-chain ledger preflight'

# A timestamp collision must never claim an existing old-ledger directory and
# then prune it. The current ledger is owned; the destination is unrelated.
mkdir -p "$t/collision-ledger.old-fixed"
echo precious >"$t/collision-ledger.old-fixed/keep"
mkdir "$t/collision-ledger"
printf '%s\n' "$t/collision-ledger" >"$t/collision-ledger/.tego-supply-chain-ledger"
echo run >"$t/collision-ledger/run"
printf '#!/bin/sh\nprintf fixed\n' >"$t/bin/date"
chmod +x "$t/bin/date"
rc=0
env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/go" DEMO_AGENT=claude \
	"DEMO_STAGE=$t/supply" "DEMO_LEDGER=$t/collision-ledger" "DEMO_CONFIG=$t/config" DEMO_KEEP_LEDGERS=0 \
	sh "$t/checkout/examples/supply-chain-demo/demo.sh" reset --stop >"$t/out" 2>&1 || rc=$?
if [ ! -f "$t/collision-ledger.old-fixed/keep" ]; then
	echo 'FAIL: supply-chain rotation claimed and pruned an unrelated timestamp collision'; fail=1
else echo 'ok: supply-chain rotation preserves an unrelated timestamp collision'; fi
rm "$t/bin/date"

# A marked ledger with a newline-only child holds state and must rotate too.
entry=$'\n\n'
mkdir -p "$t/rotation-ledger/$entry"
printf '%s\n' "$t/rotation-ledger" >"$t/rotation-ledger/.tego-supply-chain-ledger"
echo precious >"$t/rotation-ledger/$entry/keep"
rc=0
env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/go" DEMO_AGENT=claude \
	"DEMO_STAGE=$t/supply" "DEMO_LEDGER=$t/rotation-ledger" "DEMO_CONFIG=$t/config" \
	sh "$t/checkout/examples/supply-chain-demo/demo.sh" reset --stop >"$t/out" 2>&1 || rc=$?
rotated=0
for old in "$t/rotation-ledger".old-*; do
	if [ -f "$old/$entry/keep" ]; then rotated=1; fi
done
if [ "$rc" != 0 ] || [ "$rotated" != 1 ] || [ -e "$t/rotation-ledger/$entry" ]; then
	echo 'FAIL: supply-chain rotation missed a newline-only child'; fail=1
else echo 'ok: supply-chain rotation retains newline-only children in the old ledger'; fi

# Prune is line-oriented. A ledger path containing a newline must not turn into
# a different, separately marked directory after ls output is split.
newline_ledger="$t/ledger"$'\n'"$t/other"
mkdir -p "$t/newline-stage/without/proj" "$t/newline-stage/without/claude-home" \
	"$t/newline-stage/with/proj" "$t/newline-stage/with/claude-home" "$newline_ledger" "$t/other.old-1"
printf '%s\n' "$t/newline-stage" >"$t/newline-stage/.tego-supply-chain-stage"
printf '%s\n' "$newline_ledger" >"$newline_ledger/.tego-supply-chain-ledger"
printf '%s\n' "$t/other.old-1" >"$t/other.old-1/.moved-by-demo-sh"
echo precious >"$t/other.old-1/keep"
mkdir -p "$newline_ledger.old-1"
rc=0
env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/go" DEMO_AGENT=claude \
	"DEMO_STAGE=$t/newline-stage" "DEMO_LEDGER=$newline_ledger" "DEMO_CONFIG=$t/config" DEMO_KEEP_LEDGERS=0 \
	sh "$t/checkout/examples/supply-chain-demo/demo.sh" reset --stop >"$t/out" 2>&1 || rc=$?
if [ ! -f "$t/other.old-1/keep" ]; then
	echo 'FAIL: supply-chain prune split a newline path into another marked directory'; fail=1
else echo 'ok: supply-chain prune preserves other directories with newline candidates'; fi

mkdir -p "$t/bpf-scratch/tree"
echo precious >"$t/bpf-scratch/tree/keep"
rc=0
PATH="$t/bin:$PATH" BPF_CHECK_TMP="$t/bpf-scratch" BPF_CHECK_REPO="$t/head" \
	"$here/check-bpf-objects.sh" >"$t/out" 2>&1 || rc=$?
kept "$t/bpf-scratch/tree/keep" 'check-bpf-objects with unmarked scratch'

mkdir "$t/toolchain"
echo precious >"$t/toolchain/keep"
echo unrelated >"$t/toolchain/stamp"
rc=0
PATH="$t/bin:$PATH" "$here/bpf-toolchain.sh" "$t/toolchain" >"$t/out" 2>&1 || rc=$?
kept "$t/toolchain/keep" 'bpf-toolchain with an unrelated stamp'

echo marker-target >"$t/marker-target"
for script in coverage bench-gate; do
	mkdir -p "$t/$script/base"
	echo precious >"$t/$script/base/keep"
	if [ "$script" = coverage ]; then marker=.tego-coverage; else marker=.bench-gate; fi
	ln -s "$t/marker-target" "$t/$script/$marker"
	rc=0
	if [ "$script" = coverage ]; then
		HOME="$t/home" GO="$t/bin/go" "$here/coverage.sh" -o "$t/$script" >"$t/out" 2>&1 || rc=$?
	else
		HOME="$t/home" GO="$t/bin/go" BENCHSTAT=false BENCH_GATE_PACKAGES='fake Bench' \
			"$here/bench-gate.sh" -n 1 --head "$t/head" -o "$t/$script" "$t/base" >"$t/out" 2>&1 || rc=$?
	fi
	kept "$t/$script/base/keep" "$script with a symlinked marker"
done

# Shared tool guard: protected paths and their physical aliases stay protected
# even if a marker is present. All candidates and HOME are scratch directories.
# shellcheck source=scripts/safe-output-dir.sh
. "$here/safe-output-dir.sh"
# Assert refusal before adoption, not merely a later failure in a stand-in tool.
unclaimed() {
	kept "$1/$entry/keep" "$3"
	if [ -e "$1/$2" ]; then echo "FAIL: $3 wrote an ownership marker"; fail=1; fi
}
for shape in newline newlines hidden listing-error; do
	entry=$'\n'
	case $shape in newlines) entry=$'\n\n' ;; hidden) entry=$'.\n' ;; esac
	if [ "$shape" = listing-error ]; then
		for tool in ls find; do printf '#!/bin/sh\nexit 65\n' >"$t/bin/$tool"; chmod +x "$t/bin/$tool"; done
	fi
	candidate="$t/helper-$shape"
	mkdir -p "$candidate/$entry"
	echo precious >"$candidate/$entry/keep"
	rc=0
	HOME="$t/home" PATH="$t/bin:$PATH" safe_output_dir "$candidate" .test-owner "$t/checkout" >"$t/out" 2>&1 || rc=$?
	unclaimed "$candidate" .test-owner "shared output guard ($shape)"
	for script in coverage bpf-toolchain timing-budgets; do
		candidate="$t/$script-$shape"
		mkdir -p "$candidate/$entry"
		echo precious >"$candidate/$entry/keep"
		rc=0
		case $script in
			coverage) marker=.tego-coverage; args=(-o "$candidate") ;;
			bpf-toolchain) marker=.tego-bpf-toolchain; args=("$candidate") ;;
			timing-budgets) marker=.timing-budgets; args=(-o "$candidate") ;;
		esac
		HOME="$t/home" PATH="$t/bin:$PATH" GO="$t/bin/go" TIMING_BUDGETS_TESTS='fake - TestFake' \
			"$here/$script.sh" "${args[@]}" >"$t/out" 2>&1 || rc=$?
		unclaimed "$candidate" "$marker" "$script ($shape)"
	done
	for kit in supply-chain-demo live-modes-demo; do
		candidate="$t/$kit-ledger-$shape"
		mkdir -p "$candidate/$entry"
		echo precious >"$candidate/$entry/keep"
		case $kit in supply-chain-demo) marker=.tego-supply-chain-ledger ;; live-modes-demo) marker=.tego-live-demo-ledger ;; esac
		rc=0
		env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/go" DEMO_AGENT=claude \
			"DEMO_STAGE=$t/stage-$shape" "DEMO_LEDGER=$candidate" "DEMO_CONFIG=$t/config-$shape" \
			sh "$t/checkout/examples/$kit/demo.sh" setup >"$t/out" 2>&1 || rc=$?
		unclaimed "$candidate" "$marker" "$kit ledger ($shape)"
	done
	# The vault uses the same live-modes claim function, with a different marker.
	candidate="$t/checkout/examples/live-modes-demo/vault-data"
	rm -rf "$candidate"
	mkdir -p "$candidate/$entry"
	echo precious >"$candidate/$entry/keep"
	rc=0
	env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/go" \
		"DEMO_LEDGER=$t/live-vault-ledger-$shape" "DEMO_CONFIG=$t/live-vault-config-$shape" \
		sh "$t/checkout/examples/live-modes-demo/demo.sh" setup >"$t/out" 2>&1 || rc=$?
	unclaimed "$candidate" .tego-live-demo-vault "live-modes vault ($shape)"
	if [ "$shape" = listing-error ]; then rm "$t/bin/ls" "$t/bin/find"; fi
done

for candidate in "$t/home" "$t/checkout"; do
	: >"$candidate/.test-owner"
	ln -s "$candidate" "$t/alias"
	for spelling in "$candidate" "$t/alias" "$candidate/../${candidate##*/}"; do
		rc=0
		HOME="$t/home" safe_output_dir "$spelling" .test-owner "$t/checkout" >"$t/out" 2>&1 || rc=$?
		if [ "$rc" != 2 ]; then echo "FAIL: tool output guard accepted $spelling"; fail=1
		else echo "ok: tool output guard refuses $spelling"; fi
	done
	rm "$t/alias"
done

# Positive live-modes lifecycle: a fresh setup marks both generated directories,
# and reset accepts those exact directories (the engine remains a stand-in).
rm -rf "$t/checkout/examples/live-modes-demo/vault-data"
printf '#!/bin/sh\nexit 0\n' >"$t/bin/tego"
chmod +x "$t/bin/tego"
for cmd in setup reset; do
	rc=0
	env -i "HOME=$t/home" "PATH=$t/bin:$PATH" "TEGO=$t/bin/tego" \
		"DEMO_CONFIG=$t/live-config" "DEMO_LEDGER=$t/owned-ledger" \
		sh "$t/checkout/examples/live-modes-demo/demo.sh" "$cmd" >"$t/out" 2>&1 || rc=$?
	if [ "$rc" != 0 ]; then echo "FAIL: live-modes $cmd on its own generated data"; cat "$t/out"; fail=1
	else echo "ok: live-modes $cmd accepts its own generated data"; fi
done
exit "$fail"
