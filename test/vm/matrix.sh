#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# matrix.sh — `make vm-matrix`: the kernel matrix of P0-DESIGN §10 in one command, without root and without
# virtme-ng. For each row it fetches the distro's own kernel (test/vm/fetch-kernel.py), boots it in
# a KVM guest the way a fresh install boots — the kernel's own lsm= list, no lockdown — with
# test/vm/kvm-run.sh --sudo --delegate-user, and runs test/vm/run-matrix-row.sh there: `tego doctor` as the user and as
# root, then kill tests 1, 2, 4, 5, 6 and 7 with their root halves. When the row's kernel does not have `bpf`
# in its active LSM list, kill test 6 prints the lsm= line doctor gave, and this script boots the row a
# second time with exactly that line to run half (c), as R16 (c) describes.
#
# Why here and not only in CI: the privileged halves need root and a kernel of the row's own version, and
# a KVM guest gives both on a box that has neither; the same command is what the scheduled workflow runs.
#
# What goes into the guest: the tego binary with the BPF objects when `go build -tags tegobpf` works
# (bpf/README.md), else the plain one (tier cgroup then reports "not built" and the root halves skip by
# name); test/e2e, test/workloads, examples and test/vm, and the price table kt_config names
# (internal/runtime/limits/testdata/prices.yaml); jq and the libraries it loads, which the kill tests
# use and the guest's base image does not carry; and the Python packages test/e2e/pydeps.sh caches (pip,
# the build workload's wheels, the Anthropic SDK, and the Claude Agent SDK with VM_KT7A=1), since the guest
# has no network. npm, node and go go in only with VM_KT4_TOOLS=1, about 450 MB more of the guest's RAM;
# without it, kill test 4's npm and go kinds are named skips in the guest. With VM_KT3=1, kill test 3's noop
# and cpu workloads go in prebuilt (test/e2e/overhead/run.sh --workload-bin, through TEGO_BENCH_BIN), since
# its harness would otherwise build them with a go the guest may lack; its npm workload is a named skip there
# unless VM_KT4_TOOLS=1 carries npm, and with it this host's primed npm cache for the harness, since the guest
# has no network to prime one.
#
# A doctor-only row (fetch-kernel.py's DOCTOR_ONLY: Ubuntu 22.04's 5.15, below Landlock ABI 2, where no tier is
# offered) boots once and runs run-matrix-row.sh --only doctor-refusal, which is test/vm/doctor-refusal.sh as the user
# and as root: doctor and `tego run` refuse the machine, with their fix. It runs no kill test and owes no second boot.
#
# Output, per row, under $VM_OUT/matrix/<row>/: boot*.console (the full console), results.tsv (one line
# per check: row, check, as, verdict, exit, detail; KT-HALF lines as check "<test>/<half>"), and fixtures/
# (the ledgers the kill tests saved). The last output is a table of every row and $VM_OUT/matrix/summary.json.
# Nothing is written into the tree unless --save-fixtures names a row, whose fixtures then replace
# test/fixtures/ledger/<kill test>/ (test/fixtures/README.md).
#
# VM_COVER=1 is scripts/coverage.sh --kill-tests's switch: the staged tego is built with `-cover
# -covermode=atomic -coverpkg=<module>/...`, the rest of its build unchanged, and run-matrix-row.sh then
# collects what every run of it wrote and prints it on the console as TEGO-COVFILE lines (its header says
# how), where coverage.sh reads it from boot*.console. A row run this way is a coverage run: the binary under
# test is not the one a release ships, so its verdicts are not the matrix's.
#
# Usage: test/vm/matrix.sh [--save-fixtures ROW] [row...]   (default: every row of fetch-kernel.py --list; the
#   row `host`, named only, boots this box's own kernel)
# Environment: GO (go), VM_OUT (bin/vm), VM_KT3=1 (also run kill test 3), VM_KT7A=1 (carry the Claude Agent
#   SDK, git and the libraries Claude Code loads, so kill test 7 (a) runs), VM_COVER=1 (a -cover tego whose
#   coverage data comes back on the console, for scripts/coverage.sh), VM_KT4_TOOLS=1 (carry this host's
#   node, npm and Go toolchain, so kill test 4's npm and go kinds run as root instead of skipping),
#   VM_ROW_TIMEOUT (seconds per boot, default 3600, and 3600 plus VM_TEST_TIMEOUT with VM_KT3=1),
#   VM_TEST_TIMEOUT (seconds per kill test, default 1500), VM_ONLY=kt4 or kt5 (one boot per row that runs kill test 4
#   or 5 as root and nothing else), VM_ONLY=smoke (one boot per row that runs ADR 0048's smoke-exec-rules cell as the
#   user and as root, and nothing else), VM_ONLY_LSM (the lsm= line of that one boot, default the kernel's own list: a
#   row whose kernel does not list bpf, such as host on Ubuntu, runs tier bpflsm only with bpf added here), VM_KT4_TIERS
#   (the tiers kill test 4 runs at, its KT4_TIERS: "bpflsm" for tier 3 on a row
#   whose kernel lists bpf; empty keeps its default), VM_KT5_TIERS, VM_KT5_RUNS and VM_KT5_PLANES (kill test 5's
#   KT5_TIERS, KT5_RUNS and KT5_PLANES, whose defaults are the tiers the boot allows, the ten runs of R7's median and
#   the plane the boot selects), VM_TESTHOOKS=1 (a tego built with -tags tegotesthooks, which VM_KT5_PLANES needs:
#   it is a test build, not the binary a release ships), and kvm-run.sh's TEGO_VM_* knobs; TEGO_VM_MEM and
#   TEGO_VM_SMP default to 1536M and 2 here.
# Exit 0 when no row failed a check; 1 when one did; 97 when no guest ran on any row (kvm-run.sh reported the box cannot boot one, or no kernel was fetched); 2 on a usage error,
# an unknown row included, before anything is created or removed.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/vm/fwd-run.sh
. "$here/fwd-run.sh"
repo="$(cd "$here/../.." && pwd)"
GO="${GO:-go}"
OUT="${VM_OUT:-$repo/bin/vm}"
case "$OUT" in /*) ;; *) OUT="$repo/$OUT" ;; esac
OUT="$OUT/matrix"
TEST_TIMEOUT="${VM_TEST_TIMEOUT:-1500}"
# One boot runs every check of its row, and kill test 3 alone may take its whole VM_TEST_TIMEOUT: at its default
# counts it makes hundreds of root runs, which took seconds each on the slower rows of the 2026-09-23 acceptance
# run. The row's default bound left it no room, so raising VM_TEST_TIMEOUT for a slow row still let the guest be
# killed at 3600 s with kill test 3 unfinished. With VM_KT3=1 the default grows by that bound; a VM_ROW_TIMEOUT
# given by hand is kept as given, and then has to cover it.
if [ -n "${VM_ROW_TIMEOUT:-}" ]; then
	ROW_TIMEOUT="$VM_ROW_TIMEOUT"
elif [ "${VM_KT3:-0}" = 1 ]; then
	ROW_TIMEOUT=$((3600 + TEST_TIMEOUT))
else
	ROW_TIMEOUT=3600
fi
export TEGO_VM_MEM="${TEGO_VM_MEM:-1536M}" TEGO_VM_SMP="${TEGO_VM_SMP:-2}"
LOCK="${TEGO_VM_CACHE:-$HOME/.cache/tego-vm}/guest.lock"
# flock creates the lock file, not its directory; only fetch-kernel.py made it, and the host row never runs that.
mkdir -p "$(dirname "$LOCK")"

usage() {
	echo "usage: test/vm/matrix.sh [--save-fixtures ROW] [ROW...]" >&2
	echo "rows: ${known[*]}" >&2
	exit 2
}
listing="$(python3 "$here/fetch-kernel.py" --list)"
mapfile -t known < <(awk '{print $1}' <<<"$listing")
[ "${#known[@]}" -gt 0 ] || { echo "matrix: fetch-kernel.py --list named no rows" >&2; exit 2; }
# The rows whose body is the refusal check alone (the fourth column of --list: fetch-kernel.py's DOCTOR_ONLY, where
# doctor offers no tier and no kill test has one to run at).
mapfile -t doctor_only < <(awk '$4 == "doctor-only" {print $1}' <<<"$listing")
is_doctor_only() { case " ${doctor_only[*]} " in *" $1 "*) return 0 ;; esac; return 1; }
# host is this box's own kernel, which kvm-run.sh fetches for itself: named only, never a default row.
known_default=("${known[@]}")
known+=(host)
case "${VM_ONLY:-}" in "" | kt4 | kt5 | smoke) ;; *) echo "matrix: VM_ONLY must be empty, kt4, kt5 or smoke, not $VM_ONLY" >&2; exit 2 ;; esac
save_row=""
if [ "${1:-}" = --save-fixtures ]; then
	[ $# -ge 2 ] || usage
	save_row="$2"
	shift 2
fi
rows=("$@")
[ "${#rows[@]}" -gt 0 ] || rows=("${known_default[@]}")
[ -z "$save_row" ] || case " ${rows[*]} " in *" $save_row "*) ;; *) rows+=("$save_row") ;; esac
# Every row names a directory this script empties ($OUT/<row>) and one it replaces fixtures from, so a row
# is checked against the list before anything is created or removed: "../../x" is not a row, it is a path.
for row in "${rows[@]}"; do
	case " ${known[*]} " in
	*" $row "*) ;;
	*) echo "matrix: unknown row \"$row\"" >&2; usage ;;
	esac
done

mkdir -p "$OUT"
stage="$OUT/stage"
rm -rf "$stage"
mkdir -p "$stage/src/test" "$stage/bin" "$stage/lib"
export CGO_ENABLED=0

# ---- what every row's guest gets -----------------------------------------------------------------

cd "$repo" || exit 1
cover=()
if [ "${VM_COVER:-0}" = 1 ]; then
	module="$("$GO" list -m)" || { echo "matrix: go list -m failed" >&2; exit 1; }
	cover=(-cover -covermode=atomic "-coverpkg=$module/...")
fi
# VM_TESTHOOKS=1 builds the staged tego with -tags tegotesthooks too, whose TEGO_TEST_PLANE pins tier cgroup's
# decision plane (lsm, fmod_ret, or fanotify, the listener): what kill test 5's KT5_PLANES (VM_KT5_PLANES) needs to
# measure each mode on one boot. Like a coverage run, it is not the binary a release ships.
tags=tegobpf
hooks=()
if [ "${VM_TESTHOOKS:-0}" = 1 ]; then
	tags=tegobpf,tegotesthooks
	hooks=(-tags tegotesthooks)
fi
bin_note="with the BPF objects"
if ls internal/bpf/*_bpfel.o >/dev/null 2>&1 && "$GO" build -tags "$tags" "${cover[@]}" -o "$stage/bin/tego" ./cmd/tego 2>"$OUT/build.log"; then
	:
else
	bin_note="without the BPF objects ($(tail -1 "$OUT/build.log" 2>/dev/null || echo 'none generated'); run make gen)"
	"$GO" build "${hooks[@]}" "${cover[@]}" -o "$stage/bin/tego" ./cmd/tego || { echo "matrix: go build ./cmd/tego failed" >&2; exit 1; }
fi
[ "${#cover[@]}" = 0 ] || bin_note="$bin_note, instrumented for coverage (VM_COVER=1)"
[ "${#hooks[@]}" = 0 ] || bin_note="$bin_note, with the test hooks (VM_TESTHOOKS=1)"
echo "matrix: tego built $bin_note"
for d in test/e2e test/workloads test/vm examples; do
	mkdir -p "$stage/src/$(dirname "$d")"
	cp -r "$d" "$stage/src/$d"
done
# kt_config (test/e2e/lib.sh) gives each kill test's machine config the limits package's test price table: the
# examples declare cost_usd, and a run of one with no price table loaded is refused [budget-unmetered].
prices=internal/runtime/limits/testdata/prices.yaml
mkdir -p "$stage/src/$(dirname "$prices")"
cp "$prices" "$stage/src/$prices" || { echo "matrix: could not stage $prices for the kill tests' machine config" >&2; exit 1; }
# The agent a root run drops to reads the workloads and examples as the user.
chmod -R go+rX "$stage/src"

jq_files=()
if command -v jq >/dev/null 2>&1; then
	cp "$(command -v jq)" "$stage/bin/jq"
	jq_files+=(--file "$stage/bin/jq:/usr/local/bin/jq")
	# The libraries go where they are on this host, which is where the guest's copy of this host's loader
	# looks without a cache entry (the multiarch directories are built into Debian's and Ubuntu's glibc);
	# /usr/local/lib is not searched in the guest, whose /etc/ld.so.conf.d is not copied.
	while read -r lib; do
		[ -n "$lib" ] || continue
		cp -L "$lib" "$stage/lib/$(basename "$lib")"
		# The physical directory: on a merged-/usr host /lib is a symlink, and a payload directory named
		# lib would replace that symlink in the guest.
		jq_files+=(--file "$stage/lib/$(basename "$lib"):$(cd "$(dirname "$lib")" && pwd -P)/$(basename "$lib")")
	done < <(ldd "$(command -v jq)" | awk '/=> \// && $1 ~ /^lib(jq|onig)/ {print $3}')
else
	echo "matrix: jq is not on this host's PATH; every kill test would fail on it in the guest" >&2
	exit 97
fi

# The cache's directories go in one by one: the Claude Agent SDK's (about 270 MB, with the Claude Code binary
# it bundles) only with VM_KT7A=1, since the guest's root is held in its RAM, which other guests share with it,
# and kill test 7 (a) copies the SDK once more into its work directory. Without it, kill test 7 (a) is a named
# skip in the guest.
py_files=()
sdk_arg=()
[ "${VM_KT7A:-0}" != 1 ] || sdk_arg=(--claude-sdk)
if py="$("$repo/test/e2e/pydeps.sh" "${sdk_arg[@]}" 2>"$OUT/pydeps.log")"; then
	for d in pip-bootstrap wheelhouse anthropic-site ${sdk_arg[@]:+claude-sdk-site}; do
		py_files+=(--file "$py/$d:/vm/pydeps/$d")
	done
	py_files+=(--env "KT_PYDEPS=/vm/pydeps")
else
	echo "matrix: no Python package cache ($(tail -1 "$OUT/pydeps.log")); kill test 4's pip kind and 7 will skip by name" >&2
fi

# Kill test 3's two Go workloads, built here as its harness would build them (CGO_ENABLED=0 is exported
# above): only with VM_KT3=1, the one check that runs them.
bench_files=()
if [ "${VM_KT3:-0}" = 1 ]; then
	mkdir -p "$stage/bench"
	for w in noop cpu; do
		"$GO" build -o "$stage/bench/$w" "./test/workloads/build/$w" ||
			{ echo "matrix: go build ./test/workloads/build/$w failed" >&2; exit 1; }
	done
	bench_files=(--file "$stage/bench:/vm/bench" --env "TEGO_BENCH_BIN=/vm/bench")
fi

# Kill test 4's npm and go kinds need node, npm and a Go toolchain, which the guest's base does not carry. Only
# VM_KT4_TOOLS=1 brings them in, since they cost about 450 MB of the guest's RAM, which holds its root. node goes
# at its physical path with the libraries it loads, placed as jq's are. npm goes as the directory that holds its
# package, because on Debian and Ubuntu its dependencies are that directory's other packages; symlinks in it are
# followed, since some lead into /usr/share/javascript, except npm's man pages, which lead to the host's whole
# man tree. GOROOT goes to /usr/local/go without the parts a build of another module never reads (the
# toolchain's own sources in src/cmd, and test, api, doc and misc). All three are on the guest's PATH through
# /usr/local/bin. A tool this host lacks stays out, with a note, and its kind is a named skip as before.
kt4_files=()
if [ "${VM_KT4_TOOLS:-0}" = 1 ]; then
	mkdir -p "$stage/kt4/bin" "$stage/kt4/lib"
	node="$(command -v node 2>/dev/null)" npm="$(command -v npm 2>/dev/null)"
	npm_cli="$(readlink -f "$npm" 2>/dev/null)"
	case "$npm_cli" in
	*/npm/bin/npm-cli.js)
		node="$(readlink -f "$node")"
		npm_root="$(dirname "$(dirname "$(dirname "$npm_cli")")")"
		mkdir -p "$stage/kt4/npm-root"
		tar -C "$npm_root" --exclude=./npm/man -chf - . | tar -C "$stage/kt4/npm-root" -xf - ||
			{ echo "matrix: could not stage $npm_root for kill test 4's npm kind" >&2; exit 1; }
		ln -s "$node" "$stage/kt4/bin/node"
		ln -s "$npm_cli" "$stage/kt4/bin/npm"
		kt4_files+=(--file "$node:$node" --file "$stage/kt4/npm-root:$npm_root"
			--file "$stage/kt4/bin/node:/usr/local/bin/node" --file "$stage/kt4/bin/npm:/usr/local/bin/npm")
		while read -r lib; do
			[ -n "$lib" ] || continue
			cp -L "$lib" "$stage/kt4/lib/$(basename "$lib")"
			kt4_files+=(--file "$stage/kt4/lib/$(basename "$lib"):$(cd "$(dirname "$lib")" && pwd -P)/$(basename "$lib")")
		done < <(ldd "$node" 2>/dev/null | awk '/=> \// {print $3}' | sort -u)
		# With VM_KT3=1 too, npm lets kill test 3's npm workload run, from the npm cache its harness keeps on
		# this host (test/e2e/overhead/run.sh --cache), which the guest, with no network, could not prime. It
		# goes where kill test 3 points the harness as root in the guest: /root/.cache/tego-overhead-bench/npm.
		bench_npm="${TEGO_BENCH_CACHE:-$HOME/.cache/tego-overhead-bench}/npm"
		if [ "${VM_KT3:-0}" = 1 ] && [ -n "$(ls -A "$bench_npm/cache" 2>/dev/null)" ]; then
			kt4_files+=(--file "$bench_npm:/root/.cache/tego-overhead-bench/npm")
		fi
		;;
	*) echo "matrix: VM_KT4_TOOLS=1, but this host has no node with an npm laid out as <dir>/npm/bin/npm-cli.js; kill test 4's npm kind will skip by name" >&2 ;;
	esac
	if goroot="$("$GO" env GOROOT 2>/dev/null)" && [ -x "$goroot/bin/go" ]; then
		mkdir -p "$stage/kt4/go"
		tar -C "$goroot" --exclude=./src/cmd --exclude=./test --exclude=./api --exclude=./doc --exclude=./misc -cf - . |
			tar -C "$stage/kt4/go" -xf - || { echo "matrix: could not stage $goroot for kill test 4's go kind" >&2; exit 1; }
		# Relative, so it resolves here as well, where kvm-run.sh checks that every --file exists: bin and go
		# sit side by side in the stage as /usr/local/bin and /usr/local/go do in the guest.
		ln -s ../go/bin/go "$stage/kt4/bin/go"
		kt4_files+=(--file "$stage/kt4/go:/usr/local/go" --file "$stage/kt4/bin/go:/usr/local/bin/go")
	else
		echo "matrix: VM_KT4_TOOLS=1, but $GO names no GOROOT with a bin/go; kill test 4's go kind will skip by name" >&2
	fi
fi

# The cache's compiled modules load glibc's compatibility libraries (librt, libpthread, libdl), which nothing in
# the guest's base needs: the Anthropic SDK's pydantic_core, which kill test 7 (b) imports, and with VM_KT7A=1 the
# Claude Agent SDK's modules and the Claude Code it bundles. So they go in whenever the cache does: carried only
# with VM_KT7A=1, they were missing from a row run without it, and half (b) failed there on `ImportError:
# librt.so.1`. Kill test 7 (a) also needs git, which both Claude Code examples name and the base does not carry.
# Each library goes at its physical path on this host, as jq's do.
kt7_files=()
if [ "${#py_files[@]}" -gt 0 ]; then
	if [ "${#sdk_arg[@]}" -gt 0 ] && command -v git >/dev/null 2>&1; then
		cp "$(command -v git)" "$stage/bin/git"
		kt7_files+=(--file "$stage/bin/git:/usr/local/bin/git")
	fi
	while read -r lib; do
		[ -n "$lib" ] || continue
		cp -L "$lib" "$stage/lib/$(basename "$lib")"
		kt7_files+=(--file "$stage/lib/$(basename "$lib"):$(cd "$(dirname "$lib")" && pwd -P)/$(basename "$lib")")
	done < <({ find "$py/anthropic-site" -name '*.so*' -type f -exec ldd {} \;
		if [ "${#sdk_arg[@]}" -gt 0 ]; then
			ldd "$py/claude-sdk-site/claude_agent_sdk/_bundled/claude"
			find "$py/claude-sdk-site" -name '*.so*' -type f -exec ldd {} \;
			! command -v git >/dev/null 2>&1 || ldd "$(command -v git)"
		fi; } 2>/dev/null | awk '/=> \// {print $3}' | sort -u)
fi

# ---- one boot ----------------------------------------------------------------------------------------

# boot runs run-matrix-row.sh in the row's guest and turns its console into results.tsv lines.
# $1 row, $2 boot label, $3 lsm (kernel = the kernel's own), then run-matrix-row.sh's extra arguments.
boot() {
	local row="$1" label="$2" lsm="$3" dir="$OUT/$1" code st
	shift 3
	echo "matrix: $row: $label (lsm=$lsm)"
	TEGO_VM_KERNEL="$(if [ "$row" = host ]; then uname -r; else python3 "$here/fetch-kernel.py" --name "$row"; fi)" \
		TEGO_VM_LSM="$lsm" TEGO_VM_LOCKDOWN=none \
		fwd_run -L flock -o "$LOCK" "$here/kvm-run.sh" --sudo --delegate-user --timeout "$ROW_TIMEOUT" --log "$dir/$label.console" \
		--status "$dir/$label.status" \
		--file "$stage/src:/src" --file "$stage/bin/tego:/vm/tego" "${jq_files[@]}" "${py_files[@]}" "${kt7_files[@]}" "${bench_files[@]}" \
		"${kt4_files[@]}" \
		--env "KT_FIXTURE_DIR=/tmp/fixtures" --env "VM_KT3=${VM_KT3:-0}" --env "VM_KT4_TIERS=${VM_KT4_TIERS:-}" --env "VM_KT5_TIERS=${VM_KT5_TIERS:-}" --env "VM_KT5_RUNS=${VM_KT5_RUNS:-}" --env "VM_KT5_PLANES=${VM_KT5_PLANES:-}" --env "KT6_LSM_FIX=$fix" --env "VM_COVER=${VM_COVER:-0}" \
		--env "VM_TEST_TIMEOUT=$TEST_TIMEOUT" --cwd /tmp \
		-- /bin/bash -c 'mkdir -m 1777 -p /tmp/fixtures && exec /bin/bash /src/test/vm/run-matrix-row.sh /vm/tego "$@"' \
		row "$@" >"$dir/$label.out" 2>&1
	code=$?
	st="$(cat "$dir/$label.status" 2>/dev/null)"
	tr -d '\r' <"$dir/$label.console" >"$dir/$label.clean"
	awk -v row="$row" -v boot="$label" '
		/^MATRIX-RESULT / { d = ""; for (i = 6; i <= NF; i++) d = d (i > 6 ? " " : "") $i
			printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", row, boot, $2, $3, $4, $5, d }
		/^KT-HALF / { d = ""; for (i = 5; i <= NF; i++) d = d (i > 5 ? " " : "") $i
			printf "%s\t%s\t%s/%s\t-\t%s\t-\t%s\n", row, boot, $2, $3, $4, d }' "$dir/$label.clean" >>"$dir/results.tsv"
	sed -n "s/^MATRIX-KERNEL //p" "$dir/$label.clean" | head -1 >"$dir/$label.kernel"
	# What doctor said about the boot (run-matrix-row.sh's MATRIX-FACTS, doctor-facts.sh): the Landlock ABI and
	# tier cgroup's decision plane, for summary.json.
	sed -n "s/^MATRIX-FACTS //p" "$dir/$label.clean" | head -1 >"$dir/$label.facts"
	if sed -n '/^MATRIX-FIXTURES-BEGIN$/,/^MATRIX-FIXTURES-END$/p' "$dir/$label.clean" | grep -v '^MATRIX-FIXTURES' | base64 -d >"$dir/$label.fixtures.tgz" 2>/dev/null &&
		[ -s "$dir/$label.fixtures.tgz" ]; then
		mkdir -p "$dir/fixtures"
		tar -xzf "$dir/$label.fixtures.tgz" -C "$dir/fixtures"
	fi
	rm -f "$dir/$label.fixtures.tgz"
	case "$st" in
	"guest "*)
		booted=1
		# A guest that ran but reported no check, or that exited non-zero without one failing check, did
		# not complete the row: run-matrix-row.sh died early or was killed partway. A row is green only on
		# its own results.
		local gcode="${st#guest }" nres nfail
		nres="$(awk -F'\t' -v b="$label" '$2 == b' "$dir/results.tsv" | wc -l)"
		nfail="$(awk -F'\t' -v b="$label" '$2 == b && ($5 == "FAIL" || ($5 == "SKIP" && $4 != "-" && $3 !~ /^kt3-overhead/))' "$dir/results.tsv" | wc -l)"
		if [ "$nres" -eq 0 ]; then
			printf '%s\t%s\tboot\t-\tFAIL\t%s\tthe guest reported no check (guest exit %s); see %s\n' "$row" "$label" "$gcode" "$gcode" "$dir/$label.clean" >>"$dir/results.tsv"
			return 1
		elif [ "$gcode" != 0 ] && [ "$nfail" -eq 0 ]; then
			printf '%s\t%s\tboot\t-\tFAIL\t%s\tthe guest exited %s with no failing check, so the row did not complete; see %s\n' "$row" "$label" "$gcode" "$gcode" "$dir/$label.clean" >>"$dir/results.tsv"
			return 1
		fi
		;;
	*)
		# Any status but "env" is a harness or guest failure (timeout, no report, usage, no status at all), not a
		# box that cannot boot one (exit 97 is for kvm-run.sh's "env" and a failed fetch).
		case "$st" in env*) ;; *) booted=1 ;; esac
		printf '%s\t%s\tboot\t-\tFAIL\t%s\tthe guest did not report (kvm-run.sh: %s); see %s\n' "$row" "$label" "$code" "${st:-no status}" "$dir/$label.out" >>"$dir/results.tsv"
		return 1
		;;
	esac
}

booted=0
for row in "${rows[@]}"; do
	dir="$OUT/$row"
	rm -rf "$dir"
	mkdir -p "$dir"
	if [ "$row" != host ] && ! python3 "$here/fetch-kernel.py" "$row" >"$dir/fetch.log" 2>&1; then
		printf '%s\tfetch\tkernel\t-\tNOT-RUN\t-\t%s\n' "$row" "$(tail -1 "$dir/fetch.log")" >>"$dir/results.tsv"
		continue
	fi
	# fix is the lsm= line boot1's kill test 6 printed; boot2 boots with it and hands it back to half (c)
	# as KT6_LSM_FIX, so the half can say the line it runs under is the one doctor printed.
	fix=""
	if is_doctor_only "$row"; then
		# One boot, one check: that doctor and tego run refuse the machine with their fix (doctor-refusal.sh).
		# No kill test has a tier to run at, so VM_ONLY, which picks a kill test, is not applied, and no second boot
		# is owed to kill test 6 (c), which only a row with a tier can run.
		[ -z "${VM_ONLY:-}" ] || echo "matrix: $row offers no tier, so VM_ONLY=$VM_ONLY does not apply: it runs the refusal check" >&2
		boot "$row" boot1 kernel --only doctor-refusal
		continue
	fi
	if [ -n "${VM_ONLY:-}" ]; then
		boot "$row" boot1 "${VM_ONLY_LSM:-kernel}" --only "$VM_ONLY"
		continue
	fi
	boot "$row" boot1 kernel || continue
	fix="$(sed -n 's/^KT6-LSM-FIX //p' "$dir/boot1.clean" | head -1)"
	if [ -n "$fix" ]; then
		boot "$row" boot2 "$fix" --only kt6c
	elif ! tr ',' '\n' <"$dir/boot1.kernel" | sed -n 's/^.*lsm=//p;t;p' | grep -qx bpf; then
		# The kernel booted without bpf in its LSM list (or the list could not be read) and kill test 6
		# printed no line to add: half (c), the reboot, never ran, and a half's skip is otherwise
		# accepted. That is a failed row, not a silent pass.
		printf '%s\tboot1\tkt6/c-fix-missing\t-\tFAIL\t-\tno bpf in the active lsm= list (%s) and kill test 6 printed no KT6-LSM-FIX line, so R16(c) was not run\n' \
			"$row" "$(cat "$dir/boot1.kernel")" >>"$dir/results.tsv"
	fi
done

# ---- report --------------------------------------------------------------------------------------------

python3 - "$OUT" "${rows[@]}" <<'PY'
import json, os, sys
out, rows = sys.argv[1], sys.argv[2:]
summary, failed = {}, False
for row in rows:
    path = os.path.join(out, row, "results.tsv")
    lines = [l.rstrip("\n").split("\t") for l in open(path)] if os.path.exists(path) else []
    kernel = ""
    kp = os.path.join(out, row, "boot1.kernel")
    if os.path.exists(kp):
        kernel = open(kp).read().strip()
    src = os.path.expanduser(os.path.join(os.environ.get("TEGO_VM_CACHE", "~/.cache/tego-vm"), "kernel",
                                          "matrix-" + row, "source.json"))
    pkg = json.load(open(src)) if os.path.exists(src) else {}
    checks = [dict(zip(["row", "boot", "check", "as", "verdict", "exit", "detail"], l)) for l in lines if len(l) >= 7]
    # The facts of each boot (doctor-facts.sh: landlock_abi=<n> cgroup_mode=<lsm|fmod_ret|fanotify|none|unknown>).
    # cgroup_mode is ADR 0021 (7)'s "every matrix row selects a plane mode" as a column: the mode tier cgroup decides
    # opens by on that boot, where doctor offers the tier. A boot that printed none leaves its slot out.
    facts = {}
    for boot in ("boot1", "boot2"):
        fp = os.path.join(out, row, boot + ".facts")
        if os.path.exists(fp):
            kv = dict(w.split("=", 1) for w in open(fp).read().split() if "=" in w)
            if kv:
                facts[boot] = kv
    abis = [kv["landlock_abi"] for kv in facts.values() if kv.get("landlock_abi", "").isdigit()]
    modes = {boot: kv["cgroup_mode"] for boot, kv in facts.items() if "cgroup_mode" in kv}
    summary[row] = {"kernel": kernel, "package": pkg, "landlock_abi": int(abis[0]) if abis else None,
                    "cgroup_mode": modes, "checks": checks}
    print(f"\n{row}: {kernel or '(not booted)'}  [{pkg.get('package', '')} {pkg.get('version', '')}]")
    if facts:
        print(f"  landlock_abi: {abis[0] if abis else '?'}  cgroup_mode: " + " ".join(f"{b}={m}" for b, m in modes.items()))
    for c in checks:
        # A skipped whole kill test is a failure but for kill test 3 (VM_KT3 off), whose skip is named and
        # expected; a half ("<test>/<half>", as "-") may skip, its reason printed.
        skipped = c["verdict"] == "SKIP" and c["as"] != "-" and not c["check"].startswith("kt3-overhead")
        failed |= skipped or c["verdict"] in ("FAIL", "NOT-RUN")
        print(f"  {c['boot']:<6} {c['check']:<34} {c['as']:<5} {c['verdict']:<8} {c['detail'][:150]}")
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(f"\nmatrix: {os.path.join(out, 'summary.json')}")
sys.exit(1 if failed else 0)
PY
status=$?

if [ -n "$save_row" ]; then
	src="$OUT/$save_row/fixtures"
	if [ -d "$src" ] && [ -n "$(ls -A "$src")" ]; then
		for f in "$src"/*/; do
			name="$(basename "$f")"
			rm -rf "$repo/test/fixtures/ledger/$name"
			cp -r "$f" "$repo/test/fixtures/ledger/$name"
		done
		chmod -R u+rw,go+r "$repo/test/fixtures/ledger"
		echo "matrix: fixtures from $save_row saved under test/fixtures/ledger/"
	else
		echo "matrix: $save_row saved no fixtures" >&2
	fi
fi

[ "$booted" = 1 ] || exit 97
exit "$status"
