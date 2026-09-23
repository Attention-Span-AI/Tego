# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# lib.sh — shared plumbing for the kill test scripts (test/e2e/kt*.sh) and the VM matrix row
# (test/vm/run-matrix-row.sh). Not a kill test itself: nothing here attacks a guarantee, it only
# gives every kt*.sh the same note/pass/fail/skip vocabulary so each script stays about the one
# numbered test it names (docs/P0-DESIGN.md §10, §12).
#
# Sourced, never executed directly:
#   repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
#   . "$repo_root/e2e/lib.sh"

# Exit codes every script under test/e2e returns (KT_PASS, KT_FAIL, KT_SKIP = 77) and kt_verdict.
# shellcheck source=test/e2e/kt-exit.sh
. "$(dirname "${BASH_SOURCE[0]}")/kt-exit.sh"

kt_repo_root() { cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd; }

kt_note() { echo "== $*"; }

# kt_forwarded_problem EVENTS WANT judges "every model request is ssl_request source=forwarder" for one
# ledger: WANT ssl_request events, none from another source, a parsed 200 response for each, and WANT
# request/response pairs (a response whose request_seq names that request's seq, test/e2e/kt2-pairs.jq), so
# duplicated, mis-sequenced or orphaned responses do not pass on their counts. It prints what was wrong, or nothing.
kt_forwarded_problem() {
	local events="$1" want="$2" nq nr nother ncg nrg npairs
	# shellcheck disable=SC2034 # ncg/nrg occupy unused positions in the shared six-field output.
	read -r nq nr nother ncg nrg npairs <<<"$(jq -rs --arg src forwarder \
		-f "$(dirname "${BASH_SOURCE[0]}")/kt2-pairs.jq" "$events")"
	if [ "$nq" != "$want" ] || [ "$nother" != 0 ]; then
		echo "$want model requests expected; the ledger holds $nq ssl_request, $nother of them not source=forwarder"
	elif [ "$nr" != "$want" ]; then
		echo "$nr of $want ssl_response events parsed with status 200"
	elif [ "$npairs" != "$want" ]; then
		echo "only $npairs of $want ssl_request events have a parsed ssl_response whose request_seq names them"
	fi
}

# kt_skip prints a named reason on stderr and exits 77 (KT_SKIP). Call it the moment a script discovers it
# cannot exercise the guarantee here (no root, wrong tier, a tool or credential this box lacks) —
# before running any part of the check — so a skip is never mistaken for a pass that happened to
# find nothing wrong (the ticket's "skip vacuously" failure mode).
kt_skip() { echo "SKIP: $*" >&2; exit "$KT_SKIP"; }

# kt_fail prints what broke and exits 1.
kt_fail() { echo "FAIL: $*" >&2; exit "$KT_FAIL"; }

# kt_pass prints a one-line summary and exits 0.
kt_pass() { echo "PASS: $*"; exit "$KT_PASS"; }

# kt_half prints one machine-readable result line for a part of a kill test: "KT-HALF <test> <part>
# <PASS|FAIL|SKIP> <reason>". A kill test with halves (kt2, kt6, kt7) has one exit code for all of
# them, and a pass with named skips is not the same result as a pass of every half; the kernel matrix
# (test/vm/matrix.sh) reads these lines so its report says which half ran where.
kt_half() { echo "KT-HALF $1 $2 $3 ${*:4}"; }

# kt_need_jq is the first call of every kill test that reads the ledger with jq. A jq that cannot run turns
# each check of the form "count the lines that are wrong" into a count of zero: the kernel-matrix guest once
# carried a jq whose library it could not load, and kill test 1's attribution check passed there without
# reading a line. So a jq that does not answer a trivial query is a named skip before any check runs.
kt_need_jq() {
	[ "$(echo '{"ok":1}' | jq -r .ok 2>/dev/null)" = 1 ] ||
		kt_skip "jq is not usable here ($(echo '{}' | jq . 2>&1 >/dev/null | head -1)); this kill test reads the ledger with it"
}

# kt_am_root reports whether this process is euid 0, the precondition of tiers cgroup and bpflsm.
kt_am_root() { [ "$(id -u)" -eq 0 ]; }

# kt_sudo_user reports whether a root run has a user to drop the agent to. A root `tego run` drops the
# agent to SUDO_UID and refuses to start without one (docs/p0/runtime-launch.md), so a root half needs
# to have been started with sudo from a user account, as FEATURES R16 (b) says it is.
kt_sudo_user() { kt_am_root && [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; }

# kt_agent_owns hands directories to the user a root run drops its agent to: a directory made by this
# script as root is not writable by that user, where the same directory made by the user's own shell
# would be. A no-op when not root.
kt_agent_owns() {
	kt_sudo_user || return 0
	chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@"
}

# KT_ROOT is this script's one scratch directory, made when lib.sh is sourced: every work directory,
# helper binary and helper pid file lives under it, so the exit trap can clean up everything the script
# made, including what a function made inside a $(...) subshell, whose variables never come back.
KT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/tego-kt-XXXXXX")"
# The machine config refuses a relative $TEGO_CONFIG layer (identity-config R14), so the directory is made absolute.
if [ -z "$KT_ROOT" ] || ! KT_ROOT="$(cd "$KT_ROOT" && pwd)"; then
	echo "lib.sh: no scratch directory under ${TMPDIR:-/tmp}" >&2
	exit 2
fi
chmod 755 "$KT_ROOT"

# kt_require_testhooks BIN refuses a binary that is not built with -tags tegotesthooks, unless this is a disposable
# machine (TEGO_DISPOSABLE_HOST, which the KVM guests set: test/vm/run-matrix-row.sh, root-suites.sh). A product
# build ignores TEGO_TEST_CHAIN_ANCHOR and anchors every run in the invoking user's own ~/.tego/chain.log, where
# nothing says afterwards which lines were a test's (identity-config.md R27; tools/isocheck). The test hooks build is
# the only one that contains the variable's name, so its presence in the file is the check.
kt_require_testhooks() {
	grep -aq TEGO_TEST_CHAIN_ANCHOR "$1" 2>/dev/null && return 0
	[ -z "${TEGO_DISPOSABLE_HOST:-}" ] || return 0
	kt_fail "$1 is not built with -tags tegotesthooks, so it would append this test's runs to the invoking user's own ~/.tego/chain.log; build it with the tag, or run in a disposable machine (TEGO_DISPOSABLE_HOST)"
}

# kt_ensure_tego builds ./cmd/tego once and prints the binary's path. When $TEGO_BIN is already
# set to an existing executable it is reused as-is: test/vm/run-matrix-row.sh hands every kt*.sh the
# binary it was given, instead of every kill test rebuilding from scratch. The build carries the BPF
# objects when they are generated (bpf/README.md), since tiers cgroup and bpflsm need them and a tagged
# build runs tier landlock the same as an untagged one.
kt_ensure_tego() {
	if [ -n "${TEGO_BIN:-}" ] && [ -x "${TEGO_BIN:-}" ]; then
		kt_require_testhooks "$TEGO_BIN"
		echo "$TEGO_BIN"
		return 0
	fi
	# tegotesthooks lets kt_config point the binary's chain anchor into the work directory
	# (internal/cli/anchor_testhook.go), so a kill test never appends to the developer's own
	# ~/.tego/chain.log. A binary handed in as $TEGO_BIN anchors where the product does, which
	# kt_require_testhooks refuses outside a disposable machine.
	local root bin tags="-tags=tegotesthooks"
	root="$(kt_repo_root)"
	bin="$KT_ROOT/bin/tego"
	mkdir -p "$KT_ROOT/bin"
	chmod 755 "$KT_ROOT/bin"
	if ls "$root"/internal/bpf/*_bpfel.o >/dev/null 2>&1; then
		tags="-tags=tegobpf,tegotesthooks"
	fi
	(cd "$root" && CGO_ENABLED=0 go build $tags -o "$bin" ./cmd/tego) 1>&2 || kt_fail "go build ./cmd/tego: see above"
	echo "$bin"
}

# kt_workdir creates one scratch directory under KT_ROOT, mode 0755 (pkg/spec/config refuses a layer
# any other user can write), and prints its path. Every call gets its own directory — kt1 and kt7 need
# two live at once, for the two concurrent runs.
kt_workdir() {
	local w
	w="$(mktemp -d "$KT_ROOT/w-XXXXXX")"
	chmod 755 "$w"
	echo "$w"
}

# kt_track_pid records a helper process (a model stand-in, a listener) for the exit trap to stop. The
# list is a file, not a variable, so a helper started inside a $(...) is stopped too.
kt_track_pid() { echo "$1" >>"$KT_ROOT/.pids"; }

# kt_cleanup stops every helper process this script started and removes KT_ROOT, unless KT_KEEP=1.
kt_cleanup() {
	local p
	# shellcheck disable=SC2013 # the file holds pids, one word each
	for p in $(cat "$KT_ROOT/.pids" 2>/dev/null); do
		kill "$p" 2>/dev/null
	done
	[ "${KT_KEEP:-0}" = 1 ] && return 0
	rm -rf "$KT_ROOT"
}
trap kt_cleanup EXIT

# kt_config writes a minimal machine config into $1/config.yaml (mode 600, as config.Load's
# trusted-mode check requires) and exports TEGO_CONFIG to it. $2, if given, is the ledger_root;
# default is $1/runs. `extends:` names resolve under a copy of the repository's examples/profiles, the
# profiles the kill tests are specified against (FEATURES R18: "under examples/profiles/base/python-dev"),
# made in $1 and owned by whoever runs this, with no group or other write: the profiles directory follows
# the machine config's trust rule, which a checkout under umask 002, or one owned by another uid than a
# root run's, would fail. A copy of this file outside a checkout (a self-test's stand-in harness, which sources it and so
# meets the isolation at the end of this file) has no profiles to copy: its config then names none. The price table is
# the limits package's test table, copied to $1/prices.yaml: a run of a contract that declares cost_usd (the examples
# do) is refused [budget-unmetered] when no price table loads, and the default path is the invoking user's own
# ~/.tego/prices.yaml, which a test must not depend on. A copy outside a checkout has no such table either, and its
# config names none.
kt_config() {
	local dir="$1" ledger="${2:-$1/runs}" profiles prices
	profiles="$(kt_repo_root)/examples/profiles"
	prices="$(kt_repo_root)/internal/runtime/limits/testdata/prices.yaml"
	rm -rf "$dir/profiles" "$dir/prices.yaml"
	if [ -d "$profiles" ]; then
		cp -R "$profiles" "$dir/profiles"
		chmod -R go-w "$dir/profiles"
	fi
	if [ -f "$prices" ]; then
		cp "$prices" "$dir/prices.yaml"
		chmod 600 "$dir/prices.yaml"
	fi
	cat >"$dir/config.yaml" <<-EOF
	version: 0
	ledger_root: $ledger
	stop_grace: 3s
	EOF
	[ ! -d "$dir/profiles" ] || echo "profiles: $dir/profiles" >>"$dir/config.yaml"
	[ ! -f "$dir/prices.yaml" ] || echo "prices: $dir/prices.yaml" >>"$dir/config.yaml"
	chmod 600 "$dir/config.yaml"
	export TEGO_CONFIG="$dir/config.yaml"
	export TEGO_TEST_CHAIN_ANCHOR="$dir/chain.log"
	# The own log and the shell history too: a test build keeps no own log without a home for it, and a shell a kill test
	# starts must not append to the developer's own ~/.bash_history (HOME does not decide where tego looks, but it
	# decides where bash does).
	mkdir -p "$dir/log-home"
	export TEGO_TEST_OWN_LOG_HOME="$dir/log-home"
	export HISTFILE=/dev/null
	# And a runtime directory of the test's own (R27 clause b4): a launch makes <XDG_RUNTIME_DIR>/tego and first removes
	# the directories there whose launcher's lock is free, so a kill test under the invoking user's XDG_RUNTIME_DIR made
	# their /run/user/<uid>/tego and removed what their crashed runs left there, and kt_run's SIGKILL left its own. 0700
	# whatever the umask: tego makes its directory only under one no other user can write. A root launcher makes none.
	mkdir -p "$dir/run"
	chmod 700 "$dir/run"
	export XDG_RUNTIME_DIR="$dir/run"
}

# kt_doctor_tier prints the highest tier `tego doctor --json` reports on this machine ("" if none).
kt_doctor_tier() {
	local tego="$1"
	"$tego" doctor --json 2>/dev/null | jq -r '.tier // ""'
}

# kt_tier_available reports whether `tego doctor --require <tier>` accepts this machine, and prints
# doctor's last line (its reason) when it does not.
kt_tier_available() {
	local tego="$1" tier="$2" out
	out="$("$tego" doctor --require "$tier" 2>&1)" && return 0
	echo "$out" | tail -1
	return 1
}

# kt_run runs one `tego run` with a bound on how long it may take, KT_RUN_TIMEOUT seconds (default 300, far
# above what any kill test's agent takes). The bound is the kill test's, not the contract's: a contract may
# allow longer (the shipped examples kill test 7 runs set limits.wall to 30m), and a kill-test run still
# going at 300 s is broken whatever its contract allows. A launcher that never returns is a failure the kill
# test has to report, not a wait it may sit in: on the kernel matrix a hung tier-2 run once held kill test 4
# until the row's own timeout killed the whole guest, and every later kill test of the row went unrun. When
# the bound is hit, the line it leaves on stderr is the one kt_err_line reports, and it returns 124.
#
# At the bound timeout(1) sends SIGTERM to the process group it makes for itself and the command. A launcher
# that survives SIGTERM gets SIGKILL ten seconds later from kt_run's own watchdog, not from `timeout -k`:
# uutils' timeout (coreutils 0.2.2, Ubuntu 25.10's) takes -k and never sends the SIGKILL, and goes on waiting
# for a command that ignores SIGTERM (`timeout -k 2 1 sh -c 'trap "" TERM; sleep 8'` returned after 8 s, GNU's
# after 3 s), which made such a launcher a wait again wherever the host's timeout is uutils'. The watchdog is
# the one escalation with either timeout (test/e2e/lib_test.sh).
kt_run() {
	local bound="${KT_RUN_TIMEOUT:-300}" start=$SECONDS rc pgfile watchdog
	pgfile="$(mktemp "$KT_ROOT/.kt-run-XXXXXX")"
	# The watchdog is outside timeout's group, so the kill it sends does not reach it. It is stopped, with its
	# sleep, the moment timeout returns, so no watchdog outlives its run to signal a group id reused since. Its
	# trap kills $s, not $!, because a subshell inherits its parent's $!, which may be another run the caller
	# started (run A, in kill test 1); s starts empty so a TERM before the sleep exists kills nothing. The
	# watchdog shares the kill test's own process group, so a TERM sent to that group (run-matrix-row.sh's
	# outer bound) stops it too, and the escalation lapses for a run the kill test was ended around.
	(
		s=
		trap 'kill $s 2>/dev/null; exit 0' TERM
		sleep $((bound + 10)) &
		s=$!
		wait "$s" && kill -KILL -- "-$(cat "$pgfile")" 2>/dev/null
	) </dev/null >/dev/null 2>&1 &
	watchdog=$!
	# The subshell's pid becomes timeout's through exec, and timeout leads its group, so the pid is the group's.
	(
		echo "$BASHPID" >"$pgfile"
		exec timeout "$bound" "$@"
	)
	rc=$?
	kill "$watchdog" 2>/dev/null
	wait "$watchdog" 2>/dev/null
	rm -f "$pgfile"
	if [ $((SECONDS - start)) -ge "$bound" ]; then
		echo "tego: did not return within ${bound}s; the kill test stopped it (KT_RUN_TIMEOUT)" >&2
		return 124
	fi
	return "$rc"
}

# kt_err_line prints the one line of a run's stderr that says why tego stopped: its last diagnostic of
# its own ("tego run: ...", "tego: ..."), else the last line. A result line holds one line, and the first
# lines of a run's stderr are usually warnings (a tier below the contract's, no price table) that say
# nothing about the failure.
kt_err_line() {
	local line
	line="$(grep -E '^tego( run)?:' "$1" 2>/dev/null | grep -v -e '\[tier-unavailable\]' -e '\[not-found\]' | tail -1)"
	[ -n "$line" ] || line="$(tail -1 "$1" 2>/dev/null)"
	echo "$line" | cut -c1-400
}

# kt_ledger_valid FILE: every line of the ledger parses as JSON. jq stops at the first line it cannot parse and
# exits 2, so a scan of the ledger that discards jq's status (a pipe into wc, a `2>/dev/null` process
# substitution) goes on to judge only the lines before it; a check over "every line" runs this first.
kt_ledger_valid() { jq -c . "$1" >/dev/null 2>&1; }

# kt_rundir prints the one run directory under a work directory's ledger root.
kt_rundir() { find "$1/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' 2>/dev/null | head -1; }

# kt_tls_cert writes a throwaway certificate for 127.0.0.1 into $1 (cert.pem, key.pem), readable by
# every user (the agent a root run drops to trusts it through SSL_CERT_FILE). keyUsage and
# extendedKeyUsage are set because CPython 3.13 verifies with VERIFY_X509_STRICT by default.
kt_tls_cert() {
	local dir="$1"
	command -v openssl >/dev/null 2>&1 || return 1
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
		-keyout "$dir/key.pem" -out "$dir/cert.pem" -subj /CN=127.0.0.1 \
		-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
		-addext "keyUsage=critical,digitalSignature,keyCertSign" \
		-addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || return 1
	chmod 644 "$dir/cert.pem"
}

# kt_model_stub starts test/workloads/model-stub/server.py over the certificate in $1, answering from
# the JSON script $2 when given, and sets KT_STUB_PORT and KT_STUB_LOG (one line per request). The
# server runs outside every run, in this script's own cgroup, so its own TLS calls are never the run's.
kt_model_stub() {
	local dir="$1" script="${2:-}"
	KT_STUB_LOG="$dir/stub-requests.log"
	: >"$KT_STUB_LOG"
	python3 "$(kt_repo_root)/test/workloads/model-stub/server.py" --cert "$dir/cert.pem" --key "$dir/key.pem" \
		--ready "$dir/stub.port" --log "$KT_STUB_LOG" ${script:+--script "$script"} 2>"$dir/stub.err" &
	kt_track_pid "$!"
	for _ in $(seq 100); do
		[ -s "$dir/stub.port" ] && break
		sleep 0.1
	done
	KT_STUB_PORT="$(cat "$dir/stub.port" 2>/dev/null)"
	[ -n "$KT_STUB_PORT" ] || return 1
}

# kt_pydeps prints the directory test/e2e/pydeps.sh fills (pip, the build workload's wheels, the
# Anthropic SDK, and with --claude-sdk the Claude Agent SDK), priming it when the network allows, or returns
# 1 when it cannot be had here.
kt_pydeps() {
	local d
	d="$("$(kt_repo_root)/test/e2e/pydeps.sh" "$@" 2>/dev/null)" || return 1
	echo "$d"
}

# kt_save_fixture copies one run's ledger into $KT_FIXTURE_DIR/<name>/ when the caller asked for
# fixtures (P0-DESIGN §10 "every kill test adds a recorded fixture"; test/fixtures/README.md). A kill
# test saves the ledger of the run it judges, whatever its verdict: the fixture is the product's record of
# a real run, which every view must read, not a record that the kill test passed. What is saved is what a
# view reads: events.jsonl, and contract.yaml and blobs/ when the run has them, plus the
# run's line of the chain anchor ($TEGO_TEST_CHAIN_ANCHOR for the binary kt_ensure_tego builds, else
# ~/.tego/chain.log of the user the run belongs to) as chain.log, which
# is what verifying an ended run checks its head against. The chain is copied as recorded, never
# rewritten, so a saved ledger still verifies; a ledger that names the invoking account anywhere — its
# name, in a home directory or in any other path such as a TMPDIR derived from one, or its uid's
# /run/user/<uid> — or any /home/ directory, or any home flattened into one directory name (/-home-, as
# in Claude Code's /tmp/claude-<uid>/-home-<name>-<project>/), is not saved at all, because the redaction
# that matters here is not recording it: the kill tests keep their paths under their own work
# directories, and a run whose TMPDIR names the account is recorded again from one that does not
# (TMPDIR=/tmp). The account's name counts wherever it occurs, inside a longer word too, since here it is
# the recording account's own; test/fixtures' TestFixturesNameNoAccount, which runs as whoever runs the
# tests, matches a name only where it stands alone.
kt_save_fixture() {
	local name="$1" run="$2" dest who id anchor uid pats=()
	[ -n "${KT_FIXTURE_DIR:-}" ] || return 0
	[ -s "$run/events.jsonl" ] || return 0
	pats+=(-e "/home/" -e "/-home-")
	for who in "${SUDO_USER:-}" "$(id -un 2>/dev/null)"; do
		[ -n "$who" ] && [ "$who" != root ] && pats+=(-e "$who")
	done
	for uid in "${SUDO_UID:-}" "$(id -u)"; do
		[ -n "$uid" ] && [ "$uid" != 0 ] && pats+=(-e "/run/user/$uid")
	done
	if grep -rqF "${pats[@]}" "$run/events.jsonl" "$run/contract.yaml" "$run/blobs" 2>/dev/null; then
		kt_note "fixture $name not saved: the ledger names the account or a home directory ($(grep -rhoF "${pats[@]}" "$run/events.jsonl" "$run/contract.yaml" "$run/blobs" 2>/dev/null | sort -u | paste -sd, -))"
		return 0
	fi
	dest="$KT_FIXTURE_DIR/$name"
	rm -rf "$dest"
	mkdir -p "$dest"
	cp "$run/events.jsonl" "$dest/events.jsonl"
	[ ! -f "$run/contract.yaml" ] || cp "$run/contract.yaml" "$dest/contract.yaml"
	[ ! -d "$run/blobs" ] || [ -z "$(ls -A "$run/blobs" 2>/dev/null)" ] || cp -r "$run/blobs" "$dest/blobs"
	id="$(basename "$run")"
	for anchor in "${TEGO_TEST_CHAIN_ANCHOR:-/nonexistent}" "$HOME/.tego/chain.log" "$(getent passwd "${SUDO_UID:-$(id -u)}" | cut -d: -f6)/.tego/chain.log"; do
		if grep -m1 "^$id " "$anchor" >"$dest/chain.log" 2>/dev/null; then
			break
		fi
		rm -f "$dest/chain.log"
	done
	chmod -R u+rwX,go+rX "$dest"
	kt_note "fixture saved: $dest"
}

# Every script that sources this file starts with an isolation of its own, so a command it runs before it writes its
# own machine config (kt_tier_available's `doctor --require`, kt_doctor_tier, the doctor calls of kill test 6) cannot
# reach the invoking user's own ~/.tego. A binary built with -tags tegotesthooks, which kt_ensure_tego builds,
# refuses every command (doctor and compile included) while its machine config has no ledger_root of its own; the
# product build would run and anchor in the developer's chain.log. kt_config, called later with the script's own work
# directory, replaces this one (identity-config.md R27).
mkdir -p "$KT_ROOT/iso"
chmod 755 "$KT_ROOT/iso"
kt_config "$KT_ROOT/iso"
