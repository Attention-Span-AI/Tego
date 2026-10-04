#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# precommit_test.sh — the two claims precommit.sh and ci.yml make about each other and about the platform:
#   1. precommit.sh runs every *_test.sh script CI's build-test job runs (its header says it is that job, run here);
#   2. ci.yml's concurrency group gives each push its own group (the commit's SHA), so a newer push never replaces
#      the pending run of an older one (GitHub cancels all but the newest pending run of a group);
#   3. the toolchain and tool pins repeated across the workflows, go.mod and the Makefile agree (Go, goreleaser,
#      govulncheck), so the reproducible job proves what release.yml builds;
#   4. CODEOWNERS covers the release, signing and installer files and the committed BPF objects.
#   5. every gating go test (gated-test.sh, precommit.sh and its runner, ci.yml, make race) runs with -count=1, so no
#      cached pass is replayed.
# Exit: 0 when all hold, 1 otherwise.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

fail=0
ci=.github/workflows/ci.yml

while IFS= read -r t; do
	grep -q -- "$t" scripts/precommit.sh || { echo "FAIL: $ci runs $t but scripts/precommit.sh does not"; fail=1; }
done < <(grep -o '[A-Za-z0-9_./-]*_test\.sh' "$ci" | sed 's#^\./##' | sort -u)

# 1b. every tracked *_test.sh is named by CI (a test no job runs guards nothing).
for t in $(./scripts/tree-files.sh | tr '\0' '\n' | grep '_test\.sh$'); do
	grep -q -- "$t" "$ci" || { echo "FAIL: $t is tracked but $ci does not run it"; fail=1; }
done

group="$(sed -n '/^concurrency:/,/^$/p' "$ci" | grep '^  group:')"
case "$group" in
*github.sha*) ;;
*) echo "FAIL: $ci's concurrency group ($group) has no per-commit group for pushes"; fail=1 ;;
esac

# 3. the bpftool step derives its objects from the tree, so a newly committed object is loaded too; a hardcoded
#    list once left the plane's out.
if grep -q 'internal/bpf/[a-z0-9_]*_bpfel\.o' "$ci"; then
	echo "FAIL: $ci names a bpfel object; bpf-load's bpftool step must glob internal/bpf/*_bpfel.o"; fail=1
fi
grep -q 'for obj in internal/bpf/\*_bpfel\.o' "$ci" ||
	{ echo "FAIL: $ci's bpftool step does not loop over internal/bpf/*_bpfel.o"; fail=1; }

# 4. the gates' file lists come from tree-files.sh: git ls-files still names a tracked file that was deleted from
#    the working tree and not yet from the index, and gofmt, shellcheck and head then fail on it.
if grep -n 'git ls-files' scripts/precommit.sh scripts/check-spdx.sh; then
	echo "FAIL: precommit.sh or check-spdx.sh lists files with git ls-files; use scripts/tree-files.sh"; fail=1
fi

# 5. one Go toolchain everywhere: every workflow's GO_VERSION equals go.mod's toolchain line.
want_go="$(sed -n 's/^toolchain go//p' go.mod)"
[ -n "$want_go" ] || { echo "FAIL: go.mod has no toolchain line"; fail=1; }
for w in .github/workflows/*.yml; do
	while IFS= read -r v; do
		[ "$v" = "$want_go" ] || { echo "FAIL: $w has GO_VERSION $v, go.mod's toolchain is go$want_go"; fail=1; }
	done < <(sed -n "s/^ *GO_VERSION: *'\{0,1\}\([0-9.]*\)'\{0,1\} *\$/\1/p" "$w")
done

# 6. one goreleaser: release.yml's GORELEASER_VERSION is the version every goreleaser-action step installs.
flag="$(mktemp)"
trap 'rm -f "$flag"' EXIT
want_gr="$(sed -n 's/^ *GORELEASER_VERSION: *//p' .github/workflows/release.yml | head -n 1)"
[ -n "$want_gr" ] || { echo "FAIL: release.yml has no GORELEASER_VERSION"; fail=1; }
for w in .github/workflows/*.yml; do
	while IFS= read -r v; do
		[ "$v" = "$want_gr" ] || { echo "FAIL: $w has GORELEASER_VERSION $v, release.yml's is $want_gr"; fail=1; }
	done < <(sed -n 's/^ *GORELEASER_VERSION: *//p' "$w")
	grep -A3 'goreleaser/goreleaser-action' "$w" | sed -n 's/^ *version: *//p' | while IFS= read -r v; do
		# shellcheck disable=SC2016 # Match the workflow's literal expression.
		case "$v" in
		'${{ env.GORELEASER_VERSION }}') ;;
		"$want_gr") ;;
		*) echo "FAIL: $w installs goreleaser $v, release.yml's GORELEASER_VERSION is $want_gr"; echo x >>"$flag" ;;
		esac
	done
done
[ ! -s "$flag" ] || fail=1

# 7. one govulncheck across ci.yml, release.yml and the Makefile.
vulns="$(grep -ho 'govulncheck@v[0-9.]*' .github/workflows/*.yml Makefile | sort -u)"
[ "$(printf '%s\n' "$vulns" | wc -l)" -eq 1 ] && [ -n "$vulns" ] ||
	{ echo "FAIL: govulncheck is pinned to more than one version: $vulns"; fail=1; }

# 8. CODEOWNERS covers what a hostile change would target: the release pipeline, the installer, the committed
#    objects the root binary loads, and the dependency and entry-point files.
for p in /.github/ /.goreleaser.yaml /scripts/install.sh /scripts/release.sh /go.mod /go.sum /internal/bpf/ /cmd/ /Makefile; do
	grep -qE "^${p//./\\.}[[:space:]]" .github/CODEOWNERS || { echo "FAIL: .github/CODEOWNERS has no owner line for $p"; fail=1; }
done

# 9. the CODEOWNERS lines for the gates themselves: the scripts, and the lists that decide what may skip.
for p in /scripts/ /test/unit-skips.txt /test/integration-skips.txt /test/vm/root-skips.txt /test/vm/root-must-pass.txt /.golangci.yml /tools/ /test/vm/ /test/e2e/ /.githooks/; do
	grep -qE "^${p//./\\.}[[:space:]]" .github/CODEOWNERS || { echo "FAIL: .github/CODEOWNERS has no owner line for $p"; fail=1; }
done

# 10. make lint names the files gofmt would change (a swallowed list left only "make: *** Error 1").
gd="$(mktemp -d)"
printf 'package x\nfunc  f(){}\n' >"$gd/bad.go"
if out="$(./scripts/gofmt-clean.sh "$gd/bad.go" 2>&1)"; then echo "FAIL: gofmt-clean.sh passed an unformatted file"; fail=1; fi
case "$out" in *bad.go*) ;; *) echo "FAIL: gofmt-clean.sh did not name the unformatted file: $out"; fail=1 ;; esac
rm -rf "$gd"
[[ "$(make -n lint 2>&1)" == *scripts/gofmt-clean.sh* ]] || { echo "FAIL: make lint does not use scripts/gofmt-clean.sh"; fail=1; }

# 9b. make race and make coverage run in the user manager as CI's do (cgroup placement tests skip outside it),
#     race with -shuffle=on; make lint runs precommit's static steps.
[[ "$(make -n race 2>&1)" == *"in-user-manager.sh"*"-race -shuffle=on"* ]] ||
	{ echo "FAIL: make race does not run through in-user-manager.sh with -shuffle=on"; fail=1; }
[[ "$(make -n coverage 2>&1)" == *"in-user-manager.sh"*coverage.sh* ]] ||
	{ echo "FAIL: make coverage does not run through in-user-manager.sh"; fail=1; }
for w in "'integration tegobpf'" lint-untagged.sh check-skiplists.sh check-exits.sh check-fd.sh tools/rulecheck tools/isocheck; do
	[[ "$(make -n lint 2>&1)" == *"$w"* ]] || { echo "FAIL: make lint does not run $w"; fail=1; }
done

# 11. make test and make integration are CI's gated steps (user manager, skip list; integration cgo-free), which
#     release.sh check runs.
[[ "$(make -n test 2>&1)" == *"gated-test.sh test/unit-skips.txt"*"-count=1"* ]] ||
	{ echo "FAIL: make test does not run the unit suite through gated-test.sh and its skip list, with -count=1"; fail=1; }
[[ "$(make -n integration 2>&1)" == *"gated-test.sh test/integration-skips.txt 0 -count=1 -tags integration"* ]] ||
	{ echo "FAIL: make integration does not run through gated-test.sh with its skip list, CGO_ENABLED=0 and -count=1"; fail=1; }

# 19. every gating go test runs fresh (-count=1): go test's cache rechecks only the files the test process opens,
#     so a link gate or binary-closure test whose verdict a go list/build subprocess decides replayed a stale pass
#     after a tree change that fails it. Builds (-c) and the fuzz runs are exempt.
# fresh_tests LINE: every go test in LINE (a command after another on the line too) runs with -count=1, or is a test
# build (go test -c). Each go test is read up to its line's next ;, & or |, so one command's flags never cover another's.
fresh_tests() {
	local rest=$1 seg
	while [[ "$rest" =~ (go|GO\"|GO|GO:-go\}\"|GO:-go\})\ test( |$) ]]; do
		rest=${rest#*"${BASH_REMATCH[0]}"}
		seg=${rest%%[;&|]*}
		[[ " $seg" == *" -count=1"* || " $seg" == " -c "* ]] || return 1
	done
}
# shellcheck disable=SC2016 # Match the script's literal text.
grep -vE '^[[:space:]]*#' scripts/gated-test.sh | grep -qF '"${GO:-go}" test -count=1 -json "$@"' ||
	{ echo "FAIL: scripts/gated-test.sh's go test does not run with -count=1"; fail=1; }
# shellcheck disable=SC2016 # Match the script's literal text.
while IFS= read -r l; do
	fresh_tests "$l" || { echo "FAIL: scripts/precommit.sh or its runner runs go test without -count=1: $l"; fail=1; }
done < <(grep -hE '(\$GO|\$\{GO[^}]*\}|(^|[^[:alnum:]_])go)"? test( |$)' scripts/precommit.sh scripts/precommit-runner.sh | grep -vE '^[[:space:]]*#')
while IFS= read -r l; do
	fresh_tests "$l" || { echo "FAIL: $ci runs go test without -count=1: ${l#"${l%%[![:space:]]*}"}"; fail=1; }
done < <(grep -E '(^|[ /])go test( |$)' "$ci" | grep -vE '^[[:space:]]*#')
# make test and make integration run through gated-test.sh (11 holds them to it); make race calls go test itself.
while IFS= read -r l; do
	[[ "$l" == *"-count=1"* ]] || { echo "FAIL: make race runs go test without -count=1: $l"; fail=1; }
done < <(make -n race 2>&1 | grep ' test ')

# 12. ci.yml and container.yml do not rerun on the v* tag release.sh pushes after ci is green (release.yml gates on
#     that run), and they do run on a branch push: with tags-ignore and no branches key GitHub starts a push run for
#     tags only, so master would get no run, and root-suites, which only a push to master starts, would never run.
for w in "$ci" .github/workflows/container.yml; do
	on="$(sed -n '/^on:/,/^permissions:/p' "$w")"
	grep -qE "^    tags-ignore: *\[.v\*.\]" <<<"$on" || { echo "FAIL: $w's push trigger does not ignore v* tags"; fail=1; }
	grep -qE "^    branches: *\[.\*\*.\]" <<<"$on" || { echo "FAIL: $w's push trigger names no branches, so a branch push runs nothing"; fail=1; }
done

# 22. the reproducible job's own script, against a stand-in goreleaser that behaves as the real one does with three
#     builds: it writes dist/<id>_linux_amd64_v1/<binary> and ignores --output, with exit 0 and no file (the job once
#     read --output's path, so it failed on every run and never compared a binary). The script passes when the two
#     builds match and fails when any one binary differs or is missing, each case proving one binary is compared.
repro="$(sed -n '/- name: build the release target twice and compare/,/^$/p' "$ci" | sed -n '/^        run: |$/,$p' | sed '1d;/^$/d;s/^ \{10\}//')"
[ -n "$repro" ] || { echo "FAIL: $ci has no reproducible step to run"; fail=1; }
rd="$(mktemp -d)"
mkdir -p "$rd/bin" "$rd/src/scripts"
cat >"$rd/bin/goreleaser" <<'STUB'
#!/bin/sh
# The bytes depend on the directory only for the binary named by REPRO_DIFFERS; REPRO_MISSING is never written.
for b in tego tego-control maze; do
	[ "$b" = "${REPRO_MISSING:-}" ] && continue
	mkdir -p "dist/${b}_linux_amd64_v1"
	if [ "$b" = "${REPRO_DIFFERS:-}" ]; then pwd; else echo same; fi >"dist/${b}_linux_amd64_v1/$b"
done
echo x >>"$REPRO_RUNS"
STUB
printf '#!/bin/sh
exit 0
' >"$rd/src/scripts/check-control-pin.sh"
chmod +x "$rd/bin/goreleaser" "$rd/src/scripts/check-control-pin.sh"
# repro_run DIFFERS MISSING: the job's script in a fresh runner directory; its exit status is the result.
repro_run() (
	rm -rf "$rd/tmp" "$rd/src/dist" "$rd/runs"
	mkdir "$rd/tmp"
	cd "$rd/src" && RUNNER_TEMP="$rd/tmp" REPRO_RUNS="$rd/runs" REPRO_DIFFERS=$1 REPRO_MISSING=$2 PATH="$rd/bin:$PATH" \
		bash -c "$repro" >"$rd/out" 2>&1
)
if ! repro_run "" ""; then
	echo "FAIL: $ci's reproducible step failed on two identical builds:"; sed 's/^/    /' "$rd/out"; fail=1
elif [ "$(wc -l <"$rd/runs")" -ne 2 ]; then
	echo "FAIL: $ci's reproducible step did not build twice"; fail=1
fi
for b in tego tego-control maze; do
	repro_run "$b" "" && { echo "FAIL: $ci's reproducible step passed with two different $b binaries"; fail=1; }
	repro_run "" "$b" && { echo "FAIL: $ci's reproducible step passed with no $b binary"; fail=1; }
done
rm -rf "$rd"

# 23. the tag name stops at the gate's shape check, its first command, before any gh call or any later job passes it
#     on; every step runs it through env, and make through the environment (release_test.sh holds the Makefile to it).
gate="$(sed -n '/^  gate:/,/^  release:/p' .github/workflows/release.yml)"
shape="$(sed -n '/^ *set -euo pipefail$/{n;s/^ *//;p;q}' <<<"$gate")"
# shellcheck disable=SC2016 # Match the workflow's literal text.
[[ "$shape" == *'[[ "$TAG" =~ '* ]] || { echo "FAIL: release.yml's gate does not start with the tag's shape check: $shape"; fail=1; }
for t in v1.2.3 v0.1.0-rc.1; do
	TAG=$t bash -c "$shape" >/dev/null 2>&1 || { echo "FAIL: release.yml's gate refuses the tag $t"; fail=1; }
done
# shellcheck disable=SC2016 # Literal tag names.
for t in 'v0.1.0$(id)' 'v0.1.0";id;"' 'v0.1.0;id' "v0.1.0'" 'v1.2' 'latest' 'v1.2.3-' 'v1.2.3+x' $'v1.2.3\nv1.2.3'; do
	if TAG=$t bash -c "$shape" >/dev/null 2>&1; then echo "FAIL: release.yml's gate takes the tag $t"; fail=1; fi
done
if grep -nE 'make [^#]*VERSION=|VERSION=.*\$\{\{' .github/workflows/release.yml; then
	echo "FAIL: release.yml gives make a tag on its command line or pastes one, where make would expand it"; fail=1
fi
# shellcheck disable=SC2016 # Match the Makefile's literal text.
if sed -n '/^preset-freeze:/,/^[^[:space:]]/p' Makefile | grep -q '\$(VERSION)'; then
	echo "FAIL: the Makefile's preset-freeze pastes \$(VERSION) into its recipe"; fail=1
fi

# 24. both installers are in the checksums file, so the signature over it and the attestations of what it lists cover
#     them; release.extra_files alone uploads them and adds nothing to it.
sums="$(sed -n '/^checksum:/,/^[a-z#]/p' .goreleaser.yaml)"
for f in scripts/install.sh scripts/install-maze.sh; do
	grep -qE "^ +- glob: \./$f\$" <<<"$sums" || { echo "FAIL: .goreleaser.yaml's checksum section does not list $f"; fail=1; }
done

# 13. no govulncheck in release.yml's release job, which holds id-token, attestations and contents write.
if sed -n '/^  release:/,/^  reproduce:/p' .github/workflows/release.yml | grep -q 'govulncheck@'; then
	echo "FAIL: release.yml runs govulncheck in the release job, beside the signing identity and the write token"; fail=1
fi
sed -n '/^  reproduce:/,/^  publish:/p' .github/workflows/release.yml | grep -q 'govulncheck@' ||
	{ echo "FAIL: release.yml's reproduce job does not run govulncheck"; fail=1; }

# 14. every Makefile target `make help` lists (a "##" comment) is phony: a file of a target's name at the root would
#     otherwise make it "up to date" and skip its recipe (deadcode-report-test was once left out).
phony=" $(sed -n 's/^\.PHONY://p' Makefile | tr '\n' ' ') "
while IFS= read -r target; do
	case "$phony" in *" $target "*) ;; *) echo "FAIL: Makefile target $target is not in a .PHONY line"; fail=1 ;; esac
done < <(sed -n 's/^\([A-Za-z0-9_-]*\):.*##.*/\1/p' Makefile)

# 15. the unit tests only a -tags tegotesthooks build compiles (identity-config.md R27) run in precommit and in CI's
#     build-test over the same packages: every package with a test file behind that tag is named by both, as a whole
#     word: ./internal/runtime/enforce/landlock/ does not name ./internal/runtime/enforce/ (it once passed for it).
for pkg in $(grep -rl --include='*_test.go' 'go:build.*tegotesthooks' internal | xargs -n1 dirname | sort -u); do
	for f in scripts/precommit.sh "$ci"; do
		grep -qE -- "-tags tegotesthooks.* \./${pkg//./\\.}/( |\$)" "$f" ||
			{ echo "FAIL: $f does not run ./$pkg/ with -tags tegotesthooks, which holds tests only that tag compiles"; fail=1; }
	done
done

# 16. the maze Homebrew cask is never uploaded while its tap is unnamed: release.yml's token writes this
#     repository alone, so an upload fails the release; and no GitHub namespace but
#     the repository's own owner is named as an owner or a homepage.
cask="$(sed -n '/^homebrew_casks:/,/^[a-z]/p' .goreleaser.yaml)"
if [[ "$cask" == *"owner: attention-span-ai"* ]] && [[ "$cask" != *"skip_upload: 'true'"* ]]; then
	echo "FAIL: .goreleaser.yaml's maze cask uploads to a tap no one has named"; fail=1
fi
while IFS= read -r line; do
	echo "FAIL: .goreleaser.yaml names a GitHub namespace other than attention-span-ai: $line"; fail=1
done < <(grep -nE '^ *(owner: |homepage: https://github\.com/)' .goreleaser.yaml | grep -v 'attention-span-ai')

# 17. maze's release artifacts are held as tego's are: reproduce compares its binaries and govulncheck scans them,
#     and the release job checks that install-maze.sh names the repository, like install.sh.
rp="$(sed -n '/^  reproduce:/,/^  publish:/p' .github/workflows/release.yml)"
[[ "$rp" == *maze-binaries.sha256* ]] || { echo "FAIL: release.yml's reproduce job does not compare the maze binaries"; fail=1; }
[[ "$rp" == *"dist/maze_*/maze"* ]] || { echo "FAIL: release.yml's govulncheck does not scan the maze binaries"; fail=1; }
grep -q 'INSTALLER=scripts/install-maze.sh scripts/check-installer-repo.sh' .github/workflows/release.yml ||
	{ echo "FAIL: release.yml does not check that install-maze.sh names the repository"; fail=1; }

# 18. the checksums artifact downloads flat, where reproduce looks: upload-artifact roots several paths at their
#     common ancestor, so every path it is handed must sit directly in dist/, beside the checksums file (one in
#     $RUNNER_TEMP would root it at the runner's work directory, and reproduce would find neither file).
up="$(sed -n '/name: hand the checksums file to reproduce/,/if-no-files-found:/p' .github/workflows/release.yml |
	sed -n '/^ *path: |/,/if-no-files-found:/p' | sed '1d;$d;s/^ *//')"
[ -n "$up" ] || { echo "FAIL: release.yml hands reproduce no checksums artifact paths"; fail=1; }
while IFS= read -r p; do
	[ -n "$p" ] || continue
	# shellcheck disable=SC2016 # a literal GitHub expression in release.yml, never expanded by the shell
	case "$p" in
	'${{ steps.sums.outputs.path }}') ;;
	dist/*/* | dist/) echo "FAIL: release.yml's checksums artifact path $p is not directly in dist/"; fail=1 ;;
	dist/*) [[ "$rp" == *"\$RUNNER_TEMP/published/${p#dist/}"* ]] ||
		{ echo "FAIL: release.yml's reproduce job does not read ${p#dist/} from the downloaded artifact's top level"; fail=1; } ;;
	*) echo "FAIL: release.yml's checksums artifact path $p is outside dist/, so the artifact does not download flat"; fail=1 ;;
	esac
done <<<"$up"

# 21. precommit.sh's runner (scripts/precommit-runner.sh): steps are reported in the order they were added whatever
#     finished first, with their output; a failing step fails the run; a killed step (a command killed by a signal,
#     or a job whose shell was killed, and the steps after it in that job) is a FAIL, never ok; TEGO_PRECOMMIT_JOBS=1
#     runs the steps one after another in the order added.
# runner JOBS OUT: runs a fixed set of steps with PC_JOBS=JOBS, its output in OUT, the order steps ended in OUT.order.
# shellcheck disable=SC2329 # the steps are called by name, through pc_add
runner() (
	PC_JOBS=$1 PC_TMP="$(mktemp -d)"
	order=$2.order
	trap 'rm -rf "$PC_TMP"' EXIT
	: >"$order"
	# shellcheck source=scripts/precommit-runner.sh
	. ./scripts/precommit-runner.sh
	s_slow() { sleep 0.5; echo "slow output"; echo a >>"$order"; }
	s_fast() { echo b >>"$order"; }
	s_fail() { echo "the failure's own output"; echo c >>"$order"; return 3; }
	s_signal() { echo d >>"$order"; sh -c 'kill -9 $$'; }
	s_job_killed() { kill -9 "$BASHPID"; }
	s_after() { echo f >>"$order"; }
	s_report() { echo "a report line"; return 1; }
	pc_add static a "a-slow" step s_slow
	pc_add static b "b-fast" step s_fast
	pc_add static c "c-fail" step s_fail
	pc_add static d "d-signal" step s_signal
	pc_add static - "e-note" note "a note's text"
	pc_add static r "r-report" report s_report
	if [ "$PC_JOBS" -gt 1 ]; then
		pc_add static k "k-job-killed" step s_job_killed
		pc_add static k "k-never-ran" step s_fast
	fi
	pc_add tests f "f-next-phase" step s_after
	pc_run static
	pc_run tests
	pc_finish
	echo "rc=$?"
) >"$2" 2>&1
rt="$(mktemp -d)"
for jobs in 1 4; do
	out="$rt/out-$jobs"
	runner "$jobs" "$out"
	want="a-slow b-fast c-fail d-signal e-note r-report"
	[ "$jobs" = 1 ] || want="$want k-job-killed k-never-ran"
	got="$(grep -oE '^[a-z]-[a-z-]+' "$out" | tr '\n' ' ')"
	[ "$got" = "$want f-next-phase " ] || { echo "FAIL: runner with $jobs job(s) reported steps in the order '$got', want '$want f-next-phase '"; fail=1; }
	grep -qE '^a-slow +ok \([0-9]+s\)$' "$out" || { echo "FAIL: runner with $jobs job(s) did not report a-slow ok with its duration"; fail=1; }
	grep -q 'slow output' "$out" && { echo "FAIL: runner with $jobs job(s) printed a passing step's output"; fail=1; }
	if ! grep -qE '^c-fail +FAIL' "$out" || ! grep -q "^    the failure's own output" "$out"; then
		echo "FAIL: runner with $jobs job(s) did not report c-fail as FAIL with its output"; fail=1
	fi
	grep -qE '^d-signal +FAIL' "$out" || { echo "FAIL: runner with $jobs job(s) did not fail a step killed by a signal"; fail=1; }
	grep -qE "^e-note +a note's text\$" "$out" || { echo "FAIL: runner with $jobs job(s) did not print the note"; fail=1; }
	grep -qE '^r-report +a report line$' "$out" || { echo "FAIL: runner with $jobs job(s) did not print the report's line"; fail=1; }
	if [ "$jobs" -gt 1 ]; then
		if ! grep -qE '^k-job-killed +FAIL' "$out" || ! grep -qE '^k-never-ran +FAIL' "$out"; then
			echo "FAIL: runner with $jobs jobs reported a killed job's steps as anything but FAIL"; fail=1
		fi
		[ "$(head -n 1 "$out.order")" != a ] || { echo "FAIL: runner with $jobs jobs did not run b-fast while a-slow ran"; fail=1; }
		grep -q 'precommit: failed: c-fail d-signal k-job-killed k-never-ran$' "$out" ||
			{ echo "FAIL: runner with $jobs jobs did not name every failed step in its verdict"; fail=1; }
	else
		[ "$(tr '\n' ' ' <"$out.order")" = "a b c d f " ] || { echo "FAIL: runner with 1 job ran the steps in the order '$(tr '\n' ' ' <"$out.order")'"; fail=1; }
		grep -q 'precommit: failed: c-fail d-signal$' "$out" || { echo "FAIL: runner with 1 job did not name every failed step in its verdict"; fail=1; }
	fi
	grep -qx 'rc=1' "$out" || { echo "FAIL: runner with $jobs job(s) passed a run with failed steps"; fail=1; }
	grep -q 'every step passed' "$out" && { echo "FAIL: runner with $jobs job(s) said every step passed"; fail=1; }
done
# A run whose steps all pass says so and exits 0.
if ! (
	PC_JOBS=3 PC_TMP="$rt/pass"
	mkdir "$PC_TMP"
	# shellcheck source=scripts/precommit-runner.sh
	. ./scripts/precommit-runner.sh
	pc_add static a "a" step true
	pc_add static b "b" step true
	pc_run static
	pc_finish
) >"$rt/pass.out" 2>&1 || ! grep -qx 'precommit: every step passed' "$rt/pass.out"; then
	echo "FAIL: runner did not pass a run whose steps passed: $(cat "$rt/pass.out")"; fail=1
fi
# A step whose phase is never run (here "tests"), and a failed step after it, fail the run: neither is left out of
# the verdict. A step with an unknown phase is refused and fails the run. A word holding a space or a * reaches the
# command as one word. PC_FIRST's job starts first; the print order stays the order added. PC_VERDICT is the pass line.
if (
	PC_JOBS=4 PC_TMP="$rt/never"
	mkdir "$PC_TMP"
	# shellcheck source=scripts/precommit-runner.sh
	. ./scripts/precommit-runner.sh
	pc_add static a "a" step true
	pc_add tests b "b-unrun" step true
	pc_add static c "c-fail-after" step false
	pc_run static
	pc_finish
) >"$rt/never.out" 2>&1; then
	echo "FAIL: runner passed a run with a step whose phase never ran: $(cat "$rt/never.out")"; fail=1
fi
grep -qE '^b-unrun +FAIL \(never ran' "$rt/never.out" || { echo "FAIL: runner did not report the never-run step: $(cat "$rt/never.out")"; fail=1; }
grep -qE '^c-fail-after +FAIL' "$rt/never.out" || { echo "FAIL: runner hid a failed step after a never-run one: $(cat "$rt/never.out")"; fail=1; }
grep -q 'every step passed' "$rt/never.out" && { echo "FAIL: runner said every step passed over a never-run step"; fail=1; }
if (
	PC_JOBS=2 PC_TMP="$rt/phase"
	mkdir "$PC_TMP"
	# shellcheck source=scripts/precommit-runner.sh
	. ./scripts/precommit-runner.sh
	pc_add statc a "a-typo" step true
	pc_add static b "b" step true
	pc_run static
	pc_finish
) >"$rt/phase.out" 2>&1; then
	echo "FAIL: runner passed a run with a step of an unknown phase: $(cat "$rt/phase.out")"; fail=1
fi
# shellcheck disable=SC2329 # called by name, through pc_add
nargs() { echo "$# [$1] [$2]"; }
args_out="$(
	PC_JOBS=1 PC_TMP="$rt/args"
	mkdir "$PC_TMP"
	# shellcheck source=scripts/precommit-runner.sh
	. ./scripts/precommit-runner.sh
	pc_add static x "x" step nargs "a b" '*'
	pc_run static >/dev/null
	cat "$PC_TMP/0.out"
)"
[ "$args_out" = "2 [a b] [*]" ] || { echo "FAIL: runner split or globbed a step's words: '$args_out'"; fail=1; }
first_out="$(
	# shellcheck disable=SC2030,SC2034 # this subshell's own settings, read by the sourced runner
	PC_JOBS=1 PC_TMP="$rt/first" PC_FIRST=long PC_VERDICT="custom verdict"
	mkdir "$PC_TMP"
	# shellcheck source=scripts/precommit-runner.sh
	. ./scripts/precommit-runner.sh
	pc_add static short "short" step true
	pc_add static long "long" step true
	PC_JOBS=2
	pc_run static
	pc_finish
)"
[ "$(grep -oE '^(short|long)' <<<"$first_out" | tr '\n' ' ')" = "short long " ] ||
	{ echo "FAIL: PC_FIRST changed the print order: $first_out"; fail=1; }
grep -qx 'custom verdict' <<<"$first_out" || { echo "FAIL: runner did not print PC_VERDICT as its pass line: $first_out"; fail=1; }
# The default job count reads what the gate's cgroups have left, and the page cache charged to them is not used
# memory: the slice's cache from earlier builds left a gate serial with nothing else running. The fixture stands in
# for /proc/meminfo (64 GB free) and for this process's cgroup, in $rt.
default_jobs_with() (
	# shellcheck disable=SC2034 # read by default_jobs, which the next line defines
	PC_SYSROOT=$1
	eval "$(sed -n '/^default_jobs() {/,/^}/p' scripts/precommit.sh)"
	default_jobs
)
cgleaf="$rt/sys/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)"
mkdir -p "$cgleaf" "$rt/sys/proc"
gib=1073741824
echo 'MemAvailable: 67108864 kB' >"$rt/sys/proc/meminfo"
echo $((10 * gib)) >"$cgleaf/memory.max"
echo $((10 * gib - gib / 2)) >"$cgleaf/memory.current"
[ "$(default_jobs_with "$rt/sys")" = 1 ] || { echo "FAIL: default_jobs took more than 1 job with half a GB left in the cgroup"; fail=1; }
# 8.5 GB left after the cache: GB/2 is 4, so the cores decide below that.
want_jobs=$(($(nproc) / 2))
[ "$want_jobs" -le 4 ] || want_jobs=4
[ "$want_jobs" -ge 1 ] || want_jobs=1
echo "inactive_file $((8 * gib))" >"$cgleaf/memory.stat"
got_jobs="$(default_jobs_with "$rt/sys")"
[ "$got_jobs" = "$want_jobs" ] || { echo "FAIL: default_jobs took $got_jobs job(s) with 8 GB of inactive page cache, want $want_jobs"; fail=1; }
# An interrupt stops what a running step started, not only the job's shell (go test and golangci-lint kept running
# after Ctrl-C): pc_stop from the EXIT trap, as precommit.sh sets it.
pidf="$rt/sleep.pid"
(
	PC_JOBS=2 PC_TMP="$rt/stop"
	mkdir "$PC_TMP"
	# shellcheck source=scripts/precommit-runner.sh
	. ./scripts/precommit-runner.sh
	trap 'pc_stop' EXIT
	trap 'exit 130' INT TERM
	# shellcheck disable=SC2329 # called by name, through pc_add
	s_sleep() { sleep 300 & echo "$!" >"$pidf"; wait; }
	pc_add static s "s-sleep" step s_sleep
	pc_run static
) >/dev/null 2>&1 &
stopper=$!
for _ in $(seq 1 50); do [ -s "$pidf" ] && break; sleep 0.1; done
kill -TERM "$stopper" 2>/dev/null
wait "$stopper" 2>/dev/null
sleeper="$(cat "$pidf" 2>/dev/null)"
if [ -z "$sleeper" ]; then
	echo "FAIL: the interrupt test's step never started"; fail=1
else
	for _ in $(seq 1 30); do kill -0 "$sleeper" 2>/dev/null || break; sleep 0.1; done
	if kill -0 "$sleeper" 2>/dev/null; then
		echo "FAIL: an interrupted run left its step's child (pid $sleeper) running"; fail=1
		kill "$sleeper" 2>/dev/null
	fi
fi
rm -rf "$rt"
for j in 0 x -1; do
	TEGO_PRECOMMIT_JOBS=$j ./scripts/precommit.sh >/dev/null 2>&1
	[ $? -eq 2 ] || { echo "FAIL: precommit.sh accepted TEGO_PRECOMMIT_JOBS=$j"; fail=1; }
done

# 21b. every step that runs golangci-lint shares the lint job in the full gate: a second golangci-lint fails while one
#      holds its lock ("parallel golangci-lint is running"), and the script self-tests run it (check-fd_test.sh,
#      check-edgelint_test.sh).
for fn in lint_tagged lint_untagged script_tests; do
	grep -qE "^[[:space:]]*pc_add static lint \"[^\"]*\" step $fn( |\$)" scripts/precommit.sh ||
		{ echo "FAIL: precommit.sh's full gate does not run $fn in the lint job"; fail=1; }
done
while IFS= read -r t; do
	[ "$t" = scripts/precommit_test.sh ] && continue
	grep -q "$t" scripts/precommit.sh || { echo "FAIL: $t names golangci but precommit.sh's script self-tests do not run it"; fail=1; }
done < <(grep -l 'golangci' scripts/*_test.sh test/vm/*_test.sh test/e2e/*_test.sh test/e2e/overhead/*_test.sh 2>/dev/null)

# 21c. every go test step runs with -count=1: go test's cache replays a pass whose verdict came from a go build or
#      go list the test ran (the link gate, the binary-closure suites) when the test binary is unchanged.
for fn in gated_unit gated_integration hooks_test; do
	grep -qE "^$fn\(\) \{.* -count=1 " scripts/precommit.sh || { echo "FAIL: precommit.sh's $fn does not pass -count=1"; fail=1; }
done
# 21d. scoped mode runs check-licenses (a Go-only change can link a new third-party package) and prints a note when
#      the shell linter is missing; the tegotesthooks tests share the unit job (after it, never beside it).
scoped_fn="$(sed -n '/^add_scoped() {/,/^}/p' scripts/precommit.sh)"
grep -q 'step check_licenses' <<<"$scoped_fn" || { echo "FAIL: precommit.sh's scoped mode does not run check-licenses"; fail=1; }
grep -q 'note "not installed' <<<"$scoped_fn" || { echo "FAIL: precommit.sh's scoped mode drops shellcheck without a note"; fail=1; }
grep -qE '^[[:space:]]*pc_add tests unit "unit tests \(-tags tegotesthooks\)" step hooks_test ' scripts/precommit.sh ||
	{ echo "FAIL: precommit.sh's full gate does not run the tegotesthooks tests in the unit job"; fail=1; }
# 21e. the full gate's tegotesthooks list is the set of directories holding tegotesthooks test files (scoped mode
#      derives it from go list; a hard-coded list would leave a new one out).
hooks_listed="$(grep -E '^[[:space:]]*pc_add tests unit "unit tests \(-tags tegotesthooks\)"' scripts/precommit.sh |
	grep -oE '\./[A-Za-z0-9_/.-]+/' | sed 's#^\./##; s#/$##' | sort -u | tr '\n' ' ')"
hooks_tree="$(./scripts/tree-files.sh | tr '\0' '\n' | grep '_test\.go$' |
	while IFS= read -r f; do grep -qE '^//go:build .*tegotesthooks' "$f" && dirname "$f"; done | sort -u | tr '\n' ' ')"
[ -n "$hooks_tree" ] && [ "$hooks_listed" = "$hooks_tree" ] ||
	{ echo "FAIL: precommit.sh tests -tags tegotesthooks in '$hooks_listed', but those test files are in '$hooks_tree'"; fail=1; }

# 20. make precommit-affected is the scoped mode, through TEGO_PRECOMMIT_SINCE, with BASE as its revision; make
#     precommit and the commit hook, the full gate, clear an inherited TEGO_PRECOMMIT_SINCE.
[[ "$(make -n precommit-affected BASE=abc123 2>&1)" == *'TEGO_PRECOMMIT_SINCE="abc123"'*scripts/precommit.sh* ]] ||
	{ echo "FAIL: make precommit-affected does not pass BASE to precommit.sh as TEGO_PRECOMMIT_SINCE"; fail=1; }
[[ "$(TEGO_PRECOMMIT_SINCE=master make -n precommit 2>&1)" == *'TEGO_PRECOMMIT_SINCE= '*scripts/precommit.sh* ]] ||
	{ echo "FAIL: make precommit does not clear an inherited TEGO_PRECOMMIT_SINCE"; fail=1; }
grep -qx 'unset TEGO_PRECOMMIT_SINCE' .githooks/pre-commit || { echo "FAIL: .githooks/pre-commit does not clear TEGO_PRECOMMIT_SINCE"; fail=1; }
grep -q 'PC_VERDICT="precommit: every selected step passed' scripts/precommit.sh ||
	{ echo "FAIL: precommit.sh's scoped and docs modes do not print their own verdict line"; fail=1; }

[ "$fail" -eq 0 ] && echo "precommit_test: ok"
exit "$fail"
