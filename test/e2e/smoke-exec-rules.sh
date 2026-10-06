#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# smoke-exec-rules.sh — the kernel matrix's exec command-rule cell (ADR 0048 C6). It runs one `tego run`
# under `exec: {deny: [rm -r, git push]}` at $KT_TIER and checks that the denied commands are refused at their
# execve and their neighbours run, on the row's own kernel:
#   - `rm -r`, `rm -fr` and `rm --recursive` exit 126 (EACCES at execve) and the tree is still there;
#   - `rm -f` of a file exits 0 and removes it;
#   - with git in the guest, `git -C . push` exits 126 and `git --version` exits 0;
#   - the ledger has a refused exec line with rule exec.deny[rm -r], command_via, and argv_facts copied_syscall for each;
# and a second run under `exec: {allow: [/bin/sh, rm -f, git status]}`: rm -f and git status run, while rm -r and
# git push are refused as unlisted (exec.args[rm], exec.args[git]).
# The unit, decision-core and real-kernel Go tests hold the semantics (internal/runtime/execrules_integration_test.go,
# internal/runtime/enforce/cgroup/execrules_e2e_integration_test.go); this cell holds that they reach every row.
#
# Tier: $KT_TIER (default landlock) through `tego run --tier`; the matrix runs it as the user at landlock and under
# sudo at cgroup (test/vm/run-matrix-row.sh).
# Exit 0 pass, 1 fail, 77 skip (never a silent pass): see test/e2e/kt-exit.sh.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
kt_need_jq

tego="$(kt_ensure_tego)"
tier="${KT_TIER:-landlock}"
if ! reason="$(kt_tier_available "$tego" "$tier")"; then
	kt_skip "$tier tier unavailable on this machine: $reason"
fi
if kt_am_root && ! kt_sudo_user; then
	kt_skip "running as root without SUDO_UID: a root tego run drops the agent to the sudo user and has none here"
fi

work="$(kt_workdir)"
out="$work/out"
mkdir -p "$out/t1/sub" "$out/t2/sub" "$out/t3/sub"
: >"$out/file"
# tego's own files (config, ledger, chain anchor) live in a directory of their own: a write entry inside it is refused.
cfg="$(kt_workdir)"
kt_config "$cfg" >/dev/null
have_git=no
command -v git >/dev/null 2>&1 && have_git=yes
cat >"$work/task.sh" <<-EOF
	#!/bin/sh
	cd "$out" || exit 3
	rm -r t1 2>/dev/null; echo "rm-r \$?" >>st
	rm -fr t2 2>/dev/null; echo "rm-fr \$?" >>st
	rm --recursive t3 2>/dev/null; echo "rm-long \$?" >>st
	rm -f file; echo "rm-f \$?" >>st
	if [ $have_git = yes ]; then
		git -C . push >/dev/null 2>&1; echo "git-push \$?" >>st
		git --version >/dev/null 2>&1; echo "git-version \$?" >>st
	fi
	exit 0
EOF
chmod 755 "$work/task.sh"
cat >"$work/agent.yaml" <<-EOF
	version: 0
	name: smoke-exec-rules
	command: ["/bin/sh", "$work/task.sh"]
	fs:
	  write: ["$out/", "/dev/null"]
	exec:
	  deny: [rm -r, git push]
	env:
	  pass: ["PATH", "HOME"]
	limits:
	  wall: 60s
	record: summary
EOF
kt_agent_owns "$out"

kt_note "one run at tier $tier under exec.deny [rm -r, git push] (git in the guest: $have_git)"
(cd "$work" && kt_run "$tego" run agent.yaml --tier "$tier" --offline -- /bin/sh "$work/task.sh") >"$work/run.out" 2>"$work/run.err"
rc=$?
[ "$rc" -eq 0 ] || kt_fail "tego run exited $rc, expected 0: $(kt_err_line "$work/run.err")"

st() { sed -n "s/^$1 //p" "$out/st" 2>/dev/null | head -1; }
for c in rm-r rm-fr rm-long; do
	[ "$(st "$c")" = 126 ] || kt_fail "$c exited '$(st "$c")', want 126: the denied command was not refused at its execve"
done
for d in t1 t2 t3; do
	[ -d "$out/$d/sub" ] || kt_fail "$out/$d was removed although rm -r is denied"
done
[ "$(st rm-f)" = 0 ] || kt_fail "rm -f exited '$(st rm-f)', want 0: a neighbour of the denied command was refused"
[ ! -e "$out/file" ] || kt_fail "rm -f left $out/file"
if [ "$have_git" = yes ]; then
	[ "$(st git-push)" = 126 ] || kt_fail "git -C . push exited '$(st git-push)', want 126"
	[ "$(st git-version)" = 0 ] || kt_fail "git --version exited '$(st git-version)', want 0"
fi

dir="$(kt_rundir "$cfg")"
[ -n "$dir" ] || kt_fail "the run left no run directory under $cfg/runs"
kt_ledger_valid "$dir/events.jsonl" || kt_fail "$dir/events.jsonl has a line that is not JSON"
refused="$(jq -c 'select(.kind == "exec" and .verdict == "refused" and .rule == "exec.deny[rm -r]")
	| select(.command_via != null and .argv_facts == "copied_syscall")' "$dir/events.jsonl" | wc -l)"
[ "$refused" -ge 3 ] || kt_fail "$dir/events.jsonl has $refused refused exec lines with rule exec.deny[rm -r], command_via and argv_facts copied_syscall, want at least 3"

# The allow side: rm and git constrained to the listed invocations, everything else of theirs refused as unlisted.
work2="$(kt_workdir)"
out2="$work2/out"
mkdir -p "$out2/t4/sub"
: >"$out2/file"
cfg2="$(kt_workdir)"
kt_config "$cfg2" >/dev/null
git_allow=""
[ "$have_git" = no ] || git_allow=', "git status"'
cat >"$work2/task.sh" <<-EOF
	#!/bin/sh
	cd "$out2" || exit 3
	rm -f file; echo "rm-f \$?" >>st
	rm -r t4 2>/dev/null; echo "rm-r \$?" >>st
	if [ $have_git = yes ]; then
		git status >/dev/null 2>&1; echo "git-status \$?" >>st
		git push >/dev/null 2>&1; echo "git-push \$?" >>st
	fi
	exit 0
EOF
chmod 755 "$work2/task.sh"
cat >"$work2/agent.yaml" <<-EOF
	version: 0
	name: smoke-exec-rules-allow
	command: ["/bin/sh", "$work2/task.sh"]
	fs:
	  write: ["$out2/", "/dev/null"]
	exec:
	  allow: ["/bin/sh", "rm -f"$git_allow]
	env:
	  pass: ["PATH", "HOME"]
	limits:
	  wall: 60s
	record: summary
EOF
kt_agent_owns "$out2"
kt_note "one run at tier $tier under exec.allow [/bin/sh, rm -f$git_allow]"
(cd "$work2" && kt_run "$tego" run agent.yaml --tier "$tier" --offline -- /bin/sh "$work2/task.sh") >"$work2/run.out" 2>"$work2/run.err"
rc=$?
[ "$rc" -eq 0 ] || kt_fail "the allow run: tego run exited $rc, expected 0: $(kt_err_line "$work2/run.err")"
st2() { sed -n "s/^$1 //p" "$out2/st" 2>/dev/null | head -1; }
[ "$(st2 rm-f)" = 0 ] || kt_fail "the allow run: rm -f exited '$(st2 rm-f)', want 0"
[ "$(st2 rm-r)" = 126 ] || kt_fail "the allow run: rm -r exited '$(st2 rm-r)', want 126 (unlisted)"
[ -d "$out2/t4/sub" ] || kt_fail "the allow run removed $out2/t4 although only rm -f is listed"
if [ "$have_git" = yes ]; then
	# Outside a repository git status exits 128; what matters is that its execve was not refused.
	case "$(st2 git-status)" in "" | 126) kt_fail "the allow run: git status exited '$(st2 git-status)': its execve was refused" ;; esac
	[ "$(st2 git-push)" = 126 ] || kt_fail "the allow run: git push exited '$(st2 git-push)', want 126 (unlisted)"
fi
dir2="$(kt_rundir "$cfg2")"
[ -n "$dir2" ] || kt_fail "the allow run left no run directory under $cfg2/runs"
unlisted="$(jq -c 'select(.kind == "exec" and .verdict == "refused" and .rule == "exec.args[rm]")' "$dir2/events.jsonl" | wc -l)"
[ "$unlisted" -ge 1 ] || kt_fail "$dir2/events.jsonl has no refused exec line with rule exec.args[rm]"

kt_pass "tier $tier: under a deny-list rm -r in three spellings was refused at execve ($refused ledger lines) and rm -f ran; under an allow-list rm -f ran and rm -r was unlisted$([ "$have_git" = yes ] && echo '; git push was refused both ways, git --version and git status ran')"
