// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeExecLiveWords runs liveWordsChecks: the target starts one child per command line of a program the contract grants.
const modeExecLiveWords = "exec-live-words"

// wordsTool is the program the target runs: a copy of true(1) the harness puts in its directory under this name, which the
// matcher's built-in rows know as git (a program it has no row for is read with every option's value unknown, and an
// exec.deny entry of such a tool refuses `tool stash push` as ambiguous, as the block does).
const wordsTool = "git"

// liveWordsChecks starts the program with each argument list and waits for it: "" is a child that ran and exited 0, an
// errno the exec's refusal.
func liveWordsChecks() []checkResult {
	dir := os.Getenv(helperDir)
	var out []checkResult
	for _, c := range [][]string{{"push"}, {"push", "origin", "main"}, {"status"}, {"stash", "push"}} {
		name := wordsTool
		for _, a := range c {
			name += "_" + a
		}
		pid, err := syscall.ForkExec(filepath.Join(dir, wordsTool), append([]string{wordsTool}, c...), &syscall.ProcAttr{})
		if err != nil {
			out = append(out, checkResult{Name: name, Err: errText(err)})
			continue
		}
		var ws unix.WaitStatus
		if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
			out = append(out, checkResult{Name: name, Err: errText(err)})
			continue
		}
		res := ""
		if !ws.Exited() || ws.ExitStatus() != 0 {
			res = "exit " + strconv.Itoa(ws.ExitStatus())
		}
		out = append(out, checkResult{Name: name, Err: res})
	}
	return out
}

// TestLiveWordsBlockOnARealKernel is TestLiveWordsBlockRefusesTheNextCommandOnly on a real kernel, real seccomp filter, real
// Loop and real child processes (the supervisor at tier landlock decides every exec): a program the contract grants (by a
// bare grant, and by command rules that allow `git push` and `git status`) runs every command line with no block; with
// a block on `git push` the next such command is refused EACCES under live.block[exec:git push], `git push origin
// main` too, and the same program with other words (`status`, and under the bare grant `stash push`) runs and exits 0.
func TestLiveWordsBlockOnARealKernel(t *testing.T) {
	payload := truePayload(t)
	for _, tc := range []struct {
		name  string
		rules bool
		block bool
		runs  map[string]bool // the command lines that run
	}{
		{"a bare grant, no block", false, false, map[string]bool{"git_push": true, "git_push_origin_main": true, "git_status": true, "git_stash_push": true}},
		{"a bare grant, blocked", false, true, map[string]bool{"git_status": true, "git_stash_push": true}},
		{"command rules, no block", true, false, map[string]bool{"git_push": true, "git_push_origin_main": true, "git_status": true}},
		{"command rules, blocked", true, true, map[string]bool{"git_status": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var set *liveblock.Set
			if tc.block {
				o := liveblock.New("r-test")
				if _, _, err := o.Add(liveblock.KindExec, "git push", "uid:1 pid:2 cli", time.Now()); err != nil {
					t.Fatal(err)
				}
				set = liveblock.Compile(o, liveblock.Resolved{})
			}
			h := startHarnessWith(t, harnessOpts{mode: modeExecLiveWords,
				prepare: func(dir string) {
					b, err := os.ReadFile(payload)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, wordsTool), b, 0o755); err != nil { //nolint:gosec // an executable fixture
						t.Fatal(err)
					}
				},
				live: func() *liveblock.Set { return set },
				rules: func(rt *agent.RuleTable, dir string) {
					p := filepath.Join(dir, wordsTool)
					rt.Exec = []agent.ExecRule{{Raw: p, Path: p, Basename: wordsTool, Source: agent.ExecSourceAllow}}
					rt.Tier = backend.TierLandlock
					sec := &agent.ExecSection{Allow: []string{p}}
					if tc.rules {
						var ps []*execmatch.Pattern
						for _, e := range []string{"git push", "git status"} {
							pat, err := execmatch.Parse(e, execmatch.ListAllow, rows.Builtin())
							if err != nil {
								t.Fatal(err)
							}
							ps = append(ps, pat)
							sec.Allow = append(sec.Allow, e)
						}
						ec := &agent.ExecCommands{Index: execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})}
						for _, pat := range ps {
							ec.Entries = append(ec.Entries, agent.ExecCommandEntry{Pattern: pat})
						}
						rt.ExecCommands = ec
					}
					rt.Contract = &agent.Contract{Exec: sec}
				}})
			got := map[string]string{}
			for _, c := range h.report.Checks {
				got[c.Name] = c.Err
			}
			for _, name := range []string{"git_push", "git_push_origin_main", "git_status", "git_stash_push"} {
				if tc.rules && name == "git_stash_push" {
					continue // refused by the contract's own rules, with or without a block
				}
				want := unix.EACCES.Error()
				if tc.runs[name] {
					want = ""
				}
				if g, ok := got[name]; !ok || g != want {
					t.Errorf("%s: %q (reported %v), want %q", name, g, ok, want)
				}
			}
			// The ledger: a refusal the block made names the block; the contract's own refusals keep their rule.
			blocked := 0
			for _, ev := range h.sink.all() {
				if ev.Kind == record.KindExec && ev.Verdict == record.VerdictRefused && ev.Rule == "live.block[exec:git push]" {
					blocked++
				}
			}
			if want := map[bool]int{true: 2, false: 0}[tc.block]; blocked != want {
				t.Errorf("%d exec lines refused under the block, want %d", blocked, want)
			}
		})
	}
}
