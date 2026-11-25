// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// wordsSet is a Set of command-word blocks (ADR 0171) with the limits given: values added now, each ending after d when
// d is not zero.
func wordsSet(t *testing.T, until map[string]time.Duration, values ...string) *liveblock.Set {
	t.Helper()
	o := liveblock.New("r-test")
	now := time.Now()
	for _, v := range values {
		var end time.Time
		if d := until[v]; d != 0 {
			end = now.Add(d)
		}
		if _, _, err := o.AddUntil(liveblock.KindExec, v, "t", now, end); err != nil {
			t.Fatal(err)
		}
	}
	return liveblock.Compile(o, liveblock.Resolved{})
}

// grantedGit is a policy whose contract grants git by its path, as a bare exec.allow entry does, and holds no command
// rule: a run that decides no argv until a block on words asks it to.
func grantedGit() *Policy {
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Raw: "git", Path: "/usr/bin/git", Basename: "git", ByName: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow}}
	return pol
}

// TestLiveWordsBlockRefusesTheNextCommandOnly is the host half of the guest row: under each kind of contract (one whose
// command rules allow `git push` and `git status`, one with a bare grant of git and no command rule), with the kernel
// handing execs over or not (the decision plane's tiers and tier landlock), a block on `git push` refuses the next
// `git push` under every spelling the contract's matcher reads as it, and runs `git status` (and, under the bare grant,
// `git stash push` and a bare `git`) as before; with no block `git push` runs. The refusal is the loop's EACCES under the
// block's rule, never a continue, and no exec is handed to the kernel while the block stands.
func TestLiveWordsBlockRefusesTheNextCommandOnly(t *testing.T) {
	nr := nrFor(t, "execve")
	push := [][]string{
		{"git", "push"},
		{"git", "push", "origin", "main"},
		{"git", "-C", ".", "push"},
		{"git", "-c", "x=y", "push", "--force"},
	}
	for _, p := range []struct {
		name  string
		pol   func(t *testing.T) *Policy
		other [][]string // commands the block must leave to the contract, which allows them
		rules bool
	}{
		{"a contract with command rules", func(t *testing.T) *Policy { return commandPolicy(t, "allow: git push", "allow: git status") },
			[][]string{{"git", "status"}}, true},
		{"a bare grant and no command rule", func(*testing.T) *Policy { return grantedGit() },
			[][]string{{"git", "status"}, {"git", "stash", "push"}, {"git"}}, false},
	} {
		for _, handoff := range []bool{false, true} {
			t.Run(p.name+map[bool]string{false: ", the supervisor decides", true: ", the kernel's plane decides"}[handoff], func(t *testing.T) {
				run := func(set *liveblock.Set, argv []string) (verdict record.Verdict, rule string, continued, handed bool) {
					f := newFake()
					f.tgid[42] = 40
					l, sink := newTestLoopOpts(t, f, p.pol(t), Options{LiveBlocks: func() *liveblock.Set { return set }})
					l.kernelExecHandoff = func() bool { return handoff }
					execAt(l, f, nr, 42, 0, "/usr/bin/git", argv...)
					resp, ok := f.lastResp()
					if !ok {
						t.Fatalf("%v: no response", argv)
					}
					evs := sink.all()
					if len(evs) == 1 {
						verdict, rule = evs[0].Verdict, evs[0].Rule
					}
					continued = resp.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
					// An exec the plane takes over is continued with no line of the loop's: a run with command rules never
					// is (its allowed lines are quiet at this record level, so no line says nothing there).
					handed = continued && len(evs) == 0 && !p.rules
					return verdict, rule, continued, handed
				}
				set := wordsSet(t, nil, "git push")
				for _, argv := range push {
					// Without the block the contract allows the command; a plane hands a bare grant's exec over undecided.
					verdict, _, cont, handed := run(nil, argv)
					if verdict == record.VerdictRefused || !cont || handed != (handoff && !p.rules) {
						t.Errorf("%v, no block: %q continued %v handed over %v, want allowed (handed over only by a plane under a bare grant)", argv, verdict, cont, handed)
					}
					// With the block the loop decides, whatever the kernel would have: refused under the block's rule.
					verdict, rule, cont, handed := run(set, argv)
					if verdict != record.VerdictRefused || rule != "live.block[exec:git push]" || cont || handed {
						t.Errorf("%v, blocked: %s %q continued %v handed over %v, want refused live.block[exec:git push]", argv, verdict, rule, cont, handed)
					}
				}
				for _, argv := range p.other {
					verdict, rule, cont, handed := run(set, argv)
					if verdict == record.VerdictRefused || !cont || handed || rule == "live.block[exec:git push]" {
						t.Errorf("%v, blocked: %s %q continued %v handed over %v, want left to the contract and decided by the loop", argv, verdict, rule, cont, handed)
					}
				}
				// Another program with the same words is no git.
				f := newFake()
				pol := p.pol(t)
				pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: "hg", Path: "/usr/bin/hg", Basename: "hg", ByName: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
				l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
				execAt(l, f, nr, 42, 0, "/usr/bin/hg", "hg", "push")
				if ev := sink.one(t); ev.Rule == "live.block[exec:git push]" {
					t.Errorf("hg push refused under the git block: %s", ev.Rule)
				}
			})
		}
	}
}

// TestLiveWordsBlockEndsAndIsLifted: a block past its limit, one lifted (no Set, or one without it), and one dormant under
// an unblock for a while refuse nothing; a block that is in force is not shadowed by another that is not, whichever the
// overlay lists first.
func TestLiveWordsBlockEndsAndIsLifted(t *testing.T) {
	nr := nrFor(t, "execve")
	now := time.Now()
	past := now.Add(-time.Hour)
	entry := func(v string, until, from time.Time) liveblock.Entry {
		return liveblock.Entry{Kind: liveblock.KindExec, Value: v, By: "t", At: past.Add(-time.Hour), Until: until, From: from}
	}
	for _, tc := range []struct {
		name    string
		entries []liveblock.Entry
		push    string // the rule `git push` is refused under, "" when it runs
		force   string // and `git push --force`
	}{
		{"in force", []liveblock.Entry{entry("git push", time.Time{}, time.Time{})}, "live.block[exec:git push]", "live.block[exec:git push]"},
		{"ended", []liveblock.Entry{entry("git push", past, time.Time{})}, "", ""},
		{"dormant under an unblock for a while", []liveblock.Entry{entry("git push", time.Time{}, now.Add(time.Hour))}, "", ""},
		{"in force again after the unblock", []liveblock.Entry{entry("git push", time.Time{}, past)}, "live.block[exec:git push]", "live.block[exec:git push]"},
		{"a block that ended listed before one in force",
			[]liveblock.Entry{entry("git push", past, time.Time{}), entry("git push --force", time.Time{}, time.Time{})}, "", "live.block[exec:git push --force]"},
		{"a dormant block listed before one in force",
			[]liveblock.Entry{entry("git push --force", time.Time{}, now.Add(time.Hour)), entry("git push", time.Time{}, time.Time{})},
			"live.block[exec:git push]", "live.block[exec:git push]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := liveblock.CompileEntries(tc.entries, 1, liveblock.Resolved{})
			for argv, want := range map[string]string{"push": tc.push, "push --force": tc.force} {
				f := newFake()
				l, sink := newTestLoopOpts(t, f, grantedGit(), Options{LiveBlocks: func() *liveblock.Set { return set }})
				execAt(l, f, nr, 42, 0, "/usr/bin/git", append([]string{"git"}, strings.Fields(argv)...)...)
				ev := sink.one(t)
				got := ""
				if ev.Verdict == record.VerdictRefused {
					got = ev.Rule
				}
				if got != want {
					t.Errorf("git %s: refused under %q, want %q", argv, got, want)
				}
			}
		})
	}
}

// TestLiveWordsBlockFailsClosedAsExecDenyDoes: facts the matcher cannot read are refused under the rule the contract's own
// command rules refuse them under (an unreadable vector: args-unreadable), as an exec.deny entry in the contract would,
// while a vector that is NULL or empty is the kernel's own empty one and runs.
func TestLiveWordsBlockFailsClosedAsExecDenyDoes(t *testing.T) {
	nr := nrFor(t, "execve")
	const pathAddr, ptrAddr, strAddr, nowhere = 0x100000, 0x200000, 0x300000, 0xdead0000
	ptrArray := func(ptrs ...uint64) []byte {
		b := make([]byte, 8*(len(ptrs)+1))
		for i, p := range ptrs {
			putU64(b[i*8:], p)
		}
		return b
	}
	set := wordsSet(t, nil, "git push")
	for _, tc := range []struct {
		name    string
		argv    uint64
		mem     map[uint64][]byte
		verdict record.Verdict
		rule    string
	}{
		{"pointer array faults", nowhere, nil, record.VerdictRefused, ruleArgsUnreadable},
		{"argv[0] faults", ptrAddr, map[uint64][]byte{ptrAddr: ptrArray(nowhere, strAddr)}, record.VerdictRefused, ruleArgsUnreadable},
		{"NULL argv", 0, nil, record.VerdictAllow, ""},
		{"empty vector", ptrAddr, map[uint64][]byte{ptrAddr: ptrArray()}, record.VerdictAllow, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoopOpts(t, f, grantedGit(), Options{LiveBlocks: func() *liveblock.Set { return set }})
			f.put(pathAddr, cstr("/usr/bin/git"))
			for addr, data := range tc.mem {
				f.put(addr, data)
			}
			l.handle(notifFor(nr, 42, pathAddr, tc.argv, 0))
			wantExecAnswer(t, f, tc.verdict)
			if ev := sink.one(t); tc.rule != "" && ev.Rule != tc.rule {
				t.Errorf("rule %q, want %q", ev.Rule, tc.rule)
			}
		})
	}
}
