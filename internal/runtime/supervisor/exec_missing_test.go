// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// missPolicies are the run shapes a miss is answered the same way in: a restricted run with a basename grant on PATH
// (R28's candidates), a deny-list and an allow-list run with command rules (ADR 0048), and a contract with no exec:
// section (deny nothing, the exec was continued and recorded allow unmatched before).
func missPolicies(t *testing.T) map[string]func() *Policy {
	return map[string]func() *Policy{
		"restricted":          searchPolicy,
		"deny-list commands":  func() *Policy { return commandPolicy(t, "deny: git push", "deny: rm -r") },
		"allow-list commands": func() *Policy { return commandPolicy(t, "allow: git status") },
		"no exec section":     func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) },
	}
}

// TestExecMissWritesNoLine is R16b (0): an exec whose pathname names nothing (the walk, made as the task's own lookup,
// met ENOENT or ENOTDIR) is answered with that errno by the loop, never continued, and writes no line at any record
// level, in every run shape; run_end's exec_missing counts it. A program started by name is one execve per PATH
// directory, and each miss was a refused line (restricted), an observed one (a PATH candidate, a run with command
// rules) or an allowed one (no exec: section): in the custom-agent POC seven tries of git push made 133 refused
// lines, and drift read exec[bash] as 25 allowed and 300 observed for 25 starts.
func TestExecMissWritesNoLine(t *testing.T) {
	nr := nrFor(t, "execve")
	misses := []struct {
		path string
		err  unix.Errno
	}{
		{"/opt/bin/python3", unix.ENOENT},           // a PATH candidate of the python3 grant
		{"/usr/local/bin/git", unix.ENOENT},         // a ruled tool's name in a directory that has none
		{"/usr/local/sbin/rm", unix.ENOENT},         // and another
		{"/work/file/git", unix.ENOTDIR},            // a component that is a file
		{"/work/dangling-link-to-git", unix.ENOENT}, // a symlink to nothing: the kernel's ENOENT too
	}
	for name, mk := range missPolicies(t) {
		for _, mode := range []agent.RecordMode{agent.RecordSummary, agent.RecordFull, agent.RecordOff} {
			t.Run(name+"/"+string(mode), func(t *testing.T) {
				f := newFake()
				for _, m := range misses {
					f.imageErrs[m.path] = m.err
				}
				pol := mk()
				pol.Rules.Record = mode
				l, sink := newTestLoop(t, f, pol)
				for i, m := range misses {
					execAt(l, f, nr, 42, i, m.path, "git", "push", "-r")
					got, _ := f.lastResp()
					if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(m.err) {
						t.Errorf("%s: response %+v, want %v answered by the loop, never CONTINUE", m.path, got, m.err)
					}
				}
				if evs := sink.all(); len(evs) != 0 {
					t.Errorf("%d lines for %d misses, want none: %+v", len(evs), len(misses), evs)
				}
				if got := l.Metrics().ExecMissing; got != int64(len(misses)) {
					t.Errorf("exec_missing = %d, want %d", got, len(misses))
				}
			})
		}
	}
}

// TestExecMissKeepsEveryRefusal: only a pathname that names nothing is a miss. An exec whose pathname names something
// keeps its decision and its line exactly as before R16b (0): a file no exec.allow entry grants, a command rule's
// refusal of a file that exists, a PATH candidate that holds a file, a script whose #! interpreter is missing (the
// script exists: interpreter-unresolved), a loader whose program is missing (loader-unresolved), and an image whose
// head cannot be read (image-unreadable). None counts as missing.
func TestExecMissKeepsEveryRefusal(t *testing.T) {
	nr := nrFor(t, "execve")
	const ld = "/lib64/ld-linux-x86-64.so.2"
	for _, c := range []struct {
		name    string
		pol     func() *Policy
		path    string
		argv    []string
		setup   func(f *fakeKernel)
		verdict record.Verdict
		rule    string
		errno   unix.Errno // 0: refusalErrno
	}{
		{"an unlisted file", searchPolicy, "/usr/bin/curl", []string{"curl"}, nil, record.VerdictRefused, ruleUnmatched, 0},
		{"a PATH candidate that holds a file", searchPolicy, "/usr/local/sbin/python3", []string{"python3"}, nil, record.VerdictObserved, "exec[python3]", 0},
		{"git push under a deny", func() *Policy { return commandPolicy(t, "deny: git push") }, "/usr/bin/git", []string{"git", "push"}, nil,
			record.VerdictRefused, "exec.deny[git push]", 0},
		{"git push unlisted", func() *Policy { return commandPolicy(t, "allow: git status") }, "/usr/bin/git", []string{"git", "push"}, nil,
			record.VerdictRefused, "exec.args[git]", 0},
		{"a missing #! interpreter", func() *Policy { return commandPolicy(t, "deny: python3") }, "/opt/x/tool", []string{"tool"},
			func(f *fakeKernel) {
				f.images["/opt/x/tool"] = execImage{id: fakeID("/opt/x/tool"), linked: true, link: "/opt/x/tool", here: true, head: []byte("#!/opt/none/python3\n")}
				f.imageErrs["/opt/none/python3"] = unix.ENOENT
			}, record.VerdictRefused, ruleInterpUnresolved, unix.ENOENT},
		// A script reached through a directory whose search answer was not sure (an access
		// ACL, a magic link of another process) may be one the task cannot reach, so its missing interpreter is answered
		// EACCES, the kernel's answer then, never ENOENT; and so is a missing interpreter of an interpreter reached so.
		{"a missing #! interpreter behind an unsure directory", func() *Policy { return commandPolicy(t, "deny: python3") }, "/opt/acl/tool", []string{"tool"},
			func(f *fakeKernel) {
				f.images["/opt/acl/tool"] = execImage{id: fakeID("/opt/acl/tool"), linked: true, link: "/opt/acl/tool", here: true, unsure: true, head: []byte("#!/opt/none/python3\n")}
				f.imageErrs["/opt/none/python3"] = unix.ENOENT
			}, record.VerdictRefused, ruleInterpUnresolved, 0},
		{"a missing interpreter of an interpreter behind an unsure directory", func() *Policy { return commandPolicy(t, "deny: python3") }, "/opt/x/tool", []string{"tool"},
			func(f *fakeKernel) {
				f.images["/opt/x/tool"] = execImage{id: fakeID("/opt/x/tool"), linked: true, link: "/opt/x/tool", here: true, head: []byte("#!/opt/acl/wrap\n")}
				f.images["/opt/acl/wrap"] = execImage{id: fakeID("/opt/acl/wrap"), linked: true, link: "/opt/acl/wrap", here: true, unsure: true, head: []byte("#!/opt/none/python3\n")}
				f.imageErrs["/opt/none/python3"] = unix.ENOENT
			}, record.VerdictRefused, ruleInterpUnresolved, 0},
		// A walk that failed in an autofs directory may have missed a mount the kernel's own
		// walk makes, so it is no miss: decided as before R16b (0), refused with its lookup's errno and recorded.
		{"a failure in an autofs directory", searchPolicy, "/auto/tools/git", []string{"git"},
			func(f *fakeKernel) { f.imageErrs["/auto/tools/git"] = automountLookup{unix.ENOENT} }, record.VerdictRefused, ruleUnmatched, unix.ENOENT},
		{"a loader's missing program", func() *Policy { return commandPolicy(t, "deny: rm -r") }, ld, []string{ld, "/work/gone", "-r", "t"},
			func(f *fakeKernel) {
				f.images[ld] = execImage{id: fakeID(ld), linked: true, link: ld, here: true, head: elfHead(3, 1)}
				f.imageErrs["/work/gone"] = unix.ENOENT
			}, record.VerdictRefused, ruleLoaderUnresolved, 0},
		{"an unreadable head", func() *Policy { return commandPolicy(t, "deny: rm -r") }, "/work/xonly", []string{"xonly"},
			func(f *fakeKernel) { f.headless = map[string]bool{"/work/xonly": true} }, record.VerdictRefused, ruleImageUnreadable, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			if c.setup != nil {
				c.setup(f)
			}
			l, sink := newTestLoop(t, f, c.pol())
			execAt(l, f, nr, 42, 0, c.path, c.argv...)
			got, _ := f.lastResp()
			want := c.errno
			if want == 0 {
				want = refusalErrno
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(want) {
				t.Errorf("response %+v, want %v answered by the loop", got, want)
			}
			ev := sink.one(t)
			if ev.Verdict != c.verdict || ev.Rule != c.rule {
				t.Errorf("line %s %s, want %s %s", ev.Verdict, ev.Rule, c.verdict, c.rule)
			}
			if m := l.Metrics().ExecMissing; m != 0 {
				t.Errorf("exec_missing = %d for a path that names something", m)
			}
		})
	}
}

// TestExecAutofsFailureIsContinuedWhereItWas: the walk's O_PATH lookup of an intermediate
// component does not mount an idle automount point the kernel's own walk mounts, so an exec under one failed the walk
// with ENOENT and was answered as a miss, with no line, where before R16b (0) a contract with no exec: section, or a
// granted spelling, continued it and it ran. A failure in an autofs directory is decided as it was: continued and
// recorded allowed, in an observe run too.
func TestExecAutofsFailureIsContinuedWhereItWas(t *testing.T) {
	for _, observe := range []bool{false, true} {
		t.Run(fmt.Sprintf("observe=%v", observe), func(t *testing.T) {
			f := newFake()
			f.imageErrs["/auto/tools/git"] = automountLookup{unix.ENOENT}
			pol := contractPolicy(&agent.Contract{}, nil, nil)
			pol.Observe = observe
			l, sink := newTestLoop(t, f, pol)
			execAt(l, f, nrFor(t, "execve"), 42, 0, "/auto/tools/git", "git", "status")
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Errorf("response %+v, want CONTINUE: the kernel's walk mounts what this walk did not", got)
			}
			want := record.VerdictAllow
			if observe {
				want = record.VerdictObserved // an observe run stamps every line observed (R30)
			}
			if ev := sink.one(t); ev.Verdict != want || execPayloadOf(t, ev).Path != "/auto/tools/git" {
				t.Errorf("line %s %q, want %s /auto/tools/git", ev.Verdict, execPayloadOf(t, ev).Path, want)
			}
			if m := l.Metrics().ExecMissing; m != 0 {
				t.Errorf("exec_missing = %d for a failure in an autofs directory", m)
			}
		})
	}
}

// TestExecUnsureWalkPerRunShape pins what an unsure walk's EACCES costs in each run shape (supervisor R16b, the walk).
// At tiers cgroup and bpflsm a walk that failed through a directory whose
// search answer for the task is not sure (a filesystem that decides by the caller, an access ACL) is answered EACCES,
// which is no miss (execMissing), so the exec is decided as any failed walk is. Only a run whose execs the supervisor
// decides answers it: refused with a refusal line in a restricted run, observed under the entry for a candidate of
// the run's own PATH search, observed under a command rule's run (never continued). Everywhere else the kernel answers
// with its own errno: a granted spelling and a contract with no exec: section are continued under an allow line, and a
// plane run with no command rules and no exec gate hands the exec to the kernel (its recorder writes the line, with the
// errno the kernel answered). The supervisor's 126 is the first shape only.
func TestExecUnsureWalkPerRunShape(t *testing.T) {
	const nfs = "/nfs/home/u/.local/bin"
	nr := nrFor(t, "execve")
	granted := func() *Policy {
		pol := testPolicy(nil, nil, nil)
		pol.Rules.Exec = []agent.ExecRule{{Raw: nfs + "/", Path: nfs, IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow}}
		return pol
	}
	for _, c := range []struct {
		name     string
		pol      func() *Policy
		handoff  bool // a decision plane takes the run's execs (the fast handover)
		path     string
		cont     bool           // continued: the kernel answers with its own errno
		verdict  record.Verdict // "": the loop writes no line
		rule     string
		recorded bool // the kernel recorder joins a handed-over attempt
	}{
		{"restricted", searchPolicy, false, nfs + "/git", false, record.VerdictRefused, ruleUnmatched, false},
		{"a PATH candidate", searchPolicy, false, "/usr/local/bin/python3", false, record.VerdictObserved, "exec[python3]", false},
		{"command rules", func() *Policy { return commandPolicy(t, "deny: git push") }, false, nfs + "/git", false, record.VerdictObserved, ruleUnmatched, false},
		{"a granted spelling", granted, false, nfs + "/git", true, record.VerdictAllow, "exec[" + nfs + "/]", false},
		{"no exec section", func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }, false, nfs + "/git", true, record.VerdictAllow, ruleUnmatched, false},
		{"restricted, handed to the plane", searchPolicy, true, nfs + "/git", true, "", "", true},
		{"no exec section, handed to the plane", func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }, true, nfs + "/git", true, "", "", true},
		{"command rules under a plane", func() *Policy { return commandPolicy(t, "deny: git push") }, true, nfs + "/git", false, record.VerdictObserved, ruleUnmatched, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 1, start: 1234}
			f.imageErrs[c.path] = unix.EACCES // walkImage's answer for a failed walk through an unsure directory
			pol := c.pol()
			pol.Rules.Tier = backend.TierCgroup
			l, sink := newTestLoop(t, f, pol)
			if c.handoff {
				l.kernelExecHandoff = func() bool { return true }
				l.mono = func() uint64 { return 100 }
			}
			execAt(l, f, nr, 42, 0, c.path, "git", "status")
			got, _ := f.lastResp()
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != c.cont {
				t.Errorf("response %+v, continued %v, want %v", got, cont, c.cont)
			}
			if !c.cont && got.Error != -int32(unix.EACCES) {
				t.Errorf("response %+v, want EACCES answered by the loop", got)
			}
			if c.verdict == "" {
				if evs := sink.all(); len(evs) != 0 {
					t.Errorf("the loop wrote %d lines for a handed-over exec: %+v", len(evs), evs)
				}
			} else if ev := sink.one(t); ev.Verdict != c.verdict || ev.Rule != c.rule || execPayloadOf(t, ev).Path != c.path {
				t.Errorf("line %s %s %q, want %s %s %q", ev.Verdict, ev.Rule, execPayloadOf(t, ev).Path, c.verdict, c.rule, c.path)
			}
			if n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick, 110); c.recorded && (!ok || n.SupervisorOwned || n.Path != c.path) {
				t.Errorf("handed-over attempt %+v, %v: want one the kernel recorder writes, named %s", n, ok, c.path)
			}
			if m := l.Metrics().ExecMissing; m != 0 {
				t.Errorf("exec_missing = %d for an unsure walk's EACCES", m)
			}
		})
	}
}

// TestExecMissUnderKernelRecorder: where a kernel recorder follows the run's execs (tiers cgroup and bpflsm), a miss
// leaves the supervisor-owned marker every exec the loop decides leaves, so the kernel's sample of the failed syscall
// is dropped rather than written as an exec of its own, and the fast handover (a run with no exec gate and no
// command rules) no longer continues it: the loop answers ENOENT itself, before handing anything to the kernel.
func TestExecMissUnderKernelRecorder(t *testing.T) {
	for name, mk := range missPolicies(t) {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 1, start: 1234}
			f.imageErrs["/usr/local/bin/git"] = unix.ENOENT
			l, sink := newTestLoop(t, f, mk())
			l.kernelExecHandoff = func() bool { return true }
			l.mono = func() uint64 { return 100 }
			execAt(l, f, nrFor(t, "execve"), 42, 0, "/usr/local/bin/git", "git", "push")
			got, _ := f.lastResp()
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.ENOENT) {
				t.Fatalf("response %+v, want ENOENT answered by the loop", got)
			}
			if len(sink.all()) != 0 {
				t.Errorf("a miss wrote a line under a kernel recorder")
			}
			n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick, 110)
			if !ok || !n.SupervisorOwned {
				t.Errorf("no supervisor-owned marker for the miss (%+v, %v): the kernel's failed sample would be written", n, ok)
			}
		})
	}
}

// TestExecMissObserveAnswersErrno: an observe run enforces nothing (R30), yet a miss is answered with its errno there
// too, never continued: the kernel answers the same errno, so nothing is enforced, while a continued miss is a second
// lookup that a file renamed into place after the walk wins, an exec that then runs with no line (and, under a kernel
// recorder, with its kernel record dropped by the supervisor-owned marker).
func TestExecMissObserveAnswersErrno(t *testing.T) {
	for _, recorder := range []bool{false, true} {
		for name, mk := range missPolicies(t) {
			t.Run(fmt.Sprintf("%s/recorder=%v", name, recorder), func(t *testing.T) {
				f := newFake()
				f.imageErrs["/usr/local/bin/git"] = unix.ENOENT
				f.imageErrs["/work/file/git"] = unix.ENOTDIR
				pol := mk()
				pol.Observe = true
				l, sink := newTestLoop(t, f, pol)
				if recorder {
					l.kernelExecHandoff = func() bool { return true }
				}
				for i, m := range []struct {
					path string
					err  unix.Errno
				}{{"/usr/local/bin/git", unix.ENOENT}, {"/work/file/git", unix.ENOTDIR}} {
					execAt(l, f, nrFor(t, "execve"), 42, i, m.path, "git")
					if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(m.err) {
						t.Errorf("%s: response %+v, want %v answered under observe, never CONTINUE", m.path, got, m.err)
					}
				}
				if len(sink.all()) != 0 || l.Metrics().ExecMissing != 2 {
					t.Errorf("observe: %d lines, exec_missing %d; want none and 2", len(sink.all()), l.Metrics().ExecMissing)
				}
			})
		}
	}
}
