// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// execFixture maps an argv into the fake address space: the pointer array at ptrAddr, the strings after it.
func execFixture(f *fakeKernel, ptrAddr uint64, argv []string) {
	ptrs := make([]byte, 8*(len(argv)+1))
	next := ptrAddr + 0x10000
	for i, a := range argv {
		putU64(ptrs[i*8:], next)
		f.put(next, cstr(a))
		next += uint64(len(a)) + 1 + 0x1000
	}
	f.put(ptrAddr, ptrs)
}

// emptyPathAddr holds "" in every fixture that names its image by descriptor: execveat honours
// AT_EMPTY_PATH only for an empty pathname, so the pointer must reach a real empty string, not an argv
// string an earlier fixture happened to leave at the same address.
const emptyPathAddr = 0x7f0000

// wantExecAnswer checks how the loop answered one exec (R16, R16b): an allowed exec is continued for
// Landlock to decide on the inode, and a refused one is refused by the loop itself with the refusal errno,
// never continued — a continued refusal is a ledger line the kernel may not honour.
func wantExecAnswer(t *testing.T, f *fakeKernel, v record.Verdict) {
	t.Helper()
	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response")
	}
	cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
	switch v {
	case record.VerdictRefused:
		if cont || got.Error != -int32(refusalErrno) || got.Val != -1 {
			t.Fatalf("response = %+v, want the loop's own refusal (error=-EACCES, val=-1): a refused exec is never continued (R16b)", got)
		}
	default:
		if !cont {
			t.Fatalf("response = %+v, want CONTINUE: Landlock's EXECUTE bit decides an allowed exec (R16)", got)
		}
	}
}

// TestExecRecordsArgv: the path and argv are read while the target is blocked, the syscall is
// continued, and the event carries the exec ids.
func TestExecRecordsArgv(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	nr := nrFor(t, "execve")
	f := newFake()
	f.put(pathAddr, cstr("/usr/bin/python3"))
	execFixture(f, argvAddr, []string{"python3", "-c", "print(1)"})
	f.tgid[4242] = 4200
	f.stats[4200] = procStat{ppid: 4100, start: 1234}
	f.stats[4100] = procStat{ppid: 1, start: 99}
	rt := []agent.ExecRule{{Path: "/usr/bin/python3", Source: agent.ExecSourceAllow}}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = rt
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nr, 4242, pathAddr, argvAddr, 0))

	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE: Landlock's EXECUTE bit enforces (R16)", got)
	}
	ev := sink.one(t)
	if ev.Kind != record.KindExec || ev.Source != record.SourceSeccomp {
		t.Errorf("kind/source = %s/%s", ev.Kind, ev.Source)
	}
	if ev.Verdict != record.VerdictAllow || ev.Rule != "exec[/usr/bin/python3]" {
		t.Errorf("verdict/rule = %s/%s, want allow/exec[/usr/bin/python3]", ev.Verdict, ev.Rule)
	}
	if ev.PID != 4200 {
		t.Errorf("pid = %d, want the thread group id 4200", ev.PID)
	}
	var p execPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.Path != "/usr/bin/python3" {
		t.Errorf("path = %q", p.Path)
	}
	if strings.Join(p.Argv, " ") != "python3 -c print(1)" {
		t.Errorf("argv = %q", p.Argv)
	}
	if p.ArgvTruncated {
		t.Error("argv_truncated on a small argv")
	}
	if want := pol.RunID + "/4200/12340000000"; p.ExecID != want {
		t.Errorf("exec_id = %q, want %q", p.ExecID, want)
	}
	if want := pol.RunID + "/4100/990000000"; p.ParentExecID != want {
		t.Errorf("parent_exec_id = %q, want %q", p.ParentExecID, want)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event does not validate: %v", err)
	}
}

// TestExecContinuedIsTheKernelsLineUnderThePlane is R7a at tier 3 (TIER3-PLAN T9): when the kernel decision plane
// decides the run's execs and a recorder reads the run (KernelExecs), an exec this loop allows is still continued,
// but its one line is the kernel's (the plane's refusal sample, or the exec record named by the plane's rule), so
// this loop writes none; an exec it refuses itself keeps its own line, since the kernel never sees it.
func TestExecContinuedIsTheKernelsLineUnderThePlane(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	nr := nrFor(t, "execve")
	for _, tc := range []struct {
		path    string
		kernel  bool
		verdict record.Verdict
		lines   int
	}{
		{"/usr/bin/python3", true, record.VerdictAllow, 0},
		{"/usr/bin/python3", false, record.VerdictAllow, 1},
		{"/usr/bin/unlisted", true, record.VerdictRefused, 1},
	} {
		f := newFake()
		f.put(pathAddr, cstr(tc.path))
		execFixture(f, argvAddr, []string{"x"})
		pol := testPolicy(nil, nil, nil)
		pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/python3", Source: agent.ExecSourceAllow}}
		l, sink := newTestLoop(t, f, pol)
		kernel := tc.kernel
		l.kernelExecs = func() bool { return kernel }
		l.handle(notifFor(nr, 4242, pathAddr, argvAddr, 0))
		wantExecAnswer(t, f, tc.verdict)
		if got := len(sink.all()); got != tc.lines {
			t.Errorf("%s with the kernel's lines %v: %d supervisor lines, want %d: %+v", tc.path, tc.kernel, got,
				tc.lines, sink.all())
		}
	}
}

// TestExecArgvBounds is R3/E10/E11: the byte budget and the entry cap both truncate and both say so.
func TestExecArgvBounds(t *testing.T) {
	nr := nrFor(t, "execve")
	tests := []struct {
		name      string
		argv      []string
		budget    int
		wantCount int
		truncated bool
	}{
		{name: "inside the budget", argv: []string{"a", "b"}, budget: 1024, wantCount: 2},
		{
			name: "budget exhausted", argv: []string{strings.Repeat("x", 64), strings.Repeat("y", 64), "z"},
			budget: 70, wantCount: 2, truncated: true,
		},
		{name: "entry cap", argv: manyArgs(argvEntries + 1), budget: 1 << 20, wantCount: argvEntries, truncated: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const pathAddr, argvAddr = 0x10000, 0x20000
			f := newFake()
			f.put(pathAddr, cstr("/bin/sh"))
			execFixture(f, argvAddr, tc.argv)
			pol := testPolicy(nil, nil, nil)
			pol.MaxArgvSize = tc.budget
			pol.Rules.Exec = []agent.ExecRule{{Path: "/bin/sh", Source: agent.ExecSourceAllow}}
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nr, 42, pathAddr, argvAddr, 0))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE even when truncated (E10)", got)
			}
			var p execPayload
			if err := sink.one(t).DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if len(p.Argv) != tc.wantCount {
				t.Errorf("argv entries = %d, want %d", len(p.Argv), tc.wantCount)
			}
			if p.ArgvTruncated != tc.truncated {
				t.Errorf("argv_truncated = %v, want %v", p.ArgvTruncated, tc.truncated)
			}
		})
	}
}

// TestExecveAtEmptyPath is the AT_EMPTY_PATH form: the binary is named by its descriptor alone.
func TestExecveAtEmptyPath(t *testing.T) {
	nr := nrFor(t, "execveat")
	const argvAddr = 0x20000
	f := newFake()
	f.links["/proc/42/fd/7"] = "/usr/bin/node"
	f.put(emptyPathAddr, cstr(""))
	execFixture(f, argvAddr, []string{"node"})
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/node", Source: agent.ExecSourceCommand}}
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nr, 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))
	wantExecAnswer(t, f, record.VerdictAllow)
	var p execPayload
	ev := sink.one(t)
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Path != "/usr/bin/node" {
		t.Errorf("path = %q, want the descriptor's target", p.Path)
	}
	if ev.Rule != "exec[/usr/bin/node]" {
		t.Errorf("rule = %q, want exec[/usr/bin/node]", ev.Rule)
	}
}

// TestExecAnonymousImageIsRefused: an anonymous image (a memfd, an anon_inode, or an unlinked
// file) is enforced by no tier below tier 3 — Landlock's file_open never governs a memfd, and tier 2's
// FAN_OPEN_EXEC_PERM sees no open a fexecve produces — so the supervisor is authoritative for it. It
// refuses the syscall itself (a real errno, not CONTINUE) and records the refusal it made, with the
// fileless flag, whether the image is reached by descriptor (AT_EMPTY_PATH) or by /proc/self/fd/N.
func TestExecAnonymousImageIsRefused(t *testing.T) {
	// The contract grants python3 by path; nothing names a runtime-created memfd, and nothing can.
	grant := []agent.ExecRule{{Path: "/usr/bin/python3", Source: agent.ExecSourceAllow}}
	tests := []struct {
		name     string
		syscall  string
		link     string // what /proc/<pid>/fd/<n> resolves to
		wantPath string
	}{
		{"memfd fexecve", "execveat", "/memfd:payload (deleted)", "/memfd:payload"},
		{"anon_inode fexecve", "execveat", "anon_inode:[userfaultfd]", "anon_inode:[userfaultfd]"},
		{"unlinked file fexecve", "execveat", "/tmp/dropped (deleted)", "/tmp/dropped"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const argvAddr = 0x20000
			f := newFake()
			f.links["/proc/42/fd/7"] = tc.link
			f.put(emptyPathAddr, cstr(""))
			execFixture(f, argvAddr, []string{"payload"})
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = grant
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, tc.syscall), 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))

			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want a refusal errno: no tier below tier 3 enforces a memfd exec (SEMANTICS §4)", got)
			}
			if got.Error == 0 || got.Val != -1 {
				t.Fatalf("response = %+v, want error=-E*, val=-1", got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonExecNotAllowed || ev.Rule != "exec-anon" {
				t.Errorf("verdict/reason/rule = %s/%s/%s, want refused/exec-not-allowed/exec-anon", ev.Verdict, ev.Reason, ev.Rule)
			}
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if !p.Fileless {
				t.Error("fileless flag not set on an anonymous-image exec")
			}
			if p.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", p.Path, tc.wantPath)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
		})
	}
}

// TestExecAnonymousImageBySpellingIsRefused is the anonymous-image refusal for every way of naming a descriptor by pathname:
// /proc/self/fd/N, its /dev/fd alias, a symlink the agent made to a descriptor, the per-task and
// thread-self directories, the thread group's /proc/<tgid>/fd from another thread, and a dirfd-relative
// execveat. The loop used to recognise two of these spellings and continue the rest as an unmatched exec
// recorded refused — which the kernel then ran. Anonymity is now decided on the image the walk reaches
// (execImage.fileless), so the spelling no longer matters: the fake maps each one to the memfd the real
// walk reaches (TestWalkExecReachesTheTasksDescriptor proves that half against the kernel).
func TestExecAnonymousImageBySpellingIsRefused(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	memfd := fakeImage("/memfd:payload (deleted)")
	for _, tc := range []struct {
		name    string
		syscall string
		dirfd   uint64
		path    string
		key     string // the R6 spelling the fake walk is keyed on
	}{
		{"/proc/self/fd", "execve", 0, "/proc/self/fd/3", "/proc/self/fd/3"},
		{"/dev/fd alias", "execve", 0, "/dev/fd/3", "/dev/fd/3"},
		{"agent symlink to a descriptor", "execve", 0, "/work/run", "/work/run"},
		{"per-task fd directory", "execve", 0, "/proc/self/task/42/fd/3", "/proc/self/task/42/fd/3"},
		{"thread-self", "execve", 0, "/proc/thread-self/fd/3", "/proc/thread-self/fd/3"},
		{"thread group's fd from another thread", "execve", 0, "/proc/40/fd/3", "/proc/40/fd/3"},
		{"dirfd-relative execveat", "execveat", 9, "3", "/proc/40/fd/3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			f.links["/proc/42/fd/9"] = "/proc/40/fd"
			f.images[tc.key] = memfd
			execFixture(f, argvAddr, []string{"payload"})
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/python3", Source: agent.ExecSourceAllow}}
			l, sink := newTestLoop(t, f, pol)
			if tc.syscall == "execveat" {
				l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.dirfd, pathAddr, argvAddr, 0, 0))
			} else {
				l.handle(notifFor(nrFor(t, tc.syscall), 42, pathAddr, argvAddr, 0))
			}
			wantExecAnswer(t, f, record.VerdictRefused)
			ev := sink.one(t)
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleExecAnon || !p.Fileless {
				t.Errorf("verdict/rule/fileless = %s/%s/%v, want refused/exec-anon/true", ev.Verdict, ev.Rule, p.Fileless)
			}
			if p.Path != "/memfd:payload" {
				t.Errorf("path = %q, want the image the kernel would load, not the spelling that named it", p.Path)
			}
		})
	}
}

// TestExecEmptyPathFlagWithAPathnameWalksThePathname: execveat honours AT_EMPTY_PATH only for an empty
// pathname. A non-empty one is resolved as usual, so a descriptor of a granted binary beside a pathname
// naming a memfd must be decided on the pathname — the loop used to read the descriptor on the flag alone
// and continue what the kernel then loaded from the pathname.
func TestExecEmptyPathFlagWithAPathnameWalksThePathname(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	f := newFake()
	f.put(pathAddr, cstr("/proc/self/fd/5"))
	f.links["/proc/42/fd/7"] = "/usr/bin/python3" // the granted binary, on the descriptor the flag names
	f.images["/proc/self/fd/5"] = fakeImage("/memfd:payload (deleted)")
	execFixture(f, argvAddr, []string{"payload"})
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/python3", Source: agent.ExecSourceAllow}}
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "execveat"), 42, 7, pathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))
	wantExecAnswer(t, f, record.VerdictRefused)
	if ev := sink.one(t); ev.Rule != ruleExecAnon {
		t.Errorf("rule = %s, want exec-anon: the pathname, not the descriptor, is what the kernel loads", ev.Rule)
	}
}

// TestExecMemfdNameCannotForgeAPath is the second half of the anonymous-image record: a memfd's name is the agent's to
// choose and may hold "/" and "..", and readlink reports it after "/memfd:". Cleaned, a memfd named
// "/../usr/local/bin/python3" read as the PATH-search candidate /usr/local/bin/python3 — continued as an
// observed search probe, so the memfd ran — and one named "/../usr/bin/python3" read as the granted binary.
// The image is classified before any spelling is matched, and its name is recorded raw.
func TestExecMemfdNameCannotForgeAPath(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	for _, tc := range []struct{ name, memfd string }{
		{"a PATH-search candidate", "/../usr/local/bin/python3"},
		{"the granted binary", "/../usr/bin/python3"},
	} {
		link := "/memfd:" + tc.memfd + deletedSuffix
		for _, form := range []string{"AT_EMPTY_PATH", "/proc/self/fd"} {
			t.Run(tc.name+" via "+form, func(t *testing.T) {
				f := newFake()
				execFixture(f, argvAddr, []string{"python3"})
				l, sink := newTestLoop(t, f, searchPolicy())
				if form == "AT_EMPTY_PATH" {
					f.links["/proc/42/fd/7"] = link
					f.put(emptyPathAddr, cstr(""))
					l.handle(notifFor(nrFor(t, "execveat"), 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))
				} else {
					f.put(pathAddr, cstr("/proc/self/fd/7"))
					f.images["/proc/self/fd/7"] = fakeImage(link)
					l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
				}
				wantExecAnswer(t, f, record.VerdictRefused)
				ev := sink.one(t)
				var p execPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if ev.Rule != ruleExecAnon || p.PathSearch || !p.Fileless {
					t.Errorf("rule/path_search/fileless = %s/%v/%v, want exec-anon/false/true", ev.Rule, p.PathSearch, p.Fileless)
				}
				if want := "/memfd:" + tc.memfd; p.Path != want {
					t.Errorf("path = %q, want the raw memfd name %q, never a cleaned disk path", p.Path, want)
				}
			})
		}
	}
}

// TestExecGrantedBinaryByAnotherSpelling is the other half of "no continued exec reads refused": a granted
// binary reached by a spelling that is not its entry's still runs, because Landlock's EXECUTE is bound to
// the inode, so the loop must record it allowed. The entry is /usr/bin/python3, a symlink to python3.13;
// the task execs the resolved path, a symlink of its own, and its own descriptor (a regular-file fexecve:
// the control case for anonymous images, which must keep running). A hard link is not another spelling of the entry but
// another name of the inode, and is refused (TestExecHardLinkOfGrantedBinaryIsRefused).
func TestExecGrantedBinaryByAnotherSpelling(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	real := fakeImage("/usr/bin/python3.13")
	for _, tc := range []struct {
		name string
		path string // "" for the descriptor form
	}{
		{"symlink-resolved path", "/usr/bin/python3.13"},
		{"agent symlink to the binary", "/work/py"},
		{"regular-file fexecve", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.statIDs["/usr/bin/python3"] = real.id // the entry resolves to python3.13, as stat(2) follows it
			f.evalLinks["/usr/bin/python3"] = "/usr/bin/python3.13"
			execFixture(f, argvAddr, []string{"python3", "-c", "print(1)"})
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Raw: "python3", Path: "/usr/bin/python3", Basename: "python3", ByName: true, Source: agent.ExecSourceAllow}}
			l, sink := newTestLoop(t, f, pol)
			if tc.path == "" {
				f.links["/proc/42/fd/7"] = "/usr/bin/python3.13"
				f.put(emptyPathAddr, cstr(""))
				l.handle(notifFor(nrFor(t, "execveat"), 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))
			} else {
				f.images[tc.path] = real
				f.put(pathAddr, cstr(tc.path))
				l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
			}
			wantExecAnswer(t, f, record.VerdictAllow)
			ev := sink.one(t)
			if ev.Verdict != record.VerdictAllow || ev.Rule != "exec[python3]" {
				t.Errorf("verdict/rule = %s/%s, want allow/exec[python3]: the kernel runs it (Landlock matches the inode)", ev.Verdict, ev.Rule)
			}
		})
	}
}

// TestExecDirectLoaderIsRefused is the half of the loader gap this tier can close (SEMANTICS §4): a directly-invoked ELF loader
// is an execve this loop sees. The loader holds EXECUTE as some granted binary's PT_INTERP, so Landlock
// runs it, and it then maps whatever file it is handed PROT_EXEC. It is not an exec.allow entry, so the
// loop refuses it itself — the line reads refused and nothing runs. The PROT_EXEC-mmap spelling makes no
// exec and stays tier 3's (SEMANTICS §4, GAPS C31).
func TestExecDirectLoaderIsRefused(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	f := newFake()
	f.put(pathAddr, cstr("/lib64/ld-linux-x86-64.so.2"))
	execFixture(f, argvAddr, []string{"/lib64/ld-linux-x86-64.so.2", "/usr/bin/getent", "passwd", "root"})
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{
		Path: "/usr/bin/python3", Interp: "/lib64/ld-linux-x86-64.so.2", Source: agent.ExecSourceAllow,
	}}
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
	wantExecAnswer(t, f, record.VerdictRefused)
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonExecNotAllowed {
		t.Errorf("verdict/reason = %s/%s, want refused/exec-not-allowed", ev.Verdict, ev.Reason)
	}
}

// TestExecNoContinuedRefusal sweeps the decisions this file drives and asserts the invariant the record
// owes: no exec the loop continued is recorded refused, and no exec it refused is
// continued. It runs each case through the whole handler, so a future branch that continues a refusal
// fails here whatever its spelling.
func TestExecNoContinuedRefusal(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	cases := []struct {
		name  string
		setup func(f *fakeKernel)
		path  string
	}{
		{"granted", nil, "/usr/bin/python3"},
		{"unlisted", nil, "/usr/bin/curl"},
		{"missing", func(f *fakeKernel) { f.imageErrs["/opt/tool"] = unix.ENOENT }, "/opt/tool"},
		{"candidate, missing", func(f *fakeKernel) { f.imageErrs["/opt/bin/python3"] = unix.ENOENT }, "/opt/bin/python3"},
		{"candidate, present", nil, "/usr/local/bin/python3"},
		{"memfd by path", func(f *fakeKernel) { f.images["/dev/fd/3"] = fakeImage("/memfd:x (deleted)") }, "/dev/fd/3"},
		{"loader", nil, "/lib64/ld-linux-x86-64.so.2"},
		{"walk cannot vouch", func(f *fakeKernel) { f.imageErrs["/proc/x"] = unix.EXDEV }, "/proc/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			if tc.setup != nil {
				tc.setup(f)
			}
			f.put(pathAddr, cstr(tc.path))
			execFixture(f, argvAddr, []string{"x"})
			l, sink := newTestLoop(t, f, searchPolicy())
			l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
			got, _ := f.lastResp()
			cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
			if strings.HasPrefix(tc.name, "missing") || strings.HasSuffix(tc.name, "missing") {
				// A miss (R16b (0)): answered with the walk's ENOENT, never continued, and no line.
				if cont || got.Error != -int32(unix.ENOENT) || len(sink.all()) != 0 {
					t.Errorf("a miss: response %+v, %d lines; want ENOENT answered by the loop and no line", got, len(sink.all()))
				}
				return
			}
			ev := sink.one(t)
			if cont && ev.Verdict == record.VerdictRefused {
				t.Errorf("continued an exec recorded refused (%s): the kernel may run it", ev.Rule)
			}
			if !cont && ev.Verdict == record.VerdictAllow {
				t.Errorf("refused an exec recorded allowed (%s)", ev.Rule)
			}
		})
	}
}

// TestExecAnonymousImageObserveContinues: an observe run enforces nothing (R30), so even an anonymous
// image is continued, recorded observed rather than refused. The bypass this closes is an enforcement
// one; observe only records.
func TestExecAnonymousImageObserveContinues(t *testing.T) {
	const argvAddr = 0x20000
	f := newFake()
	f.links["/proc/42/fd/7"] = "/memfd:payload (deleted)"
	f.put(emptyPathAddr, cstr(""))
	execFixture(f, argvAddr, []string{"payload"})
	pol := testPolicy(nil, nil, nil)
	pol.Observe = true
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "execveat"), 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))

	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE under observe (R30)", got)
	}
	ev := sink.one(t)
	if ev.Verdict != record.VerdictObserved {
		t.Errorf("verdict = %s, want observed under an observe run", ev.Verdict)
	}
	var p execPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if !p.Fileless {
		t.Error("fileless flag not set under observe")
	}
}

// TestExecAnonymousImageOptInIsAllowed is the opt-out half of the anonymous-image refusal: under a contract that set
// exec.anonymous: true, an anonymous image is continued rather than refused, and still recorded fileless —
// the walk is the record, never the enforcement, for a run that asked for it. The seccomp memfd arm is
// also absent for such a run (Prepare), so the image can be created; this is what happens when it is then
// exec'd.
func TestExecAnonymousImageOptInIsAllowed(t *testing.T) {
	const argvAddr = 0x20000
	f := newFake()
	f.links["/proc/42/fd/7"] = "/memfd:payload (deleted)"
	f.put(emptyPathAddr, cstr(""))
	execFixture(f, argvAddr, []string{"payload"})
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/python3", Source: agent.ExecSourceAllow}}
	pol.Rules.Contract = &agent.Contract{Exec: &agent.ExecSection{Allow: []string{"/usr/bin/python3"}, Anonymous: true}}
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "execveat"), 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))

	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE under exec.anonymous: true", got)
	}
	ev := sink.one(t)
	if ev.Verdict != record.VerdictAllow {
		t.Errorf("verdict = %s, want allow under exec.anonymous: true", ev.Verdict)
	}
	var p execPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if !p.Fileless {
		t.Error("fileless flag not set on an opted-in anonymous exec: the record must still say it was anonymous")
	}
}

// TestExecUnlistedIsRefusedByTheLoop: an exec no entry grants is refused by the loop itself (R16b). It
// used to be continued for Landlock to refuse, which made the refused line a claim about what the kernel
// would do — false for every spelling Landlock's inode rule allowed and the path match did not.
func TestExecUnlistedIsRefusedByTheLoop(t *testing.T) {
	nr := nrFor(t, "execve")
	const pathAddr, argvAddr = 0x10000, 0x20000
	f := newFake()
	f.put(pathAddr, cstr("/usr/bin/curl"))
	execFixture(f, argvAddr, []string{"curl", "https://example.com"})
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(nr, 42, pathAddr, argvAddr, 0))
	wantExecAnswer(t, f, record.VerdictRefused)
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonExecNotAllowed {
		t.Errorf("verdict/reason = %s/%s, want refused/exec-not-allowed", ev.Verdict, ev.Reason)
	}
}

// manyArgs builds n one-byte arguments.
func manyArgs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "a"
	}
	return out
}

// searchPolicy is the M0 demo's shape: a contract that granted python3 by basename, resolved on
// a PATH whose earlier directories hold no python3 at all, so glibc's execvp walks them first.
func searchPolicy() *Policy {
	pol := testPolicy(nil, nil, nil)
	pol.Rules.PATH = "/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/sbin"
	pol.Rules.Exec = []agent.ExecRule{{
		Raw: "python3", Path: "/usr/bin/python3", Basename: "python3", ByName: true, Source: agent.ExecSourceAllow,
	}}
	return pol
}

// execAt issues one execve notification from thread tid naming p with argv. slot picks a private range of
// the fake address space, so one fake target can hold several execs without its regions overlapping.
func execAt(l *Loop, f *fakeKernel, nr int32, tid, slot int, p string, argv ...string) {
	pathAddr := uint64(slot+1) * 0x100000
	argvAddr := pathAddr + 0x10000
	f.put(pathAddr, cstr(p))
	execFixture(f, argvAddr, argv)
	l.handle(notifFor(nr, tid, pathAddr, argvAddr, 0))
}

// TestExecPathSearchCandidates: a path the run's own PATH search has to try before the granted
// binary is recorded observed against the entry it is searching for, and everything outside that closed
// set still refuses. The bound is what the table is for: same basename is not enough.
func TestExecPathSearchCandidates(t *testing.T) {
	nr := nrFor(t, "execve")
	tests := []struct {
		name    string
		path    string
		spelled string // the pathname the task passes, when it is not path
		image   string // where the walk lands, when it is not path
		line    string // the path the line names, when it is not path
		present bool   // a file exists at the candidate
		verdict record.Verdict
		rule    string
		reason  record.Reason
		search  bool
	}{{
		name: "a directory PATH searches before the grant", path: "/usr/local/bin/python3",
		verdict: record.VerdictObserved, rule: "exec[python3]", search: true,
	}, {
		name: "the first directory on PATH", path: "/opt/bin/python3",
		verdict: record.VerdictObserved, rule: "exec[python3]", search: true,
	}, {
		name: "the granted binary itself", path: "/usr/bin/python3",
		verdict: record.VerdictAllow, rule: "exec[python3]",
	}, {
		// The search stops at the first execve that does not return, so it never reaches /sbin: an
		// execve naming it is the agent's own, not the search's.
		name: "a PATH directory after the grant", path: "/sbin/python3",
		verdict: record.VerdictRefused, rule: ruleUnmatched, reason: record.ReasonExecNotAllowed,
	}, {
		name: "the same basename off PATH", path: "/tmp/python3",
		verdict: record.VerdictRefused, rule: ruleUnmatched, reason: record.ReasonExecNotAllowed,
	}, {
		name: "another basename in a PATH directory", path: "/usr/local/bin/nmap",
		verdict: record.VerdictRefused, rule: ruleUnmatched, reason: record.ReasonExecNotAllowed,
	}, {
		name: "a basename nothing granted", path: "/usr/local/bin/curl",
		verdict: record.VerdictRefused, rule: ruleUnmatched, reason: record.ReasonExecNotAllowed,
	}, {
		// Something the run's PATH search reaches before the grant exists at the candidate: it is still the
		// search's probe, but the loop answers it EACCES itself — Landlock would have, since nothing grants
		// it — rather than continuing a file planted there.
		name: "a candidate that exists", path: "/usr/local/sbin/python3", present: true,
		verdict: record.VerdictObserved, rule: "exec[python3]", search: true,
	}, {
		// R6 cleans ".." lexically, so this spelling cleans to a candidate; the kernel resolves it
		// physically, through link, a symlink the agent made, and would load a file elsewhere. It is the
		// agent reaching for that file, not the search, and the line names that file where the image walk
		// landed its directory (execImage.name): it named the candidate, a refusal of /usr/local/bin/python3 that
		// was never asked (2c6-1).
		name: "a candidate spelled through ..", path: "/usr/local/bin/python3",
		spelled: "/usr/local/bin/link/../python3", image: "/tmp/evil/python3", line: "/tmp/evil/python3",
		verdict: record.VerdictRefused, rule: ruleUnmatched, reason: record.ReasonExecNotAllowed,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			if tc.search && !tc.present {
				// The common case R28 exists for: the directory holds no such name.
				f.imageErrs[tc.path] = unix.ENOENT
			}
			if tc.image != "" {
				img := fakeImage(tc.image)
				// Where the image walk landed the spelling's directory, with its final name: the line's name
				// (execImage.name).
				img.name = tc.line
				f.images[tc.path] = img
			}
			spelled := tc.path
			if tc.spelled != "" {
				spelled = tc.spelled
			}
			l, sink := newTestLoop(t, f, searchPolicy())
			execAt(l, f, nr, 42, 0, spelled, "python3", "-c", "print(1)")
			got, _ := f.lastResp()
			switch {
			case tc.search:
				// A candidate is answered by the loop with its own lookup's errno, so the search walks on
				// exactly as when the kernel answered it, and nothing planted after the walk can run.
				want := -int32(unix.ENOENT)
				if tc.present {
					want = -int32(refusalErrno)
				}
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != want {
					t.Fatalf("response = %+v, want error %d and no CONTINUE (R28, R16b)", got, want)
				}
			default:
				wantExecAnswer(t, f, tc.verdict)
			}
			if tc.search && !tc.present {
				// The directory holds no such name: a miss (R16b (0)), which writes no line at all, so the search
				// leaves only its start in the record.
				if evs := sink.all(); len(evs) != 0 {
					t.Errorf("a missing candidate wrote %d lines, want none", len(evs))
				}
				return
			}
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule || ev.Reason != tc.reason {
				t.Errorf("verdict/rule/reason = %s/%s/%s, want %s/%s/%s",
					ev.Verdict, ev.Rule, ev.Reason, tc.verdict, tc.rule, tc.reason)
			}
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.PathSearch != tc.search {
				t.Errorf("path_search = %v, want %v", p.PathSearch, tc.search)
			}
			line := tc.path
			if tc.line != "" {
				line = tc.line
			}
			if p.Path != line {
				t.Errorf("path = %q, want %q: the candidate keeps its own line (R28), and a spelling through .. names where it landed", p.Path, line)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
		})
	}
}

// TestExecPathSearchIsNotBasenameMatching bounds R28 against the declared form: an entry named by path or
// by directory is executed by that path and never searched for, so its PATH neighbours stay refused even
// though they share its basename.
func TestExecPathSearchIsNotBasenameMatching(t *testing.T) {
	nr := nrFor(t, "execve")
	tests := []struct {
		name string
		rule agent.ExecRule
	}{{
		name: "declared by path",
		rule: agent.ExecRule{
			Raw: "/usr/bin/python3", Path: "/usr/bin/python3", Basename: "python3",
			Source: agent.ExecSourceAllow,
		},
	}, {
		name: "declared as a directory",
		rule: agent.ExecRule{
			Raw: "/usr/bin/", Path: "/usr/bin", Basename: "bin", IsDir: true, Source: agent.ExecSourceAllow,
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol := searchPolicy()
			pol.Rules.Exec = []agent.ExecRule{tc.rule}
			f := newFake()
			l, sink := newTestLoop(t, f, pol)
			execAt(l, f, nr, 42, 0, "/usr/local/bin/python3", "python3")
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonExecNotAllowed {
				t.Errorf("verdict/reason = %s/%s, want refused/exec-not-allowed: only a basename entry "+
					"searches PATH (R28)", ev.Verdict, ev.Reason)
			}
		})
	}
}

// TestExecPathSearchInterleaved is the two-thread case R28 is stateless for: two threads of one process
// walk PATH at the same time, their notifications arrive interleaved, and each execve decides on its own
// path alone. Neither thread's probe is charged to the other, and both successes are allowed.
func TestExecPathSearchInterleaved(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	f.tgid[4242], f.tgid[4243] = 4200, 4200
	f.stats[4200] = procStat{ppid: 4100, start: 1234}
	l, sink := newTestLoop(t, f, searchPolicy())
	// Thread A and thread B alternate: A probes, B probes, A probes, B succeeds, A succeeds.
	steps := []struct {
		tid  int
		path string
	}{
		{4242, "/opt/bin/python3"},
		{4243, "/opt/bin/python3"},
		{4242, "/usr/local/sbin/python3"},
		{4243, "/usr/bin/python3"},
		{4242, "/usr/bin/python3"},
	}
	for i, s := range steps {
		execAt(l, f, nr, s.tid, i, s.path, "python3", "-c", "print(1)")
	}
	evs := sink.all()
	if len(evs) != len(steps) {
		t.Fatalf("got %d events, want one per execve (%d)", len(evs), len(steps))
	}
	for i, ev := range evs {
		want := record.VerdictObserved
		if steps[i].path == "/usr/bin/python3" {
			want = record.VerdictAllow
		}
		if ev.Verdict != want {
			t.Errorf("event %d (%s, tid %d): verdict %s, want %s", i, steps[i].path, steps[i].tid, ev.Verdict, want)
		}
		if ev.Rule != "exec[python3]" {
			t.Errorf("event %d: rule %q, want exec[python3]", i, ev.Rule)
		}
		if ev.TID != steps[i].tid {
			t.Errorf("event %d: tid %d, want %d", i, ev.TID, steps[i].tid)
		}
		if ev.PID != 4200 {
			t.Errorf("event %d: pid %d, want the thread group id 4200", i, ev.PID)
		}
	}
}

// TestExecPathSearchExhausted covers the search that never succeeds. A basename no entry granted has no
// candidates at all, so every directory it walks is a refusal the ledger keeps: R28 removes the noise of a
// search that reaches a grant, never the record of one that does not.
func TestExecPathSearchExhausted(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	l, sink := newTestLoop(t, f, searchPolicy())
	dirs := []string{"/opt/bin", "/usr/local/sbin", "/usr/local/bin", "/usr/bin", "/sbin"}
	for i, d := range dirs {
		execAt(l, f, nr, 42, i, d+"/nmap", "nmap", "-sS", "10.0.0.0/24")
	}
	evs := sink.all()
	if len(evs) != len(dirs) {
		t.Fatalf("got %d events, want one per execve (%d)", len(evs), len(dirs))
	}
	for i, ev := range evs {
		if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonExecNotAllowed {
			t.Errorf("event %d (%s): verdict/reason = %s/%s, want refused/exec-not-allowed",
				i, dirs[i], ev.Verdict, ev.Reason)
		}
	}
}

// TestExecPathSearchAbandoned is the search that starts and stops: the probes stand on their own as
// non-decisions, and nothing in the ledger claims an exec happened. R28 needs no completion to be right,
// which is why it holds no state waiting for one.
func TestExecPathSearchAbandoned(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	l, sink := newTestLoop(t, f, searchPolicy())
	execAt(l, f, nr, 42, 0, "/opt/bin/python3", "python3")
	execAt(l, f, nr, 42, 1, "/usr/local/sbin/python3", "python3")
	evs := sink.all()
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2", len(evs))
	}
	for i, ev := range evs {
		if ev.Verdict != record.VerdictObserved {
			t.Errorf("event %d: verdict %s, want observed", i, ev.Verdict)
		}
		if ev.Kind != record.KindExec {
			t.Errorf("event %d: kind %s, want exec", i, ev.Kind)
		}
	}
}

// TestExecPathSearchRecordOff is the record: off half of R28: a candidate is neither a refusal nor a
// decision, so it is as quiet as an allowed exec, while a real forbidden binary is still recorded.
func TestExecPathSearchRecordOff(t *testing.T) {
	nr := nrFor(t, "execve")
	pol := searchPolicy()
	pol.Record = agent.RecordOff
	f := newFake()
	l, sink := newTestLoop(t, f, pol)
	execAt(l, f, nr, 42, 0, "/opt/bin/python3", "python3")
	execAt(l, f, nr, 42, 1, "/usr/bin/python3", "python3")
	if evs := sink.all(); len(evs) != 0 {
		t.Fatalf("record: off recorded %d events for a PATH search, want none: %+v", len(evs), evs)
	}
	execAt(l, f, nr, 42, 2, "/usr/local/bin/nmap", "nmap")
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused {
		t.Errorf("verdict %s, want refused: record: off never suppresses a refusal", ev.Verdict)
	}
}

// TestExecPathSearchSurvivesACommandDeclaredByPath is R28 against the compiled table rather than a
// hand-written one.
//
// compile_exec.go collapses every spelling that resolves to one file into one rule and keeps the first
// spelling in Raw, so `command: ["/usr/bin/python3"]` beside `exec.allow: ["python3"]` compiles to a rule
// whose Raw is the path and whose ByName records that the author also wrote the basename. pathSearchSet
// read Raw, saw a path and produced no candidates, so the run's own execvp probes of /opt/bin/python3 and
// its neighbours were recorded refused/exec-not-allowed — drift for a search the contract asked for.
func TestExecPathSearchSurvivesACommandDeclaredByPath(t *testing.T) {
	nr := nrFor(t, "execve")
	pol := searchPolicy()
	pol.Rules.Exec = []agent.ExecRule{{
		Raw: "/usr/bin/python3", Path: "/usr/bin/python3", Basename: "python3", ByName: true,
		Source: agent.ExecSourceCommand + "," + agent.ExecSourceAllow,
	}}
	f := newFake()
	l, sink := newTestLoop(t, f, pol)
	execAt(l, f, nr, 42, 0, "/opt/bin/python3", "python3")
	ev := sink.one(t)
	if ev.Verdict != record.VerdictObserved || ev.Rule != "exec[/usr/bin/python3]" {
		t.Errorf("verdict/rule = %s/%s, want observed/exec[/usr/bin/python3]: the basename spelling "+
			"still searches PATH (R28)", ev.Verdict, ev.Rule)
	}
	var p execPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if !p.PathSearch {
		t.Error("path_search = false for a candidate of a basename the author declared")
	}
}

// TestPathSearchSetBounds checks the candidate table itself, which is where R28's bound lives.
func TestPathSearchSetBounds(t *testing.T) {
	tests := []struct {
		name string
		rt   *agent.RuleTable
		want map[string]string
	}{{
		name: "no PATH, no candidates",
		rt: &agent.RuleTable{Exec: []agent.ExecRule{
			{Raw: "python3", Path: "/usr/bin/python3", ByName: true, Source: agent.ExecSourceAllow},
		}},
	}, {
		name: "the grant is not on the run's PATH",
		rt: &agent.RuleTable{PATH: "/opt/bin:/usr/bin", Exec: []agent.ExecRule{
			{Raw: "python3", Path: "/snap/bin/python3", ByName: true, Source: agent.ExecSourceAllow},
		}},
	}, {
		// An empty element is the cwd and a relative one is resolved against it; this package has no
		// cwd at policy time, so neither becomes a candidate (fail closed).
		name: "empty and relative PATH elements are skipped",
		rt: &agent.RuleTable{PATH: ":bin:/opt/bin:/usr/bin", Exec: []agent.ExecRule{
			{Raw: "python3", Path: "/usr/bin/python3", ByName: true, Source: agent.ExecSourceAllow},
		}},
		want: map[string]string{"/opt/bin/python3": "exec[python3]"},
	}, {
		name: "one entry per PATH element before the grant, deduplicated",
		rt: &agent.RuleTable{PATH: "/opt/bin:/opt/bin/:/usr/bin", Exec: []agent.ExecRule{
			{Raw: "python3", Path: "/usr/bin/python3", ByName: true, Source: agent.ExecSourceAllow},
		}},
		want: map[string]string{"/opt/bin/python3": "exec[python3]"},
	}, {
		// compile_exec.go keeps the first spelling in Raw when two entries resolve to one file; ByName
		// is what says one of them was a basename.
		name: "a basename merged into an entry declared by path",
		rt: &agent.RuleTable{PATH: "/opt/bin:/usr/bin", Exec: []agent.ExecRule{
			{Raw: "/usr/bin/python3", Path: "/usr/bin/python3", ByName: true, Source: agent.ExecSourceCommand},
		}},
		want: map[string]string{"/opt/bin/python3": "exec[/usr/bin/python3]"},
	}, {
		name: "declared by path alone",
		rt: &agent.RuleTable{PATH: "/opt/bin:/usr/bin", Exec: []agent.ExecRule{
			{Raw: "/usr/bin/python3", Path: "/usr/bin/python3", Source: agent.ExecSourceCommand},
		}},
	}, {
		name: "two basename entries each get their own prefix",
		rt: &agent.RuleTable{PATH: "/opt/bin:/usr/bin", Exec: []agent.ExecRule{
			{Raw: "python3", Path: "/usr/bin/python3", ByName: true, Source: agent.ExecSourceCommand},
			{Raw: "rg", Path: "/usr/bin/rg", ByName: true, Source: agent.ExecSourceAllow},
		}},
		want: map[string]string{
			"/opt/bin/python3": "exec[python3]",
			"/opt/bin/rg":      "exec[rg]",
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pathSearchSet(tc.rt)
			if len(got) != len(tc.want) {
				t.Fatalf("candidates = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("candidate %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestExecDropAndExecuteIsFlagged is the dropped flag's other half: an exec whose image the run itself wrote under a
// write entry — its inode changed after the loop started — carries dropped, allowed or refused alike, so a
// drop-and-execute is visible in the record without a join. A binary outside every write entry, or one
// that last changed before the run, is not flagged. The flag is judged where the kernel spells the image
// (imageWhere), confirmed in this process's view or not: an agent that made the image's directory unsearchable, so
// the walk could not confirm the spelling, and ran it through a descriptor, hid the flag.
// An unconfirmed removed name is judged without its " (deleted)" marker (imageWhere): the two cases whose fs
// entries name the file itself are flagged, and left unflagged, only on the name without it (under the /work/proj
// entry alone the marker changed no answer, so nothing pinned it).
func TestExecDropAndExecuteIsFlagged(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	proj := []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite, Raw: "./proj"}}
	ownWrite := []agent.FSRule{{Path: "/work/proj/sub/tool", Kind: agent.FSWrite, Raw: "./proj/sub/tool"}}
	deniedUnder := []agent.FSRule{proj[0], {Path: "/work/proj/sub/tool", Kind: agent.FSDenyRead, Raw: "./proj/sub/tool"}}
	for _, tc := range []struct {
		name    string
		path    string
		grant   bool
		before  bool   // the image last changed before the loop started
		via     string // the exec's spelling when it is not the image's path: the image's own descriptor
		hidden  bool   // the walk could not confirm the kernel's spelling here (execImage.here false)
		fs      []agent.FSRule
		dropped bool
		verdict record.Verdict
	}{
		{"written in the run and granted", "/work/proj/bin/tool", true, false, "", false, proj, true, record.VerdictAllow},
		{"written in the run and refused", "/work/proj/bin/tool", false, false, "", false, proj, true, record.VerdictRefused},
		{"older than the run", "/work/proj/bin/tool", true, true, "", false, proj, false, record.VerdictAllow},
		{"changed outside every write entry", "/usr/bin/tool", false, false, "", false, proj, false, record.VerdictRefused},
		{"written in the run, its directory unsearchable, run through its descriptor", "/work/proj/sub/tool", false, false, "/proc/42/fd/7", true, proj, true, record.VerdictRefused},
		{"a removed name another link outlives, run through its descriptor", "/work/proj/sub/tool (deleted)", false, false, "/proc/42/fd/7", true, proj, true, record.VerdictRefused},
		{"a removed name whose write entry names it", "/work/proj/sub/tool (deleted)", false, false, "/proc/42/fd/7", true, ownWrite, true, record.VerdictRefused},
		{"a removed name a deny_read under the write entry names", "/work/proj/sub/tool (deleted)", false, false, "/proc/42/fd/7", true, deniedUnder, false, record.VerdictRefused},
		{"unconfirmed and outside every write entry", "/usr/lib/tool", false, false, "/proc/42/fd/7", true, proj, false, record.VerdictRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			pol := testPolicy(nil, tc.fs, nil)
			if tc.grant {
				pol.Rules.Exec = []agent.ExecRule{{Raw: "./proj/bin/", Path: "/work/proj/bin", IsDir: true, Source: agent.ExecSourceAllow}}
			}
			l, sink := newTestLoop(t, f, pol)
			img := fakeImage(tc.path)
			img.changed = l.started.Add(time.Second)
			if tc.before {
				img.changed = l.started.Add(-time.Hour)
			}
			spelled := tc.path
			if tc.via != "" {
				spelled = tc.via
			}
			if tc.hidden {
				img.linked, img.here = true, false
			}
			f.images[spelled] = img
			f.put(pathAddr, cstr(spelled))
			execFixture(f, argvAddr, []string{"tool"})
			l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
			wantExecAnswer(t, f, tc.verdict)
			ev := sink.one(t)
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || p.Dropped != tc.dropped {
				t.Errorf("verdict/dropped = %s/%v, want %s/%v", ev.Verdict, p.Dropped, tc.verdict, tc.dropped)
			}
		})
	}
}

// TestExecNamedByTheWalkWhenTheJoinFails: an exec whose pathname R6 cannot name — its join to the cwd longer
// than PATH_MAX, or the cwd unreadable — while the walk from the task's own cwd reached a file is recorded
// under that file, where the kernel's exec lands, not under "" or a relative name nobody can place.
func TestExecNamedByTheWalkWhenTheJoinFails(t *testing.T) {
	nr := nrFor(t, "execve")
	long := "/"
	for len(long) < pathMax {
		long += "d/"
	}
	for _, tc := range []struct {
		name, cwd, joined string
	}{
		{"a join past PATH_MAX", long, ""},
		{"an unreadable cwd", "", "bin/tool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			if tc.cwd != "" {
				f.links["/proc/42/cwd"] = tc.cwd
			}
			f.images[tc.joined] = fakeImage("/opt/tool/bin/tool")
			l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
			execAt(l, f, nr, 42, 0, "bin/tool", "tool")
			ev := sink.one(t)
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Path != "/opt/tool/bin/tool" {
				t.Errorf("path = %q (verdict %s), want /opt/tool/bin/tool, the file the walk reached", p.Path, ev.Verdict)
			}
		})
	}
}

// TestExecWalkFailsOtherThanLookup: when the walk of an exec fails other than as the task's own
// lookup would (EMFILE, ENFILE, ENOMEM, EIO in this process, EXDEV), the spelling is never verified, so it
// admits no grant: the exec is refused path-unreliable, answered by this loop, and never continued. A
// lookup-class failure (ELOOP) keeps the spelling match, as the kernel's own exec fails there too. Under a
// contract with no exec: section the exec is still continued (deny nothing).
func TestExecWalkFailsOtherThanLookup(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	const p = "/work/bin/x"
	for _, tc := range []struct {
		name         string
		err          error
		unrestricted bool
		verdict      record.Verdict
		rule         string
	}{
		{"EMFILE", unix.EMFILE, false, record.VerdictRefused, rulePathUnreliable},
		{"ENFILE", unix.ENFILE, false, record.VerdictRefused, rulePathUnreliable},
		{"ENOMEM", unix.ENOMEM, false, record.VerdictRefused, rulePathUnreliable},
		{"EIO", unix.EIO, false, record.VerdictRefused, rulePathUnreliable},
		{"EXDEV", unix.EXDEV, false, record.VerdictRefused, rulePathUnreliable},
		// ENOENT and ENOTDIR are misses, answered with no line (R16b (0), TestExecMissWritesNoLine).
		{"ELOOP keeps the spelling", unix.ELOOP, false, record.VerdictAllow, "exec[/work/bin/]"},
		{"EMFILE, no exec: section", unix.EMFILE, true, record.VerdictAllow, ruleUnmatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.imageErrs[p] = tc.err
			f.put(pathAddr, cstr(p))
			execFixture(f, argvAddr, []string{"x"})
			pol := contractPolicy(&agent.Contract{}, nil, nil)
			if !tc.unrestricted {
				pol = testPolicy(nil, nil, nil)
				pol.Rules.Exec = []agent.ExecRule{{Raw: "/work/bin/", Path: "/work/bin", IsDir: true, Source: agent.ExecSourceAllow}}
			}
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
			wantExecAnswer(t, f, tc.verdict)
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
			if tc.verdict == record.VerdictRefused && ev.Reason != record.ReasonExecNotAllowed {
				t.Errorf("reason = %s, want %s", ev.Reason, record.ReasonExecNotAllowed)
			}
		})
	}
}
