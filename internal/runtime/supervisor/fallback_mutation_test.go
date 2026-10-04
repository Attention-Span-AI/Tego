// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fallbackContract is ADR0021(5)'s shape: a deny_read nested in a write entry, with a write entry regranted
// inside it, at the tier whose listener decides opens and execs when no plane mode is selected.
const fallbackContract = `version: 0
name: fixture
command: [fixture]
tier: %s
capture: off
fs:
  write: [work, work/secret/open]
  deny_read: [work/secret]
net: {}
`

// fallbackTree is the project fallbackContract's entries name.
func fallbackTree() contracttest.Tree {
	return contracttest.Tree{"work/secret/open/": "", "work/plain/": ""}
}

// fallbackLoop is a loop deciding by compiled's rules. Each test compiles its own fixture with contracttest.Build in
// its own body, which contracttest's fixture gate (TestRuntimeFixturesAreCompiledOrExplicitSyntheticInputs) reads.
func fallbackLoop(t *testing.T, f *fakeKernel, compiled *contracttest.Fixture) (*Loop, *testSink) {
	t.Helper()
	pol := testPolicy(nil, nil, nil)
	pol.Rules = compiled.Rules
	return newTestLoop(t, f, pol)
}

// The addresses a mutation's ends are read from: the end under test, and a two-path syscall's other end (or a
// symlink's target text).
const (
	mutatedAddr = 0x10000
	otherAddr   = 0x11000
)

// fallbackCase is one syscall TestFallbackMutationConverges drives.
type fallbackCase struct {
	name, syscall string
	args          []uint64
	// other is the other end's path below work/ (the source a link or rename moves into the tree, the
	// partner of an exchange); target is a symlink's text.
	other, target string
	exchange      bool
	// legacy marks a dirfd-less form, which exists on x86-64 only (dispatch.go): arm64's generic table has none of
	// open, creat, mkdir, rmdir, unlink, mknod, symlink, link or rename, and the *at forms beside them in the table
	// cover it there.
	legacy bool
}

// fallbackMutationCases is TestFallbackMutationConverges' table for arch: thirty syscall forms on x86-64,
// twenty on arm64. A case the architecture lacks is left out rather than skipped, so CI's unit skip gate (test/unit-skips.txt)
// sees no skip on an arm64 runner.
func fallbackMutationCases(arch uint32) []fallbackCase {
	var out []fallbackCase
	for _, tc := range []fallbackCase{
		{name: "mkdirat", syscall: "mkdirat", args: []uint64{argCWD, mutatedAddr, 0o700}},
		{name: "mkdir", syscall: "mkdir", legacy: true, args: []uint64{mutatedAddr, 0o700}},
		{name: "unlinkat", syscall: "unlinkat", args: []uint64{argCWD, mutatedAddr, 0}},
		{name: "unlinkat AT_REMOVEDIR", syscall: "unlinkat", args: []uint64{argCWD, mutatedAddr, unix.AT_REMOVEDIR}},
		{name: "rmdir", syscall: "rmdir", legacy: true, args: []uint64{mutatedAddr}},
		{name: "truncate", syscall: "truncate", args: []uint64{mutatedAddr, 0}},
		{name: "mknodat", syscall: "mknodat", args: []uint64{argCWD, mutatedAddr, unix.S_IFIFO | 0o600, 0}},
		{name: "creat", syscall: "creat", legacy: true, args: []uint64{mutatedAddr, 0o600}},
		{name: "openat O_CREAT", syscall: "openat", args: []uint64{argCWD, mutatedAddr, unix.O_WRONLY | unix.O_CREAT, 0o600}},
		{name: "openat O_CREAT|O_EXCL", syscall: "openat", args: []uint64{argCWD, mutatedAddr, unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL, 0o600}},
		// The write opens without O_CREAT: the filter notifies an open with any WriteFlagMask bit
		// (landlock/filter.go), O_TRUNC alone included, and O_TMPFILE carries O_WRONLY or O_RDWR. Each is a
		// write fallbackMutation refuses under the nested deny_read; the *at form keeps them on arm64 too.
		{name: "openat O_WRONLY", syscall: "openat", args: []uint64{argCWD, mutatedAddr, unix.O_WRONLY, 0}},
		{name: "openat O_RDWR", syscall: "openat", args: []uint64{argCWD, mutatedAddr, unix.O_RDWR, 0}},
		{name: "openat O_WRONLY|O_TRUNC", syscall: "openat", args: []uint64{argCWD, mutatedAddr, unix.O_WRONLY | unix.O_TRUNC, 0}},
		{name: "openat O_RDONLY|O_TRUNC", syscall: "openat", args: []uint64{argCWD, mutatedAddr, unix.O_RDONLY | unix.O_TRUNC, 0}},
		{name: "openat O_WRONLY|O_TMPFILE", syscall: "openat", args: []uint64{argCWD, mutatedAddr, unix.O_WRONLY | unix.O_TMPFILE, 0o600}},
		{name: "symlinkat", syscall: "symlinkat", args: []uint64{otherAddr, argCWD, mutatedAddr}, target: "../anywhere"},
		{name: "linkat into", syscall: "linkat", args: []uint64{argCWD, otherAddr, argCWD, mutatedAddr, 0}, other: "plain/src"},
		{name: "renameat into", syscall: "renameat", args: []uint64{argCWD, otherAddr, argCWD, mutatedAddr}, other: "plain/src"},
		{name: "renameat2 into", syscall: "renameat2", args: []uint64{argCWD, otherAddr, argCWD, mutatedAddr, 0}, other: "plain/src"},
		{name: "renameat2 RENAME_EXCHANGE into", syscall: "renameat2",
			args: []uint64{argCWD, otherAddr, argCWD, mutatedAddr, unix.RENAME_EXCHANGE}, other: "plain/src", exchange: true},
		{name: "renameat2 RENAME_EXCHANGE out", syscall: "renameat2",
			args: []uint64{argCWD, mutatedAddr, argCWD, otherAddr, unix.RENAME_EXCHANGE}, other: "plain/src", exchange: true},
		{name: "renameat2 RENAME_NOREPLACE into", syscall: "renameat2",
			args: []uint64{argCWD, otherAddr, argCWD, mutatedAddr, unix.RENAME_NOREPLACE}, other: "plain/src"},
		{name: "linkat AT_SYMLINK_FOLLOW into", syscall: "linkat",
			args: []uint64{argCWD, otherAddr, argCWD, mutatedAddr, unix.AT_SYMLINK_FOLLOW}, other: "plain/src"},
		// The legacy forms beside the *at ones: the filter notifies each (landlock/filter.go), and each is a
		// mutation fallbackMutation must refuse as its *at form is.
		{name: "open O_CREAT", syscall: "open", legacy: true, args: []uint64{mutatedAddr, unix.O_WRONLY | unix.O_CREAT, 0o600}},
		{name: "open O_TRUNC", syscall: "open", legacy: true, args: []uint64{mutatedAddr, unix.O_WRONLY | unix.O_TRUNC, 0}},
		{name: "unlink", syscall: "unlink", legacy: true, args: []uint64{mutatedAddr}},
		{name: "mknod", syscall: "mknod", legacy: true, args: []uint64{mutatedAddr, unix.S_IFIFO | 0o600, 0}},
		{name: "symlink", syscall: "symlink", legacy: true, args: []uint64{otherAddr, mutatedAddr}, target: "../anywhere"},
		{name: "link into", syscall: "link", legacy: true, args: []uint64{otherAddr, mutatedAddr}, other: "plain/src"},
		{name: "rename into", syscall: "rename", legacy: true, args: []uint64{otherAddr, mutatedAddr}, other: "plain/src"},
	} {
		if tc.legacy && arch != auditArchX86 {
			continue
		}
		out = append(out, tc)
	}
	return out
}

// dispatchNR is the number table gives the syscall name, if it has one.
func dispatchNR(table dispatchTable, name string) (int32, bool) {
	for k, e := range table {
		if e.name == name {
			return k.nr, true
		}
	}
	return 0, false
}

// TestFallbackMutationCasesDispatch holds fallbackMutationCases to both architectures' dispatch tables: every
// case it keeps for an architecture is a syscall that architecture's table answers, so no subtest of
// TestFallbackMutationConverges skips on either (an arm64 runner's skip gate would fail on one).
func TestFallbackMutationCasesDispatch(t *testing.T) {
	for _, arch := range []uint32{auditArchX86, auditArchARM} {
		table := buildDispatchFor(arch)
		for _, tc := range fallbackMutationCases(arch) {
			if _, ok := dispatchNR(table, tc.syscall); !ok {
				t.Errorf("arch %#x: the case %q drives %s, which that architecture's dispatch table has no entry for", arch, tc.name, tc.syscall)
			}
		}
	}
	if n := len(fallbackMutationCases(auditArchX86)); n != 30 {
		t.Errorf("x86-64 drives %d syscall forms, want thirty (ADR 0021's FALLBACK-CELLS note)", n)
	}
	if n := len(fallbackMutationCases(auditArchARM)); n != 20 {
		t.Errorf("arm64 drives %d syscall forms, want twenty (ADR 0021's FALLBACK-CELLS note)", n)
	}
}

// TestFallbackMutationConverges is ADR0021(5)/ADR0028 S3: every notified mutation under a nested deny_read is
// actually refused in the listener fallback, even if Landlock's union grants it — the ADR's "a write, create,
// delete, rename or mkdir", each syscall that makes one, and a link, rename or exchange whose destination end
// lands there (decideMoveDest). A write entry regranted inside the deny_read and a plain directory beside it
// keep the CONTINUE, save an exchange with the regrant: under RENAME_EXCHANGE both ends leave their names, and R15d
// refuses a move of any name beneath the unenforced deny_read, the regrant included (DenyReadMoveTarget, which
// compile --test's tier cgroup column asks too).
func TestFallbackMutationConverges(t *testing.T) {
	table := buildDispatch()
	for _, tc := range fallbackMutationCases(nativeAuditArch()) {
		for _, path := range []string{"secret/x", "secret/open/x", "plain/x"} {
			t.Run(tc.name+" "+path, func(t *testing.T) {
				nr, ok := dispatchNR(table, tc.syscall)
				if !ok { // fallbackMutationCases leaves out what this architecture lacks (TestFallbackMutationCasesDispatch)
					t.Fatalf("%s has no dispatch entry on this architecture", tc.syscall)
				}
				f := newFake()
				compiled := contracttest.Build(t, fmt.Sprintf(fallbackContract, "cgroup"), fallbackTree())
				l, sink := fallbackLoop(t, f, compiled)
				f.put(mutatedAddr, cstr(compiled.Path("work/"+path)))
				switch {
				case tc.other != "":
					f.put(otherAddr, cstr(compiled.Path("work/"+tc.other)))
				case tc.target != "":
					f.put(otherAddr, cstr(tc.target))
				}
				l.handle(notifFor(nr, 42, tc.args...))
				response, _ := f.lastResp()
				refused := response.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
				want := path == "secret/x" || (tc.exchange && path == "secret/open/x")
				if refused != want {
					t.Fatalf("response %+v: refused=%v want %v", response, refused, want)
				}
				if want && response.Error != -int32(refusalErrno) {
					t.Errorf("refusal errno %d, want %d (R10)", -response.Error, refusalErrno)
				}
				if ev := sink.one(t); want && (ev.Verdict != record.VerdictRefused || ev.Rule != "fs.deny_read[work/secret]") {
					t.Fatalf("refusal %+v", ev)
				}
			})
		}
	}
}

// TestFallbackMutationLeavesOthersAlone holds fallbackMutation's guard (fs.go): the supervisor refuses nothing
// itself where a kernel plane decides the run (Options.PlaneAttrs), at tier landlock (no listener runs: the union
// is the stated limit beneath the nested deny_read, SEMANTICS §2, and Landlock refuses what lies outside every
// write entry itself), for a read-open (the listener's own decision, R15) or for a chmod (no tier below the plane
// decides one, CAPABILITIES fs.deny_chmod). Each is continued, the verdict the model gives it left advisory; the
// paths outside every entry are the ones whose advisory verdict is a refusal, so a guard that let them through
// would refuse them here.
func TestFallbackMutationLeavesOthersAlone(t *testing.T) {
	for _, tc := range []struct {
		name, tier, syscall, path string
		plane                     bool
		args                      []uint64
	}{
		{name: "the plane decides mkdirat", tier: "cgroup", plane: true, syscall: "mkdirat", path: "work/secret/x",
			args: []uint64{argCWD, mutatedAddr, 0o700}},
		{name: "the plane decides unlinkat", tier: "cgroup", plane: true, syscall: "unlinkat", path: "work/secret/x",
			args: []uint64{argCWD, mutatedAddr, 0}},
		{name: "the plane decides an O_CREAT open", tier: "cgroup", plane: true, syscall: "openat", path: "work/secret/x",
			args: []uint64{argCWD, mutatedAddr, unix.O_WRONLY | unix.O_CREAT, 0o600}},
		{name: "the plane decides a mkdirat outside every entry", tier: "cgroup", plane: true, syscall: "mkdirat", path: "elsewhere/x",
			args: []uint64{argCWD, mutatedAddr, 0o700}},
		{name: "tier landlock mkdirat", tier: "landlock", syscall: "mkdirat", path: "work/secret/x", args: []uint64{argCWD, mutatedAddr, 0o700}},
		{name: "tier landlock unlinkat", tier: "landlock", syscall: "unlinkat", path: "work/secret/x", args: []uint64{argCWD, mutatedAddr, 0}},
		{name: "tier landlock mkdirat outside every entry", tier: "landlock", syscall: "mkdirat", path: "elsewhere/x",
			args: []uint64{argCWD, mutatedAddr, 0o700}},
		{name: "a read-open", tier: "cgroup", syscall: "openat", path: "work/secret/x", args: []uint64{argCWD, mutatedAddr, unix.O_RDONLY, 0}},
		{name: "fchmodat", tier: "cgroup", syscall: "fchmodat", path: "work/secret/x", args: []uint64{argCWD, mutatedAddr, 0o600}},
		{name: "fchmodat outside every entry", tier: "cgroup", syscall: "fchmodat", path: "elsewhere/x", args: []uint64{argCWD, mutatedAddr, 0o600}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			compiled := contracttest.Build(t, fmt.Sprintf(fallbackContract, tc.tier), fallbackTree())
			l, _ := fallbackLoop(t, f, compiled)
			l.planeAttrs = tc.plane
			f.put(mutatedAddr, cstr(compiled.Path(tc.path)))
			l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args...))
			response, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if response.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response %+v: refused, want continued (fallbackMutation leaves this to another mechanism)", response)
			}
		})
	}
}

// TestFallbackMutationWalkFailures holds decideFS's failed-walk arms to R15's 2026-10-17 amendment at tier cgroup
// with no plane mode. A walk that failed other than as the task's own lookup
// fails (EMFILE, EIO, EXDEV) is refused here under path-unreliable, with R10's errno, since the table has a
// deny_read. One that reached an object with no path in this process's view (errOtherView: a pipe behind
// /dev/stdout, an unlinked file, or a file linked elsewhere, errLinkedElsewhere) is not refused here: a nameless
// object's write-open must run, and a linked file this process cannot see is the CONTINUE race R15c names. Its
// line keeps the spelling's refusal or is observed under path-unreliable, never allow, and the syscall is
// continued. A lookup failure keeps the spelling's verdict, a refusal beneath the deny_read included.
func TestFallbackMutationWalkFailures(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		err        error
		refused    bool
		verdict    record.Verdict
		rule       string
	}{
		{"EIO", "work/plain/x", unix.EIO, true, record.VerdictRefused, rulePathUnreliable},
		{"EMFILE", "work/plain/x", unix.EMFILE, true, record.VerdictRefused, rulePathUnreliable},
		{"EXDEV", "work/plain/x", unix.EXDEV, true, record.VerdictRefused, rulePathUnreliable},
		{"another view", "work/plain/x", errOtherView, false, record.VerdictObserved, rulePathUnreliable},
		{"linked elsewhere", "work/plain/x", errLinkedElsewhere, false, record.VerdictObserved, rulePathUnreliable},
		{"another view beneath the deny_read", "work/secret/x", errOtherView, false, record.VerdictRefused, "fs.deny_read[work/secret]"},
		{"lookup failure beneath the deny_read", "work/secret/x", unix.ENOENT, true, record.VerdictRefused, "fs.deny_read[work/secret]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			compiled := contracttest.Build(t, fmt.Sprintf(fallbackContract, "cgroup"), fallbackTree())
			l, sink := fallbackLoop(t, f, compiled)
			p := compiled.Path(tc.path)
			f.put(mutatedAddr, cstr(p))
			f.fsTargetErrs[p] = tc.err
			l.handle(notifFor(nrFor(t, "mkdirat"), 42, argCWD, mutatedAddr, 0o700))
			response, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			refused := response.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
			if refused != tc.refused {
				t.Fatalf("response %+v: refused=%v, want %v", response, refused, tc.refused)
			}
			if refused && response.Error != -int32(refusalErrno) {
				t.Errorf("refusal errno %d, want %d (R10)", -response.Error, refusalErrno)
			}
			if ev := sink.one(t); ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Errorf("line %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
		})
	}
}
