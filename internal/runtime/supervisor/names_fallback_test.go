// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// namesContract is a project the agent may write all of, at the tier whose fanotify listener decides opens when no
// plane mode is selected: the built-in .env entries cover it (ADR 0043 D10: beneath the contract file's directory).
const namesContract = `version: 0
name: fixture
command: [fixture]
tier: cgroup
capture: off
fs:
  write: [work]
net: {}
`

// TestSupervisorRefusesNameMutationAtTier2 is the listener fallback's supervisor half of ADR 0043 D7 (R15f, R15, R17,
// fallbackMutation): each notified mutation that makes, writes, truncates, removes or moves a file at a name an entry
// covers (work/plain/.env.local, created after the run started, as a file no expansion row names) is refused by this
// loop with the entry's own rule (D8), and continued for a name no entry covers; a directory of that name is no name
// entry's to decide, so a mkdir and an rmdir of it are continued. A write-open is refused read-denied, as the listener
// refuses it.
func TestSupervisorRefusesNameMutationAtTier2(t *testing.T) {
	table := buildDispatch()
	// O_TMPFILE names the directory the unnamed file is made in (its O_DIRECTORY bit says so); linking it to a name is
	// the link the name entries decide.
	dirOps := map[string]bool{"mkdirat": true, "mkdir": true, "unlinkat AT_REMOVEDIR": true, "rmdir": true, "openat O_WRONLY|O_TMPFILE": true}
	for _, tc := range fallbackMutationCases(nativeAuditArch()) {
		for _, path := range []string{"plain/.env.local", "plain/x"} {
			t.Run(tc.name+" "+path, func(t *testing.T) {
				nr, ok := dispatchNR(table, tc.syscall)
				if !ok {
					t.Fatalf("%s has no dispatch entry on this architecture", tc.syscall)
				}
				f := newFake()
				compiled := contracttest.Build(t, namesContract, fallbackTree())
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
				want := path == "plain/.env.local" && !dirOps[tc.name]
				if refused != want {
					t.Fatalf("response %+v: refused=%v want %v", response, refused, want)
				}
				ev := sink.one(t)
				if !want {
					return
				}
				if ev.Verdict != record.VerdictRefused || !strings.HasSuffix(ev.Rule, "/**/.env.*]") || !strings.HasPrefix(ev.Rule, "fs.deny_read[") {
					t.Fatalf("refusal %+v, want one named by the built-in .env.* entry", ev)
				}
				if open := tc.syscall == "openat" || tc.syscall == "open" || tc.syscall == "creat"; open && ev.Reason != record.ReasonReadDenied {
					t.Errorf("write-open refused %s, want read-denied (the listener's)", ev.Reason)
				}
			})
		}
	}
}

// TestNameMoveRefusedAtTier2 is ADR 0043 D5 in the listener fallback's supervisor (nameMove, R15f, beside R15d): a
// directory renamed beneath a dependency directory takes the files beneath it out of the built-in entries' coverage,
// so the rename is refused with the entry's rule, rename-outside-contract; a file renamed there, and a directory
// renamed within the covered tree, are continued; and a run whose table has no name entries stats no rename's source.
// A source whose kind the stat could not tell is asked as a file and as a directory (fail closed): a
// directory leaving the coverage is refused even so.
func TestNameMoveRefusedAtTier2(t *testing.T) {
	table := buildDispatch()
	nr, ok := dispatchNR(table, "renameat")
	if !ok {
		t.Fatal("renameat has no dispatch entry on this architecture")
	}
	for _, tc := range []struct {
		name     string
		names    bool
		src, dst string
		dir      bool
		statErr  error
		refused  bool
	}{
		{"directory into node_modules", true, "plain/sub", "node_modules/sub", true, nil, true},
		{"a source whose stat failed, into node_modules", true, "plain/sub", "node_modules/sub", true, unix.EIO, true},
		{"file into node_modules", true, "plain/f", "node_modules/f", false, nil, false},
		{"directory within the tree", true, "plain/sub", "plain/sub2", true, nil, false},
		{"no name entries", false, "plain/sub", "node_modules/sub", true, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			compiled := contracttest.Build(t, namesContract, fallbackTree())
			if !tc.names {
				compiled.Rules.NameDeny = nil
			}
			l, sink := fallbackLoop(t, f, compiled)
			src := compiled.Path("work/" + tc.src)
			if tc.dir {
				f.finalDirs = map[string]bool{src: true}
			}
			if tc.statErr != nil {
				f.finalDirErrs = map[string]error{src: tc.statErr}
			}
			f.put(mutatedAddr, cstr(src))
			f.put(otherAddr, cstr(compiled.Path("work/"+tc.dst)))
			l.handle(notifFor(nr, 42, argCWD, mutatedAddr, argCWD, otherAddr))
			response, _ := f.lastResp()
			refused := response.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0
			if refused != tc.refused {
				t.Fatalf("response %+v: refused=%v want %v", response, refused, tc.refused)
			}
			ev := sink.one(t)
			if tc.refused && (ev.Reason != record.ReasonRenameOutsideContract || !strings.HasPrefix(ev.Rule, "fs.deny_read[") || !strings.Contains(ev.Rule, "/**/.env")) {
				t.Fatalf("refusal %+v, want rename-outside-contract named by a built-in .env entry", ev)
			}
			if !tc.names && f.dirStats != 0 {
				t.Errorf("a run without name entries stat'ed %d rename sources", f.dirStats)
			}
		})
	}
}
