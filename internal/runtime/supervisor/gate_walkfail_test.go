// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGateFSWalkFailureRefusesUnreadable is gate.md R1's "missing relevant facts refuse as unreadable" for the
// supervisor's own walk (ADR 0041 Step 1, finding failopen-3): a walk that failed with an errno the task's own
// lookup would not have failed with (this process's fd table, memory or I/O), or that reached a linked file
// whose path this process cannot see, left the gate with the lexical spelling only. That spelling ("notes.txt")
// is not where the kernel lands (a symlink to secrets/.env, or out of the worktree), so it is no fact the gate
// can score: the action is refused as gate.unreadable, never scored on the spelling and continued. A walk that
// reached a nameless object (a pipe, an unlinked file) is complete, since no name of one can match, and a lookup
// failure fails the task's syscall the same way, so both still score as before.
func TestGateFSWalkFailureRefusesUnreadable(t *testing.T) {
	const pathAddr = 0x10000
	for _, tc := range []struct {
		name    string
		err     error
		refused bool
	}{
		{"EMFILE", unix.EMFILE, true},
		{"ENFILE", unix.ENFILE, true},
		{"ENOMEM", unix.ENOMEM, true},
		{"EIO", unix.EIO, true},
		{"EXDEV", unix.EXDEV, true},
		{"linked elsewhere", errLinkedElsewhere, true},
		{"nameless", errOtherView, false},
		{"ENOENT", unix.ENOENT, false},
	} {
		for _, call := range []struct {
			name, syscall string
			args          []uint64
		}{
			{"read-open", "openat", []uint64{argCWD, pathAddr, unix.O_RDONLY}},
			{"write-open", "openat", []uint64{argCWD, pathAddr, unix.O_WRONLY}},
			{"unlink", "unlinkat", []uint64{argCWD, pathAddr, 0}},
		} {
			t.Run(tc.name+"/"+call.name, func(t *testing.T) {
				root := t.TempDir()
				compiled := contracttest.BuildAt(t, root, `version: 0
name: gate-walk
command: [fixture]
capture: off
record: full
fs:
  write: [./]
  deny_read: []
gate:
  rules:
    - 'fs.read matches "*.env"': 95
    - fs.write outside worktree: 95
`, contracttest.Tree{"work/notes.txt": "", "work/secrets/.env": "owned"}, agent.WithCwd(filepath.Join(root, "work")))
				notes := compiled.Path("work/notes.txt")
				f := newFake()
				f.put(pathAddr, cstr(notes))
				f.fsTargetErrs = map[string]error{notes: tc.err}
				pol := testPolicy(nil, nil, nil)
				pol.Rules = compiled.Rules
				l, sink := newTestLoop(t, f, pol)
				l.handle(notifFor(nrFor(t, call.syscall), 42, call.args...))
				got, ok := f.lastResp()
				if !ok {
					t.Fatal("unanswered")
				}
				ev := sink.one(t)
				if !tc.refused {
					if got.Flags == 0 || ev.Verdict == record.VerdictRefused {
						t.Fatalf("a %s walk is facts the gate scores as before; response %+v, line %+v", tc.name, got, ev)
					}
					return
				}
				if got.Flags != 0 || got.Error != -int32(refusalErrno) {
					t.Fatalf("a %s walk scored the spelling and answered %+v; want the refusal", tc.name, got)
				}
				if call.name != "read-open" && !errors.Is(tc.err, errLinkedElsewhere) {
					if ev.Verdict != record.VerdictRefused || ev.Rule != agent.BuiltinHostIPC || ev.Authority != record.AuthorityRule {
						t.Fatalf("immutable floor must precede the gate on an unreadable mutation: %+v", ev)
					}
					return
				}
				if ev.Verdict != record.VerdictRefused || ev.Rule != "gate.unreadable" || ev.Reason != record.ReasonFSGate ||
					ev.Authority != record.AuthorityGate {
					t.Fatalf("line %+v; want refused gate.unreadable fs-gate under the gate's authority", ev)
				}
			})
		}
	}
}
