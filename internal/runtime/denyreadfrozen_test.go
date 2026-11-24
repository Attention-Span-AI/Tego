// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// frozenHandle is a handle whose ruleset listed dirs to build its deny_read entries, as landlock.Handle and a root
// tier's composed handle say (DenyReadFrozen).
type frozenHandle struct {
	fakeHandle
	dirs []string
}

func (h *frozenHandle) DenyReadFrozen() []string { return h.dirs }

// observedFrozen is an --observe run's handle that would list directories: a records-only run builds no ruleset.
type observedFrozen struct{ frozenHandle }

func (*observedFrozen) Verdict() record.Verdict { return record.VerdictObserved }

// TestRunStartNamesTheFrozenDirectories (GAPS A12): run_start.deny_read_frozen names the directories the run's
// ruleset listed once at launch, sorted, and the run prints one note naming them under [deny-read-frozen] before the
// agent runs; a handle that lists none, or a records-only run, writes no field and prints nothing.
func TestRunStartNamesTheFrozenDirectories(t *testing.T) {
	var said []string
	warn := func(code, what string) { said = append(said, code+": "+what) }
	r := &runner{handle: &frozenHandle{dirs: []string{"/home/u", "/", "/home"}}, deps: Deps{Warn: warn}}
	f := r.denyReadFrozen()
	if f == nil || strings.Join(f.Dirs, " ") != "/ /home /home/u" || f.Omitted != 0 {
		t.Fatalf("deny_read_frozen = %+v, want / /home /home/u", f)
	}
	if err := (&record.RunStartPayload{RecordMinor: launchMinor, DenyReadFrozen: f}).ValidateFields(); err != nil {
		t.Fatalf("the field is refused at the launch revision: %v", err)
	}
	r.noteFrozen(f)
	if len(said) != 1 || !strings.HasPrefix(said[0], WarnDenyReadFrozen+": deny_read lists /, /home, /home/u once, at launch") ||
		!strings.Contains(said[0], "made directly in one of them during this run cannot be read until it ends") {
		t.Fatalf("the run said %q", said)
	}
	said = nil
	for name, h := range map[string]*runner{
		"lists none":   {handle: &frozenHandle{}, deps: Deps{Warn: warn}},
		"no such list": {handle: &fakeHandle{}, deps: Deps{Warn: warn}},
		"records-only": {handle: &observedFrozen{frozenHandle{dirs: []string{"/"}}}, deps: Deps{Warn: warn}},
	} {
		f := h.denyReadFrozen()
		if f != nil {
			t.Errorf("%s: deny_read_frozen = %+v, want none", name, f)
		}
		h.noteFrozen(f)
	}
	if len(said) != 0 {
		t.Errorf("a run whose ruleset listed nothing said %q", said)
	}
}

// TestFrozenNoteNamesEveryDirectory: the note names every directory run_start names, and counts those it omitted.
func TestFrozenNoteNamesEveryDirectory(t *testing.T) {
	dirs := []string{"/", "/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i"}
	if got := FrozenNote(dirs, 3, "a run"); !strings.HasPrefix(got, "deny_read lists /, /a, /b, /c, /d, /e, /f, /g, /h, /i and 3 more once") {
		t.Errorf("FrozenNote = %q", got)
	}
	if got := FrozenNote(nil, 2, "a run"); !strings.HasPrefix(got, "deny_read lists 2 directories once") {
		t.Errorf("FrozenNote with every directory omitted = %q", got)
	}
}

// snapshotHandle is a frozenHandle that also hands the supervisor its snapshot, as landlock.Handle and a root tier's
// composed handle do (DenyReadSnapshot).
type snapshotHandle struct {
	frozenHandle
	refuses func(string) bool
}

func (h *snapshotHandle) DenyReadSnapshot() func(string) bool { return h.refuses }

// TestFrozenWithoutSnapshotFailsClosed (GAPS A12): a run whose ruleset froze a deny_read enumeration
// (run_start names the directories) must hand the supervisor the snapshot of it, at every tier that builds one; a handle
// that lists directories and gives none would have every read of a name made after launch continued and recorded allow
// or observed, so the run does not start. A records-only run, a run that froze nothing and a handle with a snapshot
// start as before.
func TestFrozenWithoutSnapshotFailsClosed(t *testing.T) {
	refuses := func(string) bool { return true }
	for name, tc := range map[string]struct {
		h        any
		observe  bool
		snapshot func(string) bool
		refused  bool
	}{
		"listed, no snapshot":      {h: &frozenHandle{dirs: []string{"/"}}, refused: true},
		"listed, snapshot":         {h: &snapshotHandle{frozenHandle{dirs: []string{"/"}}, refuses}, snapshot: refuses},
		"listed, records-only run": {h: &frozenHandle{dirs: []string{"/"}}, observe: true},
		"listed nothing":           {h: &frozenHandle{}},
		"no list at all":           {h: &fakeHandle{}},
	} {
		err := frozenWithoutSnapshot(tc.h, tc.observe, tc.snapshot)
		if (err != nil) != tc.refused {
			t.Errorf("%s: error %v, want refused=%t", name, err, tc.refused)
		}
	}
}

// TestStartNotifyLoopRefusesAFrozenRulesetWithoutItsSnapshot is the same condition through startNotifyLoop: the error
// is the run's start failing before the supervisor is built, and the listener stays with the runner for the unwind to
// release (a handle that gives its snapshot gets past the check, to the policy error an empty run id raises).
func TestStartNotifyLoopRefusesAFrozenRulesetWithoutItsSnapshot(t *testing.T) {
	for name, tc := range map[string]struct {
		h    any
		want string
	}{
		"no snapshot": {&frozenHandle{dirs: []string{"/"}}, "froze a deny_read enumeration"},
		"snapshot":    {&snapshotHandle{frozenHandle{dirs: []string{"/"}}, func(string) bool { return false }}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			testutil.NoFDLeak(t)
			g, gctx := newGroup(context.Background())
			notifyFD := listenerPipe(t)
			r := &runner{
				log: slog.New(slog.DiscardHandler), rt: &agent.RuleTable{}, queue: NewQueue(4), group: g, notifyFD: notifyFD,
				handle: tc.h.(api.Handle),
			}
			t.Cleanup(func() {
				if r.notifyFD != nil {
					_ = r.notifyFD.Close()
				}
			})
			err := r.startNotifyLoop(gctx)
			if err == nil {
				t.Fatal("startNotifyLoop succeeded, want a failure")
			}
			if got := strings.Contains(err.Error(), tc.want); tc.want != "" && !got || tc.want == "" && strings.Contains(err.Error(), "froze a deny_read") {
				t.Errorf("error %q, want one naming %q", err, tc.want)
			}
			if tc.want != "" && r.notifyFD == nil {
				t.Error("the runner gave up the listener of a run that never started its supervisor")
			}
		})
	}
}
