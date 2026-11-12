// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

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
