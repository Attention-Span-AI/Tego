// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
)

// The held-label note says how held file opens are decided on this machine; it is shown once for a machine state, not on
// every run (on WSL, whose kernel lists SELinux with no policy behind it, it read as a fault each time). A new kernel
// or other words are another state, and anything uncertain shows it again.
func TestHeldNoteShownOncePerMachineState(t *testing.T) {
	root := t.TempDir()
	const note = "on SELinux a file open that tego checks and makes for the agent requires the same domain as the process opening the file"
	if heldNoteShown(root, "6.18.58.1-microsoft-standard-WSL2", note) {
		t.Fatal("the first run's note was hidden")
	}
	if !heldNoteShown(root, "6.18.58.1-microsoft-standard-WSL2", note) {
		t.Error("the same state's second note was shown again")
	}
	if heldNoteShown(root, "6.18.59", note) {
		t.Error("a new kernel's note was hidden")
	}
	if heldNoteShown(root, "6.18.59", note+"; SELinux file creation contexts must also match before creating a file") {
		t.Error("another note's words were hidden")
	}
	if !heldNoteShown(root, "6.18.59", note+"; SELinux file creation contexts must also match before creating a file") {
		t.Error("the changed state was not remembered")
	}
}

func TestHeldNoteShownIsUncertainSafe(t *testing.T) {
	if heldNoteShown("", "k", "n") {
		t.Error("no ledger root hid the note")
	}
	if heldNoteShown(filepath.Join(t.TempDir(), "missing"), "k", "n") {
		t.Error("a root that does not exist hid the note")
	}
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "planted")
	if err := os.WriteFile(target, []byte(heldNoteKey("k", "n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, heldNoteFile)); err != nil {
		t.Fatal(err)
	}
	if heldNoteShown(root, "k", "n") {
		t.Error("a marker that is a link hid the note")
	}
	got, _ := os.ReadFile(target)
	if string(got) != heldNoteKey("k", "n")+"\n" {
		t.Error("the note wrote through a link")
	}
}

// Through the command: the second run on this machine does not print the note the first one printed.
func TestRunPrintsTheHeldLabelNoteOnce(t *testing.T) {
	summaryHarness(t)
	old := kernelRelease
	kernelRelease = func() string { return "6.18.58.1-microsoft-standard-WSL2" }
	t.Cleanup(func() { kernelRelease = old })
	const note = "on SELinux a file open that tego checks and makes for the agent requires the same domain as the process opening the file"
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		d.Warn(tegoruntime.WarnHeldLabel, note)
		return tegoruntime.Result{}, nil
	}
	for i, wantNote := range []bool{true, false} {
		code, _, got := terminalRunOutput(t, "testdata/minimal.yaml", "--offline")
		if code != identity.ExitOK {
			t.Fatalf("run %d: exit %d: %s", i+1, code, got)
		}
		if has := strings.Contains(got, "note: tego run: "+note+" [held-label]"); has != wantNote {
			t.Errorf("run %d: note shown %v, want %v:\n%s", i+1, has, wantNote, got)
		}
	}
}
