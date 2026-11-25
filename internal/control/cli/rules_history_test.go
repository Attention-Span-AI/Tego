// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const undoBaseText = `version: 0
name: tester
command: ["sh"]
exec:
  allow: [sh, cat, ls]
fs:
  write: ["./out/"]
  ask_read: ["./docs/"]
net:
  allow: ["api.example.com:443"]
`

// undoFix is a project with one rules file that a run ran, a ledger root, and the rule service the commands use (the
// dashboard's Service, with its compiler replaced as the rule service's own tests do).
type undoFix struct {
	base, root, proj, contract string
	svc                        *rules.Service
	confirm                    *bytes.Buffer
}

func newUndoFix(t *testing.T) *undoFix {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	f := &undoFix{base: base, root: filepath.Join(base, "runs"), proj: filepath.Join(base, "proj"), confirm: &bytes.Buffer{}}
	f.contract = filepath.Join(f.proj, "agent.yaml")
	for _, d := range []string{f.root, f.proj} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.contract, []byte(undoBaseText), 0o600); err != nil {
		t.Fatal(err)
	}
	const id = "r-12345678-0000000000000-abcdef"
	ev := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off", ContractHash: strings.Repeat("0", 64),
		Command: []string{"sh"}, Cwd: f.proj, Kernel: "6", StopGrace: "1s", RecordMinor: record.MinorLearn,
		ContractSource: &record.ContractSource{Path: f.contract}})
	ev.Run, ev.Seq, ev.TS = id, 0, time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.root, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, id, ledger.EventsFile), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+f.root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	f.svc = &rules.Service{Ledger: f.root, Home: filepath.Join(base, "home"),
		Now:     func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) },
		Compile: func(context.Context, rules.CheckContext, []byte) error { return nil }}
	oldAnchor, oldSvc, oldTTY, oldIn, oldSelf, oldZone := anchorPath, newRulesService, stdinIsTerminal, confirmInput, selfGoverned, shownIn
	t.Cleanup(func() {
		anchorPath, newRulesService, stdinIsTerminal, confirmInput, selfGoverned, shownIn = oldAnchor, oldSvc, oldTTY, oldIn, oldSelf, oldZone
	})
	anchorPath = func(*config.Machine, bool) (string, error) { return ledger.DefaultAnchorPath(f.root), nil }
	newRulesService = func(string, string, *config.Machine, bool) *rules.Service { return f.svc }
	stdinIsTerminal = func() bool { return false }
	confirmInput = f.confirm
	selfGoverned = answertest.Outside
	shownIn = time.UTC
	return f
}

// ref is the contract's entry in the service's set.
func (f *undoFix) ref(t *testing.T) rules.ContractRef {
	t.Helper()
	cs, err := f.svc.Contracts()
	if err != nil || len(cs) != 1 {
		t.Fatalf("contracts: %+v %v", cs, err)
	}
	return cs[0]
}

// change makes one reviewed change, as the dashboard does, and returns its journal id.
func (f *undoFix) change(t *testing.T, op, key, entry string) string {
	t.Helper()
	c := f.ref(t)
	req := rules.ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []rules.Edit{{Op: op, Key: key, Entry: entry}}}
	p, err := f.svc.PlanChange(t.Context(), req)
	if err != nil || p.Err != "" {
		t.Fatalf("plan: %+v %v", p, err)
	}
	req.Ack = p.Ack
	a, err := f.svc.ApplyChange(t.Context(), req)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return a.ID
}

func (f *undoFix) text(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.contract)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRulesHistoryIsTheDashboardsHistory (C130): `tego rules history` lists what rules.Service.History returns, the one
// reader the dashboard's history list reads, with its one wording (HistoryEntry.What) and its one rule for which entry
// can be undone (HistoryEntry.Undoable); --json is the same entries, versioned. An agent's name and a file's path name the
// same contract.
func TestRulesHistoryIsTheDashboardsHistory(t *testing.T) {
	f := newUndoFix(t)
	narrow := f.change(t, "remove", "exec.allow", "cat")
	wide := f.change(t, "add", "exec.allow", "git")
	// A free edit, its undo and the undo of that undo (a redo), as the page's history test makes them.
	c := f.ref(t)
	raw := rules.RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(strings.Replace(f.text(t), "git", "git, wget", 1))}
	pr, err := f.svc.PlanRaw(t.Context(), raw)
	if err != nil || pr.Err != "" {
		t.Fatalf("plan the free edit: %+v %v", pr, err)
	}
	raw.Ack = pr.Ack
	if _, err := f.svc.ApplyRaw(t.Context(), raw); err != nil {
		t.Fatalf("apply the free edit: %v", err)
	}
	for _, what := range []string{"undo", "redo"} {
		es, err := f.svc.History(f.ref(t).Ref)
		if err != nil || len(es) == 0 {
			t.Fatalf("before the %s: %+v %v", what, es, err)
		}
		if code, _, errs := run(t, user, "rules", "undo", "tester", "--yes"); code != identity.ExitOK {
			t.Fatalf("the %s: exit %d %q", what, code, errs)
		}
	}
	hs, err := f.svc.History(f.ref(t).Ref)
	if err != nil || len(hs) != 5 || hs[3].ID != wide || hs[4].ID != narrow {
		t.Fatalf("history: %+v %v", hs, err)
	}
	for _, target := range []string{"tester", f.contract} {
		code, out, errs := run(t, user, "rules", "history", target)
		if code != identity.ExitOK || errs != "" {
			t.Fatalf("history %s: exit %d stderr %q", target, code, errs)
		}
		for _, h := range hs {
			line := ""
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), h.ID) { // not the "undone by" of another entry
					line = l
				}
			}
			if line == "" || !strings.Contains(line, h.What()) || !strings.Contains(line, "["+h.Direction+"]") || !strings.Contains(line, "  cli") && !strings.Contains(line, "  dashboard") {
				t.Errorf("history %s: no line for %s with %q, direction %s and writer:\n%s", target, h.ID, h.What(), h.Direction, out)
			}
		}
		if !strings.Contains(out, "Undo the newest change: tego rules undo ") {
			t.Errorf("the history of %s offers no Undo:\n%s", target, out)
		}
	}
	// --json, in either place, is the same entries in the same order, with the Undo the page offers.
	for _, args := range [][]string{{"rules", "history", "tester", "--json"}, {"rules", "history", "--json", "tester"},
		{"rules", "history", "--json", "--", "tester"}} {
		code, out, errs := run(t, user, args...)
		var got historyJSON
		if code != identity.ExitOK || json.Unmarshal([]byte(out), &got) != nil || errs != "" {
			t.Fatalf("%v: exit %d %q %q", args, code, out, errs)
		}
		if got.V != 1 || got.Contract.Agent != "tester" || got.Contract.Path != f.contract || len(got.Entries) != len(hs) {
			t.Fatalf("%v: %+v", args, got)
		}
		for i, h := range hs {
			e := got.Entries[i]
			if e.ID != h.ID || e.What != h.What() || e.Direction != h.Direction || e.CanUndo != h.Undoable(f.ref(t).Base) || !e.At.Equal(h.At) {
				t.Errorf("%v entry %d: %+v differs from the service's %+v", args, i, e, h)
			}
		}
		if !got.Entries[0].CanUndo || got.Entries[1].CanUndo {
			t.Errorf("only the newest change can be undone: %+v", got.Entries)
		}
	}
}

// TestRulesEditIsListedAndUndone: what `tego rules edit` writes (internal/cli/rules_edit.go: rulefile.Replace under
// the ledger root's guard, via "cli", the dashboard's summary for a whole-text edit, direction mixed) is one entry of the
// history the dashboard and these commands read: listed in the same words, current while the file holds its text, and
// undone like a free edit, with the word (here --yes).
func TestRulesEditIsListedAndUndone(t *testing.T) {
	f := newUndoFix(t)
	c := f.ref(t)
	edited := undoBaseText + "# edited by hand\n"
	e, err := rulefile.Replace(t.Context(), rulefile.DefaultGuard(f.root), f.contract, c.Base, []byte(edited),
		rulefile.Change{Via: "cli", Summary: "free edit of the whole text", Direction: "mixed"})
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, user, "rules", "history", "tester")
	if code != identity.ExitOK || errs != "" || !strings.Contains(out, e.ID) || !strings.Contains(out, "free edit of the whole text") || !strings.Contains(out, "[mixed]") ||
		!strings.Contains(out, "Undo the newest change") {
		t.Fatalf("history: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, out, errs := run(t, user, "rules", "undo", "tester"); code != identity.ExitUsage || !strings.Contains(errs, "--yes") || f.text(t) != edited {
		t.Fatalf("an undo of a free edit with no terminal: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, out, errs := run(t, user, "rules", "undo", "tester", "--yes"); code != identity.ExitOK || f.text(t) != undoBaseText {
		t.Fatalf("the undo: exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestRulesHistoryWordsAreEscaped: what a ledger or a journal holds is shown as text, never as a control sequence, and
// the text lists the newest entries only.
func TestRulesHistoryWordsAreEscaped(t *testing.T) {
	c := &rules.ContractRef{Agent: "ag\x1b[2Jent", Path: "/p/agent\n.yaml", Base: "b"}
	var hs []rules.HistoryEntry
	for i := range historyLimit + 5 {
		hs = append(hs, rules.HistoryEntry{ID: fmt.Sprintf("rc-%02d", i), Op: rulefile.OpChange, At: time.Date(2026, 11, 23, 12, i, 0, 0, time.UTC),
			Via: "cli\x1b", Summary: "remove \u202eevil\nline", Direction: "narrows"})
	}
	hs[0].Current = true
	var out, errs bytes.Buffer
	if code := writeHistory(&out, &errs, c, hs, false); code != identity.ExitOK || errs.Len() != 0 {
		t.Fatalf("exit %d %q", code, errs.String())
	}
	if strings.ContainsAny(out.String(), "\x1b\u202e") || strings.Count(out.String(), "\n") > historyLimit+5 {
		t.Errorf("the history carries a control character or lists too much:\n%q", out.String())
	}
	if !strings.Contains(out.String(), "and 5 older") || !strings.Contains(out.String(), `remove \u202eevil\nline`) {
		t.Errorf("the history does not say what it left out or escape what it showed:\n%s", out.String())
	}
}

// TestRulesUndoExitTable (C130): every path of `tego rules undo` and its exit code. An undo that only narrows needs no
// confirmation; one that lets the next run do more asks for "undo" at a terminal, and without one needs --yes (exit 2);
// a wrong word is exit 1 and nothing is written; a file that changed since is exit 1 "changed since"; a widening undo
// from inside a run is exit 1 [governed]; a guard or I/O failure is exit 125. Every written undo is journaled "cli".
func TestRulesUndoExitTable(t *testing.T) {
	tty := func(f *undoFix, typed string) {
		stdinIsTerminal = func() bool { return true }
		f.confirm.Reset()
		f.confirm.WriteString(typed)
	}
	t.Run("a narrowing undo needs no confirmation and no terminal", func(t *testing.T) {
		f := newUndoFix(t)
		wide := f.change(t, "add", "exec.allow", "git") // undoing a widening narrows
		code, out, errs := run(t, user, "rules", "undo", "tester")
		if code != identity.ExitOK || strings.Contains(out, "Type") || strings.Contains(errs, "Type") || f.text(t) != undoBaseText ||
			!strings.Contains(out, "Undone: ") || !strings.Contains(out, "journal records the undo") {
			t.Fatalf("exit %d stdout %q stderr %q text %q", code, out, errs, f.text(t))
		}
		es, err := rulefile.History(f.root, f.ref(t).Path)
		if err != nil || len(es) != 2 || es[0].Op != rulefile.OpRevert || es[0].Via != rules.ViaCLI || es[0].Reverts != wide || es[1].UndoneBy != es[0].ID {
			t.Fatalf("journal %+v (%v): want a revert of %s written via cli", es, err, wide)
		}
		if es[0].Direction != "narrows" || es[1].Via != rules.Via {
			t.Errorf("the revert's direction %q, the change's writer %q", es[0].Direction, es[1].Via)
		}
	})
	t.Run("a widening undo at a terminal types the word", func(t *testing.T) {
		f := newUndoFix(t)
		narrow := f.change(t, "remove", "exec.allow", "cat")
		changed := f.text(t)
		tty(f, "yes\n")
		code, out, errs := run(t, user, "rules", "undo", "tester", narrow)
		if code != identity.ExitFinding || !strings.Contains(errs, "[not-confirmed]") || !strings.Contains(out, "lets the next run do more") || f.text(t) != changed {
			t.Fatalf("the wrong word: exit %d stdout %q stderr %q", code, out, errs)
		}
		tty(f, "undo\n")
		code, out, errs = run(t, user, "rules", "undo", "tester", narrow)
		if code != identity.ExitOK || !strings.Contains(errs, "Type undo to confirm") || f.text(t) != undoBaseText {
			t.Fatalf("the word: exit %d stdout %q stderr %q", code, out, errs)
		}
		if es, err := rulefile.History(f.root, f.ref(t).Path); err != nil || es[0].Via != rules.ViaCLI || es[0].Direction != "widens" {
			t.Errorf("journal %+v (%v)", es, err)
		}
	})
	t.Run("a widening undo with no terminal needs --yes", func(t *testing.T) {
		f := newUndoFix(t)
		f.change(t, "remove", "exec.allow", "cat")
		changed := f.text(t)
		code, out, errs := run(t, user, "rules", "undo", "tester")
		if code != identity.ExitUsage || out != "" || !strings.Contains(errs, "--yes") || !strings.Contains(errs, "[usage]") || f.text(t) != changed {
			t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
		}
		code, out, errs = run(t, user, "rules", "undo", "--yes", "tester")
		if code != identity.ExitOK || f.text(t) != undoBaseText || strings.Contains(errs, "Type") {
			t.Fatalf("--yes: exit %d stdout %q stderr %q", code, out, errs)
		}
	})
	t.Run("a file that changed since is changed since", func(t *testing.T) {
		f := newUndoFix(t)
		id := f.change(t, "remove", "exec.allow", "cat")
		edited := f.text(t) + "# by hand\n"
		if err := os.WriteFile(f.contract, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"rules", "undo", "tester", "--yes"}, {"rules", "undo", "tester", id, "--yes"}} {
			code, out, errs := run(t, user, args...)
			if code != identity.ExitFinding || !strings.Contains(errs, "changed since") || !strings.Contains(errs, "[stale]") || f.text(t) != edited || out != "" {
				t.Errorf("%v: exit %d stdout %q stderr %q", args, code, out, errs)
			}
		}
	})
	t.Run("a stale file after the check passed is changed since", func(t *testing.T) {
		f := newUndoFix(t)
		id := f.change(t, "remove", "exec.allow", "cat")
		edited := f.text(t) + "# by hand\n"
		// The file moves between the check and the write: the service's own check, under its lock, refuses.
		_, err := f.svc.Revert(t.Context(), rules.RevertReq{ID: id, Base: f.ref(t).Base, Ack: "x", Via: rules.ViaCLI})
		if err == nil {
			t.Fatal("an undo with a made-up acknowledgement was written")
		}
		if err := os.WriteFile(f.contract, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		var errs bytes.Buffer
		c := f.ref(t)
		hs, _ := f.svc.History(c.Ref)
		stale := c
		stale.Base = rulefile.Sum([]byte(undoBaseText))
		if code := undoChange(t.Context(), f.svc, &stale, hs, id, true, &bytes.Buffer{}, &errs); code != identity.ExitFinding || !strings.Contains(errs.String(), "changed since") {
			t.Errorf("exit %d stderr %q", code, errs.String())
		}
	})
	t.Run("a widening undo from inside a run is refused", func(t *testing.T) {
		for _, row := range answertest.Rows() {
			f := newUndoFix(t)
			f.change(t, "remove", "exec.allow", "cat")
			changed := f.text(t)
			selfGoverned = func() runscope.Answer { return row.Answer }
			code, out, errs := run(t, user, "rules", "undo", "tester", "--yes")
			if row.Permits {
				if code != identity.ExitOK || f.text(t) != undoBaseText {
					t.Errorf("%s: exit %d stdout %q stderr %q", row.Name, code, out, errs)
				}
				continue
			}
			if code != identity.ExitFinding || !strings.Contains(errs, "[governed]") || f.text(t) != changed || out != "" {
				t.Errorf("%s: exit %d stdout %q stderr %q", row.Name, code, out, errs)
			}
		}
	})
	t.Run("a narrowing undo is allowed from inside a run", func(t *testing.T) {
		f := newUndoFix(t)
		f.change(t, "add", "exec.allow", "git")
		selfGoverned = func() runscope.Answer { return answertest.Inside(runscope.CauseGoverned) }
		if code, out, errs := run(t, user, "rules", "undo", "tester"); code != identity.ExitOK || f.text(t) != undoBaseText {
			t.Errorf("exit %d stdout %q stderr %q", code, out, errs)
		}
	})
	// A run's own rules can hide the ledger root, so from inside a run the rules files runs here ran are not listed.
	// The undo then cannot be shown to narrow: the governed refusal comes first (exit 1, [governed], nothing written),
	// not a usage error about a file "no run here has run".
	t.Run("an undo from inside a run that lists no rules file is refused as governed", func(t *testing.T) {
		for _, row := range answertest.Rows() {
			f := newUndoFix(t)
			f.change(t, "remove", "exec.allow", "cat")
			changed := f.text(t)
			hidden := &rules.Service{Ledger: filepath.Join(f.base, "hidden-runs"), Home: f.svc.Home, Now: f.svc.Now, Compile: f.svc.Compile}
			if err := os.Mkdir(hidden.Ledger, 0o700); err != nil {
				t.Fatal(err)
			}
			newRulesService = func(string, string, *config.Machine, bool) *rules.Service { return hidden }
			selfGoverned = func() runscope.Answer { return row.Answer }
			for _, args := range [][]string{{"rules", "undo", "tester", "--yes"}, {"rules", "undo", f.contract}, {"rules", "undo", "tester", "rc-x"}} {
				code, out, errs := run(t, user, args...)
				if row.Permits {
					if code != identity.ExitUsage || !strings.Contains(errs, "[usage]") || out != "" {
						t.Errorf("%s %v: outside every run, exit %d stdout %q stderr %q, want the usage error", row.Name, args, code, out, errs)
					}
					continue
				}
				if code != identity.ExitFinding || !strings.Contains(errs, "[governed]") || strings.Contains(errs, "[usage]") || out != "" ||
					!strings.Contains(errs, "cannot show that this undo only narrows") || f.text(t) != changed {
					t.Errorf("%s %v: exit %d stdout %q stderr %q, want exit 1 [governed]", row.Name, args, code, out, errs)
				}
			}
		}
	})
	t.Run("what names nothing is usage", func(t *testing.T) {
		f := newUndoFix(t)
		id := f.change(t, "add", "exec.allow", "git")
		for _, args := range [][]string{{"rules", "undo"}, {"rules", "undo", "tester", id, "extra"}, {"rules", "undo", "nobody"}, {"rules", "history", "nobody"},
			{"rules", "undo", "tester", "rc-nosuch"}, {"rules", "history"}, {"rules", "history", "tester", "extra"}, {"rules", "history", "/no/such/agent.yaml"},
			{"rules", "undo", "--nonesuch", "tester"}} {
			if code, out, errs := run(t, user, args...); code != identity.ExitUsage || out != "" || errs == "" {
				t.Errorf("%v: exit %d stdout %q stderr %q, want 2", args, code, out, errs)
			}
		}
		if f.text(t) == undoBaseText {
			t.Error("a usage error wrote")
		}
	})
	t.Run("nothing to undo, and an undo already made", func(t *testing.T) {
		f := newUndoFix(t)
		code, _, errs := run(t, user, "rules", "undo", "tester", "--yes")
		if code != identity.ExitFinding || !strings.Contains(errs, "nothing to undo") || !strings.Contains(errs, "[no-change]") || strings.Contains(errs, "[stale]") {
			t.Errorf("no change recorded: exit %d stderr %q", code, errs)
		}
		id := f.change(t, "add", "exec.allow", "git")
		if code, _, errs := run(t, user, "rules", "undo", "tester"); code != identity.ExitOK {
			t.Fatalf("undo: %d %q", code, errs)
		}
		code, _, errs = run(t, user, "rules", "undo", "tester", id)
		if code != identity.ExitFinding || !strings.Contains(errs, "undone already") {
			t.Errorf("a change undone already: exit %d stderr %q", code, errs)
		}
	})
	t.Run("a file that cannot be written is exit 125 [io], and nothing is written", func(t *testing.T) {
		if testutil.RerunAsOrdinaryUser(t) { // root writes into a folder whatever its mode: an ordinary uid is refused
			return
		}
		f := newUndoFix(t)
		f.change(t, "add", "exec.allow", "git") // undoing it narrows: no prompt
		changed := f.text(t)
		dir := filepath.Dir(f.contract)
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		code, out, errs := run(t, user, "rules", "undo", "tester")
		if code != identity.ExitError || !strings.Contains(errs, "[io]") || strings.Contains(errs, "[usage]") || f.text(t) != changed || strings.Contains(out, "Undone") {
			t.Errorf("exit %d stdout %q stderr %q, want 125 [io]", code, out, errs)
		}
	})
	t.Run("a cancelled context during the write is exit 125 [io]", func(t *testing.T) {
		f := newUndoFix(t)
		id := f.change(t, "add", "exec.allow", "git")
		c := f.ref(t)
		hs, _ := f.svc.History(c.Ref)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var errs bytes.Buffer
		if code := undoChange(ctx, f.svc, &c, hs, id, true, &bytes.Buffer{}, &errs); code != identity.ExitError || !strings.Contains(errs.String(), "[io]") {
			t.Errorf("exit %d stderr %q, want 125 [io]", code, errs.String())
		}
	})
	t.Run("an older text that no longer compiles is refused, exit 1", func(t *testing.T) {
		f := newUndoFix(t)
		f.change(t, "add", "exec.allow", "git")
		changed := f.text(t)
		f.svc.Compile = func(context.Context, rules.CheckContext, []byte) error {
			return errors.New("the old text does not compile here")
		}
		code, out, errs := run(t, user, "rules", "undo", "tester")
		if code != identity.ExitFinding || !strings.Contains(errs, "[refused]") || !strings.Contains(errs, "nothing was changed") || f.text(t) != changed || out != "" && strings.Contains(out, "Undone") {
			t.Errorf("exit %d stdout %q stderr %q, want 1 [refused]", code, out, errs)
		}
	})
	t.Run("a change the journal does not hold is usage, exit 2", func(t *testing.T) {
		f := newUndoFix(t)
		f.change(t, "add", "exec.allow", "git")
		c := f.ref(t)
		_, err := f.svc.Revert(t.Context(), rules.RevertReq{ID: "rc-nosuch", Base: c.Base})
		if !errors.Is(err, rules.ErrRefused) || !errors.Is(err, rulefile.ErrNoChange) {
			t.Fatalf("Revert of an id the journal lacks: %v", err)
		}
		var errs bytes.Buffer
		if code := undoFailed(&bytes.Buffer{}, &errs, &c, &rules.HistoryEntry{ID: "rc-nosuch"}, nil, err); code != identity.ExitUsage || !strings.Contains(errs.String(), "[usage]") {
			t.Errorf("exit %d stderr %q, want 2 [usage]", code, errs.String())
		}
	})
	t.Run("an interrupt at the prompt ends it at once, not confirmed", func(t *testing.T) {
		f := newUndoFix(t)
		f.change(t, "remove", "exec.allow", "cat") // undoing it widens
		changed := f.text(t)
		c := f.ref(t)
		hs, _ := f.svc.History(c.Ref)
		pr, pw := io.Pipe() // a terminal that nobody types at
		t.Cleanup(func() { _ = pw.Close() })
		stdinIsTerminal = func() bool { return true }
		confirmInput = pr
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan int, 1)
		var out, errs syncBuffer
		go func() { done <- undoChange(ctx, f.svc, &c, hs, "", false, &out, &errs) }()
		deadline := time.After(20 * time.Second)
		for !strings.Contains(errs.String(), "Type undo to confirm") {
			select {
			case <-deadline:
				t.Fatalf("no prompt: %q", errs.String())
			case <-time.After(5 * time.Millisecond):
			}
		}
		cancel()
		select {
		case code := <-done:
			if code != identity.ExitFinding || !strings.Contains(errs.String(), "[not-confirmed]") || f.text(t) != changed {
				t.Errorf("exit %d stderr %q", code, errs.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("an interrupt at the prompt did not end it")
		}
		// Typing the word afterwards must not write anything either.
		go func() { _, _ = pw.Write([]byte("undo\n")) }()
		time.Sleep(50 * time.Millisecond)
		if f.text(t) != changed {
			t.Error("the word typed after the interrupt wrote")
		}
	})
	t.Run("a journal that cannot be read is exit 125", func(t *testing.T) {
		if testutil.RerunAsOrdinaryUser(t) { // root reads a file whatever its mode: an ordinary uid is refused
			return
		}
		f := newUndoFix(t)
		f.change(t, "add", "exec.allow", "git")
		j := filepath.Join(f.root, rulefile.JournalDirName, rulefile.JournalFile)
		if err := os.Chmod(j, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(j, 0o600) })
		for _, args := range [][]string{{"rules", "history", "tester"}, {"rules", "undo", "tester", "--yes"}} {
			code, _, errs := run(t, user, args...)
			if code != identity.ExitError || !strings.Contains(errs, "[io]") {
				t.Errorf("%v: exit %d stderr %q, want 125 [io]", args, code, errs)
			}
		}
	})
}

// TestRulesUndoNamesTheBlocksItLeaves: an undo from a terminal lifts no live block (version one); it prints each kept block
// and the tego unblock command that ends it, and none for a value that is not plain text.
func TestRulesUndoNamesTheBlocksItLeaves(t *testing.T) {
	c := &rules.ContractRef{Agent: "tester", Path: "/p/agent.yaml"}
	h := &rules.HistoryEntry{ID: "rc-1", Summary: "add git"}
	r := &rules.Reverted{ID: "rc-2", Contract: "/p/agent.yaml", Kept: []rules.LiftOption{
		{Run: "r-1-2-abc", Kind: "exec", Value: "/usr/bin/git", Block: "exec:/usr/bin/git"},
		{Run: "r-1-2-abc", Kind: "read", Value: "/home/u/my docs", Block: "read:/home/u/my docs"},
		{Run: "r-1-2-abc", Kind: "exec", Value: "evil\x1b[2J", Block: "exec:evil\x1b[2J"},
	}}
	out := undone(c, h, r)
	for _, want := range []string{"tego unblock r-1-2-abc exec -- /usr/bin/git", "tego unblock r-1-2-abc read -- '/home/u/my docs'", "stay in force"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Count(out, "end it:") != 2 {
		t.Errorf("an escape byte, or a command for a value that is not plain text:\n%q", out)
	}
	if got := undone(c, h, &rules.Reverted{ID: "rc-2", Contract: "/p/agent.yaml"}); strings.Contains(got, "stay in force") {
		t.Errorf("no kept block, but:\n%s", got)
	}
}

// TestRulesUndoIsJournaledUnderOneWriter: a revert asked with another writer than the dashboard's or the terminal's is
// refused, so a caller cannot name itself in the journal.
func TestRulesUndoIsJournaledUnderOneWriter(t *testing.T) {
	f := newUndoFix(t)
	id := f.change(t, "add", "exec.allow", "git")
	for _, via := range []string{"root", "dashboard-x", "CLI"} {
		if _, err := f.svc.Revert(t.Context(), rules.RevertReq{ID: id, Base: f.ref(t).Base, Via: via}); err == nil {
			t.Errorf("a revert journaled as %q was written", via)
		}
	}
	if f.text(t) == undoBaseText {
		t.Fatal("a refused revert wrote")
	}
	if _, err := f.svc.Revert(t.Context(), rules.RevertReq{ID: id, Base: f.ref(t).Base}); err != nil {
		t.Fatalf("a revert with no writer named: %v", err)
	}
	if es, _ := rulefile.History(f.root, f.ref(t).Path); es[0].Via != rules.Via {
		t.Errorf("a revert that names none is journaled as %q, want %q", es[0].Via, rules.Via)
	}
}

// TestRulesUndoCodesHaveTheirExits (C130): each reason code of an undo refused as a finding is in one table, with exit 1,
// and none of them is a code tego-control's own table (main.go) maps to another exit. The refusals are written through
// that table, so a code that is not in it has no exit.
func TestRulesUndoCodesHaveTheirExits(t *testing.T) {
	want := []string{codeStale, codeNotConfirmed, codeGoverned, codeRefused, codeNoChange}
	if len(findingExits) != len(want) {
		t.Errorf("findingExits holds %d codes, want %d: %v", len(findingExits), len(want), findingExits)
	}
	for _, code := range want {
		if exit, ok := findingExits[code]; !ok || exit != identity.ExitFinding {
			t.Errorf("[%s] exits %d (in the table: %v), want %d", code, exit, ok, identity.ExitFinding)
		}
		if _, clash := exits[code]; clash {
			t.Errorf("[%s] is also one of tego-control's own codes", code)
		}
	}
}
