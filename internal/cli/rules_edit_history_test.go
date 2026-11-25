// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// editWith makes $VISUAL a script that appends line to the file it is given.
func editWith(t *testing.T, line string) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "ed.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+line+"' >> \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", script)
}

// TestRulesEditIsInTheChangeHistory: a saved `tego rules edit` is one journal entry, written through the writer
// the dashboard uses (rulefile.Replace): the same journal that tego rules history and the dashboard read, in the
// dashboard's own wording for a whole-text edit, direction mixed (so an undo of it asks for the word), via "cli", with
// the old text kept as <file>.bak. The output says so, and says where the history lists it.
func TestRulesEditIsInTheChangeHistory(t *testing.T) {
	w := newRegistryWorld(t)
	path := filepath.Join(w.project, "agent.yaml")
	const good = "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	editWith(t, "# edited")
	code, out, errs := run(t, "rules", "edit", path)
	if code != identity.ExitOK || !strings.HasPrefix(out, "✓ Saved and checked "+path+"\n") || !strings.Contains(out, "Recorded in the change history as ") ||
		!strings.Contains(out, "tego rules undo "+shellQuote(path)) || strings.Contains(out, "Not in the change history") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	es, err := rulefile.History(w.runs, path)
	if err != nil || len(es) != 1 {
		t.Fatalf("journal %+v (%v): want one entry", es, err)
	}
	e := es[0]
	if e.Op != rulefile.OpChange || e.Via != "cli" || e.Direction != "mixed" || e.Summary != "free edit of the whole text" ||
		e.OldSHA256 != rulefile.Sum([]byte(good)) || !strings.Contains(out, e.ID) {
		t.Errorf("entry %+v", e)
	}
	if b, err := os.ReadFile(path + ".bak"); err != nil || string(b) != good {
		t.Errorf("the old text is not kept: %q %v", b, err)
	}
	if now, _ := os.ReadFile(path); string(now) != good+"# edited\n" {
		t.Errorf("file %q", now)
	}
	if b, err := rulefile.Blob(w.runs, e.OldSHA256); err != nil || string(b) != good {
		t.Errorf("the journal does not hold the old text: %q %v", b, err)
	}
	// A rejected edit and an unchanged one write no entry.
	editWith(t, "invalid: [")
	if code, _, _ := run(t, "rules", "edit", path); code != identity.ExitFinding {
		t.Fatalf("a bad edit: exit %d", code)
	}
	if es, _ := rulefile.History(w.runs, path); len(es) != 1 {
		t.Errorf("a rejected edit was journaled: %+v", es)
	}
}

// TestRulesEditSaysWhenItCannotBeUndone: where the writer cannot keep the history (no ledger root yet, or a file
// its guards refuse), the edit is still saved as before and the output says it is not in the history and cannot be
// undone, instead of leaving that unsaid.
func TestRulesEditSaysWhenItCannotBeUndone(t *testing.T) {
	for _, tc := range []string{"no-ledger-root", "group-writable"} {
		t.Run(tc, func(t *testing.T) {
			w := newRegistryWorld(t)
			path := filepath.Join(w.project, "agent.yaml")
			const good = "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\n"
			if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
				t.Fatal(err)
			}
			switch tc {
			case "no-ledger-root":
				if err := os.Remove(w.runs); err != nil {
					t.Fatal(err)
				}
			case "group-writable":
				if err := os.Chmod(path, 0o666); err != nil { // writable by every user: the writer's guard refuses it
					t.Fatal(err)
				}
			}
			editWith(t, "# edited")
			code, out, errs := run(t, "rules", "edit", path)
			if code != identity.ExitOK || !strings.HasPrefix(out, "✓ Saved and checked "+path+"\n") || !strings.Contains(out, "Not in the change history, so tego rules undo cannot give the old text back") ||
				strings.Contains(out, "Recorded in the change history") {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
			if now, _ := os.ReadFile(path); string(now) != good+"# edited\n" {
				t.Errorf("file %q", now)
			}
		})
	}
}
