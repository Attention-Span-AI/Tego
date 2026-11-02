// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// Pending is a run's rules file changed after the run started: the run keeps the rules it started with, the next
// run of that file gets the new ones (F10). The page shows it as a banner with the changes' sentences, or, when
// nothing dates a change (Differs), with a line that says the file differs.
type Pending struct {
	// Changes is each change and revert of the rules file the rule-change journal holds with a time after the run's
	// start that still stands, oldest first: what `tego rule` and the dashboard wrote, each with its summary and
	// sentences. A change undone since is left out, and so is the revert that undid it; a revert of a change made
	// before the run started stays, with what it undid in words as its Summary (UndoWords) and no Sentences.
	Changes []rulefile.Entry `json:"changes,omitempty"`
	// Edited is the file's modification time when the journal does not account for it (the file was changed after
	// its last journaled write, or with none after the run started): an editor or a script changed it. Zero when the
	// journal accounts for every change.
	Edited time.Time `json:"edited,omitzero"`
	// Unchecked: the file could not be compared with what the run ran (it extends profiles this view could not
	// resolve, no longer loads, or the run recorded no contract_hash), so Pending rests on the journal and the file's
	// time alone.
	Unchecked bool `json:"unchecked,omitempty"`
	// Differs: the file loads to other rules than the run ran, and neither the journal nor the file's time dates a
	// change after the run started (Changes and Edited are empty): a profile it extends changed, or the run started
	// from other bytes (a copy put back with its own older time, a change while the run was starting). The next run
	// gets the file's rules all the same. Set only from a comparison, so never with Unchecked.
	Differs bool `json:"differs,omitempty"`
}

// editSlack is how much later than the newest journaled write the file's mtime may be and still be that write: the
// journal line is appended after the rename that set the mtime.
const editSlack = 2 * time.Second

// pendingOf is the Pending of a run that started at started under the ledger root root, whose rules file is path
// and checkSource found src. A file that still loads to the run's contract_hash has nothing pending, even when the
// journal holds changes since (a change and its revert). A journal that cannot be read is treated as empty; the
// file's time still says whether it changed. A file that loads to other rules with nothing to date the change is
// pending as Differs; one that could not be compared and that nothing dates has nothing pending.
func pendingOf(root, path string, started time.Time, src source) *Pending {
	if path == "" || !src.read || src.matches || started.IsZero() {
		return nil
	}
	p := &Pending{Unchecked: !src.checked}
	hist, _ := rulefile.History(root, resolvedPath(path)) // newest first; unreadable: rest on the file's time
	byID := make(map[string]rulefile.Entry, len(hist))
	for _, e := range hist {
		byID[e.ID] = e
	}
	since := func(e rulefile.Entry) bool { return e.At.After(started) }
	var newest time.Time
	for i := len(hist) - 1; i >= 0; i-- {
		e := hist[i]
		if !since(e) || (e.Op != rulefile.OpChange && e.Op != rulefile.OpRevert) {
			continue
		}
		newest = e.At // every journaled write since the start, shown or not, accounts for the file's time
		if e.UndoneBy != "" {
			continue // undone since: not what the next run gets
		}
		if e.Op == rulefile.OpRevert {
			if t, ok := byID[e.Reverts]; ok && since(t) {
				continue // it undid a change made since the start: the two leave the file as it was
			}
			e.Summary, e.Sentences = UndoWords(e, byID), nil
		}
		p.Changes = append(p.Changes, e)
	}
	if src.mtime.After(started) && (newest.IsZero() || src.mtime.After(newest.Add(editSlack))) {
		p.Edited = src.mtime
	}
	if len(p.Changes) == 0 && p.Edited.IsZero() {
		if !src.checked {
			// Nothing dates a change, and the file was not compared with what the run ran: nothing says it differs.
			return nil
		}
		// It loads to other rules than the run ran, yet nothing dates a change after the start: a profile it extends
		// changed, or the run started from other bytes. The next run still gets the file's rules, so the page says the
		// file differs, without a time.
		p.Differs = true
	}
	return p
}

// resolvedPath is path with its directory's symlinks resolved, as the journal names a contract.
func resolvedPath(path string) string {
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Join(dir, filepath.Base(path))
}

// UndoWords is the revert e in one plain line, said from the change it undid (byID holds the contract's journal
// entries by id): "Undid: Can never read ./confidential/" from that change's sentences ("before → after", as the
// journal keeps them), "Redid: …" when it undid an undo, and "Undid an earlier change" when the journal holds no
// sentences for it (a change written before sentences were journaled).
func UndoWords(e rulefile.Entry, byID map[string]rulefile.Entry) string {
	verb := "Undid"
	t := byID[e.Reverts]
	if t.Op == rulefile.OpRevert {
		verb, t = "Redid", byID[t.Reverts]
	}
	var after []string
	for _, s := range t.Sentences {
		if _, a, cut := strings.Cut(s, " → "); cut {
			s = a
		}
		if s = strings.TrimSpace(s); s != "" {
			after = append(after, s)
		}
	}
	if len(after) == 0 {
		return verb + " an earlier change"
	}
	return verb + ": " + strings.Join(after, "; ")
}
