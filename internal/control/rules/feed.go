// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// The rule-change feed: the journal's changes, undos and new rules files of every rules file,
// read for the Logs page and the run timeline, which show them as rows of their own between the ledger's lines. It
// reads only: the journal under the ledger root and the blobs of the texts written, never a rules file.

// FeedMax bounds how many entries Feed returns, newest first: a page shows the ones around its lines.
const FeedMax = 2000

// FeedEntry is one journal entry as a row of Logs or a run's timeline says it.
type FeedEntry struct {
	ID, Op string
	At     time.Time
	Via    string
	// Contract is the rules file's resolved path, Ref its opaque ref (the Change rules page's c=), Agent the name the
	// text it wrote gives (name:, else the file's name).
	Contract, Ref, Agent string
	// Run and Line are the run and its line the change was made from ("" and 0 for none).
	Run  string
	Line uint64
	// Words is the entry in one plain line: its sentences ("Asks you before it reads ./docs/ → Can never read
	// ./docs/"), an undo's "Undid: …", a new file's "Set up the rules file", else its summary.
	Words string
	// Direction is narrows, widens or mixed ("" for a new file).
	Direction string
	// UndoneBy is the revert that undid the entry, "" while it stands.
	UndoneBy string
	// Live are the live blocks it placed on running runs (or, with Lift, an undo lifted).
	Live []LiveResult
	// Runs are the runs of the same rules file that started before the entry: the run of them still running then
	// kept the rules it started with, and its next run got these (a page narrows them by each run's end).
	Runs []string
}

// Created reports whether the entry set up a new rules file ("Set up a new agent"): no older text, no direction.
func (e FeedEntry) Created() bool { return e.Op == rulefile.OpCreate }

// feedCache is the last feed read and the journal's size and time it was read at.
type feedCache struct {
	size   int64
	mtime  time.Time
	runs   int
	es     []FeedEntry
	agents map[string]string // agent name by the sha256 of the text an entry wrote
}

// JournalPath is the rule-change journal of the ledger root root, the file Feed reads: a page that keeps an answer
// while nothing it shows moved (the run page's region key, web runkey.go) stats it to see a change, an undo or a new
// rules file.
func JournalPath(root string) string {
	return filepath.Join(root, rulefile.JournalDirName, rulefile.JournalFile)
}

// Feed is every change, revert and creation the rule-change journal holds, of every rules file, newest first, at most
// FeedMax. It is read again only when the journal file or the set of runs changed, so a page that re-renders each
// second reads it once. A journal that cannot be read is no feed and no error a page must show: its lines still show.
func (s *Service) Feed() ([]FeedEntry, error) {
	fi, err := os.Stat(JournalPath(s.Ledger))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sts, err := s.starts()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	fc := s.feed
	s.mu.Unlock()
	if fc != nil && fc.size == fi.Size() && fc.mtime.Equal(fi.ModTime()) && fc.runs == len(sts) {
		return fc.es, nil
	}
	raw, err := rulefile.ReadJournal(s.Ledger)
	if err != nil {
		return nil, err
	}
	agents := map[string]string{}
	if fc != nil {
		agents = maps.Clone(fc.agents) // another Feed may be reading the cached one
	}
	folded := rulefile.Fold(raw, nil)
	byID := make(map[string]rulefile.Entry, len(folded))
	for _, e := range folded {
		byID[e.ID] = e
	}
	out := make([]FeedEntry, 0, min(len(folded), FeedMax))
	for _, e := range folded {
		if len(out) == FeedMax {
			break
		}
		f := FeedEntry{ID: e.ID, Op: e.Op, At: e.At, Via: e.Via, Contract: e.Contract, Ref: refOf(e.Contract), Run: e.Run,
			Line: e.Line, Direction: e.Direction, UndoneBy: e.UndoneBy, Agent: s.feedAgent(agents, e)}
		f.Words = feedWords(e, byID)
		for _, l := range e.Live {
			f.Live = append(f.Live, LiveResult{Run: l.Run, Block: l.Block, OK: l.OK, Err: l.Err, Lift: l.Lift})
		}
		for _, st := range sts {
			if st.Resolved == e.Contract && st.At.Before(e.At) {
				f.Runs = append(f.Runs, st.Run)
			}
		}
		out = append(out, f)
	}
	s.mu.Lock()
	s.feed = &feedCache{size: fi.Size(), mtime: fi.ModTime(), runs: len(sts), es: out, agents: agents}
	s.mu.Unlock()
	return out, nil
}

// feedAgent is the agent name the text e wrote gives, remembered by its sha256 in agents.
func (s *Service) feedAgent(agents map[string]string, e rulefile.Entry) string {
	if n, ok := agents[e.NewSHA256]; ok {
		return n
	}
	n := strings.TrimSuffix(filepath.Base(e.Contract), filepath.Ext(e.Contract))
	if b, err := rulefile.Blob(s.Ledger, e.NewSHA256); err == nil {
		n = agentName(b, e.Contract)
	}
	if e.NewSHA256 != "" {
		agents[e.NewSHA256] = n
	}
	return n
}

// feedWords is e in one plain line (FeedEntry.Words).
func feedWords(e rulefile.Entry, byID map[string]rulefile.Entry) string {
	switch {
	case e.Op == rulefile.OpRevert:
		return rulesview.UndoWords(e, byID)
	case e.Op == rulefile.OpCreate:
		return "Set up the rules file"
	case len(e.Sentences) > 0:
		return strings.Join(e.Sentences, "; ")
	case e.Summary != "":
		return e.Summary
	}
	return "Changed the rules file"
}
