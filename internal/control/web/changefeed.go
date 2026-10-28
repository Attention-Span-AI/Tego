// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// Rule changes as rows: the rule-change journal lives beside the ledgers, not in them, so a
// change, an undo or a new rules file never reached Logs or a run's timeline; only the launcher's gap line of a live
// block it placed did. Logs and the timeline now show each journal entry as a row of its own at its time, between the
// ledger's rows: what changed in plain words, its direction, the line it was made from, the live blocks it placed or
// lifted, whether it was undone, and a link to the rules file's History (where Undo is). The rows come from the rule
// service (ChangeFeed, rules.Service.Feed); this file only places them and decides nothing.
//
// Logs shows them while the search narrows only by run, agent and time (a kind, verdict, text, rule, path or host
// term is about ledger lines, which a rule change is not). A run's timeline shows the changes of its rules file made
// while it ran (the run kept the rules it started with: they are what its next run gets), the ones made from one of
// its lines, and the ones that placed or lifted a live block on it.

// ChangeFeed is the rule service's journal feed (rules.Service.Feed); a Config.Rules without it shows no rule-change
// rows.
type ChangeFeed interface {
	Feed() ([]rules.FeedEntry, error)
}

// changeRow is one journal entry as a row.
type changeRow struct {
	rules.FeedEntry
	// Key is the row's key ("rc-<id>"): the timeline's live rows replace a row with the same key.
	Key string
	// Href is the rules file's Change rules page, with its History and Undo; From the line the change was made from
	// ("" for none) and FromWords that line in words ("line #12 of this run", "line #12 of r-…").
	Href, From, FromWords string
	// Live are the live blocks it placed or lifted, in words, on the run of the timeline when there is one ("this
	// run"), on every run otherwise.
	Live []string
	// Note is what the change is to the timeline's run: made after it ended, or kept for the file's next run.
	Note string
}

// changesAt is change rows placed among a page's rows (placedChanges): Before by the Cursor of the row each goes
// before, Tail after the last row.
type changesAt struct {
	Before map[string][]changeRow
	Tail   []changeRow
}

// tlOf is the "tl" template func: a timeline's rows, whether its run is live and names a contract file, and the change
// rows among them (none, or one changesAt).
func tlOf(rows []ledgerview.Row, live, contract bool, ch ...changesAt) tlRows {
	t := tlRows{Rows: rows, Live: live, Contract: contract}
	if len(ch) > 0 {
		t.Changes = ch[0]
	}
	return t
}

// placed is cs placed among rows (placedChanges) as a changesAt.
func placed(rows []ledgerview.Row, cs []changeRow, top, bottom bool) changesAt {
	b, t := placedChanges(rows, cs, top, bottom)
	return changesAt{Before: b, Tail: t}
}

// feed is the rule service's journal feed, nil without one or when it cannot be read.
func (s *Server) feed() []rules.FeedEntry {
	f, ok := s.cfg.Rules.(ChangeFeed)
	if !ok {
		return nil
	}
	es, err := f.Feed()
	if err != nil {
		return nil
	}
	return es
}

// rowOf is e as a row, said from run (the timeline's run; "" for Logs).
func rowOf(e rules.FeedEntry, run string) changeRow {
	r := changeRow{FeedEntry: e, Key: "rc-" + e.ID, Href: "/rules/change?c=" + url.QueryEscape(e.Ref) + "#h-hist"}
	if e.Run != "" && e.Line > 0 {
		r.From = lineAct(e.Run, e.Line)
		n := strconv.FormatUint(e.Line, 10)
		if e.Run == run {
			r.FromWords = "line #" + n + " of this run"
		} else {
			r.FromWords = "line #" + n + " of " + shortRun(e.Run)
		}
	}
	home := homeDir()
	for _, l := range e.Live {
		if !l.OK || l.Block == "" || run != "" && l.Run != run {
			continue
		}
		where := "this run"
		if l.Run != run {
			where = shortRun(l.Run)
		}
		w := liveWords(l.Block, shortener{home: home})
		if l.Lift {
			r.Live = append(r.Live, "lifted from "+where+": "+w)
		} else {
			r.Live = append(r.Live, "live on "+where+": "+w)
		}
	}
	return r
}

// changesOfRun is the feed's entries about run, newest first (the package comment says which).
func changesOfRun(feed []rules.FeedEntry, run *ledgerview.Run) []changeRow {
	var out []changeRow
	for _, e := range feed {
		if !aboutRun(e, run) {
			continue
		}
		r := rowOf(e, run.ID)
		switch {
		case run.Ended && !run.End.IsZero() && e.At.After(run.End):
			r.Note = "after this run ended"
		case len(r.Live) == 0 && !e.Created():
			r.Note = "this run kept the rules it started with; the next run of the file gets these"
		}
		out = append(out, r)
	}
	return out
}

// aboutRun reports whether e is about run: made from one of its lines, placing or lifting a live block on it, or a
// change of its rules file made after it started and before it ended.
func aboutRun(e rules.FeedEntry, run *ledgerview.Run) bool {
	if e.Run == run.ID {
		return true
	}
	for _, l := range e.Live {
		if l.Run == run.ID && l.Block != "" {
			return true
		}
	}
	for _, id := range e.Runs {
		if id == run.ID {
			return !run.Ended || run.End.IsZero() || !e.At.After(run.End)
		}
	}
	return false
}

// logsChanges is the feed's entries a Logs search shows, newest first: none when it narrows by anything but run,
// agent and time; else each entry about a run it names (aboutRun), of an agent it names (the name the entry's text
// gives), and inside its time range.
func logsChanges(feed []rules.FeedEntry, f ledgerview.Filter, snap *ledgerview.Snapshot) []changeRow {
	if len(feed) == 0 || !contextOnly(f) {
		return nil
	}
	runs := append([]string{}, f.Runs...)
	if f.Run != "" {
		runs = append(runs, f.Run)
	}
	agents := append([]string{}, f.Agents...)
	if f.Agent != "" {
		agents = append(agents, f.Agent)
	}
	var out []changeRow
	for _, e := range feed {
		if !f.Since.IsZero() && e.At.Before(f.Since) || !f.Until.IsZero() && !e.At.Before(f.Until) {
			continue
		}
		if len(agents) > 0 && !slices.Contains(agents, e.Agent) || slices.Contains(f.Not.Agents, e.Agent) {
			continue
		}
		if len(runs) > 0 && !anyRun(e, runs, snap) || len(f.Not.Runs) > 0 && anyRun(e, f.Not.Runs, snap) {
			continue
		}
		out = append(out, rowOf(e, ""))
	}
	return out
}

// contextOnly reports whether f narrows Logs only by run, agent and time.
func contextOnly(f ledgerview.Filter) bool {
	n := f.Not
	return f.Kind == "" && len(f.Kinds) == 0 && len(f.Verdicts) == 0 && f.Text == "" && len(f.Words) == 0 &&
		len(f.Rules) == 0 && f.PathPrefix == "" && len(f.Hosts) == 0 && f.Source == "" && f.PID == 0 && !f.OnlyRefus &&
		len(n.Kinds) == 0 && len(n.Verdicts) == 0 && len(n.Rules) == 0 && len(n.Hosts) == 0 && len(n.Words) == 0
}

// anyRun reports whether e is about one of the runs ids names.
func anyRun(e rules.FeedEntry, ids []string, snap *ledgerview.Snapshot) bool {
	for _, id := range ids {
		if r := snap.Find(id); r != nil && aboutRun(e, r) || r == nil && e.Run == id {
			return true
		}
	}
	return false
}

// placedChanges is where change rows go among rows (both newest first): each before the newest row that is not
// newer than it (keyed by that row's Cursor), or in tail after the last row. top says the rows are the newest page
// (a change newer than every row goes before the first); bottom that they are the oldest (a change older than every
// row goes in tail). With no rows, every change goes in tail when the page is both.
func placedChanges(rows []ledgerview.Row, cs []changeRow, top, bottom bool) (before map[string][]changeRow, tail []changeRow) {
	for _, c := range cs {
		i := 0
		for i < len(rows) && rows[i].TS.After(c.At) {
			i++
		}
		switch {
		case i == len(rows):
			if bottom && (top || len(rows) > 0) {
				tail = append(tail, c)
			}
		case i == 0 && !top:
			// newer than this page's newest row: it belongs to a newer page
		default:
			if before == nil {
				before = map[string][]changeRow{}
			}
			k := rows[i].Cursor()
			before[k] = append(before[k], c)
		}
	}
	return before, tail
}

// liveChanges is the change rows a live timeline's poll (GET /runs/<id>/rows?after=<seq>) adds with its new rows: the
// run's changes newer than line after, which the page shows already up to that line, placed among the new rows (one
// newer than every row goes at the top, one older than every new row after them: just above the rows the page has).
// A change row the page shows already at the top comes again with its key, and live.js keeps the newest copy. None
// on a filtered timeline.
func liveChanges(feed []rules.FeedEntry, run *ledgerview.Run, rows []ledgerview.Row, after uint64, verdict string) changesAt {
	if verdict != "" || len(feed) == 0 {
		return changesAt{}
	}
	var since time.Time
	for i := len(run.Events) - 1; i >= 0; i-- {
		if run.Events[i].Seq == after {
			since = run.Events[i].TS
			break
		}
	}
	return placed(rows, changesAfter(changesOfRun(feed, run), since), true, true)
}

// changesAfter is cs without the ones at or before t (zero keeps all).
func changesAfter(cs []changeRow, t time.Time) []changeRow {
	if t.IsZero() {
		return cs
	}
	var out []changeRow
	for _, c := range cs {
		if c.At.After(t) {
			out = append(out, c)
		}
	}
	return out
}
