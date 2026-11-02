// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// Scope is what a rule from one event names: a read or written file's folder level (0 the file, 1 its folder, n an
// ancestor, up to the run's working directory or home), the program's command instead of the whole program, or the
// destination's whole host instead of its host:port.
type Scope struct {
	Level   int
	Command bool
	Host    bool
}

// Choice is one action at one scope, possible (OK, with its Effect and Direction) or not (Why).
type Choice struct {
	Action string // block | ask | allow
	Scope  Scope
	OK     bool
	Why    string
	Effect string
	// Direction is narrows, widens or mixed: which way the choice moves what the next run may do.
	Direction string
}

// ActPlan is what the event details page's "Act on this" panel shows for one line and, when an action is picked,
// its change.
type ActPlan struct {
	Contract string
	Kind     string // read | write | exec | net
	Verb     string
	What     string
	Refused  bool
	// Err says why no rule can be made from the line (a run_start, a model call); the panel then offers nothing.
	Err string
	// Base is the sha256 of the contract text the plan was made on: the preview renders it and the confirm carries
	// it back, so the write lands only on the text the person looked at .
	Base string
	// Levels is a read or write's breadcrumb: Levels[i] is the path Scope.Level i names.
	Levels []string
	// EntryScope is the scope of the ask entry that decided the line (rule.EntryLevel), where "Never allow" opens so
	// the block moves that entry; nil when no ask entry decided it.
	EntryScope *Scope
	// Program is an exec's program path; Command its command entry ("git push"), "" when the run names none.
	Program, Command string
	// Dest is a connection's destination and Host its host, "" for a unix socket.
	Dest, Host string
	// Choices are every action at every scope the event's kind has.
	Choices []Choice
	// The picked action's change; empty when none is picked or PickErr says why it cannot be made.
	Action                string
	Scope                 Scope
	Summary, Effect, Diff string
	// Direction is the picked change's: narrows, widens or mixed.
	Direction string
	// Sentences are the picked change in words, before and after (rule.Result.Sentences); empty for a change of a
	// list the words do not cover (a command entry), where Effect says it.
	Sentences []Sentence
	// Cwd and Home are the run's working directory and the invoking user's home, for display only: the page writes
	// paths under them short ("./a/b", "~/x").
	Cwd, Home string
	// Ack is the acknowledgement of the picked change (ack.go): the confirm of a change that is not a narrowing
	// carries it back, and a write whose plan computes another writes nothing.
	Ack string
	// NewBase is the sha256 of the text a Saved change wrote: Undo carries it, so it undoes only that text.
	NewBase string
	// UndoAck is the acknowledgement of the Undo of a Saved change (Revert), which its form carries when undoing is
	// not a narrowing.
	UndoAck string
	// Now are the live blocks "Also apply now" can place for the picked change on running runs of the contract.
	Now []NowOption
	// Unresolved are the host names the picked change adds to net.allow or net.ask that did not resolve here
	// (hosts.go): a warning, never a refusal. A preview looks them up; a confirm does not.
	Unresolved []UnresolvedHost
	// Saved is set when the change was written: ID is its journal entry, Bak the old file, Live what "also apply
	// now" did.
	Saved   bool
	ID, Bak string
	Live    []LiveResult
	PickErr string
	// Nothing is set when PickErr says the contract already does what was picked (not a failure); Stale when the
	// confirm's base is not what the file holds (it changed since the preview); NeedsAck when a change that is not a
	// narrowing was confirmed without the acknowledgement (ErrNeedsAck), so nothing was written; AckMismatch, with
	// NeedsAck, when an acknowledgement was posted but made for another change (ErrAckMismatch: the dashboard
	// restarted, or the day's dated comment changed the text, between the preview and the confirm).
	Nothing, Stale, NeedsAck, AckMismatch bool
}

// ActReq is one "Act on this": line Seq of Run, an action at a scope and, with Write, the confirm.
type ActReq struct {
	Run    string
	Seq    uint64
	Action string // "" lists the choices only
	Scope  Scope
	// Write confirms the picked change. Base must be the ActPlan.Base the preview showed: a write on any other text
	// is refused as stale.
	Write bool
	Base  string
	// AlsoNow are the runs to place the change's live blocks on (ActPlan.Now), each a running run of the contract.
	AlsoNow []string
	// Ack is the person's acknowledgement of a change that is not a narrowing: the ActPlan.Ack the preview showed,
	// posted by the event page's required checkbox naming the After sentence. A Write of such a change whose plan
	// computes another Ack (none, or one made for another change) writes nothing (ActPlan.NeedsAck), as ApplyChange,
	// ApplyRaw and Revert refuse one.
	Ack string
	// Hint, when set, is where the dashboard's read model saw line Seq start in the run's events file: a view (no
	// Write) reads run_start and that one line (rulefile.FindAt, which checks the hint and falls back to the scan)
	// instead of every line before it. A Write ignores it and reads the line as it always has (rulefile.FindIn).
	Hint *LineHint
}

// LineHint is where a line starts in its run's events file, and the file as the reader saw it (rulefile.Hint).
type LineHint = rulefile.Hint

// ActOn reads line r.Seq of r.Run, every action at every scope for it and, with r.Action set, the change at r.Scope;
// with r.Write it writes it on r.Base, as tego rule does (the compiler's last word in the run's context, a .bak, a
// dated comment, a journal line), then places the live blocks of r.AlsoNow. A write that is not a narrowing wants
// r.Ack, the plan's own Ack; without it the plan comes back with NeedsAck and PickErr (ErrNeedsAck's words) and
// nothing is written.
func (s *Service) ActOn(ctx context.Context, r ActReq) (*ActPlan, error) {
	hint := r.Hint
	if r.Write {
		hint = nil // the write's authority re-reads the line from the start, as tego rule does
	}
	found, cc, err := s.found(r.Run, r.Seq, hint)
	if err != nil {
		return nil, err
	}
	date := s.date()
	req := func(a rule.Action, sc Scope, check func([]byte) error) rule.Request {
		q := found.Request(a, false, s.Home, date, check)
		q.Level, q.Command, q.HostOnly = sc.Level, sc.Command, sc.Host
		return q
	}
	p := &ActPlan{Contract: found.Contract, Base: found.Base()}
	t, err := rule.TargetOf(found.Event)
	p.Kind, p.Verb, p.What, p.Refused = string(t.Kind), t.Verb(), t.What(), t.Refused
	if err != nil {
		p.Err = err.Error()
		return p, nil
	}
	cwd := found.Cwd
	if cwd == "" {
		cwd = filepath.Dir(found.Contract)
	}
	p.Cwd, p.Home = cwd, s.Home
	var scopes []Scope
	switch t.Kind {
	case rule.KindRead, rule.KindWrite:
		p.Levels = rule.Ancestors(t.Path, cwd, s.Home)
		for i := range p.Levels {
			scopes = append(scopes, Scope{Level: i})
		}
		if l := rule.EntryLevel(t, cwd, s.Home); l >= 0 {
			p.EntryScope = &Scope{Level: l}
		}
	case rule.KindExec:
		p.Program = t.Path
		p.Command = rule.CommandEntry(t)
		scopes = []Scope{{}, {Command: true}}
	case rule.KindNet:
		p.Dest, p.Host = t.Dest, rule.HostOf(t.Dest)
		scopes = []Scope{{}, {Host: true}}
	}
	for _, sc := range scopes {
		for _, a := range []rule.Action{rule.Block, rule.Ask, rule.Allow} {
			res, err := rule.Apply(req(a, sc, nil))
			c := Choice{Action: string(a), Scope: sc, OK: err == nil}
			if err != nil {
				c.Why = err.Error()
			} else {
				c.Effect, c.Direction = res.Effect, string(res.Direction)
			}
			p.Choices = append(p.Choices, c)
		}
	}
	if r.Action == "" {
		return p, nil
	}
	p.Action, p.Scope = r.Action, r.Scope
	res, err := rule.Apply(req(rule.Action(r.Action), r.Scope, s.check(ctx, cc)))
	if err != nil {
		p.PickErr, p.Nothing = err.Error(), errors.Is(err, rule.ErrNothing)
		return p, nil
	}
	p.Summary, p.Effect, p.Diff, p.Direction = res.Summary, res.Effect, res.Diff, string(res.Direction)
	ref, newSum := actRef(r.Run, r.Seq), rulefile.Sum(res.Text)
	p.Ack = s.ack(ref, p.Base, newSum)
	for _, sn := range res.Sentences {
		p.Sentences = append(p.Sentences, Sentence{Before: sn.Before, After: sn.After, Direction: string(sn.Direction)})
	}
	if res.Direction == rule.Narrows {
		p.Now = s.nowOptions(ctx, s.liveRunsOf(found.Contract), res.Changes, cwd, entriesOf(res.Text))
	}
	if !r.Write {
		p.Unresolved = s.unresolved(ctx, res.Changes)
		return p, nil
	}
	if r.Base == "" || r.Base != p.Base {
		p.PickErr, p.Stale = "the contract changed since you looked (or the confirm carried no base): nothing was written; "+
			"look at the change again", true
		return p, nil
	}
	if res.Direction != rule.Narrows && !s.ackOK(r.Ack, ref, p.Base, newSum) {
		err := ackErr(r.Ack)
		p.PickErr, p.NeedsAck, p.AckMismatch = "nothing was written: "+err.Error(), true, errors.Is(err, ErrAckMismatch)
		return p, nil
	}
	e, err := s.writer().Replace(ctx, found.Contract, r.Base, res.Text, rulefile.Change{Via: Via, Run: found.Run,
		Line: found.Event.Seq, Summary: res.Summary, Sentences: sentenceLines(p.Sentences), Direction: string(res.Direction)})
	if e != nil {
		p.ID, p.Bak, p.NewBase = e.ID, e.Bak, e.NewSHA256
	}
	if errors.Is(err, rulefile.ErrJournal) {
		p.ID = "" // written, not journaled: no journal line holds the ID, so the page offers the .bak and no Undo
	}
	if p.ID != "" && p.NewBase != "" {
		p.UndoAck = s.ack(revertRef(p.ID), p.NewBase, r.Base) // the Undo writes back the text the change was made on
	}
	if err != nil && !errors.Is(err, rulefile.ErrJournal) {
		p.PickErr, p.Stale = err.Error(), errors.Is(err, rulefile.ErrStale)
		return p, nil
	}
	p.Saved = true
	if err != nil {
		p.PickErr = err.Error() // written, not journaled: the page says so and where the old text is
	}
	if len(r.AlsoNow) > 0 {
		p.Live = s.applyNow(ctx, p.Now, r.AlsoNow)
		if p.ID != "" {
			if err := s.writer().AppendLive(ctx, p.ID, journalLive(p.Live)); err != nil {
				p.PickErr = fmt.Sprintf("the live blocks were placed but not journaled: %v", err)
			}
		}
	}
	return p, nil
}

// liveRunsOf is the running runs, newest first, whose contract_source is the contract at path.
func (s *Service) liveRunsOf(path string) []string {
	sts, err := s.starts()
	if err != nil {
		return nil
	}
	want := resolvedPath(filepath.Clean(path))
	var out []string
	for _, st := range sts {
		if st.Contract != "" && st.Resolved == want && s.isLive(filepath.Join(s.Ledger, st.Run)) {
			out = append(out, st.Run)
		}
	}
	return out
}
