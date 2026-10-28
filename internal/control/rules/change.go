// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// The errors ApplyChange, ApplyRaw and Revert refuse with; nothing is written for any of them.
var (
	// ErrStale is a confirm whose base is not what the contract holds: it changed since the person looked.
	ErrStale = errors.New("the contract changed since you looked")
	// ErrNeedsAck is a change that is not a narrowing (it widens, is mixed, or is a free edit) confirmed without the
	// acknowledgement the page asks for.
	ErrNeedsAck = errors.New("this change lets the next run do more: confirm it with the acknowledgement")
	// ErrRefused is a change the core or the compiler refuses, or one that changes nothing.
	ErrRefused = errors.New("refused")
	// ErrNotWritable is a contract of the set that fails a write guard (rulefile.Check says why).
	ErrNotWritable = errors.New("the dashboard may not change this contract")
)

// Edit is one entry added to or removed from one list of a contract, or "never" for an ask entry (rule.Edit).
type Edit struct {
	Op    string // add | remove | never
	Key   string // fs.write, fs.deny_read, fs.ask_read, fs.ask, fs.deny_write, exec.allow, net.allow, net.ask
	Entry string
}

// EditKeys is the lists an Edit may change, in the order a form offers them.
func EditKeys() []string { return rule.EditKeys() }

// MaxEntry is the longest entry an Edit adds, in bytes (rule.MaxEntry).
const MaxEntry = rule.MaxEntry

// Sentence is one change in words: what the next run did before and does after, and which way that moves.
type Sentence struct {
	Before, After string
	Direction     string
}

// ChangeReq is one change of one contract of the set (Contracts), named by its Ref.
type ChangeReq struct {
	Ref string
	// Base is the sha256 of the text the person looked at (ContractRef.Base, ChangePlan.Base).
	Base  string
	Edits []Edit
	// AlsoNow are the running runs to place the change's live blocks on (ChangePlan.Now).
	AlsoNow []string
	// Ack is the person's acknowledgement of a change that is not a narrowing: the ChangePlan.Ack of the preview
	// they confirmed (ack.go).
	Ack string
}

// ChangePlan is a change planned and not written: the preview.
type ChangePlan struct {
	Ref      string
	Contract string // the path, for display
	Agent    string
	// Base is the sha256 of the text the plan was made on, which the confirm carries back.
	Base string
	// Stale says the request's base was not that text: the plan is on the text now, and the page says it changed.
	Stale bool
	// Raw marks a free edit (PlanRaw): the full new text, which cannot be classified.
	Raw   bool
	Edits []Edit
	// Diff is the file's line diff, removed lines first; Sentences the change in words.
	Diff      string
	Sentences []Sentence
	// Summary is the change in one line, as the journal records it.
	Summary string
	// Direction is narrows, widens or mixed; Why what decided it. NeedsAck is every direction but narrows.
	Direction string
	Why       string
	NeedsAck  bool
	// Ack is the acknowledgement of this exact change (ack.go), set when the change can be made: the confirm of one
	// that needs it carries it back.
	Ack string
	// Now are the live blocks "Also apply now" offers on running runs of the contract (narrowings only).
	Now []NowOption
	// Err is why the change cannot be made (empty when it can); Nothing marks "the contract already says so".
	Err     string
	Nothing bool
	// EnvRefused marks a free edit refused because its text changes env.set values (PlanRaw).
	EnvRefused bool

	text []byte // the new text, for Apply
}

// Applied is a change written.
type Applied struct {
	Plan *ChangePlan
	// ID is the journal entry; Bak the old file.
	ID, Bak string
	// Live is what "also apply now" did.
	Live []LiveResult
	// Warn says what went wrong after the write (the journal line or the live blocks' line), when something did.
	Warn string
}

// PlanChange plans req's edits on the contract req.Ref names and writes nothing: the preview of the Change rules
// form. A ref outside the set is ErrNoContract; an edit the core or the compiler refuses is the plan's Err.
func (s *Service) PlanChange(ctx context.Context, req ChangeReq) (*ChangePlan, error) {
	c, f, err := s.writable(req.Ref)
	if err != nil {
		return nil, err
	}
	return s.planEdits(ctx, c, f, req), nil
}

// ApplyChange plans req again on the text the contract holds now and writes it: refused when req.Base is not that
// text (ErrStale), when the change is not a narrowing and req.Ack is not this plan's Ack (ErrNeedsAck), and when the plan
// has an Err (ErrRefused). The write is guarded, base-checked under the contract's lock and journaled; then the live
// blocks of req.AlsoNow are placed and journaled after it.
func (s *Service) ApplyChange(ctx context.Context, req ChangeReq) (*Applied, error) {
	c, f, err := s.writable(req.Ref)
	if err != nil {
		return nil, err
	}
	p := s.planEdits(ctx, c, f, req)
	return s.apply(ctx, c, p, req.Base, req.Ack, req.AlsoNow)
}

// writable is the contract ref names and its text, read through the guards.
func (s *Service) writable(ref string) (*contractInfo, *rulefile.File, error) {
	c, err := s.contract(ref)
	if err != nil {
		return nil, nil, err
	}
	f, err := s.readContract(c)
	return c, f, err
}

// readContract reads c's file through the guards, refused when the recorded path now resolves to another file than
// the one the run here ran: a folder symlink on it was retargeted since. The write and its journal entry would land on
// a file outside the bounded set, keyed where History and Undo never look.
func (s *Service) readContract(c *contractInfo) (*rulefile.File, error) {
	f, err := s.writer().Read(c.newest.Contract)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotWritable, err)
	}
	if f.Path != c.newest.Resolved {
		return nil, fmt.Errorf("%w: the contract's folder now points elsewhere (%s, not %s); run it again from there",
			ErrNotWritable, f.Path, c.newest.Resolved)
	}
	return f, nil
}

func (s *Service) planEdits(ctx context.Context, c *contractInfo, f *rulefile.File, req ChangeReq) *ChangePlan {
	p := &ChangePlan{Ref: c.Ref, Contract: c.Path, Agent: c.Agent, Base: f.SHA256, Stale: req.Base != "" && req.Base != f.SHA256,
		Edits: req.Edits}
	cc := c.context(s)
	edits := make([]rule.Edit, 0, len(req.Edits))
	for _, e := range req.Edits {
		edits = append(edits, rule.Edit{Op: rule.Op(e.Op), Key: e.Key, Entry: e.Entry})
	}
	for _, e := range edits {
		switch e.Op {
		case rule.OpAdd, rule.OpRemove, rule.OpNever:
		default:
			p.Err = fmt.Sprintf("unknown edit %q: add, remove or never", e.Op)
			return p
		}
	}
	res, err := rule.ApplyEdits(rule.EditRequest{Contract: f.Text, ContractPath: cc.Contract, Cwd: cc.Cwd, Home: s.Home,
		Edits: edits, Date: s.date(), Via: Via, Check: s.check(ctx, cc), Relaxes: s.relaxes(ctx, cc)})
	if err != nil {
		p.Err, p.Nothing = err.Error(), errors.Is(err, rule.ErrNothing)
		return p
	}
	p.text, p.Diff, p.Direction, p.Why = res.Text, shownDiff(filepath.Base(cc.Contract), f.Text, res.Text, res.Diff), string(res.Direction), res.Why
	p.NeedsAck = res.Direction != rule.Narrows
	p.Ack = s.ack(contractAckRef(p.Ref), p.Base, rulefile.Sum(res.Text))
	var parts []string
	for _, ch := range res.Changes {
		parts = append(parts, ch.String())
	}
	p.Summary = strings.Join(parts, "; ")
	for _, sn := range res.Sentences {
		p.Sentences = append(p.Sentences, Sentence{Before: sn.Before, After: sn.After, Direction: string(sn.Direction)})
	}
	if res.Direction == rule.Narrows {
		cwd := cc.Cwd
		if cwd == "" {
			cwd = filepath.Dir(cc.Contract)
		}
		p.Now = s.nowOptions(ctx, c.Live, res.Changes, cwd, entriesOf(res.Text))
	}
	return p
}

// apply writes the plan p on base: the guards shared by a structured and a free edit.
func (s *Service) apply(ctx context.Context, c *contractInfo, p *ChangePlan, base, ack string, alsoNow []string) (*Applied, error) {
	switch {
	case base == "" || p.Stale:
		return nil, fmt.Errorf("%w: nothing was written; look at the change again", ErrStale)
	case p.Err != "":
		return nil, fmt.Errorf("%w: %s", ErrRefused, p.Err)
	case p.NeedsAck && !s.ackOK(ack, contractAckRef(p.Ref), p.Base, rulefile.Sum(p.text)):
		return nil, ackErr(ack)
	}
	e, err := s.writer().Replace(ctx, c.newest.Contract, base, p.text, rulefile.Change{Via: Via, Summary: p.Summary,
		Sentences: sentenceLines(p.Sentences), Direction: p.Direction})
	switch {
	case errors.Is(err, rulefile.ErrStale):
		return nil, fmt.Errorf("%w: %v", ErrStale, err)
	case errors.Is(err, rulefile.ErrSame):
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	case err != nil && !errors.Is(err, rulefile.ErrJournal):
		return nil, err
	}
	a := &Applied{Plan: p}
	if e != nil {
		a.ID, a.Bak = e.ID, e.Bak
	}
	if err != nil {
		// Written, not journaled: no journal line holds the ID, so the page offers the .bak and no Undo.
		a.ID, a.Warn = "", err.Error()
	}
	if len(alsoNow) > 0 {
		a.Live = s.applyNow(ctx, p.Now, alsoNow)
		if a.ID != "" && a.Warn == "" {
			if err := s.writer().AppendLive(ctx, a.ID, journalLive(a.Live)); err != nil {
				a.Warn = "the live blocks were placed but not journaled: " + err.Error()
			}
		}
	}
	return a, nil
}

// sentenceLines is the journal's form of sentences: "before → after".
func sentenceLines(ss []Sentence) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		b := s.Before
		if b == "" {
			b = "(nothing)"
		}
		out = append(out, b+" → "+s.After)
	}
	return out
}
