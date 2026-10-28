// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// RawReq is a free edit: the whole new text of the contract req.Ref names, from the advanced editor.
type RawReq struct {
	Ref string
	// Base is the sha256 of the text the editor was opened on.
	Base string
	Text []byte
	// Ack is the person's acknowledgement: a free edit is always confirmed like a widening, with the Ack of the
	// check (PlanRaw) that showed this text's diff (ack.go).
	Ack string
	// AlsoNow are the running runs to place the edit's live blocks on (ChangePlan.Now): the narrowings among its list
	// changes that map to one.
	AlsoNow []string
}

// freeWhy is what a free edit's plan says of its direction.
const freeWhy = "Free edit: cannot be classified; confirm it like a widening"

// PlanRaw plans a free edit and writes nothing: the text is compiled in the contract's run context, as a structured
// change is, and shown as a diff. It cannot be classified: its Direction is mixed and it always
// needs the acknowledgement. Its list changes (rawChanges: each entry of an editable list the old text has and the
// new one lacks, or the other way) are offered "also apply now" one by one where they narrow and map to a live block
// (nowOptions), and every other one says why it waits for the next run. The text may hold rulesview.Hidden for each env.set
// value, as Current.Editor shows it: each is put back from the file, and any other change to env.set but removing a
// variable is refused (EnvRefused), so a value is never carried by a page.
func (s *Service) PlanRaw(ctx context.Context, req RawReq) (*ChangePlan, error) {
	c, f, err := s.writable(req.Ref)
	if err != nil {
		return nil, err
	}
	cc := c.context(s)
	p := &ChangePlan{Ref: c.Ref, Contract: c.Path, Agent: c.Agent, Base: f.SHA256, Stale: req.Base != "" && req.Base != f.SHA256,
		Raw: true, Direction: string(rule.Mixed), Why: freeWhy, NeedsAck: true, Summary: "free edit of the whole text"}
	switch {
	case len(req.Text) == 0:
		p.Err = "the new text is empty"
	case len(req.Text) > agent.MaxContractSize:
		p.Err = fmt.Sprintf("the new text is %d bytes, more than a contract may be (%d)", len(req.Text), agent.MaxContractSize)
	case !utf8.Valid(req.Text) || bytes.IndexByte(req.Text, 0) >= 0:
		p.Err = "the new text is not UTF-8 text"
	case bytes.Equal(req.Text, f.Text):
		p.Err, p.Nothing = "the new text is what the contract already holds", true
	}
	if p.Err != "" {
		return p, nil
	}
	// The editor's own text posted back as it was opened: nothing to save, even where putting the hidden env.set
	// values back would not give the file's bytes (a value over several lines is put back on one).
	if ed, _, _ := editorOf(f.Text); ed != nil && bytes.Equal(req.Text, ed) {
		p.Err, p.Nothing = "the new text is what the contract already holds", true
		return p, nil
	}
	// The editor opened on the text with every env.set value hidden (Current.Editor): put them back, and refuse any
	// other change to env.set, since a page never carries a value.
	text, restored, err := rulesview.RestoreEnv(string(req.Text), string(f.Text))
	if err != nil {
		p.Err, p.EnvRefused = envRefusal, true
		return p, nil
	}
	switch {
	case text == string(f.Text):
		p.Err, p.Nothing = "the new text is what the contract already holds", true
		return p, nil
	case len(text) > agent.MaxContractSize:
		p.Err = fmt.Sprintf("the new text is %d bytes with its env.set values, more than a contract may be (%d)", len(text), agent.MaxContractSize)
		return p, nil
	}
	if err := s.check(ctx, cc)([]byte(text)); err != nil {
		p.Err = "the new contract does not compile, so nothing was written: " + scrub(err.Error(), restored)
		return p, nil
	}
	name := filepath.Base(cc.Contract)
	p.text, p.Diff = []byte(text), shownDiff(name, f.Text, []byte(text), rule.Diff(name, f.Text, []byte(text)))
	p.Ack = s.ack(contractAckRef(p.Ref), p.Base, rulefile.Sum(p.text))
	if changes := rawChanges(f.Text, p.text); len(changes) > 0 {
		cwd := cc.Cwd
		if cwd == "" {
			cwd = filepath.Dir(cc.Contract)
		}
		p.Now = s.nowOptions(ctx, c.Live, changes, cwd, entriesOf(p.text))
	}
	return p, nil
}

// rawChanges is the list changes from the text old to the text new: every entry of an editable list (rule.Entries)
// old spells and new does not (removed), then every one new spells and old does not (added), each in file order. A
// text that does not parse has none. An entry moved within its list, or spelled again, is no change.
func rawChanges(old, new []byte) []rule.Change {
	a, errA := rule.Entries(old)
	b, errB := rule.Entries(new)
	if errA != nil || errB != nil {
		return nil
	}
	var out []rule.Change
	for _, k := range rule.EditKeys() {
		for _, e := range a[k] {
			if !slices.Contains(b[k], e) {
				out = append(out, rule.Change{Remove: true, Key: k, Entry: e})
			}
		}
	}
	for _, k := range rule.EditKeys() {
		for _, e := range b[k] {
			if !slices.Contains(a[k], e) {
				out = append(out, rule.Change{Key: k, Entry: e})
			}
		}
	}
	return out
}

// envRefusal is a free edit's plan error when its text changes env.set beyond removing variables.
const envRefusal = "this text changes environment values (env.set). A page never shows or carries them: keep each as " +
	rulesview.Hidden + " (saving puts it back) or remove it, and set a value in a terminal; nothing was written"

// scrub is msg with every value of vals (env.set values put back) replaced by rulesview.Hidden: a compile error may
// quote a value, and the page shows the error. A value under 4 bytes is left, since it would also hide line numbers.
func scrub(msg string, vals []string) string {
	for _, v := range vals {
		if len(v) >= 4 {
			msg = strings.ReplaceAll(msg, v, rulesview.Hidden)
		}
	}
	return msg
}

// ApplyRaw writes a free edit under every guard of ApplyChange: a stale base, an acknowledgement that is not the
// Ack of this text's check, a text that does not compile are refused, and the write is base-checked under the
// contract's lock and journaled.
func (s *Service) ApplyRaw(ctx context.Context, req RawReq) (*Applied, error) {
	p, err := s.PlanRaw(ctx, req)
	if err != nil {
		return nil, err
	}
	c, err := s.contract(req.Ref)
	if err != nil {
		return nil, err
	}
	return s.apply(ctx, c, p, req.Base, req.Ack, req.AlsoNow)
}
