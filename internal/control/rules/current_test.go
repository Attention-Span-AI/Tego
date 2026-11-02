// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

// TestCurrent: the form's view of a contract is its text, base and the entries of each list, read through the guards;
// a ref outside the set is ErrNoContract, and a contract that sets environment values says so.
func TestCurrent(t *testing.T) {
	f := newFixture(t)
	ref := f.ref(t, f.contract)
	cur, err := f.s.Current(ref.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur.Text) != baseText || cur.Base != ref.Base || !cur.Writable || cur.EnvSet {
		t.Errorf("Current = base %s writable %v env %v, text %q", cur.Base, cur.Writable, cur.EnvSet, cur.Text)
	}
	if !slices.Equal(cur.Lists["exec.allow"], []string{"sh", "cat", "ls"}) || !slices.Equal(cur.Lists["fs.ask_read"], []string{"./docs/"}) {
		t.Errorf("Lists = %v", cur.Lists)
	}
	if _, err := f.s.Current("0123456789abcdef"); !errors.Is(err, ErrNoContract) {
		t.Errorf("an unknown ref: %v, want ErrNoContract", err)
	}
	if string(cur.Editor) != baseText {
		t.Errorf("Editor = %q", cur.Editor)
	}
	writeFile(t, f.contract, baseText+"env:\n  set:\n    TOKEN: sekrit-canary\n")
	if cur, err = f.s.Current(ref.Ref); err != nil || !cur.EnvSet {
		t.Fatalf("a contract with env.set: EnvSet %v, %v", cur != nil && cur.EnvSet, err)
	}
	if strings.Contains(string(cur.Editor), "sekrit-canary") || !strings.Contains(string(cur.Editor), "TOKEN: "+rulesview.Hidden) {
		t.Errorf("the editor's text of a contract with env.set: %q", cur.Editor)
	}
	// A broken text is offered to the editor unless it could spell a "set" key; "assets/" does not.
	writeFile(t, f.contract, baseText+"fs:\n  write: [./assets/\n")
	if cur, err = f.s.Current(ref.Ref); err != nil || cur.EnvSet || cur.Editor == nil || cur.ListsErr == "" {
		t.Errorf("a broken text naming assets/: EnvSet %v editor %v lists %q, %v", cur.EnvSet, cur.Editor != nil, cur.ListsErr, err)
	}
	writeFile(t, f.contract, baseText+"env:\n  set:\n    TOKEN: [sekrit-canary\n")
	if cur, err = f.s.Current(ref.Ref); err != nil || !cur.EnvSet || cur.Editor != nil || cur.EditorWhy == "" {
		t.Errorf("a broken text with env.set: EnvSet %v editor %v, %v", cur.EnvSet, cur.Editor != nil, err)
	}
	// An explicit key with a comment after it spells set with no ":" beside the word.
	writeFile(t, f.contract, baseText+"env:\n  ? set # the variables\n  : {TOKEN: sekrit-canary}\nbad: [\n")
	if cur, err = f.s.Current(ref.Ref); err != nil {
		t.Fatal(err)
	}
	if !cur.EnvSet || cur.Editor != nil || cur.EditorWhy == "" {
		t.Errorf("a broken text with an explicit set key: EnvSet %v, editor %q", cur.EnvSet, cur.Editor)
	}
	// A second YAML document is not read past: its env.set would reach the editor unhidden.
	writeFile(t, f.contract, baseText+"---\nenv:\n  set:\n    TOKEN: sekrit-canary\n")
	if cur, err = f.s.Current(ref.Ref); err != nil {
		t.Fatal(err)
	}
	if !cur.EnvSet || cur.Editor != nil || cur.EditorWhy == "" {
		t.Errorf("a text of two documents: EnvSet %v, editor %q", cur.EnvSet, cur.Editor)
	}
}

// TestRawRestoresEnv: a free edit opened on the hidden text keeps every env.set value, and one that changes a value
// is refused before it compiles.
func TestRawRestoresEnv(t *testing.T) {
	f := newFixture(t)
	withEnv := strings.Replace(baseText, "exec:\n", "env:\n  set:\n    TOKEN: sekrit-canary\nexec:\n", 1)
	writeFile(t, f.contract, withEnv)
	ref := f.ref(t, f.contract)
	cur, err := f.s.Current(ref.Ref)
	if err != nil || cur.Editor == nil {
		t.Fatalf("Current: %v %v", err, cur)
	}
	edited := strings.Replace(string(cur.Editor), "cat, ls", "cat", 1)
	raw := RawReq{Ref: ref.Ref, Base: ref.Base, Text: []byte(edited)}
	raw.Ack = rawAck(t, f.s, raw)
	a, err := f.s.ApplyRaw(context.Background(), raw)
	if err != nil {
		t.Fatalf("ApplyRaw: %v", err)
	}
	if got := f.text(t); got != strings.Replace(withEnv, "cat, ls", "cat", 1) || strings.Contains(a.Plan.Diff, "sekrit-canary") {
		t.Errorf("the saved text is %q; diff %s", got, a.Plan.Diff)
	}
	ref = f.ref(t, f.contract)
	p, err := f.s.PlanRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base,
		Text: []byte(strings.Replace(edited, "TOKEN: "+rulesview.Hidden, "TOKEN: other", 1))})
	if err != nil || !p.EnvRefused || p.Err == "" {
		t.Errorf("a changed env value: %v %+v", err, p)
	}
}

// TestRawUnchangedWithMultilineEnv: the editor's text posted back unchanged is "nothing to save", also when an env.set
// value spans lines (the editor shows it on one line, and putting it back would rewrite its formatting), and Save
// writes nothing.
func TestRawUnchangedWithMultilineEnv(t *testing.T) {
	f := newFixture(t)
	for name, env := range map[string]string{
		"literal": "env:\n  set:\n    CERT: |\n      line-one-canary\n      line-two-canary\n    PLAIN: kept\n",
		"folded":  "env:\n  set:\n    CERT: >-\n      folded-one-canary\n      folded-two-canary\n",
		"plain":   "env:\n  set:\n    CERT: plain-one-canary\n      plain-two-canary\n",
	} {
		withEnv := strings.Replace(baseText, "exec:\n", env+"exec:\n", 1)
		writeFile(t, f.contract, withEnv)
		ref := f.ref(t, f.contract)
		cur, err := f.s.Current(ref.Ref)
		if err != nil || cur.Editor == nil || strings.Contains(string(cur.Editor), "canary") {
			t.Fatalf("%s: Current: %v, editor %q (%s)", name, err, cur.Editor, cur.EditorWhy)
		}
		p, err := f.s.PlanRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: cur.Editor})
		if err != nil || !p.Nothing || p.Err == "" || p.Diff != "" {
			t.Errorf("%s: the unchanged editor text plans %+v, %v; want nothing to save", name, p, err)
		}
		if _, err := f.s.ApplyRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: cur.Editor, Ack: p.Ack}); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: saving the unchanged editor text: %v, want refused", name, err)
		}
		if f.text(t) != withEnv {
			t.Errorf("%s: an unchanged save rewrote the file:\n%s", name, f.text(t))
		}
	}
}

// TestDiffHidesEnvValues: a change next to env.set never puts a value in the plan's diff, structured or free.
func TestDiffHidesEnvValues(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.contract, strings.Replace(baseText, "exec:\n", "env:\n  set:\n    TOKEN: sekrit-canary\nexec:\n", 1))
	ref := f.ref(t, f.contract)
	p, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: ref.Ref, Base: ref.Base,
		Edits: []Edit{{Op: "remove", Key: "exec.allow", Entry: "cat"}}})
	if err != nil || p.Err != "" {
		t.Fatalf("PlanChange: %v %s", err, p.Err)
	}
	if strings.Contains(p.Diff, "sekrit-canary") || !strings.Contains(p.Diff, "TOKEN:") {
		t.Errorf("the structured diff shows an env value or lost its context:\n%s", p.Diff)
	}
	// The editor's text carries rulesview.Hidden; the text itself, value and all, is refused (no guessing oracle).
	raw := strings.Replace(f.text(t), "cat, ls", "cat", 1)
	p, err = f.s.PlanRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: []byte(raw)})
	if err != nil || !p.EnvRefused || strings.Contains(p.Err, "sekrit-canary") {
		t.Fatalf("PlanRaw of a posted value: %v %+v", err, p)
	}
	raw = strings.Replace(raw, "sekrit-canary", rulesview.Hidden, 1)
	p, err = f.s.PlanRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: []byte(raw)})
	if err != nil || p.Err != "" {
		t.Fatalf("PlanRaw: %v %s", err, p.Err)
	}
	if strings.Contains(p.Diff, "sekrit-canary") {
		t.Errorf("the free edit's diff shows an env value:\n%s", p.Diff)
	}
}
