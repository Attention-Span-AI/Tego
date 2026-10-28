// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRawChanges: a free edit's list changes are each entry of an editable list it drops or adds; an entry moved
// within its list, a comment, or a key outside the lists is no change, and a text that does not parse has none.
func TestRawChanges(t *testing.T) {
	old := []byte("exec:\n  allow: [sh, cat, ls]\nfs:\n  write: [\"./out/\", \"./tmp/\"]\nrecord: summary\n")
	cases := []struct {
		name string
		new  string
		want []string
	}{
		{"remove two, add one", "exec:\n  allow: [sh]\nfs:\n  write: [\"./out/\", \"./tmp/\"]\n  deny_write: [\"./out/x\"]\n",
			[]string{"exec.allow -= cat", "exec.allow -= ls", "fs.deny_write += ./out/x"}},
		{"reordered, commented, other keys", "exec:\n  allow: [ls, sh, cat] # same\nfs:\n  write: [\"./tmp/\", \"./out/\"]\nrecord: full\n", nil},
		{"not YAML", "exec: [\n", nil},
	}
	for _, c := range cases {
		var got []string
		for _, ch := range rawChanges(old, []byte(c.new)) {
			got = append(got, ch.String())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestRawEditOffersApplyNow: a free edit that removes a program and a write folder offers each as a live block on the
// running run, says why its widening waits for the next run, and Save places the blocks it was asked to; an entry
// another one still covers is not offered.
func TestRawEditOffersApplyNow(t *testing.T) {
	f := newFixture(t)
	f.live[runA2] = true
	ctx := context.Background()
	c := f.ref(t, f.contract)
	text := strings.Replace(strings.Replace(baseText, "allow: [sh, cat, ls]", "allow: [sh, ls, /usr/bin/python3]", 1),
		`write: ["./out/"]`, `write: []`, 1)
	p, err := f.s.PlanRaw(ctx, RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(text)})
	if err != nil || p.Err != "" {
		t.Fatalf("plan: %+v %v", p, err)
	}
	byChange := map[string]NowOption{}
	for _, o := range p.Now {
		if o.Run != runA2 {
			t.Errorf("an option for run %s", o.Run)
		}
		byChange[o.Change] = o
	}
	out := filepath.Join(f.proj, "out")
	if o := byChange["exec.allow -= cat"]; !o.OK || o.Block != "exec:cat" {
		t.Errorf("cat: %+v", o)
	}
	if o := byChange["fs.write -= ./out/"]; !o.OK || o.Block != "write:"+out {
		t.Errorf("out: %+v", o)
	}
	if o := byChange["exec.allow += /usr/bin/python3"]; o.OK || !strings.Contains(o.Why, "do more") {
		t.Errorf("the widening: %+v", o)
	}
	a, err := f.s.ApplyRaw(ctx, RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(text), Ack: p.Ack, AlsoNow: []string{runA2}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{runA2 + " write:" + out, runA2 + " exec:cat"}; !slices.Equal(f.blocks, want) { // in EditKeys order
		t.Errorf("placed %q, want %q", f.blocks, want)
	}
	if len(a.Live) != 2 || !a.Live[0].OK || !a.Live[1].OK {
		t.Errorf("live results %+v", a.Live)
	}

	// Spelling sh by its path keeps the program allowed: no block is offered for the bare name it replaces.
	c = f.ref(t, f.contract)
	f.blocks = nil
	text2 := strings.Replace(text, "allow: [sh, ls, /usr/bin/python3]", "allow: [/bin/sh, ls, /usr/bin/python3]", 1)
	p, err = f.s.PlanRaw(ctx, RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(text2)})
	if err != nil || p.Err != "" {
		t.Fatalf("plan 2: %+v %v", p, err)
	}
	if i := slices.IndexFunc(p.Now, func(o NowOption) bool { return o.Change == "exec.allow -= sh" }); i < 0 || p.Now[i].OK ||
		!strings.Contains(p.Now[i].Why, "/bin/sh") {
		t.Errorf("sh respelled: %+v", p.Now)
	}
}
