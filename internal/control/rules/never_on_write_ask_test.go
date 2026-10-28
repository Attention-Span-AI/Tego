// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

// TestNeverOnWriteAskAppliesNow: "Never allow" on a write ask (fs.ask ./held/, outside every write entry)
// offers the write block that fs.write's removal offers, on the running run of the contract, and Save places it; a
// write ask beneath a write entry becomes an fs.deny_write, whose block says it, and the ask's own removal adds no
// "keeps asking" row beside it. Remove of a write ask outside every write entry narrows the same way. (A removal
// another entry still covers is a widening, which offers nothing now; TestBlockOf holds blockOf's reasons.)
func TestNeverOnWriteAskAppliesNow(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, text, edit string
	}{
		{"outside a write entry", "fs:\n  write: [\"./out/\"]\n  ask: [\"./held/\"]\n", "never"},
		{"beneath a write entry", "fs:\n  write: [\"./\"]\n  ask: [\"./held/\"]\n", "never"},
		{"removed outside a write entry", "fs:\n  write: [\"./out/\"]\n  ask: [\"./held/\"]\n", "remove"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.live[runA2] = true
			writeFile(t, f.contract, "version: 0\nname: tester\ncommand: [\"sh\"]\nexec:\n  allow: [sh]\n"+c.text)
			ref := f.ref(t, f.contract)
			req := ChangeReq{Ref: ref.Ref, Base: ref.Base, Edits: []Edit{{c.edit, "fs.ask", "./held/"}}, AlsoNow: []string{runA2}}
			p, err := f.s.PlanChange(ctx, req)
			if err != nil || p.Err != "" {
				t.Fatalf("plan: %+v %v", p, err)
			}
			if len(p.Now) != 1 {
				t.Fatalf("now = %+v, want one option", p.Now)
			}
			o := p.Now[0]
			want := "write:" + filepath.Join(f.proj, "held")
			if !o.OK || o.Block != want || o.Run != runA2 {
				t.Fatalf("option %+v, want %s on %s", o, want, runA2)
			}
			if p.NeedsAck {
				t.Fatalf("never on a write ask needs an ack: %+v", p)
			}
			if _, err := f.s.ApplyChange(ctx, req); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(f.blocks, []string{runA2 + " " + want}) {
				t.Errorf("blocks placed = %v", f.blocks)
			}
		})
	}
}
