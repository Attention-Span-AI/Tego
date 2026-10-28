// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// hintFor is the hint the read model would give for line seq of run: the offset it starts at and the file now.
func hintFor(t *testing.T, ledger, run string, seq int) *LineHint {
	t.Helper()
	p := filepath.Join(ledger, run, "events.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	off := 0
	for range seq {
		off += bytes.IndexByte(b[off:], '\n') + 1
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return &LineHint{Off: int64(off), Dev: uint64(st.Dev), Ino: st.Ino, Size: fi.Size()} //nolint:unconvert // Dev's type differs between platforms
}

// TestActOnWithAHintPlansTheSame: the event page's view of a line with the read model's hint, with a stale hint and
// with none plans the same change on the same base, and a write that carries a hint writes as one without does.
func TestActOnWithAHintPlansTheSame(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sc := Scope{Level: 1}
	for _, seq := range []uint64{1, 2} {
		want, err := f.s.ActOn(ctx, ActReq{Run: runA, Seq: seq, Action: "block", Scope: sc})
		if err != nil {
			t.Fatal(err)
		}
		good := hintFor(t, f.ledger, runA, int(seq))
		stale := hintFor(t, f.ledger, runA, int(seq)-1)
		for name, h := range map[string]*LineHint{"the read model's hint": good, "another line's hint": stale} {
			got, err := f.s.ActOn(ctx, ActReq{Run: runA, Seq: seq, Action: "block", Scope: sc, Hint: h})
			if err != nil {
				t.Fatalf("seq %d, %s: %v", seq, name, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seq %d, %s:\n got %+v\nwant %+v", seq, name, got, want)
			}
		}
	}
	p, err := f.s.ActOn(ctx, ActReq{Run: runA, Seq: 1, Action: "block", Scope: sc})
	if err != nil || p.PickErr != "" {
		t.Fatalf("preview: %+v, %v", p, err)
	}
	w, err := f.s.ActOn(ctx, ActReq{Run: runA, Seq: 1, Action: "block", Scope: sc, Write: true, Base: p.Base,
		Hint: hintFor(t, f.ledger, runA, 1)})
	if err != nil || !w.Saved {
		t.Fatalf("write with a hint: %+v, %v", w, err)
	}
}
