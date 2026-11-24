// SPDX-License-Identifier: Apache-2.0

package askpair

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

// TestBookIsTheOpenAsks: an ask is open from its first line to its answer, and Each lists the open asks in the order
// their ids were first asked.
func TestBookIsTheOpenAsks(t *testing.T) {
	b := NewBook[string](0, 0)
	for _, id := range []string{"a", "b", "c"} {
		if b.Ask(id, "ask "+id, 10) != Opened {
			t.Fatalf("Ask(%s) not opened", id)
		}
	}
	if v, r := b.Answer("b"); r != Paired || v != "ask b" {
		t.Fatalf("Answer(b) = %q, %v", v, r)
	}
	b.Ask("d", "ask d", 5)
	var got []string
	b.Each(func(id, v string) bool { got = append(got, id+"="+v); return true })
	if want := []string{"a=ask a", "c=ask c", "d=ask d"}; !slices.Equal(got, want) {
		t.Errorf("open asks %v, want %v", got, want)
	}
	if b.Len() != 3 || b.Bytes() != 10+10+5 || b.Repeated() != 0 || b.Unpaired() != 0 {
		t.Errorf("Len %d Bytes %d Repeated %d Unpaired %d", b.Len(), b.Bytes(), b.Repeated(), b.Unpaired())
	}
}

// TestBookMalformedShapes: the first ask opens the question and each repeat is malformed and changes nothing, whether the
// question is open or answered; the answer pairs with the first ask. An answer before its ask, to an id never asked, or
// a second answer is unpaired: it never counts as an answer, and the ask that comes after an early answer is still the
// first ask of its id and stays open.
func TestBookMalformedShapes(t *testing.T) {
	b := NewBook[string](0, 0)
	if b.Ask("q", "first", 1) != Opened || b.Ask("q", "second", 1) != Repeated {
		t.Fatal("a repeat did not read as one")
	}
	if v, ok := b.Get("q"); !ok || v != "first" {
		t.Errorf("the repeat replaced the first ask: %q", v)
	}
	if v, r := b.Answer("q"); r != Paired || v != "first" {
		t.Errorf("the answer did not pair with the first ask: %q %v", v, r)
	}
	if b.Ask("q", "third", 1) != Repeated {
		t.Error("an ask of an answered id was not a repeat")
	}
	if _, r := b.Answer("q"); r != Unpaired {
		t.Error("a second answer paired")
	}
	if _, r := b.Answer("never"); r != Unpaired {
		t.Error("an answer to an id never asked paired")
	}
	if _, r := b.Answer("early"); r != Unpaired {
		t.Error("an answer before its ask paired")
	}
	if b.Ask("early", "late ask", 1) != Opened {
		t.Error("the ask after an early answer is not the first ask of its id")
	}
	if _, ok := b.Get("early"); !ok || b.Len() != 1 {
		t.Errorf("the ask after an early answer is not open: len %d", b.Len())
	}
	if b.Repeated() != 2 || b.Unpaired() != 3 {
		t.Errorf("Repeated %d (want 2), Unpaired %d (want 3)", b.Repeated(), b.Unpaired())
	}
}

// TestBookBounds: a new id past the count, or any ask past the byte budget, is refused and changes nothing; the answer to
// a refused ask is Dropped, not unpaired; an answer gives its room back.
func TestBookBounds(t *testing.T) {
	b := NewBook[int](2, 100)
	if b.Ask("a", 1, 40) != Opened || b.Ask("b", 2, 40) != Opened {
		t.Fatal("two asks within the bounds were refused")
	}
	if b.Ask("c", 3, 1) != Refused {
		t.Error("a third id passed a bound of two")
	}
	if _, r := b.Answer("c"); r != Dropped || b.Unpaired() != 0 {
		t.Errorf("the answer to a refused ask: %v, %d unpaired", r, b.Unpaired())
	}
	b.Answer("b")
	if b.Ask("d", 4, 61) != Refused {
		t.Error("an ask past the byte budget was taken")
	}
	if b.Ask("e", 5, 40) != Opened {
		t.Error("an answer did not give its room back")
	}
}

// TestBookMatchesAMapModel: over many random sequences of asks and answers the open set, its order, its weight and the
// malformed counts are what a plain model of the rule says.
func TestBookMatchesAMapModel(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		b := NewBook[int](0, 0)
		seen := map[string]bool{}
		open := map[string]int{}
		weight := map[string]int64{}
		var order []string
		repeated, unpaired := 0, 0
		for step := range 60 {
			id := fmt.Sprint("q-", r.IntN(8))
			if r.IntN(3) == 0 {
				v, res := b.Answer(id)
				if _, ok := open[id]; ok {
					if res != Paired || v != open[id] {
						t.Fatalf("step %d: Answer(%s) = %d,%v; open %d", step, id, v, res, open[id])
					}
					delete(open, id)
					delete(weight, id)
					order = slices.DeleteFunc(order, func(o string) bool { return o == id })
				} else {
					if res != Unpaired {
						t.Fatalf("step %d: Answer(%s) = %v, want Unpaired", step, id, res)
					}
					unpaired++
				}
				continue
			}
			w := int64(r.IntN(50))
			res := b.Ask(id, step, w)
			if seen[id] {
				if res != Repeated {
					t.Fatalf("step %d: Ask(%s) = %v, want Repeated", step, id, res)
				}
				repeated++
				continue
			}
			seen[id] = true
			if res != Opened {
				t.Fatalf("step %d: Ask(%s) = %v, want Opened", step, id, res)
			}
			open[id], weight[id] = step, w
			order = append(order, id)
		}
		var got []string
		var total int64
		b.Each(func(id string, v int) bool {
			got = append(got, id)
			if open[id] != v {
				t.Fatalf("%s holds %d, model %d", id, v, open[id])
			}
			return true
		})
		for _, w := range weight {
			total += w
		}
		if !slices.Equal(got, order) || b.Len() != len(open) || b.Bytes() != total || b.Repeated() != repeated || b.Unpaired() != unpaired {
			t.Fatalf("open %v (%d, %d bytes, %d/%d malformed), model %v (%d, %d bytes, %d/%d)", got, b.Len(), b.Bytes(), b.Repeated(), b.Unpaired(),
				order, len(open), total, repeated, unpaired)
		}
	}
}

// TestHeldFillsWhatTheAskLineLeftOut: the ask line's own fields win, and each empty one comes from the last held line.
func TestHeldFillsWhatTheAskLineLeftOut(t *testing.T) {
	var h Held
	op, target, rule := "", "/own", ""
	h.Fill(&op, &target, &rule)
	if op != "" || target != "/own" || rule != "" {
		t.Fatalf("filled from no held line: %q %q %q", op, target, rule)
	}
	h.Note("open", "/held", "fs.ask_read[/]")
	h.Fill(&op, &target, &rule)
	if op != "open" || target != "/own" || rule != "fs.ask_read[/]" {
		t.Errorf("filled %q %q %q", op, target, rule)
	}
}
