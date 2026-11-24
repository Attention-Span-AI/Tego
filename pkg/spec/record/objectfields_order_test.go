// SPDX-License-Identifier: Apache-2.0

package record

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestObjectFieldsOrderAndDuplicates pins what objectFieldsRaw returns for every order of the keys of an object
// (GAPS C69): the fields sorted by key bytes, the values with their keys, and the first duplicate key in sorted
// order named in the error. The records the writer emits are sorted already, a tamperer's are in any order, and a
// cheaper way to find a duplicate (a sortedness check before the sort) must give these answers on all of them.
func TestObjectFieldsOrderAndDuplicates(t *testing.T) {
	rng := rand.New(rand.NewPCG(69, 69))
	alphabet := []string{"a", "b", "ab", "abc", "B", "_", "z", "é", "日", "k1", "k10", "k2", "\\u0041", "x\\\"y"}
	for iter := 0; iter < 2000; iter++ {
		n := rng.IntN(14)
		keys := make([]string, n) // decoded key text, to sort and compare
		raws := make([]string, n) // the key as written in the JSON
		for i := range keys {
			raws[i] = alphabet[rng.IntN(len(alphabet))]
			k, err := strconv.Unquote(`"` + raws[i] + `"`)
			if err != nil {
				t.Fatalf("alphabet %q: %v", raws[i], err)
			}
			keys[i] = k
		}
		order := rng.IntN(3) // 0 as drawn, 1 sorted by raw text, 2 sorted by decoded key
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i
		}
		switch order {
		case 1:
			slices.SortStableFunc(idx, func(a, b int) int { return strings.Compare(raws[a], raws[b]) })
		case 2:
			slices.SortStableFunc(idx, func(a, b int) int { return strings.Compare(keys[a], keys[b]) })
		}
		var sb strings.Builder
		sb.WriteString("{")
		for j, i := range idx {
			if j > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `"%s":%d`, raws[i], j)
		}
		sb.WriteString("}")
		// What the answer is: stable by key, the first duplicate key in that order.
		type kv struct {
			k string
			v int
		}
		want := make([]kv, n)
		for j, i := range idx {
			want[j] = kv{keys[i], j}
		}
		slices.SortStableFunc(want, func(a, b kv) int { return strings.Compare(a.k, b.k) })
		dup := ""
		for j := 1; j < len(want); j++ {
			if want[j].k == want[j-1].k {
				dup = want[j].k
				break
			}
		}
		got, err := objectFieldsRaw([]byte(sb.String()))
		if dup != "" {
			if err == nil || err.Error() != fmt.Sprintf("duplicate key %q", dup) {
				t.Fatalf("%s: err = %v, want duplicate key %q", sb.String(), err, dup)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", sb.String(), err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: %d fields, want %d", sb.String(), len(got), len(want))
		}
		for j := range got {
			if got[j].key != want[j].k || string(got[j].val) != strconv.Itoa(want[j].v) {
				t.Fatalf("%s: field %d = %q:%s, want %q:%d", sb.String(), j, got[j].key, got[j].val, want[j].k, want[j].v)
			}
		}
	}
}

// BenchmarkObjectFieldsSorted is the split of a line's envelope as the writer emits it: keys in order.
func BenchmarkObjectFieldsSorted(b *testing.B) {
	line := []byte(`{"agent":"codex","id":"0123456789abcdef","kind":"fs","op":"open","path":"/home/u/proj/out/report.md","rule":"fs.read[./]","run":"r-aaaa-0001-xxxxxx","seq":12,"ts":"2026-10-27T09:00:00.000Z","v":1,"verdict":"allow"}`)
	b.ReportAllocs()
	for range b.N {
		if _, err := objectFieldsRaw(line); err != nil {
			b.Fatal(err)
		}
	}
}
