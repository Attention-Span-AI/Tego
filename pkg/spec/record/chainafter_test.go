// SPDX-License-Identifier: Apache-2.0

package record

import (
	"errors"
	"testing"
)

// TestChainAfterResumes pins ChainAfter: a chain resumed after line seq with id checks the next line exactly as
// the chain that verified every line before it would.
func TestChainAfterResumes(t *testing.T) {
	var lines [][]byte
	var ids []string
	prev := ""
	for i := 0; i < 3; i++ {
		e := base(KindGap, `{"what":"record","why":"x"}`)
		e.Seq, e.Prev = uint64(i), prev
		lines = append(lines, mustLine(t, e))
		prev = e.ID
		ids = append(ids, e.ID)
	}
	c := ChainAfter(1, ids[1])
	if c.Len() != 2 || c.Head() != ids[1] {
		t.Fatalf("ChainAfter(1): Len %d Head %q", c.Len(), c.Head())
	}
	if _, err := c.Add(lines[2]); err != nil {
		t.Fatalf("the line after the resume point: %v", err)
	}
	wrong := ChainAfter(0, ids[0])
	if _, err := wrong.Add(lines[2]); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("a line two past the resume point: %v, want ErrCorruptChain", err)
	}
	other := ChainAfter(1, ids[0])
	if _, err := other.Add(lines[2]); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("a resume point whose id is not the line's prev: %v, want ErrCorruptChain", err)
	}
}
