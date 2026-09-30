// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"
)

// A body of many tiny conversation elements cost one span and, past a group's first
// 4 KiB, one hash per element: about ten times the time and allocation of storing it whole. Such an array
// (under minElementBytes an element) is not split; the body is stored whole.
func TestATinyElementConversationIsStoredWhole(t *testing.T) {
	w, _ := startedWriter(t)
	body := []byte(`{"messages":[` + strings.Repeat("1,", 200000) + `1]}`)
	if _, ok, err := w.splitRequest(body); err != nil || ok {
		t.Fatalf("splitRequest of 200001 tiny elements: ok=%v err=%v, want it stored whole", ok, err)
	}
	if els := arrayElements(body, span{12, len(body) - 1}); els != nil {
		t.Errorf("arrayElements built %d spans for an array of one-byte elements", len(els))
	}
}
