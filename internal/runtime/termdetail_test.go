// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestNoteDetailKeepsADecidedReason is awaitExit's "wait:" detail arriving after another worker decided why
// the run ended: the decided detail stands, and the write goes through termMu (under -race, against fail).
func TestNoteDetailKeepsADecidedReason(t *testing.T) {
	r := &runner{}
	if !r.fail(identity.ReasonError, "ledger: disk full") {
		t.Fatal("fail did not decide")
	}
	r.noteDetail("wait: timed out")
	if r.detail != "ledger: disk full" {
		t.Errorf("detail = %q, want the decided one kept", r.detail)
	}

	var undecided runner
	undecided.noteDetail("wait: timed out")
	if undecided.detail != "wait: timed out" {
		t.Errorf("detail = %q, want the noted one when nothing was decided", undecided.detail)
	}
}

func TestNoteDetailRacesFailSafely(t *testing.T) {
	r := &runner{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.fail(identity.ReasonError, "ledger: x") }()
	go func() { defer wg.Done(); r.noteDetail("wait: y") }()
	wg.Wait()
}
