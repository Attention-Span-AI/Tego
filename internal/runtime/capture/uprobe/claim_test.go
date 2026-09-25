// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"testing"
)

// TestClaimAfterAnAttemptFinishedIsNotAnotherAttempt is I8's window between attachCandidate's ref and its
// claim, made deterministic: another attempt puts its entry (or records its failure) and lets go of its claim
// after this caller's ref missed and before it claims. The claim must then send the caller back to the cache,
// where ref takes a reference or failure answers, and never make it the attempt that attaches the binary a
// second time. Run concurrently, TestConcurrentOnExecAcrossTwoSourcesAttachesOnce met this window on a CI
// runner as six probes for three.
func TestClaimAfterAnAttemptFinishedIsNotAnotherAttempt(t *testing.T) {
	c := newCache()
	id := identity{Dev: 1, Ino: 2, BuildID: "b"}
	first := refKey{owner: 1, pid: 10}
	second := refKey{owner: 2, pid: 20}

	// The first attempt: its claim, its entry, its unclaim, all before the second caller claims.
	if wait := c.claim(id); wait != nil {
		t.Fatal("the first claim on an empty cache waited")
	}
	if _, discard := c.put(&attachedBinary{ID: id}, first); discard != nil {
		t.Fatal("the first put discarded links")
	}
	c.unclaim(id)

	wait := c.claim(id)
	if wait == nil {
		t.Fatal("a claim on a binary already attached made the caller a second attempt (I8)")
	}
	select {
	case <-wait:
	default:
		t.Fatal("the claim on a settled binary returned a channel that does not close")
	}
	if _, refs, ok := c.ref(id, second); !ok || refs != 2 {
		t.Fatalf("ref after the settled claim = %d refs, %v; want the entry with 2", refs, ok)
	}
	if _, ok := c.claims[id]; ok {
		t.Error("the settled claim left a claim behind that no one will release")
	}

	// The same for an attempt that recorded a failure.
	failedID := identity{Dev: 1, Ino: 3, BuildID: "c"}
	if wait := c.claim(failedID); wait != nil {
		t.Fatal("the first claim waited")
	}
	c.fail(failedID, errors.New("verifier"))
	c.unclaim(failedID)
	if wait := c.claim(failedID); wait == nil {
		t.Fatal("a claim on a binary with a recorded failure made the caller a second attempt (§7, no retry storm)")
	}
}
