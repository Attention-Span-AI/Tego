// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// The stuck-mount recipe's capacity page is two requests: the sign-in lands on the overview, which at capacity waits
// for a free slot for its whole request bound, and then the page it asks for waits its own. Each is answered inside
// requestBound (TestRequestScopeIsBoundedByTheWriteDeadline), so the recipe's bound for the pair has to be at least
// two of them and a margin (found on 2026-11-21: 40 s killed a page that was answered at 25 s and 50 s). Race builds
// scale requestBound, and the recipe runs the ordinary one.
func TestStuckMountRecipeBoundCoversSignInAndPageAtCapacity(t *testing.T) {
	if raceEnabled {
		t.Skip("the recipe runs an ordinary build")
	}
	src, err := os.ReadFile("../../../docs/testing/contracts-stalled-mount.py")
	if err != nil {
		t.Skip("the recipe is not in this tree (the public export)")
	}
	m := regexp.MustCompile(`(?m)^CAPACITY_PAGE_BOUND = (\d+)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("the recipe has no CAPACITY_PAGE_BOUND")
	}
	bound, _ := strconv.Atoi(string(m[1]))
	if got, want := time.Duration(bound)*time.Second, 2*requestBound+writeMargin; got < want {
		t.Fatalf("the recipe gives a capacity page %v, but its sign-in and its page can each take %v: want at least %v", got, requestBound, want)
	}
}
