// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"runtime"
	"testing"
)

func TestDumpableRoundTrip(t *testing.T) {
	// The test process is an ordinary dumpable binary; setting 1 again is a no-op that must succeed.
	if err := SetDumpable(true); err != nil {
		t.Fatal(err)
	}
	on, err := Dumpable()
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("PR_GET_DUMPABLE reports 0 after PR_SET_DUMPABLE 1")
	}
}

func TestNoNewPrivsQuery(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := NoNewPrivs(); err != nil {
		t.Fatal(err)
	}
}

func TestChildSubreaperToggle(t *testing.T) {
	if err := SetChildSubreaper(true); err != nil {
		t.Fatal(err)
	}
	if err := SetChildSubreaper(false); err != nil {
		t.Fatal(err)
	}
}
