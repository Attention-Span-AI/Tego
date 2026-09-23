// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"testing"
)

// TestLoadUnknownObject asserts an object this package does not define is an error in every build, tagged or
// not, and that the error is ErrNotGenerated so callers have one condition to handle.
func TestLoadUnknownObject(t *testing.T) {
	t.Parallel()
	if _, err := Load("no_such_object"); !errors.Is(err, ErrNotGenerated) {
		t.Fatalf("Load(unknown) = %v, want ErrNotGenerated", err)
	}
	if _, err := Raw("no_such_object"); !errors.Is(err, ErrNotGenerated) {
		t.Fatalf("Raw(unknown) = %v, want ErrNotGenerated", err)
	}
}

// TestAvailableAgreesWithObjects asserts the two reports of the registry's state cannot disagree, and that an
// untagged build fails Load and Hash cleanly rather than half-working.
func TestAvailableAgreesWithObjects(t *testing.T) {
	t.Parallel()
	if Available() != (len(Objects()) > 0) {
		t.Fatalf("Available() = %v with %d objects", Available(), len(Objects()))
	}
	if Available() {
		h, err := Hash()
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		if len(h) != HashLen {
			t.Fatalf("Hash() = %q, want %d hex characters", h, HashLen)
		}
		return
	}
	if _, err := Hash(); !errors.Is(err, ErrNotGenerated) {
		t.Fatalf("Hash() without objects = %v, want ErrNotGenerated", err)
	}
	for _, o := range []Object{ObjectCgroupNet, ObjectCgroupTrack, ObjectTraceProc} {
		if _, err := Load(o); !errors.Is(err, ErrNotGenerated) {
			t.Fatalf("Load(%s) without objects = %v, want ErrNotGenerated", o, err)
		}
	}
}

// TestObjectsSorted asserts Objects is deterministic, because Hash folds the objects in that order.
func TestObjectsSorted(t *testing.T) {
	t.Parallel()
	got := Objects()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("Objects() not sorted: %v", got)
		}
	}
}

// TestHashIsComputedOnce: the embedded bytes never change, so a second Hash is a memoized read, not another
// SHA-256 over every object.
func TestHashIsComputedOnce(t *testing.T) {
	want, err := Hash()
	if err != nil {
		if !errors.Is(err, ErrNotGenerated) {
			t.Fatalf("Hash: %v", err)
		}
		return // an untagged build embeds nothing to hash
	}
	var got string
	if n := testing.AllocsPerRun(5, func() { got, _ = Hash() }); n != 0 {
		t.Errorf("Hash allocates %v times per call after the first; want a memoized value", n)
	}
	if got != want {
		t.Errorf("Hash changed between calls: %q then %q", want, got)
	}
}
