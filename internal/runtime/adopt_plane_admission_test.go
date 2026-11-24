// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A selected backend is not proof that its mode remains admitted once Prepare
// returns. Refuse before calling Arm, rather than relying on the later migration
// check to discover the change after membership has already been installed.
func TestAdoptAdmissionRefusesBeforeArm(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.plane = "fmod_ret"
	checks := 0
	f.backend.admission = func() error {
		checks++
		return errors.New("preemption full after selected backend preparation")
	}
	spec := f.spec(t)
	spec.Boundary = true
	_, err := Adopt(t.Context(), f.rt, spec, f.deps)
	if !errors.Is(err, ErrAdoptNoPlane) || !strings.Contains(err.Error(), "live plane admission before adoption: preemption full") {
		t.Fatalf("Adopt = %v, want product live-admission refusal", err)
	}
	if checks != 1 {
		t.Errorf("admission checks=%d, want 1 before Arm", checks)
	}
	if h := f.backend.handle; h == nil || h.armed != 0 {
		t.Errorf("changed admission reached Arm: %+v", h)
	}
	assertAdmissionCleanup(t, f)
}

func TestAdoptAdmissionChangesDuringAttach(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.plane = "fmod_ret"
	admitted := true
	checks := 0
	refusal := errors.New("preemption full during attach")
	f.backend.admission = func() error {
		checks++
		if !admitted {
			return refusal
		}
		return nil
	}
	f.backend.onAttach = func() { admitted = false }
	spec := f.spec(t)
	spec.Boundary = true
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := Adopt(ctx, f.rt, spec, f.deps)
	if !errors.Is(err, ErrAdoptNoPlane) || !errors.Is(err, refusal) || !strings.Contains(err.Error(), "live plane admission before adoption") {
		t.Fatalf("Adopt = %v, want product live-admission refusal after Attach", err)
	}
	if checks != 1 {
		t.Errorf("admission checks=%d, want 1 after Attach and before Arm", checks)
	}
	if h := f.backend.handle; h == nil || h.attached != 1 || h.armed != 0 {
		t.Errorf("changed admission reached Arm or skipped Attach: %+v", h)
	}
	assertAdmissionCleanup(t, f)
}
