// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// The selected mode can stop being admitted during Prepare or a migration lock
// wait. Arm must refuse before membership exists; the final migration check must
// consult the same live callback even after the handle was successfully armed.
func TestPlaneAdmissionRecheckedBeforeArmAndMigration(t *testing.T) {
	for _, seam := range []string{"arm", "migration"} {
		t.Run(seam, func(t *testing.T) {
			admitted := true
			calls := 0
			refusal := errors.New("preemption full is no longer admitted")
			f, _ := planeFixture(t, ebpfbindings.PlaneFmodRet, func(o *Options) {
				o.Plane.RecheckAdmission = func() error {
					calls++
					if !admitted {
						return refusal
					}
					return nil
				}
			})
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			})
			if seam == "migration" {
				if err := h.Arm(); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatalf("Arm admission reads=%d, want 1", calls)
				}
			}
			admitted = false
			if seam == "arm" {
				err = h.Arm()
			} else {
				err = h.RecheckAdmission()
			}
			if !errors.Is(err, refusal) || !strings.Contains(err.Error(), "selected fmod_ret mode is no longer admitted") {
				t.Fatalf("changed admission crossed %s seam: %v", seam, err)
			}
			if seam == "arm" && (h.armed || len(f.kernel.runs) != 0 || len(h.cgroups) != 0) {
				t.Fatalf("refused Arm changed membership: armed=%t runs=%v cgroups=%v", h.armed, f.kernel.runs, h.cgroups)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			if len(f.kernel.runs) != 0 {
				t.Fatalf("refused admission left run rows: %v", f.kernel.runs)
			}
			want := 1
			if seam == "migration" {
				want = 2
			}
			if calls != want {
				t.Fatalf("admission reads=%d, want %d", calls, want)
			}
		})
	}
}

func TestFmodRetAdmissionRequiresLiveChecker(t *testing.T) {
	f, _ := planeFixture(t, ebpfbindings.PlaneFmodRet, func(o *Options) { o.Plane.RecheckAdmission = nil })
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Arm(); err == nil || !strings.Contains(err.Error(), "live admission checker is missing") {
		t.Fatalf("fmod_ret without admission proof: %v", err)
	}
	if h.armed || len(f.kernel.runs) != 0 {
		t.Fatal("missing admission checker armed the run")
	}
}
