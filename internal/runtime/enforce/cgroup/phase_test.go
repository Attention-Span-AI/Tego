// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

// TestPrepareAndArmReportTheirStartPhases: the start-latency budget (enforce-plane §10) is read from these
// phases, so each step of Prepare's order and Arm names itself once, in order, on Options.Phase.
func TestPrepareAndArmReportTheirStartPhases(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var got []string
	f := newFixture(t, func(o *Options) {
		o.Phase = func(name string, _ time.Duration) {
			mu.Lock()
			got = append(got, name)
			mu.Unlock()
		}
	})
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	// prepare.rearm, the pass over the other builds' timers (rearmExpired), is inside prepare.lock-slot and ends first.
	want := []string{"prepare.rearm", "prepare.lock-slot", "prepare.rules", "prepare.load", "prepare.fanotify", "prepare.inherit",
		"prepare.fill", "prepare.filter", "prepare", "arm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("phases = %v, want %v", got, want)
	}
}
