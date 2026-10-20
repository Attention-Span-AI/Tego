// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package bpf

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

// TestProductLoadOptionsHaveNoLog: a product build loads every program with cilium/ebpf's zero options — no
// verifier log on the first attempt, the branch-level log only on a refusal — and starts no attribution, whatever
// the environment says. Only a test build with TEGO_TEST_LOAD_STATS beside TEGO_TEST_PHASE_TIMING asks the verifier
// for its statistics (enforce-plane §10.1's cold attribution).
func TestProductLoadOptionsHaveNoLog(t *testing.T) {
	t.Setenv("TEGO_TEST_PHASE_TIMING", "1")
	t.Setenv("TEGO_TEST_LOAD_STATS", "1")
	if got := LoadOptions(); !reflect.DeepEqual(got, ebpf.ProgramOptions{}) {
		t.Fatalf("LoadOptions() = %+v, want the zero options", got)
	}
	if tr := BeginLoad(nil, "load.obj.x.maps", "load.prog.x"); tr != nil {
		t.Fatalf("BeginLoad returned %v in a product build, want nil", tr)
	}
	BeginLoad(nil, "a", "b").End(nil) // a nil trace ends as a no-op
	ReportProgram("probe.hook.x", nil)
}
