// SPDX-License-Identifier: Apache-2.0

package doctor_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestDoctorProbeDrivesEnforceSelect is the end of the wire: doctor's eight probes produce a
// backend.Probe, enforce.Select turns it into the run's backend, and on this box as uid 1000 the
// answer is landlock. It lives here because the import direction is doctor -> enforce; the enforce
// package's own tests drive Select with fake probes instead.
func TestDoctorProbeDrivesEnforceSelect(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	rep, err := doctor.Run(context.Background(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if fs, err := cgroup.Detect(os.Getuid()); !rep.Root && err == nil && errors.Is(fs.CanPlace(), cgroup.ErrOutsideSubtree) {
		t.Skip("this process runs outside its delegated cgroup subtree, where doctor offers no tier " +
			"(runtime-launch.md case 41); TestRunOnThisMachine checks that answer")
	}
	probe := rep.Probe()
	if probe[backend.TierLandlock] != (rep.Tier != "") {
		t.Fatalf("probe %v disagrees with tier %q", probe, rep.Tier)
	}
	b, ds := enforce.Select(nil, nil, probe)
	for _, d := range ds {
		if d.Severity == "error" {
			t.Fatalf("Select refused the machine doctor probed: %+v", d)
		}
		t.Logf("diagnostic: %s", d.Message)
	}
	if b == nil {
		t.Fatal("Select returned no backend")
	}
	if rep.Root {
		t.Logf("running as root: tier %s", b.Tier())
		return
	}
	if b.Tier() != backend.TierLandlock {
		t.Fatalf("tier %s as uid 1000, want landlock", b.Tier())
	}
	if !b.Capabilities().Has(backend.CapFileWriteDeny) {
		t.Errorf("the selected backend cannot deny writes: %v", b.Capabilities())
	}
}

// TestDoctorProbeRespectsAnUnreachableTier: a tier doctor could not reach must never be selected,
// whatever the contract asks for.
func TestDoctorProbeRespectsAnUnreachableTier(t *testing.T) {
	rep, err := doctor.Run(context.Background(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	probe := rep.Probe()
	for tier, ok := range probe {
		if ok {
			continue
		}
		b, ds := enforce.Select(nil, nil, backend.Probe{tier: false})
		if b != nil {
			t.Errorf("Select returned %s from an empty probe", b.Tier())
		}
		if len(ds) == 0 {
			t.Errorf("Select refused %s without saying why", tier)
		}
	}
}
