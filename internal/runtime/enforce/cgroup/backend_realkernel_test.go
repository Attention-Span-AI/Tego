// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Every other Prepare test in this package supplies Options.newKernel, so attachKernel's own default —
// "newKernel := h.opts.newKernel; if newKernel == nil { newKernel = newBPFKernel }" (attach.go) — is exactly
// what production Prepare relies on and what none of them exercise: a fake is substituted before that branch
// ever has to choose. TestPrepareUsesRealKernelByDefault is the one test in this package that leaves newKernel
// unset, so the default really is newBPFKernel, and newBPFKernel's first, unprivileged step — asserting the
// pin path is really a bpf filesystem (§6 E30) — runs for real. It needs no root and no compiled objects: a
// plain temporary directory fails the bpffs check before anything privileged (or the missing embedded objects)
// is even reached.
func TestPrepareUsesRealKernelByDefault(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	notBPFFS := filepath.Join(dir, "not-bpffs")
	if err := os.MkdirAll(notBPFFS, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", notBPFFS, err)
	}

	b := New(Options{BPFFS: notBPFFS, StateDir: dir, Hash: "realkernel"})
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull}
	run := Run{ID: "r", CgroupID: 1, CgroupPath: "/x"}

	_, err := b.Prepare(context.Background(), rt, run)
	if !errors.Is(err, ErrBpffsUnavailable) {
		t.Fatalf("Prepare through the real (unfaked) kernel path over a plain directory = %v, want ErrBpffsUnavailable (§6 E30)", err)
	}

	// §4 step 2 promises this check runs "before anything is created" — assert the pin directory that a
	// later step would make never appeared.
	if _, statErr := os.Stat(filepath.Join(notBPFFS, pinRoot)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("a pin directory was created before the bpffs check failed: %v", statErr)
	}

	// I10: the slot and build lock steps 3 acquired before the real kernel step failed must still be undone.
	slots, err := openSlotTable(t, dir, "realkernel")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	defer func() { _ = slots.close() }()
	if n, err := slots.held(); err != nil || n != 0 {
		t.Fatalf("held = %d, %v; a Prepare failing at the real kernel step must still free its slot", n, err)
	}
}
