// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestStaleSharedLinkOverARecreatedBuildIsNotAdopted is R14 as amended 2026-10-05 (v73 review, plane-2) against the
// running kernel, as root: the tracing-link twin of TestPlaneStaleLinkOverARecreatedBuildIsNotAdopted. A build whose
// map and program pins went while its link pins stayed (a sweep killed between the two, when maps went first) is
// re-created by the next launcher, which must not adopt those links: their programs read the dead run set and record
// nothing for its run, and an adopted exec-result link set ExecOutcomes, so the supervisor handed failed execs to a
// kernel that reported none. Every shared link the launcher holds must run its own program.
func TestStaleSharedLinkOverARecreatedBuildIsNotAdopted(t *testing.T) {
	requireRealPrepare(t)
	hash := fmt.Sprintf("t6stshl%09d", os.Getpid())
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })
	b := New(Options{Machine: machineLinger(time.Hour), StateDir: pinState(t), Hash: hash, Events: &sink{},
		startTimer: func(string) error { return nil }})
	prepare := func(name string) *Handle {
		t.Helper()
		rel, id := runCgroup(t, "stshl-"+name)
		h, err := b.Prepare(context.Background(), table, Run{ID: "t6-stshl-" + name, Agent: "a", CgroupID: id,
			CgroupPath: rel, CgroupMount: "/sys/fs/cgroup"})
		if err != nil {
			t.Fatalf("Prepare %s: %v", name, err)
		}
		return h
	}
	a := prepare("a")
	if err := a.Close(); err != nil { // a linger: the build's pins stay
		t.Fatalf("close A: %v", err)
	}
	if left, err := os.ReadDir(pins.Links); err != nil || len(left) == 0 {
		t.Fatalf("the build's links are not pinned after run A (%d, %v): the test needs them left", len(left), err)
	}
	// What a removal that unpinned the maps and programs and was killed before the links left.
	for _, d := range []string{pins.Maps, pins.Progs} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
				t.Fatalf("unpin %s/%s: %v", d, e.Name(), err)
			}
		}
	}
	bh := prepare("b")
	defer func() { _ = bh.Close() }()
	k := bh.kern.(*bpfKernel)
	if len(k.shared) == 0 {
		t.Fatal("run B holds no shared link")
	}
	for _, sl := range k.shared {
		name := filepath.Base(sl.pin)
		p := k.progs[name]
		if p == nil {
			t.Errorf("%s: run B loaded no program for the link", name)
			continue
		}
		pi, err := p.Info()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := pi.ID()
		info, err := sl.Info()
		if err != nil {
			t.Fatalf("%s: link info: %v", name, err)
		}
		if info.Program != want {
			t.Errorf("%s: run B adopted a pinned link of program %d, not its own %d: that program reads maps since "+
				"re-created, so its hook records nothing for the run", name, info.Program, want)
		}
	}
	t.Logf("run B holds %d shared links; exec outcomes handed to the kernel: %v", len(k.shared), k.execOutcomes())
}
