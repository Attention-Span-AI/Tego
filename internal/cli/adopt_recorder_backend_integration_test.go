// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux && tegobpf

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type adoptionRecorderGuestSink struct{}

func (adoptionRecorderGuestSink) Emit(*record.Event) {}

// TestAdoptionRecorderPreparedHandleObserved exercises the constructor and Prepare
// on a real kernel. A fabricated adoptionObservedHandle cannot prove that Prepare
// returns that wrapper or that its concrete lifecycle methods survive wrapping.
func TestAdoptionRecorderPreparedHandleObserved(t *testing.T) {
	if os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm" || os.Geteuid() != 0 {
		t.Skip("needs a disposable KVM kernel with root and compiled BPF objects")
	}
	for path, magic := range map[string]int64{
		cgroupenforce.DefaultBPFFS: unix.BPF_FS_MAGIC,
		"/sys/fs/cgroup":           unix.CGROUP2_SUPER_MAGIC,
	} {
		var fs unix.Statfs_t
		if err := unix.Statfs(path, &fs); err != nil || fs.Type != magic {
			t.Skipf("needs filesystem type %#x at %s: type=%#x, error=%v", magic, path, fs.Type, err)
		}
	}

	// This is the same empty, top-level cgroup arrangement used by the tier-2
	// kernel tests. It contains no task, so arming cannot affect the test runner.
	rel := fmt.Sprintf("/tego-adoption-recorder-%d", os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Fatalf("create recorder cgroup: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(full); err != nil {
			t.Errorf("remove recorder cgroup: %v", err)
		}
	})
	var st unix.Stat_t
	if err := unix.Stat(full, &st); err != nil {
		t.Fatal(err)
	}
	id := st.Ino

	m := config.Builtin()
	m.BPF.Linger.Value = 0
	b, err := enforce.AdoptionRecorder(m)
	if err != nil {
		t.Fatalf("AdoptionRecorder: %v", err)
	}
	// No baseline, inherited tier-1 state, filesystem rule, exec rule or net
	// section: this is the actual record-only adoption backend's input shape.
	rt := &agent.RuleTable{Contract: &agent.Contract{}, Tier: backend.TierCgroup,
		Record: agent.RecordFull, Capture: agent.CaptureOff}
	h, err := b.Prepare(context.Background(), rt, enforce.RunRef{
		ID: fmt.Sprintf("adoption-recorder-%d", os.Getpid()), Agent: "adoption-recorder",
		CgroupID: id, CgroupPath: rel, CgroupMount: "/sys/fs/cgroup", Events: adoptionRecorderGuestSink{},
	})
	if err != nil {
		t.Fatalf("AdoptionRecorder.Prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("close prepared recorder: %v", err)
		}
	})
	prepared, ok := h.(interface {
		api.Armer
		api.Listener
		api.ListenerWaiter
		enforce.KernelRecorder
		enforce.Reporter
		enforce.DecisionPlaneReporter
		enforce.PlaneKeyedReporter
		enforce.MountTableReporter
		enforce.TrackingFailureCounter
	})
	if !ok {
		t.Fatalf("prepared recorder lost lifecycle or reporting methods: %T", h)
	}
	if _, installed := h.LandlockRuleset(); installed {
		t.Fatal("record-only adoption inherited a Landlock ruleset")
	}
	if _, installed := h.SeccompFilter(); installed {
		t.Fatal("record-only adoption inherited a seccomp filter")
	}
	if mode, execs := prepared.DecisionPlane(); mode != "" || execs {
		t.Fatalf("record-only adoption selected a decision plane: %q, execs=%t", mode, execs)
	}
	if rows, filled := prepared.PlaneKeyed(); filled || len(rows) != 0 {
		t.Fatalf("record-only adoption filled keyed plane rows: %v, filled=%t", rows, filled)
	}
	if caps := prepared.Capabilities(); caps.Has(backend.CapReadDeny) || caps.Has(backend.CapExecDeny) {
		t.Fatalf("record-only adoption claims absent filesystem mechanisms: %v", caps)
	}
	if mt, err := prepared.MountTable(); mt == nil || err != nil {
		t.Fatalf("prepared recorder mount facts: table=%v, error=%v", mt, err)
	}
	if failed, err := prepared.TrackingFailures(); failed != 0 || err != nil {
		t.Fatalf("prepared recorder tracking counter: failures=%d, error=%v", failed, err)
	}
	hash := prepared.BPFHash()
	if hash == "" {
		t.Fatal("prepared recorder has no BPF build hash")
	}
	runs, err := ebpf.LoadPinnedMap(filepath.Join(cgroupenforce.DefaultBPFFS, "tego", hash,
		"maps", ebpfbindings.MapRunSet), nil)
	if err != nil {
		t.Fatalf("open prepared recorder run set: %v", err)
	}
	t.Cleanup(func() {
		if err := runs.Close(); err != nil {
			t.Errorf("close run-set descriptor: %v", err)
		}
	})
	var row ebpfbindings.Run
	if err := runs.Lookup(&id, &row); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("recorder run-set row exists before Arm: row=%+v, error=%v", row, err)
	}
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := prepared.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if err := runs.Lookup(&id, &row); err != nil || row.Descendants != 1 || row.Gen == 0 || row.Plane != 0 {
		t.Fatalf("armed recorder run-set row: row=%+v, error=%v", row, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := prepared.RunListener(ctx); err != nil {
		t.Fatalf("RunListener with no filesystem rules: %v", err)
	}
	if err := prepared.WaitListener(ctx); err != nil {
		t.Fatalf("WaitListener with no filesystem rules: %v", err)
	}
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := runs.Lookup(&id, &row); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("recorder run-set row survived Detach: row=%+v, error=%v", row, err)
	}
	if err := h.Detach(); err != nil {
		t.Fatalf("second Detach: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// Match runtime.recordsOnly's optional-method predicate. The base handle
	// lacked the method; it did not literally return an allow verdict.
	v, hasVerdict := h.(interface{ Verdict() record.Verdict })
	var verdict record.Verdict
	if hasVerdict {
		verdict = v.Verdict()
	}
	observed := hasVerdict && verdict == record.VerdictObserved
	t.Logf("prepared recorder: type=%T, verdict_reporter=%t, verdict=%q, records_only=%t; Attach/Arm/Detach/Close and reporting passed", h, hasVerdict, verdict, observed)
	if !observed {
		t.Fatalf("prepared AdoptionRecorder handle lacks observed predicate: type=%T, verdict_reporter=%t, verdict=%q", h, hasVerdict, verdict)
	}
}
