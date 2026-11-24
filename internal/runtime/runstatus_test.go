// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

type statusCgroups struct {
	*fakeCgroups
	removeErr error
	leave     bool
}

func (m *statusCgroups) Remove(_ context.Context, cg cgroup.Cgroup) error {
	m.removed++
	if m.removeErr != nil {
		return m.removeErr
	}
	if m.leave {
		return nil
	}
	return os.Remove(cg.Path)
}

func TestRunStatusRefusedBeforeScopeWritesNothing(t *testing.T) {
	m, rt, root := startupFixture(t)
	calls := 0
	_, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{Config: m, Cgroups: &fakeCgroups{root: root, createErr: errors.New("refused")}, Enforce: &fakeBackend{}, RunStatus: func(runstatus.Status) error { calls++; return nil }})
	if err == nil || calls != 0 {
		t.Fatalf("refusal err=%v writes=%d", err, calls)
	}
}

func TestRunStatusInitialPrecedesLimitsAndRefusedStartFinal(t *testing.T) {
	m, rt, root := startupFixture(t)
	cg := &fakeCgroups{root: t.TempDir(), limitsErr: errors.New("refuse limits")}
	var got []runstatus.Status
	_, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{Config: m, Cgroups: cg, Enforce: &fakeBackend{}, Cwd: root, RunStatus: func(s runstatus.Status) error { got = append(got, s); return nil }})
	if err == nil || len(got) != 2 {
		t.Fatalf("err=%v status=%+v", err, got)
	}
	if got[0].Removed || got[0].Deferred || got[0].CgroupID != "4242" || got[0].Run == "" {
		t.Fatalf("initial status %+v", got[0])
	}
	if !got[1].Removed || got[1].Deferred || got[1].Run != got[0].Run || got[1].Scope != got[0].Scope {
		t.Fatalf("final status %+v", got[1])
	}
}

func TestRunStatusInitialWriterFailureRefusesEnforcementAndExec(t *testing.T) {
	m, rt, root := startupFixture(t)
	cg := &fakeCgroups{root: t.TempDir()}
	backend := &fakeBackend{}
	boom := errors.New("initial status could not be stored")
	calls := 0
	res, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{Config: m, Cgroups: cg, Enforce: backend, Cwd: root, RunStatus: func(runstatus.Status) error { calls++; return boom }})
	if !errors.Is(err, boom) || res.ExitCode != identity.ExitLauncher || backend.handle != nil || cg.removed != 1 || calls != 2 {
		t.Fatalf("result=%+v err=%v backend=%+v removal=%d status writes=%d", res, err, backend.handle, cg.removed, calls)
	}
}

func statusRunner(t *testing.T, reason identity.EndReason, removal error, leave bool) (*runner, *[]runstatus.Status) {
	t.Helper()
	r := newTestRunner(Deps{})
	r.id = identity.RunID("r-00000000-000000000000a-aaaaaa")
	r.dir = filepath.Join(t.TempDir(), string(r.id))
	w, err := ledger.Open(r.dir, record.RunRef{ID: string(r.id), Agent: "status"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	r.writer = w
	r.group, _ = newGroup(context.Background())
	r.cg = cgroup.Cgroup{Path: filepath.Join(t.TempDir(), "run.scope"), ID: 4242}
	r.statusScopeAcquired = true
	if err := os.Mkdir(r.cg.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	r.cgm = &statusCgroups{fakeCgroups: &fakeCgroups{}, removeErr: removal, leave: leave}
	r.handle = &fakeHandle{}
	r.terminal = reason
	if reason == identity.ReasonSignal {
		r.wait.Status = syscall.WaitStatus(syscall.SIGKILL)
	}
	r.runtimeDir = t.TempDir()
	runtimeDir := r.runtimeDir
	var got []runstatus.Status
	r.deps.RunStatus = func(s runstatus.Status) error {
		if !hasRunEndOnDisk(r.dir) {
			t.Error("final status before record close")
		}
		if _, err := os.Stat(runtimeDir); !errors.Is(err, os.ErrNotExist) {
			t.Error("final status before runtime directory removal")
		}
		got = append(got, s)
		return nil
	}
	return r, &got
}

func TestRunStatusFinalCleanKilledAndFailedRemoval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reason  identity.EndReason
		removal error
		leave   bool
		removed bool
	}{
		{"clean", identity.ReasonExit, nil, false, true}, {"killed", identity.ReasonSignal, nil, false, true},
		{"remove failed", identity.ReasonExit, errors.New("busy"), false, false}, {"still present", identity.ReasonExit, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, got := statusRunner(t, tc.reason, tc.removal, tc.leave)
			res := r.shutdown(context.Background())
			if tc.reason == identity.ReasonSignal && res.ExitCode != 137 {
				t.Fatalf("killed exit=%d, want 137", res.ExitCode)
			}
			if len(*got) != 1 || (*got)[0].Removed != tc.removed || (*got)[0].Deferred {
				t.Fatalf("statuses %+v", *got)
			}
		})
	}
}

func TestRunStatusDeferredHasNoBackgroundSuccessRewrite(t *testing.T) {
	r, got := statusRunner(t, identity.ReasonExit, nil, false)
	stuck := make(chan struct{})
	r.stuckStops = []<-chan struct{}{stuck}
	_ = r.shutdown(context.Background())
	if len(*got) != 1 || (*got)[0].Removed || !(*got)[0].Deferred {
		t.Fatalf("statuses %+v", *got)
	}
	before := append([]runstatus.Status(nil), (*got)...)
	close(stuck)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		if _, err := os.Lstat(r.cg.Path); errors.Is(err, os.ErrNotExist) {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("deferred removal did not finish")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	if !reflect.DeepEqual(*got, before) {
		t.Fatalf("background rewrote status %+v", *got)
	}
}

func TestRunStatusUnknownIdentityNeverClaimsRemoval(t *testing.T) {
	r, got := statusRunner(t, identity.ReasonExit, nil, false)
	r.cg.ID = 0
	_ = r.shutdown(context.Background())
	if len(*got) != 1 || (*got)[0].Removed || (*got)[0].CgroupID != "" {
		t.Fatalf("statuses %+v", *got)
	}
}

func TestRunStatusUnknownScopeWritesExplicitUnknown(t *testing.T) {
	r, got := statusRunner(t, identity.ReasonExit, nil, false)
	r.cg.Path = ""
	_ = r.shutdown(context.Background())
	if len(*got) != 1 || (*got)[0].Removed || (*got)[0].Scope != "" {
		t.Fatalf("statuses %+v", *got)
	}
}

func TestRunStatusFinalWriterFailureIsReturned(t *testing.T) {
	r, _ := statusRunner(t, identity.ReasonExit, nil, false)
	boom := errors.New("status storage failed")
	r.deps.RunStatus = func(runstatus.Status) error { return boom }
	res := r.shutdown(context.Background())
	if !errors.Is(res.StatusErr, boom) {
		t.Fatalf("status error %v", res.StatusErr)
	}
}
