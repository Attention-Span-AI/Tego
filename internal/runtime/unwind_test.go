// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
)

// fakeCgroups is a cgroup.Manager that touches no cgroupfs: it records what the facade asked for,
// so the startup failure paths can be tested where no delegated subtree is needed.
type fakeCgroups struct {
	root       string
	createErr  error
	limitsErr  error
	created    int
	removed    int
	killed     int
	limitsSeen cgroup.Limits
}

func (f *fakeCgroups) Root() string { return f.root }

func (f *fakeCgroups) Create(agentID, runID string) (cgroup.Cgroup, error) {
	if f.createErr != nil {
		return cgroup.Cgroup{}, f.createErr
	}
	f.created++
	return cgroup.Cgroup{Path: filepath.Join(f.root, agentID, runID), ID: 4242}, nil
}

func (f *fakeCgroups) ID(cgroup.Cgroup) (uint64, error) { return 4242, nil }

func (f *fakeCgroups) SetLimits(_ cgroup.Cgroup, l cgroup.Limits) error {
	f.limitsSeen = l
	return f.limitsErr
}

func (f *fakeCgroups) Kill(cgroup.Cgroup) error { f.killed++; return nil }

func (f *fakeCgroups) WaitEmpty(context.Context, cgroup.Cgroup) error { return nil }

func (f *fakeCgroups) Events(ctx context.Context, _ cgroup.Cgroup) (<-chan bool, error) {
	ch := make(chan bool)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

func (f *fakeCgroups) OOMKilled(cgroup.Cgroup) (bool, error) { return false, nil }

func (f *fakeCgroups) Remove(context.Context, cgroup.Cgroup) error { f.removed++; return nil }

// fakeBackend is an enforce.Backend whose Prepare can be made to fail.
type fakeBackend struct {
	prepareErr error
	handle     *fakeHandle
}

func (b *fakeBackend) Tier() backend.Tier { return backend.TierLandlock }

func (b *fakeBackend) Capabilities() backend.Set { return backend.Set{} }

func (b *fakeBackend) Prepare(context.Context, *agent.RuleTable, enforce.RunRef) (api.Handle, error) {
	if b.prepareErr != nil {
		return nil, b.prepareErr
	}
	b.handle = &fakeHandle{}
	return b.handle, nil
}

// fakeHandle counts the releases the shutdown sequence performs.
type fakeHandle struct {
	detached, closed int
}

func (h *fakeHandle) LandlockRuleset() (int, bool)                { return -1, false }
func (h *fakeHandle) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (h *fakeHandle) Attach(uint64) error                         { return nil }
func (h *fakeHandle) Detach() error                               { h.detached++; return nil }
func (h *fakeHandle) Close() error                                { h.closed++; return nil }

// startupFixture is a machine and contract for the failure paths: a ledger root of its own and a
// contract that declares one write directory well away from it.
func startupFixture(t *testing.T) (*config.Machine, *agent.RuleTable, string) {
	t.Helper()
	root := t.TempDir()
	m := config.Builtin()
	m.Home = root
	m.LedgerRoot = config.Setting[string]{Value: filepath.Join(root, "runs")}
	m.StopGrace = config.Setting[time.Duration]{Value: time.Second}
	rt := &agent.RuleTable{
		Contract: &agent.Contract{Name: "fake"},
		Record:   agent.RecordSummary,
		Tier:     backend.TierLandlock,
		Capture:  agent.CaptureOff,
		FS:       []agent.FSRule{{Path: filepath.Join(root, "out"), Kind: agent.FSWrite, Raw: "./out"}},
	}
	return m, rt, root
}

// unwindLog captures the run's own operational log so that a failure to clean up names its cause.
//
// unwind cannot fail harder than it already has: it runs on the error path and logs what it could not
// remove rather than returning. That makes a leftover run directory a silent outcome in the product
// and, without this, an unexplained one in the test. This test observed exactly that once, on a box
// running twenty concurrent build-and-test agents, and it could not be reproduced in five hundred
// attempts afterwards. Keeping the log means the next occurrence arrives with the errno attached
// instead of a bare directory listing.
type unwindLog struct {
	mu   sync.Mutex
	recs []string
}

func (l *unwindLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *unwindLog) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *unwindLog) WithGroup(string) slog.Handler            { return l }

func (l *unwindLog) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Level.String())
	b.WriteString(" ")
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" ")
		b.WriteString(a.String())
		return true
	})
	l.mu.Lock()
	l.recs = append(l.recs, b.String())
	l.mu.Unlock()
	return nil
}

func (l *unwindLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.recs) == 0 {
		return "(the run logged nothing)"
	}
	return "\n  " + strings.Join(l.recs, "\n  ")
}

// newUnwindLog returns a logger and the record it fills.
func newUnwindLog() (*slog.Logger, *unwindLog) {
	l := &unwindLog{}
	return slog.New(l), l
}

func TestRunUnwindsEverythingItBuilt(t *testing.T) {
	testutil.NoFDLeak(t)
	m, rt, root := startupFixture(t)
	cgroups := &fakeCgroups{root: t.TempDir()}
	b := &fakeBackend{}
	log, logged := newUnwindLog()
	deps := Deps{
		Config: m, Cgroups: cgroups, Enforce: b, Logger: log,
		// A launcher pointed at a binary that does not exist fails after the cgroup and the
		// handle exist: exactly the "cancelled mid-handshake" shape of §6 case 26.
		Launcher: &launch.Launcher{Exe: filepath.Join(root, "no-such-binary")},
		Environ:  []string{"PATH=/bin"},
		Cwd:      root,
	}
	res, err := Run(context.Background(), rt, []string{"/bin/true"}, deps)
	if err == nil {
		t.Fatal("a launcher that cannot start the child must fail the run")
	}
	if res.ExitCode != 125 || res.Reason != "error" {
		t.Fatalf("result %+v, want exit 125 reason error (R2)", res)
	}
	if cgroups.created != 1 || cgroups.removed != 1 {
		t.Fatalf("cgroup created %d removed %d, want 1/1", cgroups.created, cgroups.removed)
	}
	if b.handle == nil || b.handle.detached != 1 || b.handle.closed != 1 {
		t.Fatalf("handle %+v, want one detach and one close", b.handle)
	}
	if left := leftBehind(t, filepath.Join(root, "runs")); len(left) != 0 {
		t.Fatalf("a run that never started left %v behind; the run logged: %s", left, logged)
	}
	if _, err := os.Stat(ledger.DefaultAnchorPath(filepath.Join(root, "runs", "r"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a run that never started must not be anchored in chain.log")
	}
}

// Also pins runtime-launch.md R2 and I10: a pre-run_start failure is a Go error and exit 125, and Run writes no run_start or run_end for it.
func TestRunUnwindsAfterAFailedPrepare(t *testing.T) {
	testutil.NoFDLeak(t)
	m, rt, root := startupFixture(t)
	cgroups := &fakeCgroups{root: t.TempDir()}
	boom := errors.New("no ruleset for you")
	log, logged := newUnwindLog()
	res, err := Run(context.Background(), rt, []string{"/bin/true"},
		Deps{Config: m, Cgroups: cgroups, Enforce: &fakeBackend{prepareErr: boom}, Environ: []string{}, Cwd: root, Logger: log})
	if !errors.Is(err, boom) {
		t.Fatalf("err %v, want the backend's own error wrapped", err)
	}
	if res.ExitCode != 125 {
		t.Fatalf("exit %d, want 125", res.ExitCode)
	}
	if cgroups.removed != 1 {
		t.Fatalf("the cgroup created before Prepare must be removed again (removed %d)", cgroups.removed)
	}
	if left := leftBehind(t, filepath.Join(root, "runs")); len(left) != 0 {
		t.Fatalf("run directory left behind: %v; the run logged: %s", left, logged)
	}
}

// TestRunUnwindsAfterAChildStageThatCannotBeCloned is runtime-launch.md E2: a clone3 that fails (ENOSPC on max
// PIDs or cgroup depth, or here an unrunnable child stage, which fails the same call) is the launcher's own
// pre-run_start failure: exit 125, the error wrapping launch.ErrClone, and the cgroup and the run directory made
// before it removed again by the same unwind that a failed Prepare takes, with no run_start and no run_end.
//
// Also pins runtime-launch.md R2: a pre-run_start failure is a Go error and exit 125.
func TestRunUnwindsAfterAChildStageThatCannotBeCloned(t *testing.T) {
	testutil.NoFDLeak(t)
	m, rt, root := startupFixture(t)
	cgroups := &fakeCgroups{root: t.TempDir()}
	log, logged := newUnwindLog()
	res, err := Run(context.Background(), rt, []string{"/bin/true"},
		Deps{Config: m, Cgroups: cgroups, Enforce: &fakeBackend{}, Environ: []string{}, Cwd: root, Logger: log,
			Launcher: &launch.Launcher{Exe: filepath.Join(root, "no-such-stage")}})
	if !errors.Is(err, launch.ErrClone) {
		t.Fatalf("err %v, want it to wrap launch.ErrClone", err)
	}
	if res.ExitCode != 125 {
		t.Fatalf("exit %d, want 125", res.ExitCode)
	}
	if cgroups.created != 1 || cgroups.removed != 1 {
		t.Fatalf("the cgroup made before clone3 must be removed again (created %d, removed %d)",
			cgroups.created, cgroups.removed)
	}
	if left := leftBehind(t, filepath.Join(root, "runs")); len(left) != 0 {
		t.Fatalf("run directory left behind: %v; the run logged: %s", left, logged)
	}
}

// recorderBackend is a fakeBackend whose handle names a BPF build, so the run builds its kernel recorder.
type recorderBackend struct{ fakeBackend }

// recorderHandle is a fakeHandle that is an enforce.KernelRecorder.
type recorderHandle struct{ *fakeHandle }

func (recorderHandle) BPFHash() string { return "deadbeef" }

func (b *recorderBackend) Prepare(context.Context, *agent.RuleTable, enforce.RunRef) (api.Handle, error) {
	b.handle = &fakeHandle{}
	return recorderHandle{b.handle}, nil
}

// stopCounter is a source that counts its Stops.
type stopCounter struct {
	plainSource
	stops atomic.Int32
}

func (s *stopCounter) Stop() error { s.stops.Add(1); return nil }

// TestRunUnwindStopsTheKernelRecorder is a run that fails after its kernel recorder was built, here because the child
// cannot start, before any source started: unwind stopped the sources that had started and never the recorder, which
// New had given the pinned ring, its reader and epoll, the lost counter and the run set, all leaked for the life of
// the launcher.
func TestRunUnwindStopsTheKernelRecorder(t *testing.T) {
	testutil.NoFDLeak(t)
	m, rt, root := startupFixture(t)
	rec := &stopCounter{plainSource: plainSource{name: "observe"}}
	b := &recorderBackend{}
	log, logged := newUnwindLog()
	deps := Deps{
		Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: b, Logger: log,
		ObserveFactory: func(string) (source.Source, error) { return rec, nil },
		Launcher:       &launch.Launcher{Exe: filepath.Join(root, "no-such-binary")},
		Environ:        []string{"PATH=/bin"},
		Cwd:            root,
	}
	if _, err := Run(context.Background(), rt, []string{"/bin/true"}, deps); err == nil {
		t.Fatal("a launcher that cannot start the child must fail the run")
	}
	if b.handle == nil || b.handle.detached != 1 {
		t.Fatalf("handle %+v, want the unwind to have run", b.handle)
	}
	if n := rec.stops.Load(); n != 1 {
		t.Errorf("the kernel recorder was stopped %d times on unwind, want once; the run logged: %s", n, logged)
	}
}

// leftBehind is what a ledger root holds besides its live index, and the index's own entries: a run that
// never started leaves none of either. The index directory itself stays, since a root without one gets a
// sweep of every run (ledger.SweepLive).
func leftBehind(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read ledger root: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != ledger.LiveDir {
			out = append(out, e.Name())
		}
	}
	listed, err := os.ReadDir(filepath.Join(root, ledger.LiveDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read the live index: %v", err)
	}
	for _, e := range listed {
		out = append(out, filepath.Join(ledger.LiveDir, e.Name()))
	}
	return out
}

func TestRunRefusesARunDirectoryInsideAWriteEntry(t *testing.T) {
	m, rt, root := startupFixture(t)
	// The machine's ledger root now sits inside the contract's write entry: the agent could
	// rewrite its own record, so the run never starts and nothing is created.
	m.LedgerRoot = config.Setting[string]{Value: filepath.Join(root, "out", "runs")}
	cgroups := &fakeCgroups{root: t.TempDir()}
	_, err := Run(context.Background(), rt, []string{"/bin/true"},
		Deps{Config: m, Cgroups: cgroups, Enforce: &fakeBackend{}, Cwd: root})
	if !errors.Is(err, ErrRunDirWritable) {
		t.Fatalf("err %v, want ErrRunDirWritable", err)
	}
	if cgroups.created != 0 {
		t.Fatal("nothing may be created for a run that is refused before it starts")
	}
	if _, err := os.Stat(filepath.Join(root, "out", "runs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the ledger root must not be created for a refused run")
	}
}

func TestRunWritesTheContractsLimitsToTheCgroup(t *testing.T) {
	m, rt, root := startupFixture(t)
	rt.Limits = agent.ResolvedLimits{CPU: "2.0", CPUWeight: 200, MemoryB: 1 << 30, Pids: 64}
	cgroups := &fakeCgroups{root: t.TempDir()}
	_, _ = Run(context.Background(), rt, []string{"/bin/true"},
		Deps{Config: m, Cgroups: cgroups, Enforce: &fakeBackend{prepareErr: errors.New("stop here")}, Cwd: root})
	want, err := cgroup.FromResolved(rt.Limits)
	if err != nil {
		t.Fatal(err)
	}
	if cgroups.limitsSeen != want {
		t.Fatalf("limits %+v, want %+v", cgroups.limitsSeen, want)
	}
	if cgroups.limitsSeen.PidsMax != 64 {
		t.Fatalf("pids.max %d, want 64", cgroups.limitsSeen.PidsMax)
	}
}
