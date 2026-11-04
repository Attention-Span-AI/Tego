// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// adoptHost is a fake machine for adoptions: /proc, the cgroup filesystem and pidfds in one, so that a move changes
// what /proc/<pid>/cgroup says, as the kernel does.
type adoptHost struct {
	mu     sync.Mutex
	mount  string
	procs  map[int]*hostProc
	frozen map[string]bool
	moves  []string
	// onAdd, when set, is called with each pid a move writes, before the write.
	onAdd func(pid int)
}

type hostProc struct {
	ppid   int
	start  uint64
	exe    string
	cgroup string
	fds    []adopt.FD
	maps   []adopt.Mapping
	// fdErr and mapsErr are returned beside fds and maps (adopt.ErrTruncated: a listing past its cap).
	fdErr, mapsErr error
	// mntns is its mount namespace's inode; 0 is hostMntNS, tego's own.
	mntns uint64
}

// hostMntNS is the mount namespace of every fake process that names none, and of this process (tego).
const hostMntNS = 1

func newAdoptHost(t *testing.T) *adoptHost {
	h := &adoptHost{mount: t.TempDir(), procs: map[int]*hostProc{}, frozen: map[string]bool{}}
	return h
}

func (h *adoptHost) add(pid, ppid int, cg, exe string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.procs[pid] = &hostProc{ppid: ppid, start: uint64(5000 + pid), exe: exe, cgroup: cg}
}

// end makes every process in rel exit, as an agent's tree ending does.
func (h *adoptHost) end(rel string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for pid, p := range h.procs {
		if p.cgroup == rel {
			delete(h.procs, pid)
		}
	}
}

func (h *adoptHost) in(rel string) []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []int
	for pid, p := range h.procs {
		if p.cgroup == rel {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}

func (h *adoptHost) get(pid int) (*hostProc, error) {
	p, ok := h.procs[pid]
	if !ok {
		return nil, fmt.Errorf("pid %d: %w", pid, proc.ErrGone)
	}
	return p, nil
}

func (h *adoptHost) PIDs() ([]int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []int
	for pid := range h.procs {
		out = append(out, pid)
	}
	sort.Ints(out)
	return out, nil
}

func (h *adoptHost) Stat(pid int) (proc.Stat, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := h.get(pid)
	if err != nil {
		return proc.Stat{}, err
	}
	return proc.Stat{PID: pid, Comm: filepath.Base(p.exe), State: 'S', PPID: p.ppid, StartTicks: p.start}, nil
}

func (h *adoptHost) Exe(pid int) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := h.get(pid)
	if err != nil {
		return "", err
	}
	return p.exe, nil
}

func (h *adoptHost) Argv(pid int) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := h.get(pid)
	if err != nil {
		return nil, err
	}
	return []string{p.exe, "--flag"}, nil
}

func (h *adoptHost) Cgroup(pid int) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := h.get(pid)
	if err != nil {
		return "", err
	}
	return p.cgroup, nil
}

func (h *adoptHost) Status(pid int) (adopt.Status, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.get(pid); err != nil {
		return adopt.Status{}, err
	}
	return adopt.Status{Tgid: pid, UID: [3]int{1000, 1000, 1000}, GID: [3]int{1000, 1000, 1000}}, nil
}

func (h *adoptHost) ExeFile(pid int) (adopt.FileID, error) {
	return adopt.FileID{Dev: 1, Ino: uint64(pid)}, nil
}

func (h *adoptHost) Namespace(pid int, kind string) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.procs[pid]; ok && kind == "mnt" && p.mntns != 0 {
		return p.mntns, nil
	}
	return hostMntNS, nil
}

func (h *adoptHost) Cwd(int) (string, error) { return "/home/u/project", nil }

func (h *adoptHost) FDs(pid int) ([]adopt.FD, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := h.get(pid)
	if err != nil {
		return nil, err
	}
	return p.fds, p.fdErr
}

func (h *adoptHost) Maps(pid int) ([]adopt.Mapping, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := h.get(pid)
	if err != nil {
		return nil, err
	}
	return p.maps, p.mapsErr
}

func (h *adoptHost) rel(dir string) string { return strings.TrimPrefix(dir, h.mount) }

func (h *adoptHost) Add(dir string, pid int) error {
	h.mu.Lock()
	hook := h.onAdd
	h.mu.Unlock()
	if hook != nil {
		hook(pid)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := os.Stat(dir); err != nil {
		return syscall.ENOENT
	}
	p, ok := h.procs[pid]
	if !ok {
		return syscall.ESRCH
	}
	p.cgroup = h.rel(dir)
	h.moves = append(h.moves, fmt.Sprintf("%d>%s", pid, h.rel(dir)))
	return nil
}

func (h *adoptHost) Procs(dir string) ([]int, error) { return h.in(h.rel(dir)), nil }

// Threads is Procs: every fake process is one task.
func (h *adoptHost) Threads(dir string) ([]int, error) { return h.in(h.rel(dir)), nil }

// Tasks is the process's own: every fake process is one task.
func (h *adoptHost) Tasks(pid int) ([]int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.get(pid); err != nil {
		return nil, err
	}
	return []int{pid}, nil
}

func (h *adoptHost) Freeze(dir string, frozen bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.frozen[h.rel(dir)] = frozen
	return nil
}

func (h *adoptHost) Exists(dir string) bool {
	_, err := os.Stat(dir)
	return err == nil
}

type hostWatch struct {
	h   *adoptHost
	pid int
}

func (h *adoptHost) Watch(pid int) (adopt.Watch, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.procs[pid]; !ok {
		return nil, syscall.ESRCH
	}
	return hostWatch{h: h, pid: pid}, nil
}

func (w hostWatch) Exited() bool {
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	_, ok := w.h.procs[w.pid]
	return !ok
}

func (hostWatch) Close() error { return nil }

func (h *adoptHost) env() adopt.Env { return adopt.Env{Proc: h, FS: h, Live: h, Mount: h.mount} }

// adoptCgroups is the scope manager over the fake host: CreateScope makes a real directory under its mount, which is
// what the host's moves check, and WaitEmpty waits until no process of the host is in it.
type adoptCgroups struct {
	h                      *adoptHost
	created, removed, kill int
	removeErr              error
}

func (c *adoptCgroups) Root() string { return c.h.mount }

func (c *adoptCgroups) Create(string, string) (cgroup.Cgroup, error) {
	return cgroup.Cgroup{}, errors.New("an adoption never makes a run-<id>.scope")
}

func (c *adoptCgroups) CreateScope(agentID, runID, scope string) (cgroup.Cgroup, error) {
	dir := filepath.Join(c.h.mount, "tego.slice", "tego-"+agentID+".slice", scope)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return cgroup.Cgroup{}, err
	}
	c.created++
	return cgroup.Cgroup{Path: dir, ID: 777}, nil
}

func (c *adoptCgroups) ID(cgroup.Cgroup) (uint64, error)             { return 777, nil }
func (c *adoptCgroups) SetLimits(cgroup.Cgroup, cgroup.Limits) error { return nil }
func (c *adoptCgroups) Kill(cgroup.Cgroup) error                     { c.kill++; return nil }
func (c *adoptCgroups) OOMKilled(cgroup.Cgroup) (bool, error)        { return false, nil }

func (c *adoptCgroups) Events(ctx context.Context, _ cgroup.Cgroup) (<-chan bool, error) {
	ch := make(chan bool)
	go func() { <-ctx.Done(); close(ch) }()
	return ch, nil
}

func (c *adoptCgroups) WaitEmpty(ctx context.Context, cg cgroup.Cgroup) error {
	for {
		if len(c.h.in(c.h.rel(cg.Path))) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (c *adoptCgroups) Remove(_ context.Context, cg cgroup.Cgroup) error {
	if c.removeErr != nil {
		return c.removeErr
	}
	c.removed++
	return os.Remove(cg.Path)
}

// adoptBackend is a tier-cgroup backend over a handle that records its calls.
type adoptBackend struct {
	prepareErr error
	attachErr  error
	armErr     error
	noArmer    bool
	plane      string
	handle     *adoptHandle
	// keyed is what the handle's PlaneKeyed reports (the files the plane's fill wrote the fs rows at), with keyedOK.
	keyed   []enforce.PlaneKeyed
	keyedOK bool
	// onArm, when set, is called by the handle's Arm, before it arms.
	onArm func()
}

func (b *adoptBackend) Tier() backend.Tier        { return backend.TierCgroup }
func (b *adoptBackend) Capabilities() backend.Set { return backend.Matrix(backend.TierCgroup) }

func (b *adoptBackend) Prepare(_ context.Context, rt *agent.RuleTable, ref enforce.RunRef) (api.Handle, error) {
	if b.prepareErr != nil {
		return nil, b.prepareErr
	}
	if rt.Tier != backend.TierCgroup {
		return nil, fmt.Errorf("table at tier %s", rt.Tier)
	}
	b.handle = &adoptHandle{plane: b.plane, ref: ref, keyed: b.keyed, keyedOK: b.keyedOK, onArm: b.onArm,
		attachErr: b.attachErr, armErr: b.armErr}
	if b.noArmer {
		return struct {
			api.Handle
			enforce.DecisionPlaneReporter
		}{b.handle, b.handle}, nil
	}
	return b.handle, nil
}

type adoptHandle struct {
	mu                                sync.Mutex
	plane                             string
	ref                               enforce.RunRef
	attached, armed, detached, closed int
	keyed                             []enforce.PlaneKeyed
	keyedOK                           bool
	onArm                             func()
	attachErr, armErr                 error
}

func (h *adoptHandle) PlaneKeyed() ([]enforce.PlaneKeyed, bool) { return h.keyed, h.keyedOK }

func (h *adoptHandle) LandlockRuleset() (int, bool)                { return -1, false }
func (h *adoptHandle) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (h *adoptHandle) Attach(uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.attached++
	return h.attachErr
}
func (h *adoptHandle) Arm() error {
	if h.onArm != nil {
		h.onArm()
	}
	h.mu.Lock()
	h.armed++
	h.mu.Unlock()
	return h.armErr
}
func (h *adoptHandle) Detach() error                 { h.mu.Lock(); h.detached++; h.mu.Unlock(); return nil }
func (h *adoptHandle) Close() error                  { h.mu.Lock(); h.closed++; h.mu.Unlock(); return nil }
func (h *adoptHandle) BPFHash() string               { return "0123456789abcdef" }
func (h *adoptHandle) DecisionPlane() (string, bool) { return h.plane, h.plane != "" }
func (h *adoptHandle) Capabilities() backend.Set     { return backend.Matrix(backend.TierCgroup) }

// fakeRecorder is the kernel recorder: on Start it records one exec of pid as the kernel would, then nothing.
type fakeRecorder struct {
	pid      int
	supExecs *bool
	plane    string
	stopped  bool
}

func (f *fakeRecorder) Name() string { return "fake-kernel-record" }

func (f *fakeRecorder) Start(_ context.Context, run source.RunRef, sink source.Sink) error {
	ev := &record.Event{Kind: record.KindExec, Source: record.SourceKernel, PID: f.pid, Run: run.ID,
		Rule: UnmatchedRule, Verdict: record.VerdictObserved, Authority: record.AuthorityRule}
	_ = ev.SetPayload(record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git", "status"}, ExecID: run.ID + "/1/1"})
	sink.Emit(ev)
	return nil
}

func (f *fakeRecorder) Stop() error                  { f.stopped = true; return nil }
func (f *fakeRecorder) Gaps() []source.Gap           { return nil }
func (f *fakeRecorder) SetSupervisorExecs(on bool)   { f.supExecs = &on }
func (f *fakeRecorder) SetDecisionPlane(mode string) { f.plane = mode }

const adoptSession = "/user.slice/user-1000.slice/session-2.scope"

// adoptFixture is a machine with a terminal: a shell (100) and, its child, the agent (200) with a child of its own
// (201), and a sibling tab's shell (300), all in one session scope; a record store of the test's own; a ledger root.
type adoptFixture struct {
	host    *adoptHost
	cgroups *adoptCgroups
	backend *adoptBackend
	rec     *fakeRecorder
	deps    AdoptDeps
	rt      *agent.RuleTable
	root    string
	state   string
}

func newAdoptFixture(t *testing.T) *adoptFixture {
	t.Helper()
	prevOwner := adoptStateOwner
	adoptStateOwner = os.Geteuid()
	t.Cleanup(func() { adoptStateOwner = prevOwner })
	m, _, root := startupFixture(t)
	h := newAdoptHost(t)
	if err := os.MkdirAll(filepath.Join(h.mount, adoptSession), 0o755); err != nil {
		t.Fatal(err)
	}
	h.add(100, 1, adoptSession, "/usr/bin/bash")
	h.add(200, 100, adoptSession, "/usr/bin/node")
	h.add(201, 200, adoptSession, "/usr/bin/git")
	h.add(300, 1, adoptSession, "/usr/bin/bash")
	state := filepath.Join(t.TempDir(), "adopted")
	f := &adoptFixture{host: h, cgroups: &adoptCgroups{h: h}, backend: &adoptBackend{}, rec: &fakeRecorder{pid: 201},
		root: root, state: state}
	f.rt = &agent.RuleTable{Contract: &agent.Contract{Name: "adopt-node"}, Record: agent.RecordFull,
		Tier: backend.TierCgroup, Capture: agent.CaptureOff}
	f.deps = AdoptDeps{Config: m, Enforce: f.backend, Cgroups: f.cgroups, StateDir: state, ReaperExe: NoAdoptReaper,
		ObserveFactory: func(string) (source.Source, error) { return f.rec, nil }}
	return f
}

func (f *adoptFixture) spec(t *testing.T) AdoptSpec {
	t.Helper()
	root, err := adopt.Identify(f.host, 200)
	if err != nil {
		t.Fatal(err)
	}
	return AdoptSpec{Root: root, Env: f.host.env(), Recheck: admitAll}
}

// admitAll is a Recheck that refuses nothing.
func admitAll(adopt.Process) error { return nil }

// recordsLeft lists what an adoption store holds besides its permanent move lock.
func recordsLeft(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if e.Name() != movesLockName {
			out = append(out, e.Name())
		}
	}
	return out
}

// adoptRunning starts an adoption and returns once it records, with what it reported and its result channel.
func (f *adoptFixture) adoptRunning(t *testing.T, ctx context.Context, spec AdoptSpec) (AdoptStarted, <-chan Result) {
	t.Helper()
	started := make(chan AdoptStarted, 1)
	spec.Started = func(s AdoptStarted) { started <- s }
	done := make(chan Result, 1)
	errc := make(chan error, 1)
	go func() {
		res, err := Adopt(ctx, f.rt, spec, f.deps)
		if err != nil {
			errc <- err
			return
		}
		done <- res
	}()
	select {
	case s := <-started:
		return s, done
	case err := <-errc:
		t.Fatalf("Adopt: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the adoption never started recording")
	}
	return AdoptStarted{}, nil
}

func waitResult(t *testing.T, done <-chan Result) Result {
	t.Helper()
	select {
	case res := <-done:
		return res
	case <-time.After(10 * time.Second):
		t.Fatal("the adoption did not end")
	}
	return Result{}
}

func TestAdoptRecordsTheAdoptedTreeAndEndsWithIt(t *testing.T) {
	f := newAdoptFixture(t)
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	scopeRel := f.host.rel(s.Scope)
	if got := f.host.in(scopeRel); !slices.Equal(got, []int{200, 201}) {
		t.Fatalf("in the run's cgroup: %v, want the agent and its child [200 201]", got)
	}
	if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 300}) {
		t.Fatalf("left in the session: %v, want the shell and the sibling [100 300]", got)
	}
	if filepath.Base(s.Scope) != adopt.ScopeName(s.RunID) || s.From != adoptSession {
		t.Errorf("scope %s from %s", s.Scope, s.From)
	}
	h := f.backend.handle
	if h.attached != 1 || h.armed != 1 {
		t.Errorf("attached %d armed %d, want 1 and 1", h.attached, h.armed)
	}
	if f.rec.supExecs == nil || *f.rec.supExecs {
		t.Error("the recorder must be told it writes every exec line: no supervisor exists")
	}
	// The record root's tools act on, while the adoption runs.
	store := &adoptStore{dir: f.state}
	rec, err := store.read(s.RunID)
	if err != nil {
		t.Fatalf("the adoption's record: %v", err)
	}
	if rec.From != adoptSession || rec.Scope != s.Scope || rec.Root.PID != 200 || rec.Adopter.PID != os.Getpid() {
		t.Errorf("record %+v", rec)
	}
	if _, err := store.claim(rec.Root); !errors.Is(err, ErrAlreadyAdopting) {
		t.Errorf("a second adopter of the same process: %v, want ErrAlreadyAdopting", err)
	}

	f.host.end(scopeRel) // the agent's tree ends
	res := waitResult(t, done)
	if res.Reason != record.RunEndExit || res.ExitCode != 0 || res.RecordErr != nil {
		t.Fatalf("result %+v, want exit 0 reason exit", res)
	}
	if f.cgroups.kill != 0 {
		t.Fatal("an adoption killed its cgroup")
	}
	if h.detached != 1 || h.closed != 1 || f.cgroups.removed != 1 {
		t.Errorf("detached %d closed %d removed %d, want 1 each", h.detached, h.closed, f.cgroups.removed)
	}
	if _, err := store.read(s.RunID); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record outlived its adoption: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.state, targetName(rec.Root))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the process's lock file outlived its adoption: %v", err)
	}

	evs := events(t, s.Dir)
	if evs[0].Kind != record.KindRunStart {
		t.Fatalf("first line %s", evs[0].Kind)
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.LauncherPID != os.Getpid() || !slices.Equal(start.Command, []string{"/usr/bin/node", "--flag"}) ||
		start.Cwd != "/home/u/project" || start.Tier != "cgroup" || start.Capture != "off" || start.Limits != nil ||
		start.ContractSource != nil {
		t.Errorf("run_start %+v", start)
	}
	for c, on := range start.Capabilities {
		if on && c != string(backend.CapRecordExecOpenNet) && c != string(backend.CapRecordReads) && c != string(backend.CapLogAllowed) {
			t.Errorf("a record-only adoption claims %s", c)
		}
	}
	var adopted []int
	var preAttach, recorded bool
	for _, ev := range evs {
		switch ev.Kind {
		case record.KindExec:
			var p record.ExecPayload
			_ = ev.DecodePayload(&p)
			if p.By == AdoptionBy {
				adopted = append(adopted, ev.PID)
				wantID := fmt.Sprintf("%s/%d/%d", s.RunID, ev.PID, (5000+uint64(ev.PID))*proc.NanosPerTick)
				if p.ExecID != wantID {
					t.Errorf("pid %d exec_id %s, want %s", ev.PID, p.ExecID, wantID)
				}
				if ev.PID == 201 && p.ParentExecID != fmt.Sprintf("%s/200/%d", s.RunID, 5200*proc.NanosPerTick) {
					t.Errorf("the child's parent_exec_id %q", p.ParentExecID)
				}
			} else if ev.PID == 201 {
				recorded = true
			}
		case record.KindGap:
			var g record.GapPayload
			_ = ev.DecodePayload(&g)
			if g.Why == GapAdoptionPreAttach {
				preAttach = g.Count == 2 && g.What == record.GapRecord && g.Binary == "/usr/bin/node"
			}
			if g.Why == GapAdoptionNoFilter {
				t.Errorf("a record-only adoption, which holds nothing, wrote %+v", g)
			}
		}
	}
	if !slices.Equal(adopted, []int{200, 201}) {
		t.Errorf("exec lines by adoption for %v, want [200 201]", adopted)
	}
	if !preAttach {
		t.Error("no gap adoption-pre-attach for the two processes")
	}
	if !recorded {
		t.Error("the kernel recorder's line of the adopted child is not in the ledger")
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil || !strings.Contains(end.Detail, "exit status is unknown") {
		t.Errorf("run_end %+v %v", end, err)
	}
	for _, left := range leftBehind(t, filepath.Join(f.root, "runs")) {
		if strings.HasPrefix(left, ledger.LiveDir) {
			t.Errorf("the live index still lists %s after run_end", left)
		}
	}
}

func TestAdoptReleasesTheTreeWhenAskedToStop(t *testing.T) {
	f := newAdoptFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	s, done := f.adoptRunning(t, ctx, f.spec(t))
	// A process the agent forked after the adoption is born in the run's cgroup, and goes back with it.
	f.host.add(202, 201, f.host.rel(s.Scope), "/usr/bin/cat")
	cancel() // SIGINT, SIGTERM or tego stop
	res := waitResult(t, done)
	if res.Reason != record.RunEndStopped || res.ExitCode != 0 {
		t.Fatalf("result %+v, want reason stopped", res)
	}
	if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 202, 300}) {
		t.Fatalf("in the session after the release: %v", got)
	}
	if f.host.frozen[f.host.rel(s.Scope)] {
		t.Error("the run's cgroup was left frozen")
	}
	if f.cgroups.kill != 0 {
		t.Fatal("a release killed")
	}
	if f.cgroups.removed != 1 {
		t.Errorf("scope removed %d times", f.cgroups.removed)
	}
	if reason := lastReason(t, s.Dir); reason != record.RunEndStopped {
		t.Errorf("run_end reason %q", reason)
	}
}

// TestAdoptKeepsTheRecordOfProcessesLeftInTheScope: a release that no cgroup takes a process back from leaves it in
// the scope, released. The record used to go with the run anyway, so `tego adopt --release --pid` of it said "no
// adoption record" and nothing could ever move it out: the record now stays, marked released, beside the kept scope,
// and a later release moves the process out from it without asking the ended adoption, then removes both.
func TestAdoptKeepsTheRecordOfProcessesLeftInTheScope(t *testing.T) {
	f := newAdoptFixture(t)
	prevEnv := adoptReleaseEnv
	adoptReleaseEnv = func() adopt.Env { return f.host.env() }
	t.Cleanup(func() { adoptReleaseEnv = prevEnv })
	ctx, cancel := context.WithCancel(context.Background())
	s, done := f.adoptRunning(t, ctx, f.spec(t))
	// The cgroup the agent came from, and every one above it, is gone: no target takes the tree back.
	if err := os.RemoveAll(filepath.Join(f.host.mount, "user.slice")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if res := waitResult(t, done); res.Reason != record.RunEndStopped {
		t.Fatalf("result %+v", res)
	}
	if got := f.host.in(f.host.rel(s.Scope)); !slices.Equal(got, []int{200, 201}) {
		t.Fatalf("the scope holds %v, want the tree left in it, released", got)
	}
	store := &adoptStore{dir: f.state}
	rec, err := store.read(s.RunID)
	if err != nil || !rec.Released {
		t.Fatalf("the record of a scope processes stay in: %+v, %v; want it kept, marked released", rec, err)
	}
	if run, err := AdoptionOf(f.host, f.state, 200); err != nil || run != s.RunID {
		t.Fatalf("AdoptionOf(200) = %q, %v", run, err)
	}

	// Still nowhere to go: the release says so and keeps the record.
	if _, err := ReleaseAdoption(context.Background(), f.state, s.RunID, "tego adopt --release", nil); err == nil ||
		!strings.Contains(err.Error(), "still stay in") {
		t.Fatalf("a release that moved nothing out: %v", err)
	}
	if _, err := store.read(s.RunID); err != nil {
		t.Fatalf("the record went while processes stay: %v", err)
	}

	// The session is back: the release moves them out, removes the scope and the record, and writes nothing to the
	// ended run.
	if err := os.MkdirAll(filepath.Join(f.host.mount, adoptSession), 0o755); err != nil {
		t.Fatal(err)
	}
	lines := len(readFile(t, filepath.Join(s.Dir, ledger.EventsFile)))
	rep, err := ReleaseAdoption(context.Background(), f.state, s.RunID, "tego adopt --release", nil)
	if err != nil || !rep.Again || rep.Orphan == nil || !rep.Orphan.Removed || rep.Orphan.Ended {
		t.Fatalf("ReleaseAdoption = %+v, %v", rep, err)
	}
	if got := f.host.in(adoptSession); !slices.Contains(got, 200) || !slices.Contains(got, 201) {
		t.Fatalf("the left processes were not released: the session holds %v", got)
	}
	if ents := recordsLeft(f.state); len(ents) != 0 {
		t.Errorf("left in the records: %v", ents)
	}
	if n := len(readFile(t, filepath.Join(s.Dir, ledger.EventsFile))); n != lines {
		t.Errorf("the ended run's ledger changed: %d bytes, was %d", n, lines)
	}
}

// TestReleaseRequestToALiveAdopterThatLeftProcesses: a live adopter (the guard; this test process here) answers a
// release request, but no cgroup takes its tree back, so the processes stay in the scope and the record stays, marked
// released. The request used to wait for the record to go, which it never does: 30 s, then a failure that did not
// happen, with the request left behind. The released record is the answer: the release says at once that the run
// ended with processes left, and removes the request.
func TestReleaseRequestToALiveAdopterThatLeftProcesses(t *testing.T) {
	f := newAdoptFixture(t)
	prevEnv, prevWait := adoptReleaseEnv, releaseWait
	adoptReleaseEnv = func() adopt.Env { return f.host.env() }
	releaseWait = 5 * time.Second
	t.Cleanup(func() { adoptReleaseEnv, releaseWait = prevEnv, prevWait })
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	if err := os.RemoveAll(filepath.Join(f.host.mount, "user.slice")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rep, err := ReleaseAdoption(context.Background(), f.state, s.RunID, "tego stop (pid 1)", nil)
	took := time.Since(start)
	if res := waitResult(t, done); res.Reason != record.RunEndStopped {
		t.Fatalf("result %+v", res)
	}
	if err == nil || !strings.Contains(err.Error(), "2 process(es) stay in") || rep.Adopter != os.Getpid() || rep.Left != 2 {
		t.Fatalf("ReleaseAdoption = %+v, %v; want the adopter's answer with 2 processes left, said as an error", rep, err)
	}
	if took >= releaseWait {
		t.Errorf("the release waited %s, its whole bound: the released record was not read as the answer", took)
	}
	if _, err := os.Stat(filepath.Join(f.state, s.RunID+releaseSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the answered release request was left behind: %v", err)
	}
	rec, err := (&adoptStore{dir: f.state}).read(s.RunID)
	if err != nil || !rec.Released || rec.Left != 2 || rec.Unstarted {
		t.Fatalf("the record %+v, %v; want it kept, released, 2 left, the run started", rec, err)
	}
}

// TestAdoptKeepsTheRecordWhenAFailedMigrationCheckLeavesProcesses: a failure after the move and before run_start
// (the keyed-path check here) releases the tree; when the cgroup it came from is gone by then (a session scope systemd removed once the tree
// left it) and none above takes it, its processes stay in the scope. The record used to go anyway, with the run
// directory: nothing could release them, and the guard refused them as governed for ever. The record now stays,
// marked released and unstarted, the error says what stays, and a later release moves them out with no run to end.
func TestAdoptKeepsTheRecordWhenAFailedMigrationCheckLeavesProcesses(t *testing.T) {
	f := newAdoptFixture(t)
	prevEnv := adoptReleaseEnv
	adoptReleaseEnv = func() adopt.Env { return f.host.env() }
	t.Cleanup(func() { adoptReleaseEnv = prevEnv })
	records := filepath.Join(t.TempDir(), ".tego")
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(records, &st); err != nil {
		t.Fatal(err)
	}
	dev := uint64(st.Dev) //nolint:unconvert // Dev differs on other architectures
	f.backend.plane = record.DecisionPlaneFmodRet
	f.backend.keyed = []enforce.PlaneKeyed{{Path: records, Dev: dev, Ino: st.Ino}}
	f.backend.keyedOK = true
	spec := f.spec(t)
	spec.Boundary = true
	spec.Keyed = []AdoptKeyed{{Path: records, ID: adopt.FileID{Dev: dev, Ino: st.Ino}, What: "records"}}
	f.host.onAdd = func(pid int) {
		if pid == 201 { // the last of the tree leaves the session, which ends
			_ = os.RemoveAll(filepath.Join(f.host.mount, "user.slice"))
			_ = os.Rename(records, records+".old")
		}
	}
	_, err := Adopt(context.Background(), f.rt, spec, f.deps)
	f.host.onAdd = nil
	if !errors.Is(err, ErrAdoptLeftInScope) || !strings.Contains(err.Error(), "was removed") ||
		!strings.Contains(err.Error(), "2 process(es) stay in") {
		t.Fatalf("Adopt = %v; want the cause and that 2 processes stay in the scope", err)
	}
	run, err := AdoptionOf(f.host, f.state, 200)
	if err != nil {
		t.Fatalf("AdoptionOf(200): %v", err)
	}
	store := &adoptStore{dir: f.state}
	rec, err := store.read(run)
	if err != nil || !rec.Released || !rec.Unstarted || rec.Left != 2 {
		t.Fatalf("the record %+v, %v; want it kept, released and unstarted, 2 left", rec, err)
	}
	if left := leftBehind(t, filepath.Join(f.root, "runs")); len(left) != 0 {
		t.Errorf("a run that never started left %v", left)
	}
	if err := os.MkdirAll(filepath.Join(f.host.mount, adoptSession), 0o755); err != nil {
		t.Fatal(err)
	}
	rep, err := ReleaseAdoption(context.Background(), f.state, run, "tego adopt --release", nil)
	if err != nil || !rep.Again || !rep.Unstarted || rep.Orphan == nil || !rep.Orphan.Removed || rep.Orphan.Ended {
		t.Fatalf("ReleaseAdoption = %+v, %v; want the processes moved out, nothing ended", rep, err)
	}
	if got := f.host.in(adoptSession); !slices.Contains(got, 200) || !slices.Contains(got, 201) {
		t.Fatalf("the session holds %v", got)
	}
	if ents := recordsLeft(f.state); len(ents) != 0 {
		t.Errorf("left in the records: %v", ents)
	}
}

// TestAdoptionOfReadsOnlyTheAdoptionsOwnScope: `tego adopt --release --pid` names a process, and AdoptionOf names the
// adoption it is in. It used to take the run id of any cgroup component adopt-<id>.scope, so a process its user had
// put in a cgroup of that name in their own delegated subtree (another adoption's run id is readable by anyone in
// /proc/<pid>/cgroup) made root release another user's adoption. Only the scope's own place counts, and only when the
// run's record names that scope.
func TestAdoptionOfReadsOnlyTheAdoptionsOwnScope(t *testing.T) {
	f := newAdoptFixture(t)
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	defer func() {
		f.host.end(f.host.rel(s.Scope))
		waitResult(t, done)
	}()
	if run, err := AdoptionOf(f.host, f.state, 200); err != nil || run != s.RunID {
		t.Fatalf("AdoptionOf(the adopted agent) = %q, %v", run, err)
	}
	for pid, cg := range map[int]string{
		500: "/user.slice/user-1001.slice/user@1001.service/app.slice/" + adopt.ScopeName(s.RunID),
		501: "/tego.slice/tego-other.slice/" + adopt.ScopeName(s.RunID), // the shape, but not the record's scope
		502: f.host.rel(s.Scope) + "/sub",
	} {
		if err := os.MkdirAll(filepath.Join(f.host.mount, cg), 0o755); err != nil {
			t.Fatal(err)
		}
		f.host.add(pid, 1, cg, "/usr/bin/sleep")
		if run, err := AdoptionOf(f.host, f.state, pid); !errors.Is(err, ErrNotAdopted) {
			t.Errorf("AdoptionOf(pid %d in %s) = %q, %v; want ErrNotAdopted", pid, cg, run, err)
		}
	}
}

// leaderExitedHost is the fake host with process pid's leader exited while its thread tid runs on (pthread_exit in
// main): the leader stats as a zombie counting two tasks and stays in leaderCg, where it died; the thread runs the
// process's program in the cgroup the host gives pid.
type leaderExitedHost struct {
	*adoptHost
	pid, tid int
	leaderCg string
}

func (h leaderExitedHost) Stat(pid int) (proc.Stat, error) {
	if pid == h.tid {
		st, err := h.adoptHost.Stat(h.pid)
		st.PID, st.StartTicks, st.NumThreads = h.tid, st.StartTicks+1, 2
		return st, err
	}
	st, err := h.adoptHost.Stat(pid)
	if pid == h.pid {
		st.State, st.NumThreads = 'Z', 2
	}
	return st, err
}

func (h leaderExitedHost) Tasks(pid int) ([]int, error) {
	if pid == h.pid {
		return []int{h.pid, h.tid}, nil
	}
	return h.adoptHost.Tasks(pid)
}

func (h leaderExitedHost) Status(pid int) (adopt.Status, error) {
	if pid == h.tid {
		return h.adoptHost.Status(h.pid)
	}
	return h.adoptHost.Status(pid)
}

func (h leaderExitedHost) Cgroup(pid int) (string, error) {
	switch pid {
	case h.pid:
		return h.leaderCg, nil
	case h.tid:
		return h.adoptHost.Cgroup(h.pid)
	}
	return h.adoptHost.Cgroup(pid)
}

// TestAdoptionOfAProcessWhoseLeaderExited: `tego adopt --release --pid` and `tego stop` name a process whose
// leader exited before the adoption. Its /proc/<pid>/cgroup is the exited leader's, which stayed in the source; the
// adoption holds its live threads, so AdoptionOf reads their cgroup and names the run.
func TestAdoptionOfAProcessWhoseLeaderExited(t *testing.T) {
	f := newAdoptFixture(t)
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	defer func() {
		f.host.end(f.host.rel(s.Scope))
		waitResult(t, done)
	}()
	h := leaderExitedHost{adoptHost: f.host, pid: 200, tid: 2001, leaderCg: adoptSession}
	if run, err := AdoptionOf(h, f.state, 200); err != nil || run != s.RunID {
		t.Errorf("AdoptionOf(a process whose leader exited, its thread in the scope) = %q, %v; want run %s", run, err,
			s.RunID)
	}
}

func TestAdoptArmsTheEmptyScopeBeforeAnyMove(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.onArm = func() {
		if len(f.host.moves) != 0 {
			t.Error("processes moved before the empty scope was armed")
		}
	}
	f.host.onAdd = func(int) {
		h := f.backend.handle
		if h == nil || h.attached != 1 || h.armed != 1 {
			t.Error("a process moved before enforcement was attached and armed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s, done := f.adoptRunning(t, ctx, f.spec(t))
	if s.Window <= 0 {
		t.Error("migration window was not measured")
	}
	cancel()
	waitResult(t, done)
}

func TestAdoptNeverMovesOnEnforcementFailure(t *testing.T) {
	for _, phase := range []string{"prepare", "attach", "arm", "plane", "no armer"} {
		t.Run(phase, func(t *testing.T) {
			f := newAdoptFixture(t)
			failure := errors.New(phase + " failed")
			spec := f.spec(t)
			switch phase {
			case "prepare":
				f.backend.prepareErr = failure
			case "attach":
				f.backend.attachErr = failure
			case "arm":
				f.backend.armErr = failure
			case "plane":
				spec.Boundary = true
				failure = ErrAdoptNoPlane
			case "no armer":
				f.backend.plane = record.DecisionPlaneFmodRet
				f.backend.noArmer = true
				spec.Boundary = true
				failure = ErrAdoptDeps
			}
			_, err := Adopt(context.Background(), f.rt, spec, f.deps)
			if !errors.Is(err, failure) {
				t.Fatalf("Adopt: %v; want %v", err, failure)
			}
			if len(f.host.moves) != 0 {
				t.Fatalf("enforcement failed but processes moved: %v", f.host.moves)
			}
		})
	}
}

func TestAdoptUnwindsAFailedPrepare(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.prepareErr = errors.New("no build")
	spec := f.spec(t)
	res, err := Adopt(context.Background(), f.rt, spec, f.deps)
	if err == nil || res.ExitCode != 125 {
		t.Fatalf("Adopt = %+v, %v; want exit 125 and the error", res, err)
	}
	if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 300}) {
		t.Fatalf("a failed adoption left %v in the session: the moved tree must go back", got)
	}
	if left := leftBehind(t, filepath.Join(f.root, "runs")); len(left) != 0 {
		t.Errorf("a run that never started left %v", left)
	}
	if ents := recordsLeft(f.state); len(ents) != 0 {
		t.Errorf("records left: %v", ents)
	}
	if f.cgroups.removed != 1 || f.cgroups.kill != 0 {
		t.Errorf("removed %d killed %d", f.cgroups.removed, f.cgroups.kill)
	}
}

func TestAdoptRefusesAProcessAnotherAdopterHolds(t *testing.T) {
	f := newAdoptFixture(t)
	spec := f.spec(t)
	store, err := openAdoptStore(f.state)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.claim(spec.Root.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer store.unclaim(lock, spec.Root.Identity)
	if _, err := Adopt(context.Background(), f.rt, spec, f.deps); !errors.Is(err, ErrAlreadyAdopting) {
		t.Fatalf("Adopt = %v, want ErrAlreadyAdopting", err)
	}
	if len(f.host.moves) != 0 || f.cgroups.created != 0 {
		t.Fatalf("moves %v, scopes made %d: nothing may happen to a process another adoption holds", f.host.moves, f.cgroups.created)
	}
}

func TestAdoptBoundaryNeedsThePlane(t *testing.T) {
	f := newAdoptFixture(t)
	spec := f.spec(t)
	spec.Boundary = true
	if _, err := Adopt(context.Background(), f.rt, spec, f.deps); !errors.Is(err, ErrAdoptNoPlane) {
		t.Fatalf("Adopt = %v, want ErrAdoptNoPlane", err)
	}
	if f.backend.handle == nil || f.backend.handle.armed != 0 {
		t.Fatal("a boundary adoption with no plane was armed")
	}
	if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 300}) {
		t.Fatalf("after the refusal the session holds %v", got)
	}
}

func TestAdoptBoundaryNamesThePlaneAndItsRows(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.plane = record.DecisionPlaneFmodRet
	spec := f.spec(t)
	spec.Boundary = true
	// The agent holds a socket and a file open for writing outside every write entry: neither is governed after
	// the adoption, and the ledger says so.
	// What no path names is the kernel's to say (adopt.FD.NoPath: the file's device is one of the kernel-internal
	// superblocks tego probed), never the name's: a memfd is not across a rule, and a file the agent named /SYSVfake
	// on a mounted filesystem is.
	f.host.procs[200].fds = []adopt.FD{{Num: 3, Target: "socket:[7]"}, {Num: 4, Target: "/home/u/notes", Flags: 0o2},
		{Num: 5, Target: "/home/u/project/a", Flags: 0o2}, {Num: 1, Target: "/dev/pts/1", Flags: 0o2},
		{Num: 6, Target: "/home/u/project/.git/config", Flags: 0o2}, {Num: 7, Target: "/dev/shm/x", Flags: 0o2},
		{Num: 8, Target: "/dev/null", Flags: 0o1}, {Num: 9, Target: "/memfd:jit (deleted)", Flags: 0o2, NoPath: true},
		{Num: 10, Target: "/SYSVfake", Flags: 0o2}}
	// Its child holds mappings, whose descriptors it closed: loads and stores through a mapping pass no hook, so a
	// shared writable one outside every write entry, and any one under deny_read, are held across a rule too. The
	// kernel-internal ones (a System V segment, the AIO ring, hugetlb memory) are on mounts no path reaches.
	f.host.procs[201].maps = []adopt.Mapping{{Path: "/home/u/db", SharedWritable: true}, {Path: "/usr/lib/libc.so.6"},
		{Path: "/home/u/project/b", SharedWritable: true}, {Path: "/home/u/.ssh/id_ed25519"},
		{Path: "/home/u/project/.git/hooks/pre-commit", SharedWritable: true},
		{Path: "/SYSV00000001", SharedWritable: true, NoPath: true}, {Path: "/[aio]", SharedWritable: true, NoPath: true},
		{Path: "/anon_hugepage", SharedWritable: true, NoPath: true}, {Path: "/dev/zero", SharedWritable: true, NoPath: true}}
	f.rt.FS = []agent.FSRule{{Path: "/home/u/project", Kind: agent.FSWrite, Raw: "./"},
		{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, Raw: "~/.ssh"}}
	// The built-in deny_write targets beneath the write entry: the plane refuses a fresh write-open of either.
	f.rt.DenyWrite = []agent.FSRule{{Path: "/home/u/project/.git/config", Kind: agent.FSDenyWrite, BuiltIn: true},
		{Path: "/home/u/project/.git/hooks", Kind: agent.FSDenyWrite, BuiltIn: true}}
	// The boundary's file, as the caller resolved it (agent-contract.md R26), is on run_start.
	f.deps.ContractSource = &record.ContractSource{Path: "/home/u/.config/tego/agents/coder.yaml", Name: "coder", Registry: "user"}
	s, done := f.adoptRunning(t, context.Background(), spec)
	if s.DecisionPlane != record.DecisionPlaneFmodRet || f.rec.plane != record.DecisionPlaneFmodRet {
		t.Errorf("plane %q, recorder told %q", s.DecisionPlane, f.rec.plane)
	}
	f.host.end(f.host.rel(s.Scope))
	waitResult(t, done)
	var start record.RunStartPayload
	gaps := map[string]record.GapPayload{}
	for _, ev := range events(t, s.Dir) {
		switch ev.Kind {
		case record.KindRunStart:
			_ = ev.DecodePayload(&start)
		case record.KindGap:
			var g record.GapPayload
			_ = ev.DecodePayload(&g)
			gaps[g.Why] = g
		}
	}
	if start.ContractSource == nil || *start.ContractSource != *f.deps.ContractSource {
		t.Errorf("run_start contract_source %+v, want %+v", start.ContractSource, f.deps.ContractSource)
	}
	if start.DecisionPlane != record.DecisionPlaneFmodRet || !start.Capabilities[string(backend.CapFileWriteDeny)] ||
		start.Capabilities[string(backend.CapNetHostDeny)] || start.Capabilities[string(backend.CapAsk)] {
		t.Errorf("run_start plane %q capabilities %v", start.DecisionPlane, start.Capabilities)
	}
	// The plane holds the built-in targets as it holds fs.deny_write, so the protected-write-targets row and
	// best_effort's deny_write/default read the same decision_plane: the row true, the cell absent (CAPABILITIES R23, a
	// target held open across the adoption is the open-files gap below).
	if !start.Capabilities[string(backend.CapProtectedWriteTargets)] || slices.Contains(start.BestEffort, agent.BestEffortDenyWrite) {
		t.Errorf("run_start under plane %q: fs.protected_write_targets %v, best_effort %v; want the row true and no %s",
			start.DecisionPlane, start.Capabilities[string(backend.CapProtectedWriteTargets)], start.BestEffort, agent.BestEffortDenyWrite)
	}
	if g := gaps[GapAdoptionOpenSockets]; g.Count != 1 {
		t.Errorf("open sockets gap %+v", g)
	}
	if g := gaps[GapAdoptionOpenFiles]; g.Count != 7 || g.What != record.GapEnforce {
		t.Errorf("open files gap %+v, want 7 (the notes file, the repository's config held for writing and its hook "+
			"mapped shared writable, deny_write targets beneath the write entry; /dev/shm/x and /SYSVfake held for "+
			"writing; the shared db mapping, the mapped key; the workspace file and mapping, the library, the terminal, "+
			"/dev/null, and the files on a kernel-internal superblock tego probed (a memfd, a System V segment, the "+
			"AIO ring, hugetlb and shared anonymous memory), which no path names, are not across a rule)", g)
	}
	if g, ok := gaps[GapAdoptionUnread]; ok {
		t.Errorf("an unread-descriptors gap %+v where every listing was read whole", g)
	}
	// What only tier 1's seccomp filter refuses (System V IPC, the socket families outside the net rules) is not held
	// on an adopted process, and the ledger says so.
	if g, ok := gaps[GapAdoptionNoFilter]; !ok || g.What != record.GapEnforce {
		t.Errorf("no-syscall-filter gap %+v (present %v), want what=enforce", g, ok)
	}
}

// TestAdoptAsksTheRowsByTheKeyedInode: the plane keys a file entry's row on the inode the fill found at its path
// (enforce.PlaneKeyedReporter), so it decides that inode under every name: a hard link of ~/.netrc the agent made in
// its workspace, or ~/.netrc renamed since the fill, held by a descriptor or a mapping, is a file held across the
// deny_read rule though no rule names the name /proc gives it. A file of the workspace
// at another inode is not; nor is one whose inode could not be read, which is asked by its name alone.
func TestAdoptAsksTheRowsByTheKeyedInode(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.plane = record.DecisionPlaneFmodRet
	f.backend.keyed = []enforce.PlaneKeyed{{Path: "/home/u/.netrc", Dev: 7, Ino: 9}, {Path: "/home/u/project", Dev: 7, Ino: 2}}
	f.backend.keyedOK = true
	netrc := adopt.FileID{Dev: 7, Ino: 9}
	f.host.procs[200].fds = []adopt.FD{{Num: 4, Target: "/home/u/project/n", ID: netrc},
		{Num: 5, Target: "/home/u/project/plain", ID: adopt.FileID{Dev: 7, Ino: 10}},
		{Num: 6, Target: "/home/u/project/unread"}}
	f.host.procs[201].maps = []adopt.Mapping{{Path: "/home/u/moved", IDs: []adopt.FileID{netrc}},
		{Path: "/home/u/project/lib.so", IDs: []adopt.FileID{{Dev: 7, Ino: 11}}}}
	f.rt.FS = []agent.FSRule{{Path: "/home/u/project", Kind: agent.FSWrite, Raw: "./"},
		{Path: "/home/u/.netrc", Kind: agent.FSDenyRead, Raw: "~/.netrc"}}
	spec := f.spec(t)
	spec.Boundary = true
	s, done := f.adoptRunning(t, context.Background(), spec)
	f.host.end(f.host.rel(s.Scope))
	waitResult(t, done)
	gaps := map[string]record.GapPayload{}
	for _, ev := range events(t, s.Dir) {
		var g record.GapPayload
		if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil {
			gaps[g.Why] = g
		}
	}
	if g := gaps[GapAdoptionOpenFiles]; g.Count != 2 {
		t.Errorf("open files gap %+v, want 2 (the link held by a descriptor, the renamed key mapped)", g)
	}
	if g, ok := gaps[GapAdoptionUnread]; ok {
		t.Errorf("an unread gap %+v where every listing was read whole", g)
	}
}

// TestAdoptAsksTheRowsByEachKeyedDirectoryAboveTheName: the plane's walk looks each directory above the object up by
// its inode (bpf/decide.bpf.c tego_walk_step), so a deny_read directory renamed after the fill (the agent runs
// unconfined until the move) still refuses a read of every file in it under its new name. The count asks the rows, for
// each directory a held file's name passes through that a row is keyed at, by the file's path under that row's path:
// a file held in the renamed directory, by a descriptor or a mapping, is across the rule, and so is a deny_read file
// beneath a renamed write entry, which the row's own path would not be; one in a directory no row keys, and a file the
// renamed write entry grants, are not.
func TestAdoptAsksTheRowsByEachKeyedDirectoryAboveTheName(t *testing.T) {
	dir := t.TempDir()
	records, moved, plain := filepath.Join(dir, "records"), filepath.Join(dir, "moved"), filepath.Join(dir, "plain")
	proj, proj2 := filepath.Join(dir, "proj"), filepath.Join(dir, "proj2")
	for _, d := range []string{filepath.Join(moved, "runs"), plain, proj2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	idOf := func(p string) (uint64, uint64) {
		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		return uint64(st.Dev), st.Ino //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
	}
	f := newAdoptFixture(t)
	f.backend.plane = record.DecisionPlaneFmodRet
	// The row for records was written at the directory now named moved, and the row for proj, a write entry with a
	// deny_read file in it, at the one now named proj2: both renamed after the fill.
	recDev, recIno := idOf(moved)
	projDev, projIno := idOf(proj2)
	f.backend.keyed = []enforce.PlaneKeyed{{Path: records, Dev: recDev, Ino: recIno}, {Path: proj, Dev: projDev, Ino: projIno}}
	f.backend.keyedOK = true
	f.host.procs[200].fds = []adopt.FD{{Num: 4, Target: filepath.Join(moved, "runs", "events.jsonl")},
		{Num: 5, Target: filepath.Join(plain, "f")}, {Num: 6, Target: filepath.Join(proj2, "secret")},
		{Num: 7, Target: filepath.Join(proj2, "notes")}}
	f.host.procs[201].maps = []adopt.Mapping{{Path: filepath.Join(moved, "blob")}, {Path: filepath.Join(plain, "lib.so")}}
	f.rt.FS = []agent.FSRule{{Path: dir, Kind: agent.FSWrite, Raw: "./"}, {Path: records, Kind: agent.FSDenyRead, Raw: "./records"},
		{Path: proj, Kind: agent.FSWrite, Raw: "./proj"}, {Path: filepath.Join(proj, "secret"), Kind: agent.FSDenyRead, Raw: "./proj/secret"}}
	spec := f.spec(t)
	spec.Boundary = true
	s, done := f.adoptRunning(t, context.Background(), spec)
	f.host.end(f.host.rel(s.Scope))
	waitResult(t, done)
	gaps := map[string]record.GapPayload{}
	for _, ev := range events(t, s.Dir) {
		var g record.GapPayload
		if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil {
			gaps[g.Why] = g
		}
	}
	if g := gaps[GapAdoptionOpenFiles]; g.Count != 3 {
		t.Errorf("open files gap %+v, want 3 (a file of the renamed deny_read directory held, one mapped, and the "+
			"deny_read file of the renamed write entry, asked by its path beneath the row's)", g)
	}
	if g, ok := gaps[GapAdoptionUnread]; ok {
		t.Errorf("an unread gap %+v where every listing was read whole", g)
	}
}

// TestAdoptCountsARingItCannotReadUnread: a file registered with an io_uring instance is read and written through the
// ring with no descriptor or mapping /proc lists, so a process holding a ring with a
// table of registered files (or whose table its fdinfo would not show) is counted in adoption-descriptors-unread,
// record-only or boundary; and, for a boundary, so is one that maps a ring it holds no descriptor of (registered with
// itself and closed). A ring with no registered files, mapped and held, is not.
func TestAdoptCountsARingItCannotReadUnread(t *testing.T) {
	ring := adopt.FileID{Dev: 15, Ino: 2077}
	for _, c := range []struct {
		name     string
		boundary bool
		fds      []adopt.FD
		maps     []adopt.Mapping
		unread   int
	}{
		{"record-only, a registered file", false, []adopt.FD{{Num: 3, Target: adopt.RingTarget, Ring: true, RegisteredFiles: true, ID: ring}}, nil, 1},
		{"boundary, a registered file", true, []adopt.FD{{Num: 3, Target: adopt.RingTarget, Ring: true, RegisteredFiles: true, ID: ring}},
			[]adopt.Mapping{{Path: adopt.RingTarget, Ring: true, IDs: []adopt.FileID{ring}}}, 1},
		{"boundary, a ring mapped with no descriptor", true, nil,
			[]adopt.Mapping{{Path: adopt.RingTarget, Ring: true, IDs: []adopt.FileID{ring}}}, 1},
		{"boundary, another ring's descriptor", true, []adopt.FD{{Num: 3, Target: adopt.RingTarget, Ring: true, ID: adopt.FileID{Dev: 15, Ino: 2078}}},
			[]adopt.Mapping{{Path: adopt.RingTarget, Ring: true, IDs: []adopt.FileID{ring}}}, 1},
		{"boundary, a ring held and mapped, nothing registered", true, []adopt.FD{{Num: 3, Target: adopt.RingTarget, Ring: true, ID: ring}},
			[]adopt.Mapping{{Path: adopt.RingTarget, Ring: true, IDs: []adopt.FileID{ring}}}, 0},
		// A ring on the kernel's shared anonymous inode has no ID (adopt.FS.unidentifySharedRings): its mapping could
		// be another ring's, which no descriptor holds.
		{"boundary, a ring with no identity, held and mapped", true, []adopt.FD{{Num: 3, Target: adopt.RingTarget, Ring: true}},
			[]adopt.Mapping{{Path: adopt.RingTarget, Ring: true, IDs: []adopt.FileID{ring}}}, 1},
		{"record-only, a ring with nothing registered", false, []adopt.FD{{Num: 3, Target: adopt.RingTarget, Ring: true, ID: ring}}, nil, 0},
	} {
		f := newAdoptFixture(t)
		f.backend.plane = record.DecisionPlaneFmodRet
		f.host.procs[200].fds = c.fds
		f.host.procs[200].maps = c.maps
		spec := f.spec(t)
		spec.Boundary = c.boundary
		s, done := f.adoptRunning(t, context.Background(), spec)
		f.host.end(f.host.rel(s.Scope))
		waitResult(t, done)
		got := 0
		for _, ev := range events(t, s.Dir) {
			var g record.GapPayload
			if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil && g.Why == GapAdoptionUnread {
				got = int(g.Count)
			}
		}
		if got != c.unread {
			t.Errorf("%s: unread %d, want %d", c.name, got, c.unread)
		}
	}
}

// TestAdoptRefusesABoundaryWhoseRequiredRowIsElsewhere: a boundary requires the plane's row for the agent owner's
// ~/.tego at the directory its table was compiled against (AdoptSpec.Keyed). The agent runs unconfined until the
// move, so it can remove or replace the directory before Prepare keys it: a row at
// another inode, no row at that path, or a tier that cannot say, fails the adoption before the attach, named, and
// no process moves. It can also do so after the fill and before the move, when the row stays on the directory it
// keyed while the path names another or nothing, and the owner's next run would write its records where no row is:
// from migration on the plane refuses a rename, removal or
// replacement of the keyed directory, so the path is checked after migration too, and one that no longer leads to it fails the
// adoption, named, with the tree given back. The row and the path at the directory compiled against run.
func TestAdoptRefusesABoundaryWhoseRequiredRowIsElsewhere(t *testing.T) {
	// replace and remove stand in for the agent, between the fill and the move.
	replace := func(t *testing.T, records string) {
		if err := os.Rename(records, records+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(records, 0o700); err != nil {
			t.Error(err)
		}
	}
	remove := func(t *testing.T, records string) {
		if err := os.Rename(records, records+".old"); err != nil {
			t.Error(err)
		}
	}
	// relink keeps the keyed directory and puts a link to it at the name: the path, followed, still leads to the keyed
	// inode, but the link itself is under no row, so under a write entry over the home the agent could replace it with
	// a fresh directory once armed.
	relink := func(t *testing.T, records string) {
		if err := os.Rename(records, records+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(records+".old", records); err != nil {
			t.Error(err)
		}
	}
	held := func(path string, id adopt.FileID) []enforce.PlaneKeyed {
		return []enforce.PlaneKeyed{{Path: path, Dev: id.Dev, Ino: id.Ino}}
	}
	for _, c := range []struct {
		name    string
		keyed   func(path string, id adopt.FileID) []enforce.PlaneKeyed
		keyedOK bool
		onMove  func(t *testing.T, records string)
		refused string
		// armed says the refusal comes after the arm (the path's check), the tree given back all the same.
		armed bool
	}{
		{"replaced", func(path string, id adopt.FileID) []enforce.PlaneKeyed {
			return []enforce.PlaneKeyed{{Path: path, Dev: id.Dev, Ino: id.Ino + 1}}
		}, true, nil, "was replaced", false},
		{"gone", func(string, adopt.FileID) []enforce.PlaneKeyed {
			return []enforce.PlaneKeyed{{Path: "/home/u/project", Dev: 7, Ino: 2}}
		}, true, nil, "is gone", false},
		{"a tier that cannot say", func(string, adopt.FileID) []enforce.PlaneKeyed { return nil }, false, nil, "cannot say", false},
		{"replaced after the fill", held, true, replace, "replaced after", true},
		{"removed after the fill", held, true, remove, "removed after", true},
		{"a link put at the name after the fill", held, true, relink, "is no directory", true},
		{"held", held, true, nil, "", false},
	} {
		records := filepath.Join(t.TempDir(), ".tego")
		if err := os.Mkdir(records, 0o700); err != nil {
			t.Fatal(err)
		}
		var st syscall.Stat_t
		if err := syscall.Stat(records, &st); err != nil {
			t.Fatal(err)
		}
		dev := uint64(st.Dev) //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
		id := adopt.FileID{Dev: unix.Mkdev(unix.Major(dev), unix.Minor(dev)), Ino: st.Ino}
		want := AdoptKeyed{Path: records, Name: records, ID: id, What: "the agent owner's own tego records"}
		f := newAdoptFixture(t)
		f.backend.plane = record.DecisionPlaneFmodRet
		f.backend.keyed, f.backend.keyedOK = c.keyed(records, id), c.keyedOK
		if c.onMove != nil {
			changed := false
			f.host.onAdd = func(pid int) {
				if pid == 200 && !changed {
					changed = true
					c.onMove(t, records)
				}
			}
		}
		spec := f.spec(t)
		spec.Boundary = true
		spec.Keyed = []AdoptKeyed{want}
		if c.refused == "" {
			s, done := f.adoptRunning(t, context.Background(), spec)
			f.host.end(f.host.rel(s.Scope))
			waitResult(t, done)
			continue
		}
		// Bounded: an adoption that is not refused runs until the context ends, which then releases it.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := Adopt(ctx, f.rt, spec, f.deps)
		cancel()
		if !errors.Is(err, ErrAdoptUnkeyed) || !strings.Contains(err.Error(), c.refused) || !strings.Contains(err.Error(), want.Path) {
			t.Errorf("%s: Adopt = %v, want ErrAdoptUnkeyed saying %q and naming %s", c.name, err, c.refused, want.Path)
		}
		h := f.backend.handle
		switch {
		case h == nil:
			t.Errorf("%s: no handle", c.name)
		case !c.armed && (h.attached != 0 || h.armed != 0):
			t.Errorf("%s: the boundary was attached or armed with its deny elsewhere", c.name)
		case c.armed && h.closed == 0:
			t.Errorf("%s: the refused boundary's handle was not closed", c.name)
		}
		if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 300}) {
			t.Errorf("%s: after the refusal the session holds %v, want the tree given back", c.name, got)
		}
	}
}

// TestAdoptSaysWhatItCouldNotRead: a process whose descriptors or mappings could not all be read (a listing past its
// cap) is counted in a gap of its own, never taken as holding only what was read; a process that exited meanwhile is
// not.
func TestAdoptSaysWhatItCouldNotRead(t *testing.T) {
	for _, boundary := range []bool{false, true} {
		f := newAdoptFixture(t)
		f.backend.plane = record.DecisionPlaneFmodRet
		spec := f.spec(t)
		spec.Boundary = boundary
		f.host.procs[200].fdErr = fmt.Errorf("pid 200: %w", adopt.ErrTruncated)
		f.host.procs[201].mapsErr = fmt.Errorf("pid 201: %w", adopt.ErrTruncated)
		s, done := f.adoptRunning(t, context.Background(), spec)
		f.host.end(f.host.rel(s.Scope))
		waitResult(t, done)
		var got *record.GapPayload
		for _, ev := range events(t, s.Dir) {
			var g record.GapPayload
			if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil && g.Why == GapAdoptionUnread {
				got = &g
			}
		}
		want, what := 1, record.GapRecord // a record-only adoption reads no mappings
		if boundary {
			want, what = 2, record.GapEnforce
		}
		if got == nil || got.Count != want || got.What != what {
			t.Errorf("boundary %v: unread gap %+v, want count %d what %s", boundary, got, want, what)
		}
	}
}

// TestAdoptCountsADescriptorItCannotNameUnread: a descriptor /proc cannot name (adopt.FD.Unread: a file open at a path
// longer than PATH_MAX, whose link readlink refuses, or one whose fdinfo cannot be read) may be a file held across a
// rule, or a socket, so its process is counted unread, record-only or boundary, never taken as holding only the rest.
func TestAdoptCountsADescriptorItCannotNameUnread(t *testing.T) {
	for _, boundary := range []bool{false, true} {
		f := newAdoptFixture(t)
		f.backend.plane = record.DecisionPlaneFmodRet
		f.host.procs[200].fds = []adopt.FD{{Num: 3, Unread: true}, {Num: 4, Target: "socket:[9]"}}
		spec := f.spec(t)
		spec.Boundary = boundary
		s, done := f.adoptRunning(t, context.Background(), spec)
		f.host.end(f.host.rel(s.Scope))
		waitResult(t, done)
		gaps := map[string]record.GapPayload{}
		for _, ev := range events(t, s.Dir) {
			var g record.GapPayload
			if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil {
				gaps[g.Why] = g
			}
		}
		what := record.GapRecord
		if boundary {
			what = record.GapEnforce
		}
		if g := gaps[GapAdoptionUnread]; g.Count != 1 || g.What != what {
			t.Errorf("boundary %v: unread gap %+v, want count 1 what=%s (pid 200's unnamed descriptor)", boundary, g, what)
		}
		if g := gaps[GapAdoptionOpenSockets]; g.Count != 1 {
			t.Errorf("boundary %v: open sockets gap %+v, want 1", boundary, g)
		}
	}
}

// TestAdoptCountsAProcessInAnotherMountNamespaceUnread: what /proc names of the files of a process in a mount
// namespace other than tego's is no path of tego's namespace, so a boundary adoption does not take those names for
// the files held across a rule: the process is counted in adoption-descriptors-unread, its sockets still counted. A
// record-only adoption counts no files, so the namespace changes nothing there.
func TestAdoptCountsAProcessInAnotherMountNamespaceUnread(t *testing.T) {
	for _, boundary := range []bool{false, true} {
		f := newAdoptFixture(t)
		f.backend.plane = record.DecisionPlaneFmodRet
		f.host.procs[201].mntns = 2
		f.host.procs[201].fds = []adopt.FD{{Num: 3, Target: "socket:[9]"}, {Num: 4, Target: "/home/u/notes", Flags: 0o2}}
		f.host.procs[201].maps = []adopt.Mapping{{Path: "/home/u/db", SharedWritable: true}}
		f.host.procs[200].fds = []adopt.FD{{Num: 4, Target: "/home/u/other", Flags: 0o2}}
		f.rt.FS = []agent.FSRule{{Path: "/home/u/project", Kind: agent.FSWrite, Raw: "./"}}
		spec := f.spec(t)
		spec.Boundary = boundary
		s, done := f.adoptRunning(t, context.Background(), spec)
		f.host.end(f.host.rel(s.Scope))
		waitResult(t, done)
		gaps := map[string]record.GapPayload{}
		for _, ev := range events(t, s.Dir) {
			var g record.GapPayload
			if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil {
				gaps[g.Why] = g
			}
		}
		if g := gaps[GapAdoptionOpenSockets]; g.Count != 1 {
			t.Errorf("boundary %v: open sockets gap %+v, want 1 (a socket is no path)", boundary, g)
		}
		if !boundary {
			if g, ok := gaps[GapAdoptionUnread]; ok {
				t.Errorf("record-only: an unread gap %+v; it counts no files, so the namespace changes nothing", g)
			}
			continue
		}
		if g := gaps[GapAdoptionOpenFiles]; g.Count != 1 {
			t.Errorf("open files gap %+v, want 1 (pid 200's; pid 201's names are its own namespace's)", g)
		}
		if g := gaps[GapAdoptionUnread]; g.Count != 1 || g.What != record.GapEnforce {
			t.Errorf("unread gap %+v, want count 1 what=enforce (pid 201, in another mount namespace)", g)
		}
	}
}

// TestAdoptAsksTheRowsOnlyByNamesOfTheFile: a boundary adoption asks the rows about a held file by a name that is a
// path of it in tego's namespace, and by every other path that reaches it (adopt.FD.Aliases), never by one that is
// not (adopt.FD.Unnamed: /proc's name for a file held through a detached clone or a lazily unmounted bind of $HOME is
// "/.ssh/id_ed25519", which no rule names, while the plane refuses a read of the key through either). An unnamed file
// counts its process unread; a file named outside every rule but reached by an alias under deny_read is across a rule.
func TestAdoptAsksTheRowsOnlyByNamesOfTheFile(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.plane = record.DecisionPlaneFmodRet
	f.host.procs[200].fds = []adopt.FD{{Num: 4, Target: "/.ssh/id_ed25519", Unnamed: true},
		{Num: 5, Target: "/srv/bind/.ssh/config", Aliases: []string{"/home/u/.ssh/config"}},
		{Num: 6, Target: "/srv/bind/notes", Aliases: []string{"/home/u/notes"}}}
	f.host.procs[201].maps = []adopt.Mapping{{Path: "/.ssh/known_hosts", Unnamed: true},
		{Path: "/srv/bind/.ssh/id_rsa", Aliases: []string{"/home/u/.ssh/id_rsa"}}}
	f.rt.FS = []agent.FSRule{{Path: "/home/u/project", Kind: agent.FSWrite, Raw: "./"},
		{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, Raw: "~/.ssh"}}
	spec := f.spec(t)
	spec.Boundary = true
	s, done := f.adoptRunning(t, context.Background(), spec)
	f.host.end(f.host.rel(s.Scope))
	waitResult(t, done)
	gaps := map[string]record.GapPayload{}
	for _, ev := range events(t, s.Dir) {
		var g record.GapPayload
		if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil {
			gaps[g.Why] = g
		}
	}
	if g := gaps[GapAdoptionOpenFiles]; g.Count != 2 || g.What != record.GapEnforce {
		t.Errorf("open files gap %+v, want 2 (the config and the key, each reached under ~/.ssh by an alias; the notes "+
			"file is read-only and outside every deny_read by both names)", g)
	}
	if g := gaps[GapAdoptionUnread]; g.Count != 2 || g.What != record.GapEnforce {
		t.Errorf("unread gap %+v, want count 2 what=enforce (pid 200's descriptor and pid 201's mapping are named by "+
			"no path of tego's namespace)", g)
	}
}

func TestReleaseOrphanReleasesWhatADeadAdopterLeft(t *testing.T) {
	f := newAdoptFixture(t)
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	// The adopter is killed: nothing of its shutdown runs. What it leaves is the record, the moved tree, the run's
	// ledger with no run_end. A copy of the record is what the reaper reads.
	store := &adoptStore{dir: f.state}
	rec, err := store.read(s.RunID)
	if err != nil {
		t.Fatal(err)
	}
	f.host.end(f.host.rel(s.Scope)) // let the adopter itself end, then put the orphan's state back
	waitResult(t, done)
	if err := store.write(rec); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rec.Scope, 0o755); err != nil {
		t.Fatal(err)
	}
	f.host.add(200, 100, f.host.rel(rec.Scope), "/usr/bin/node")
	// The run's ledger was ended by the adopter above, which the release finds and leaves.
	out, err := releaseOrphan(store, rec, f.host.env(), -1, "the adopter died", nil)
	if err != nil {
		t.Fatalf("releaseOrphan: %v", err)
	}
	if out.Ended {
		t.Error("run_end written over an ended run")
	}
	if got := f.host.in(adoptSession); !slices.Contains(got, 200) {
		t.Fatalf("the agent was not released: the session holds %v", got)
	}
	if !out.Removed {
		t.Error("the scope was not removed")
	}
	if _, err := os.Stat(rec.Scope); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("scope %s still there: %v", rec.Scope, err)
	}
	if _, err := store.read(s.RunID); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record outlived the release: %v", err)
	}
}

func TestAdoptStoreIsRootsAlone(t *testing.T) {
	prev := adoptStateOwner
	adoptStateOwner = os.Geteuid()
	defer func() { adoptStateOwner = prev }()
	dir := filepath.Join(t.TempDir(), "adopted")
	s, err := openAdoptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	run := "r-0a1b2c3d-0123456789abc-xyz123"
	rec := adoptRecord{Run: run, Agent: "a", Scope: "/sys/fs/cgroup/tego.slice/tego-a.slice/" + adopt.ScopeName(run)}
	if err := s.write(rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.read(run)
	if err != nil || got.Scope != rec.Scope {
		t.Fatalf("read back %+v %v", got, err)
	}
	// A record naming another run's scope, or another run, is not acted on.
	bad := rec
	bad.Scope = "/sys/fs/cgroup/user.slice"
	if err := s.write(bad); err != nil {
		t.Fatal(err)
	}
	if _, err := s.read(run); err == nil {
		t.Error("a record naming a scope that is not the run's was read")
	}
	if _, err := s.read("../x"); err == nil {
		t.Error("a run id that is no run id named a record")
	}
	// A directory others can write is refused.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdoptStore(dir); err == nil {
		t.Error("a directory everyone can write was accepted")
	}
	_ = os.Chmod(dir, 0o700)
	// The lock is the process's identity: another start time is another process.
	a, err := s.claim(adopt.Identity{PID: 9, Start: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.claim(adopt.Identity{PID: 9, Start: 1}); !errors.Is(err, ErrAlreadyAdopting) {
		t.Errorf("second claim: %v", err)
	}
	b, err := s.claim(adopt.Identity{PID: 9, Start: 2})
	if err != nil {
		t.Errorf("a reused pid is another process: %v", err)
	}
	s.unclaim(a, adopt.Identity{PID: 9, Start: 1})
	s.unclaim(b, adopt.Identity{PID: 9, Start: 2})
	if c, err := s.claim(adopt.Identity{PID: 9, Start: 1}); err != nil {
		t.Errorf("a released lock cannot be taken again: %v", err)
	} else {
		s.unclaim(c, adopt.Identity{PID: 9, Start: 1})
	}
}

// runEnd decodes a run's run_end.
func runEnd(t *testing.T, dir string) record.RunEndPayload {
	t.Helper()
	evs := events(t, dir)
	var end record.RunEndPayload
	if len(evs) == 0 || evs[len(evs)-1].Kind != record.KindRunEnd {
		t.Fatalf("%s has no run_end", dir)
	}
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	return end
}

// TestReleaseAdoptionReleasesItsRunAlone: one adopter (the guard) holds two adoptions; a release of one (tego stop,
// tego adopt --release) is a request that adoption alone answers: its agent goes back and its run ends stopped,
// saying who asked, while the other adoption, and its adopter, run on.
func TestReleaseAdoptionReleasesItsRunAlone(t *testing.T) {
	f := newAdoptFixture(t)
	const other = "/user.slice/user-1000.slice/session-3.scope"
	if err := os.MkdirAll(filepath.Join(f.host.mount, other), 0o755); err != nil {
		t.Fatal(err)
	}
	f.host.add(400, 1, other, "/usr/bin/node")
	f.host.add(401, 400, other, "/usr/bin/git")
	s1, done1 := f.adoptRunning(t, context.Background(), f.spec(t))
	root2, err := adopt.Identify(f.host, 400)
	if err != nil {
		t.Fatal(err)
	}
	s2, done2 := f.adoptRunning(t, context.Background(), AdoptSpec{Root: root2, Env: f.host.env(), Recheck: admitAll})

	rep, err := ReleaseAdoption(context.Background(), f.state, s1.RunID, "tego stop (pid 1)", nil)
	if err != nil || rep.Adopter != os.Getpid() || rep.Orphan != nil {
		t.Fatalf("ReleaseAdoption = %+v, %v; want released by this adopter", rep, err)
	}
	if res := waitResult(t, done1); res.Reason != record.RunEndStopped || res.ExitCode != 0 {
		t.Fatalf("the released run: %+v", res)
	}
	if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 300}) {
		t.Errorf("after the release the session holds %v", got)
	}
	if end := runEnd(t, s1.Dir); !strings.Contains(end.Detail, "at the request of tego stop (pid 1)") ||
		!strings.Contains(end.Detail, "never killed") {
		t.Errorf("run_end %+v: it says who asked", end)
	}
	if _, err := os.Stat(filepath.Join(f.state, s1.RunID+releaseSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the request outlived its adoption: %v", err)
	}
	select {
	case res := <-done2:
		t.Fatalf("releasing one adoption ended another of the same adopter: %+v", res)
	case <-time.After(3 * releasePoll):
	}
	if got := f.host.in(f.host.rel(s2.Scope)); !slices.Equal(got, []int{400, 401}) {
		t.Fatalf("the other adoption's cgroup holds %v", got)
	}
	if _, err := ReleaseAdoption(context.Background(), f.state, s1.RunID, "again", nil); !errors.Is(err, ErrNotAdopted) {
		t.Errorf("a second release of an ended adoption: %v, want ErrNotAdopted", err)
	}
	f.host.end(f.host.rel(s2.Scope))
	if res := waitResult(t, done2); res.Reason != record.RunEndExit {
		t.Errorf("the other run: %+v", res)
	}
	if f.cgroups.kill != 0 {
		t.Fatal("a release killed")
	}
}

// TestAdoptEndsStoppedWhenRootMovesTheTreeOut: root moved every process of the adopted tree out of the run's cgroup by
// hand while the agent runs on. The run is over (nothing of the agent is recorded any more), and run_end says so,
// stopped: not exit, since the agent did not end.
func TestAdoptEndsStoppedWhenRootMovesTheTreeOut(t *testing.T) {
	f := newAdoptFixture(t)
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	f.host.mu.Lock()
	for _, pid := range []int{200, 201} {
		f.host.procs[pid].cgroup = adoptSession
	}
	f.host.mu.Unlock()
	if res := waitResult(t, done); res.Reason != record.RunEndStopped {
		t.Fatalf("result %+v, want reason stopped", res)
	}
	if end := runEnd(t, s.Dir); !strings.Contains(end.Detail, "left the run's cgroup without tego") {
		t.Errorf("run_end %+v", end)
	}
	if f.cgroups.kill != 0 || f.cgroups.removed != 1 {
		t.Errorf("killed %d removed %d", f.cgroups.kill, f.cgroups.removed)
	}
}

// TestReleaseAdoptionOfAnOrphanTakesTheLock: an adoption whose adopter is gone is released from its record, under the
// adopted process's lock: while a reaper holds the lock, `tego adopt --release` waits and, the reaper done, finds
// nothing left to do; with no reaper, it releases the agent itself.
func TestReleaseAdoptionOfAnOrphanTakesTheLock(t *testing.T) {
	f := newAdoptFixture(t)
	prevEnv := adoptReleaseEnv
	adoptReleaseEnv = func() adopt.Env { return f.host.env() }
	t.Cleanup(func() { adoptReleaseEnv = prevEnv })
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	store := &adoptStore{dir: f.state}
	rec, err := store.read(s.RunID)
	if err != nil {
		t.Fatal(err)
	}
	f.host.end(f.host.rel(s.Scope))
	waitResult(t, done)
	// What a dead adopter leaves: its record (naming an adopter that no longer exists), the scope, the agent in it.
	rec.Adopter = adopt.Identity{PID: os.Getpid(), Start: 1}
	orphan := func() {
		t.Helper()
		if err := store.write(rec); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(rec.Scope, 0o755); err != nil {
			t.Fatal(err)
		}
		f.host.add(200, 100, f.host.rel(rec.Scope), "/usr/bin/node")
	}
	orphan()

	// A reaper at work holds the lock.
	reaper, err := store.claim(rec.Root)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		rep ReleaseReport
		err error
	}
	got := make(chan result, 1)
	go func() {
		rep, err := ReleaseAdoption(context.Background(), f.state, s.RunID, "tego adopt --release", nil)
		got <- result{rep, err}
	}()
	select {
	case r := <-got:
		t.Fatalf("a release did not wait for the reaper holding the lock: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
	store.remove(s.RunID) // the reaper finishes: the record goes, then its lock
	store.unclaim(reaper, rec.Root)
	select {
	case r := <-got:
		if r.err != nil || !r.rep.Reaper || r.rep.Orphan != nil {
			t.Fatalf("ReleaseAdoption = %+v, %v; want the reaper's", r.rep, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the release did not end after the reaper")
	}
	if got := f.host.in(f.host.rel(rec.Scope)); !slices.Equal(got, []int{200}) {
		t.Fatalf("a release acted beside the reaper: the scope holds %v", got)
	}

	// No reaper: the release does it.
	f.host.end(f.host.rel(rec.Scope))
	orphan()
	rep, err := ReleaseAdoption(context.Background(), f.state, s.RunID, "tego adopt --release", nil)
	if err != nil || rep.Orphan == nil || rep.Adopter != 0 {
		t.Fatalf("ReleaseAdoption = %+v, %v; want released here", rep, err)
	}
	if got := f.host.in(adoptSession); !slices.Contains(got, 200) {
		t.Errorf("the agent was not released: the session holds %v", got)
	}
	if ents := recordsLeft(f.state); len(ents) != 0 {
		t.Errorf("left in the records: %v", ents)
	}
}

// TestAdoptNeedsRecheck: an adoption with no rules to recheck its process with before the move is a caller bug, refused
// before anything exists.
func TestAdoptNeedsRecheck(t *testing.T) {
	f := newAdoptFixture(t)
	spec := f.spec(t)
	spec.Recheck = nil
	if _, err := Adopt(context.Background(), f.rt, spec, f.deps); !errors.Is(err, ErrAdoptDeps) {
		t.Fatalf("Adopt = %v, want ErrAdoptDeps", err)
	}
	if len(f.host.moves) != 0 || f.cgroups.created != 0 {
		t.Fatalf("moves %v, scopes made %d", f.host.moves, f.cgroups.created)
	}
}

// TestAdoptRechecksTheRootBeforeTheMove: the agent exec'd tego's binary between its identification and the move. The
// caller's rules, applied again to the process as read right before the move, refuse it, and nothing moves.
func TestAdoptRechecksTheRootBeforeTheMove(t *testing.T) {
	f := newAdoptFixture(t)
	spec := f.spec(t)
	f.host.mu.Lock()
	f.host.procs[200].exe = "/usr/local/bin/tego"
	f.host.mu.Unlock()
	var seen []string
	spec.Recheck = func(p adopt.Process) error {
		seen = append(seen, p.Exe)
		if p.Exe != spec.Root.Exe {
			return &adopt.Refusal{Rule: adopt.RefuseTego, PID: p.PID, Detail: "it runs tego"}
		}
		return nil
	}
	// Bounded: an adoption that went ahead would hold the run until its agent ends.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Adopt(ctx, f.rt, spec, f.deps)
	if rule, ok := adopt.IsRefusal(err); !ok || rule != adopt.RefuseTego {
		t.Fatalf("Adopt = %v, want the recheck's refusal", err)
	}
	if !slices.Equal(seen, []string{"/usr/local/bin/tego"}) {
		t.Errorf("the recheck saw %v, want the process as it is now", seen)
	}
	if len(f.host.moves) != 0 {
		t.Fatalf("moves %v: a process the recheck refused was moved", f.host.moves)
	}
	if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 300}) {
		t.Fatalf("the session holds %v", got)
	}
	if left := leftBehind(t, filepath.Join(f.root, "runs")); len(left) != 0 {
		t.Errorf("a refused adoption left %v", left)
	}
	if ents := recordsLeft(f.state); len(ents) != 0 {
		t.Errorf("records left: %v", ents)
	}
}

// TestAdoptMovesUnderTheHostWideMoveLock: every write of a member's pid happens while the adoption holds the host-wide
// move lock, so two adoptions whose trees overlap never both move one process; and an adoption that cannot take the
// lock in time moves nothing.
func TestAdoptMovesUnderTheHostWideMoveLock(t *testing.T) {
	f := newAdoptFixture(t)
	lockPath := filepath.Join(f.state, movesLockName)
	var unheld []int
	f.host.onAdd = func(pid int) { // set before the adoption starts
		fd, err := syscall.Open(lockPath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			unheld = append(unheld, pid)
			return
		}
		defer func() { _ = syscall.Close(fd) }()
		if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			unheld = append(unheld, pid) // nobody held it
			_ = syscall.Flock(fd, syscall.LOCK_UN)
		}
	}
	s, done := f.adoptRunning(t, context.Background(), f.spec(t))
	f.host.mu.Lock()
	f.host.onAdd = nil
	f.host.mu.Unlock()
	if len(unheld) != 0 {
		t.Errorf("pids %v were moved without the move lock held", unheld)
	}
	f.host.end(f.host.rel(s.Scope))
	waitResult(t, done)

	// Another adopter holds the lock: this one waits, then gives up having moved nothing.
	g := newAdoptFixture(t)
	store, err := openAdoptStore(g.state)
	if err != nil {
		t.Fatal(err)
	}
	held, err := store.lockMoves(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	prev := movesLockWait
	movesLockWait = 50 * time.Millisecond
	t.Cleanup(func() { movesLockWait = prev })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // bounded, as in the recheck's test
	defer cancel()
	if _, err := Adopt(ctx, g.rt, g.spec(t), g.deps); !errors.Is(err, ErrMovesBusy) {
		t.Fatalf("Adopt = %v, want ErrMovesBusy", err)
	}
	if len(g.host.moves) != 0 {
		t.Fatalf("moves %v while another adopter held the move lock", g.host.moves)
	}
}
