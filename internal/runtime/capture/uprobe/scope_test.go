// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	bin "encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// fakeRunSet is a build's run set under test control: rows maps a cgroup to its slot, gens to its row's
// generation (0 when absent).
type fakeRunSet struct {
	rows    map[uint64]uint32
	gens    map[uint64]uint32
	lookErr error
}

func (f *fakeRunSet) Slot(cg uint64) (uint32, uint32, bool, error) {
	if f.lookErr != nil {
		return 0, 0, false, f.lookErr
	}
	s, ok := f.rows[cg]
	return s, f.gens[cg], ok, nil
}

// inSlot stamps a chunk record with the run_idx the kernel copies from the process's run-set row.
func inSlot(rec []byte, slot uint32) []byte {
	bin.NativeEndian.PutUint32(rec[36:40], slot)
	return rec
}

// exchangeOf is one request and its response on one connection of pid, in cgroup cg and slot slot.
func exchangeOf(cg uint64, pid uint32, slot uint32) [][]byte {
	return [][]byte{
		inSlot(chunkRecord(cg, pid, pid, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false), slot),
		inSlot(chunkRecord(cg, pid, pid, 0xabc, bpf.SSLRead, 9_000_000, []byte(exchangeResponse), false), slot),
	}
}

// TestSourceKeepsToItsSlot is capture-derive.md E26 (two concurrent runs of one build): a chunk is this run's when it carries this run's slot, whichever of the run's
// cgroups the process is in (55, a cgroup the agent made and cgroup_track gave the run's row). The run's capture
// ring is its own (ADR 0026 (1)), so a chunk of another slot should never be on it; were one there, it never
// reaches this run's sink.
func TestSourceKeepsToItsSlot(t *testing.T) {
	records := append(exchangeOf(999, 60, 9), exchangeOf(55, 50, 3)...)
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3, 55: 3, 999: 9}}
	u, sink := newTestUprobe(t, records, Options{RunSet: rs})
	runSource(t, u, sink, source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41})
	evs := sink.events()
	if len(evs) != 2 {
		t.Fatalf("%d events, want this run's one exchange: %+v", len(evs), evs)
	}
	for _, ev := range evs {
		if ev.Cgroup != 55 || ev.PID != 50 {
			t.Errorf("run r-A recorded %s from pid %d cgroup %d", ev.Kind, ev.PID, ev.Cgroup)
		}
	}
}

// TestSourceDropsTheSlotsPreviousRun is capture-derive.md E26 (a leftover never reaches a new run's ring): the slot's capture ring is reused by its next run (ADR 0026 (6) as
// amended), so an exchange the slot's previous run left in it carries this run's slot. It carries that run's
// generation, though, and never reaches this run's sink.
func TestSourceDropsTheSlotsPreviousRun(t *testing.T) {
	var records [][]byte
	for _, rec := range exchangeOf(40, 60, 3) {
		records = append(records, inGen(rec, 7001))
	}
	for _, rec := range exchangeOf(41, 50, 3) {
		records = append(records, inGen(rec, 7002))
	}
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3}, gens: map[uint64]uint32{41: 7002}}
	u, sink := newTestUprobe(t, records, Options{RunSet: rs})
	runSource(t, u, sink, source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41})
	evs := sink.events()
	if len(evs) != 2 {
		t.Fatalf("%d events, want this run's one exchange: %+v", len(evs), evs)
	}
	for _, ev := range evs {
		if ev.PID != 50 {
			t.Errorf("run r-A recorded %s of pid %d, which the slot's previous run left in its ring", ev.Kind, ev.PID)
		}
	}
}

// inGen stamps a chunk record with the generation the kernel copies from the process's run-set row.
func inGen(rec []byte, gen uint32) []byte {
	bin.NativeEndian.PutUint32(rec[44:48], gen)
	return rec
}

// TestHookSampleAdoptsNoCgroup is the probe the review ran: an exec of another run's process fed to this
// source (cgroup 999, not this run's 41), then that process's chunk. With nothing but the cgroup set to
// filter on, an adoption from the hook would put the other run's plaintext into this run's ledger; the hook
// adopts nothing, so the chunk is dropped.
func TestHookSampleAdoptsNoCgroup(t *testing.T) {
	tree := newProcTree(t)
	tree.process(t, 60, "/usr/bin/sh", nil)
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	// The empty fake ring ends the drain at once, so the chunks below are handed over after the hooks ran,
	// in the order the review's probe used, by the only goroutine left touching the drain's state.
	<-u.done
	u.OnExec(60, 999, "")
	u.OnOpen(60, 999, "/usr/lib/x86_64-linux-gnu/libssl.so.3")
	u.mu.Lock()
	_, adopted := u.cgroups[999]
	u.mu.Unlock()
	if adopted {
		t.Fatal("a hook sample made cgroup 999 this run's")
	}
	for _, rec := range exchangeOf(999, 60, 0) {
		u.handle(rec)
	}
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	if evs := sink.events(); len(evs) != 0 {
		t.Fatalf("run r-A recorded %d events of cgroup 999's process: %+v", len(evs), evs)
	}
}

// TestSourceRunsBesideAnotherRunOfItsBuild is ADR 0026 (5): another run of the build, or a row a dead launcher
// left under another slot, no longer keeps a source from running. The probes are shared per library and emit
// each call once, into the ring of the run the calling process belongs to, so the source attaches and records
// its own exchange with no mechanism-unavailable gap.
func TestSourceRunsBesideAnotherRunOfItsBuild(t *testing.T) {
	tree := newProcTree(t)
	lib := tree.inRoot(t, 60, "usr/lib/x86_64-linux-gnu/libssl.so.3", hookableELF(t))
	tree.process(t, 60, "/usr/bin/sh", []string{lib})
	att := &fakeAttacher{}
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3, 77: 5, 12: 8}}
	u, sink := newTestUprobe(t, exchangeOf(41, 60, 3), Options{RunSet: rs, Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("Start failed the run: %v", err)
	}
	u.OnExec(60, 41, "")
	u.OnOpen(60, 41, lib)
	<-u.done // the fake ring ends the drain once it has handed out every chunk
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	if n := len(sink.events()); n != 2 {
		t.Errorf("%d events, want the run's one exchange", n)
	}
	if att.count() == 0 {
		t.Error("a source beside another run of its build attached no probe")
	}
	for _, g := range u.Gaps() {
		if g.Why == GapMechanismUnavailable {
			t.Errorf("gap %+v beside another run of the build", g)
		}
	}
}

// TestSourceWithoutItsRowDoesNotRun: with no row for the run's cgroup, or no cgroup at all, nothing names the
// run's slot and so its ring. The source does not run: one mechanism-unavailable gap, no drain, no attach.
func TestSourceWithoutItsRowDoesNotRun(t *testing.T) {
	cases := []struct {
		name string
		rs   *fakeRunSet
		cg   uint64
	}{
		{"no row for this run", &fakeRunSet{rows: map[uint64]uint32{77: 5}}, 41},
		{"the run names no cgroup", &fakeRunSet{rows: map[uint64]uint32{41: 3}}, 0},
		{"the run set cannot be read", &fakeRunSet{lookErr: errors.New("EPERM")}, 41},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := newProcTree(t)
			lib := tree.inRoot(t, 60, "usr/lib/x86_64-linux-gnu/libssl.so.3", hookableELF(t))
			tree.process(t, 60, "/usr/bin/sh", []string{lib})
			att := &fakeAttacher{}
			records := exchangeOf(41, 60, 3)
			u, sink := newTestUprobe(t, records, Options{RunSet: tc.rs, Proc: proc.NewAt(tree.root), Attacher: att})
			if err := u.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: tc.cg}, sink); err != nil {
				t.Fatalf("Start failed the run: %v", err)
			}
			u.OnExec(60, 41, "")
			u.OnOpen(60, 41, lib)
			if err := u.Stop(); err != nil {
				t.Fatal(err)
			}
			if att.count() != 0 {
				t.Errorf("a source that must not run attached %d probes", att.count())
			}
			if evs := sink.events(); len(evs) != 0 {
				t.Errorf("a source that must not run recorded %d events", len(evs))
			}
			gaps := u.Gaps()
			if len(gaps) != 1 || gaps[0].Why != GapMechanismUnavailable || gaps[0].Binary != Name || gaps[0].Count != 0 {
				t.Errorf("gaps %+v, want exactly mechanism-unavailable binary=%s with no count", gaps, Name)
			}
			if u.UnavailableCause() == "" {
				t.Error("an inert source names no cause")
			}
		})
	}
}

// hookableELF is a shared object exporting SSL_write and SSL_read, so an attach of it succeeds.
func hookableELF(t *testing.T) []byte {
	t.Helper()
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100, SymRead: 0x1200}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// syncBlobs is a body store that records when it was synced, relative to the bodies it stored.
type syncBlobs struct {
	fakeBlobs
	smu      sync.Mutex
	syncs    int
	putsAt   int // len(put) at the last Sync
	syncFail error
}

func (s *syncBlobs) Sync() error {
	s.smu.Lock()
	defer s.smu.Unlock()
	s.mu.Lock()
	s.putsAt = len(s.put)
	s.mu.Unlock()
	s.syncs++
	return s.syncFail
}

// TestStopSyncsTheBodiesItStored is record-ledger R6's barrier for a store the ledger writer does not own.
// The source stores bodies through its own handle on the run's blob directory, and the writer syncs only
// the store it wrote through itself before events.jsonl, so without this a crash inside the writer's Close
// could leave a ledger that ends cleanly and names bodies that were never durable. Stop runs before the
// writer writes run_end, and it syncs after the last body is stored; a sync that fails is Stop's error.
func TestStopSyncsTheBodiesItStored(t *testing.T) {
	blobs := &syncBlobs{}
	u, sink := newTestUprobe(t, exchangeOf(41, 100, 0), Options{Blobs: blobs, Rules: &agent.RuleTable{Record: agent.RecordFull}})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if len(blobs.put) == 0 {
		t.Fatal("record: full stored no body; the test proves nothing")
	}
	if blobs.syncs != 1 || blobs.putsAt != len(blobs.put) {
		t.Errorf("synced %d times, the last after %d of %d bodies; want once, after every body", blobs.syncs,
			blobs.putsAt, len(blobs.put))
	}

	failing := &syncBlobs{syncFail: errors.New("EIO")}
	u, sink = newTestUprobe(t, exchangeOf(41, 100, 0), Options{Blobs: failing, Rules: &agent.RuleTable{Record: agent.RecordFull}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-2", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	<-u.done
	if err := u.Stop(); err == nil || !errors.Is(err, failing.syncFail) {
		t.Errorf("Stop = %v, want the failed sync", err)
	}
}

// TestOpenAfterExitIsNotNoSymbols is the recorder handing an open on after its process has gone. The path
// the attach needs runs through /proc/<pid>/root and went with the process, so the library was never read:
// that says nothing about its symbols, and a static-tls-no-symbols line naming the host's libssl would say
// the host's OpenSSL exports none. It is no-openssl against the process's own image.
func TestOpenAfterExitIsNotNoSymbols(t *testing.T) {
	tree := newProcTree(t)
	so := writeELF(t, elfOptions{Dynamic: map[string]uint64{"malloc": 0x1100}})
	b, err := os.ReadFile(so)
	if err != nil {
		t.Fatal(err)
	}
	lib := tree.inRoot(t, 501, "usr/lib/libc.so.6", b)
	tree.process(t, 501, "/usr/bin/sh", []string{lib})
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	u.OnExec(501, 41, "")
	if err := os.RemoveAll(filepath.Join(tree.root, strconv.Itoa(501))); err != nil {
		t.Fatal(err)
	}
	const libssl = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	u.OnOpen(501, 41, libssl)
	u.OnExit(501)
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	gaps := u.Gaps()
	for _, g := range gaps {
		if g.Why == GapStaticTLSNoSymbols || g.Binary == libssl {
			t.Errorf("gap %+v: a library nobody could read was reported against %s", g, libssl)
		}
	}
	if len(gaps) != 1 || gaps[0].Why != GapNoOpenSSL || gaps[0].Binary != "/usr/bin/sh" || gaps[0].Count != 1 {
		t.Errorf("gaps %+v, want one no-openssl naming the process's /usr/bin/sh", gaps)
	}
}

// The pinned map is the production RunSet.
var _ RunSet = (*pinnedRunSet)(nil)
