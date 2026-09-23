// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// pinnedNet models the two verdict maps and the unix name trie. They are LIBBPF_PIN_BY_NAME
// (bpf/include/maps.h), so their rows outlive the launcher that wrote them exactly as this value outlives the
// fakeKernel that wrote them — which is what makes the slot-reuse half of §5 R12 and §8 I5 testable here: a
// test can hand a second run the host state a first, killed, run left behind.
type pinnedNet struct {
	exact map[ebpfbindings.NetKey]ebpfbindings.NetVerdict
	cidr  map[ebpfbindings.NetLPMKey]ebpfbindings.NetVerdict
	unix  map[ebpfbindings.UnixKey]ebpfbindings.NetVerdict
}

func newPinnedNet() *pinnedNet {
	return &pinnedNet{
		exact: map[ebpfbindings.NetKey]ebpfbindings.NetVerdict{},
		cidr:  map[ebpfbindings.NetLPMKey]ebpfbindings.NetVerdict{},
		unix:  map[ebpfbindings.UnixKey]ebpfbindings.NetVerdict{},
	}
}

// rowsFor counts the rows keyed by one run_idx, which is what a reused slot would inherit.
func (p *pinnedNet) rowsFor(runIdx uint32) int {
	n := 0
	for k := range p.exact {
		if k.RunIdx == runIdx {
			n++
		}
	}
	for k := range p.cidr {
		if k.RunIdx == runIdx {
			n++
		}
	}
	for k := range p.unix {
		if k.RunIdx == runIdx {
			n++
		}
	}
	return n
}

// fakeKernel records everything a Handle asks of the kernel, so Prepare's ordering, its unwinding and
// Detach's teardown order are all assertable without privilege. failAt makes one named step fail.
type fakeKernel struct {
	trackingCount uint64
	trackingErr   error
	calls         []string
	runs          map[uint64]ebpfbindings.Run
	net           *pinnedNet
	exactRows     int
	cidrRows      int
	attached      string
	owner         ebpfbindings.NetOwner
	unpinned      bool
	closed        bool
	failAt        string
	failErr       error
	ruleRemove    int
	purged        []uint32
	// live is what runSetLive answers: a run the build enforces is still alive.
	live bool
	// rings are the rings placed, by slot; otherRings is the memlock other builds' rings charge (ringUse) that no
	// reclaim can take, and idleRings what other builds' rings charge by build and slot, each reclaimable when
	// the reclaim's test says no one holds it. drained counts drainRing calls by kind.
	rings      map[uint32][]fakeRing
	otherRings uint64
	idleRings  map[string]map[uint32]uint64
	drained    map[string]int
	// reclaimErr is what reclaimRings returns after it has freed what it could: another build it could not read.
	reclaimErr error
	// crumbs are tego_reason_map's rows, by cgroup id.
	crumbs map[uint64]ebpfbindings.Breadcrumb
	// plane is what planeOf answers: the plane a plane-mode Prepare loaded with the build (plane_test.go).
	plane planeKernel
	// noExecOutcomes makes execOutcomes answer false: the build's exec-result programs did not attach.
	noExecOutcomes bool
}

func (k *fakeKernel) planeOf() planeKernel { return k.plane }

// execOutcomes is the build's exec-result coverage (bpfKernel.execOutcomes): complete unless noExecOutcomes.
func (k *fakeKernel) execOutcomes() bool { return !k.noExecOutcomes }

func (k *fakeKernel) trackingFailures(uint32) (uint64, error) {
	return k.trackingCount, k.trackingErr
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{runs: map[uint64]ebpfbindings.Run{}, net: newPinnedNet()}
}

func (k *fakeKernel) note(step string) error {
	k.calls = append(k.calls, step)
	if k.failAt == step {
		if k.failErr != nil {
			return k.failErr
		}
		return fmt.Errorf("fake kernel: %s failed", step)
	}
	return nil
}

func (k *fakeKernel) populate(rules RuleMaps) error {
	if err := k.note("populate"); err != nil {
		return err
	}
	for _, row := range rules.Exact {
		k.net.exact[row.Key] = row.Val
	}
	for _, row := range rules.CIDR {
		k.net.cidr[row.Key] = row.Val
	}
	for _, row := range rules.Unix {
		k.net.unix[row.Key] = row.Val
	}
	k.exactRows, k.cidrRows = len(rules.Exact), len(rules.CIDR)
	return nil
}

func (k *fakeKernel) purgeSlot(runIdx uint32) error {
	if err := k.note("purgeSlot"); err != nil {
		return err
	}
	k.purged = append(k.purged, runIdx)
	for key := range k.net.exact {
		if key.RunIdx == runIdx {
			delete(k.net.exact, key)
		}
	}
	for key := range k.net.cidr {
		if key.RunIdx == runIdx {
			delete(k.net.cidr, key)
		}
	}
	for key := range k.net.unix {
		if key.RunIdx == runIdx {
			delete(k.net.unix, key)
		}
	}
	return nil
}

func (k *fakeKernel) insertRun(id uint64, val ebpfbindings.Run) error {
	if err := k.note("insertRun"); err != nil {
		return err
	}
	k.runs[id] = val
	return nil
}

func (k *fakeKernel) removeRun(id uint64) error {
	if err := k.note("removeRun"); err != nil {
		return err
	}
	delete(k.runs, id)
	return nil
}

func (k *fakeKernel) breadcrumb(id uint64) (ebpfbindings.Breadcrumb, bool, error) {
	br, ok := k.crumbs[id]
	return br, ok, nil
}

func (k *fakeKernel) removeRules(rules RuleMaps) error {
	if err := k.note("removeRules"); err != nil {
		return err
	}
	for _, row := range rules.Exact {
		delete(k.net.exact, row.Key)
	}
	for _, row := range rules.CIDR {
		delete(k.net.cidr, row.Key)
	}
	for _, row := range rules.Unix {
		delete(k.net.unix, row.Key)
	}
	k.ruleRemove++
	k.exactRows, k.cidrRows = 0, 0
	return nil
}

func (k *fakeKernel) attachCgroup(path string, owner ebpfbindings.NetOwner) error {
	if err := k.note("attachCgroup"); err != nil {
		return err
	}
	k.attached = path
	k.owner = owner
	return nil
}

func (k *fakeKernel) detachCgroup() error {
	if err := k.note("detachCgroup"); err != nil {
		return err
	}
	k.attached = ""
	return nil
}

func (k *fakeKernel) unpin() error {
	if err := k.note("unpin"); err != nil {
		return err
	}
	k.unpinned = true
	return nil
}

func (k *fakeKernel) runSetLive(string) (bool, error) { return k.live, nil }

// fakeRing is one ring the fake placed: its kind and size, at its slot.
type fakeRing struct {
	kind string
	size uint32
}

// fakeRingMemlock is what the fake charges for a ring of size bytes: the size and one page of header, close to
// the kernel's own (the data pages, counted once, and the page array).
func fakeRingMemlock(size uint32) uint64 { return uint64(size) + 4096 }

func (k *fakeKernel) placeRing(kind string, slot, size uint32, room uint64) (uint64, bool, error) {
	if err := k.note("placeRing " + kind); err != nil {
		return 0, false, err
	}
	m := fakeRingMemlock(size)
	if m > room {
		return m, false, nil
	}
	if k.rings == nil {
		k.rings = map[uint32][]fakeRing{}
	}
	k.rings[slot] = append(k.rings[slot], fakeRing{kind: kind, size: size})
	return m, true, nil
}

func (k *fakeKernel) slotRings(slot uint32) (map[string]uint32, error) {
	if err := k.note("slotRings"); err != nil {
		return nil, err
	}
	out := map[string]uint32{}
	for _, r := range k.rings[slot] {
		out[r.kind] = r.size
	}
	return out, nil
}

func (k *fakeKernel) removeRing(kind string, slot uint32) error {
	if err := k.note("removeRing " + kind); err != nil {
		return err
	}
	k.rings[slot] = slices.DeleteFunc(k.rings[slot], func(r fakeRing) bool { return r.kind == kind })
	if len(k.rings[slot]) == 0 {
		delete(k.rings, slot)
	}
	return nil
}

func (k *fakeKernel) drainRing(kind string, _ uint32) error {
	if err := k.note("drainRing " + kind); err != nil {
		return err
	}
	if k.drained == nil {
		k.drained = map[string]int{}
	}
	k.drained[kind]++
	return nil
}

// reclaimRings removes this build's rings ("testhash") at slots no run-set row carries and other builds' idle
// rings, each where noOne says so.
func (k *fakeKernel) reclaimRings(_ string, noOne func(string, uint32) (bool, error)) (uint64, int, error) {
	if err := k.note("reclaimRings"); err != nil {
		return 0, 0, err
	}
	carried := map[uint32]bool{}
	for _, r := range k.runs {
		carried[r.RunIdx] = true
	}
	var (
		freed uint64
		n     int
	)
	for slot, rs := range k.rings {
		if carried[slot] {
			continue
		}
		if ok, err := noOne("testhash", slot); err != nil || !ok {
			continue
		}
		for _, r := range rs {
			freed += fakeRingMemlock(r.size)
			n++
		}
		delete(k.rings, slot)
	}
	for hash, slots := range k.idleRings {
		for slot, m := range slots {
			if ok, err := noOne(hash, slot); err != nil || !ok {
				continue
			}
			freed += m
			n++
			delete(slots, slot)
		}
	}
	return freed, n, k.reclaimErr
}

func (k *fakeKernel) ringUse(string) (uint64, int, error) {
	used, n := k.otherRings, 0
	for _, slots := range k.idleRings {
		for _, m := range slots {
			used += m
			n++
		}
	}
	for _, rs := range k.rings {
		for _, r := range rs {
			used += fakeRingMemlock(r.size)
			n++
		}
	}
	return used, n, nil
}

func (k *fakeKernel) close() error {
	if err := k.note("close"); err != nil {
		return err
	}
	k.closed = true
	return nil
}

// fixture builds a backend wired to a fake kernel and a listener whose descriptor is a pipe, plus the run
// and table a test prepares with.
type fixture struct {
	backend *Backend
	kernel  *fakeKernel
	events  *sink
	run     Run
	table   *agent.RuleTable
	dir     string
}

// machineLinger is the built-in machine config with bpf.linger set to d. The fixture's default is 0, the
// last-out removal most of these tests describe; the linger tests set their own.
func machineLinger(d time.Duration) *config.Machine {
	m := config.Builtin()
	m.BPF.Linger.Value = d
	return m
}

func newFixture(t *testing.T, opts ...func(*Options)) *fixture {
	t.Helper()
	dir := t.TempDir()
	mount := filepath.Join(dir, "cgroup")
	scope := "/tego.slice/run-1.scope"
	if err := os.MkdirAll(filepath.Join(mount, scope), 0o755); err != nil {
		t.Fatalf("make a cgroup tree: %v", err)
	}
	scopeID, err := cgroupIDOfPath(mount, scope)
	if err != nil {
		t.Fatalf("stat the scope: %v", err)
	}

	k := newFakeKernel()
	s := &sink{}
	o := Options{
		Machine:  machineLinger(0),
		BPFFS:    dir,
		StateDir: dir,
		Hash:     "testhash",
		Events:   s,
		Now:      func() time.Time { return time.Unix(0, 0).UTC() },
		newKernel: func(context.Context, *Handle) (kernel, error) {
			return k, nil
		},
		newListener: func(h *Handle) (*fanotifyListener, error) {
			l, r := testListener(t, h.opts.Events, func(fanEvent) (verdict, error) { return allowed, nil }, time.Second)
			_ = r
			l.run = h.run
			l.policy = h.policy
			return l, nil
		},
		// The launcher's own cgroup, where Attach reads the relay's id from (§5 R7): the fake mount's root.
		selfCgroup: func() (string, error) { return "/", nil },
	}
	for _, f := range opts {
		f(&o)
	}

	compiled := contracttest.BuildAt(t, dir, `version: 0
name: a
command: [fixture]
tier: cgroup
capture: off
record: full
fs:
  deny_read: [secret]
net:
  allow: [api:443]
exec:
  allow: [fixture]
`, contracttest.Tree{"secret": "private"}, agent.WithResolver(contracttest.Resolver{"api": {netip.MustParseAddr("198.51.100.4")}}))
	rt := compiled.Rules
	return &fixture{
		backend: New(o), kernel: k, events: s, table: rt, dir: dir,
		run: Run{ID: "run-1", Agent: "a", CgroupID: scopeID, CgroupPath: scope, CgroupMount: mount},
	}
}

// prepareArmed is Prepare followed by Arm, the state the runtime hands the agent (ADR 0021 (2)).
func (f *fixture) prepareArmed(t *testing.T) *Handle {
	t.Helper()
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Arm(); err != nil {
		_ = h.Close()
		t.Fatalf("Arm: %v", err)
	}
	return h
}

// TestCloseReleasesStateDir: a successful Prepare's Close closes the verified state directory the slot table
// holds, so a process hosting many runs does not keep one descriptor per run (§8 I10).
func TestCloseReleasesStateDir(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	dir := h.slots.dir
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fh, err := dir.OpenFile("probe", unix.O_RDWR|unix.O_CREAT, 0o600); err == nil {
		_ = fh.Close()
		t.Fatal("the state directory is still open after Close")
	}
}

// TestPrepareHappyPath walks the whole of §4's order and asserts each step left the state it promises.
func TestPrepareHappyPath(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()

	if h.Hash() != "testhash" {
		t.Fatalf("hash = %q", h.Hash())
	}
	if h.Slot() != 0 {
		t.Fatalf("slot = %d, want the first", h.Slot())
	}
	if got := len(h.Rules().Exact); got != 4 {
		t.Fatalf("%d exact rows, want 4 (two protocols times two address families)", got)
	}
	if f.kernel.exactRows != 4 {
		t.Fatalf("the kernel received %d exact rows", f.kernel.exactRows)
	}
	// Nothing keyed on the run exists before the arming point (ADR 0021 (2)): no run-set row, no mark.
	if _, ok := f.kernel.runs[f.run.CgroupID]; ok {
		t.Fatal("Prepare inserted the run's run-set row before Arm")
	}
	if h.fan == nil || len(h.fan.marked()) != 0 {
		t.Fatalf("after Prepare: listener %v, marks %v; want a group with no mark", h.fan != nil, h.fan.marked())
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if len(h.fan.marked()) == 0 {
		t.Fatal("Arm marked no mount for the contract's deny_read")
	}
	if err := h.Arm(); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("a second Arm = %v, want ErrNotPrepared", err)
	}
	val, ok := f.kernel.runs[f.run.CgroupID]
	if !ok {
		t.Fatalf("the run's cgroup was not inserted: %+v", f.kernel.runs)
	}
	if val.Descendants != 1 {
		t.Fatalf("descendants = %d, want 1 (§5 R11)", val.Descendants)
	}
	if val.Tier != 2 || val.RunIdx != h.Slot() || val.Record != uint8(ebpfbindings.RecordFull) {
		t.Fatalf("run-set value = %+v", val)
	}
	if h.fan == nil {
		t.Fatal("a contract with an fs rule must have a listener")
	}
	if err := h.Attach(f.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if want := filepath.Join(f.run.CgroupMount, f.run.CgroupPath); f.kernel.attached != want {
		t.Fatalf("attached %q, want %q", f.kernel.attached, want)
	}
	// The attachment's storage names the run's own cgroup and slot: that is what the deciding programs read
	// in place of the caller's cgroup, and the key their breadcrumb is written under (§5 R1, R2, R5). It also
	// names the launcher's own cgroup, the one caller connect_unix admits the relay's name from (§5 R7): the
	// fixture's is the fake mount's root.
	relay, err := cgroupIDOfPath(f.run.CgroupMount, "/")
	if err != nil {
		t.Fatal(err)
	}
	// It carries the run's generation, which cgroup/sock_create stamps on its own refusal record, and the socket
	// flags of the contract's NetSocketPolicy: api:443 names no ICMP destination, so no ping socket (§5 R4).
	if h.gen == 0 {
		t.Fatal("the run holds no generation")
	}
	if want := (ebpfbindings.NetOwner{CgroupID: f.run.CgroupID, RunIdx: h.Slot(), RelayCgroupID: relay, Gen: h.gen}); f.kernel.owner != want {
		t.Fatalf("attachment owner = %+v, want %+v", f.kernel.owner, want)
	}
}

// TestAttachOwnerCarriesTheICMPFlag is §5 R4's owner half for cgroup/sock_create: the attachment's storage says
// whether the run admits ping sockets, from agent.RuleTable.NetSocketPolicy, the predicate the seccomp filter's
// socket arm and the plane's slot header read, so the three cannot answer a ping socket two ways.
func TestAttachOwnerCarriesTheICMPFlag(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		net  []agent.NetRule
		want uint32
	}{
		{"a TCP destination", []agent.NetRule{{Raw: "198.51.100.4:443", Port: 443, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("198.51.100.4")}, Static: true}}, 0},
		{"an ICMP destination", []agent.NetRule{{Raw: "198.51.100.4:0", Port: 0, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("198.51.100.4")}, Static: true}},
			ebpfbindings.NetOwnerICMP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			rt := *f.table
			rt.Net = tc.net
			if got := rt.NetSocketPolicy().ICMP; got != (tc.want != 0) {
				t.Fatalf("the fixture's NetSocketPolicy().ICMP = %v", got)
			}
			h, err := f.backend.Prepare(context.Background(), &rt, f.run)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			defer h.Close()
			if err := h.Attach(f.run.CgroupID); err != nil {
				t.Fatalf("Attach: %v", err)
			}
			if f.kernel.owner.Flags != tc.want || f.kernel.owner.Gen != h.gen || f.kernel.owner.Gen == 0 {
				t.Fatalf("attachment owner = %+v, want flags %#x and the run's gen %d", f.kernel.owner, tc.want, h.gen)
			}
		})
	}
}

// TestAttachRefusesADirectoryThatIsNotTheRunsCgroup covers the other half of Attach's contract: the storage is
// keyed by the id of the directory the links go on, so a run whose recorded id names some other cgroup would
// configure one cgroup and remove another's breadcrumb at Detach. Attach refuses instead of guessing.
func TestAttachRefusesADirectoryThatIsNotTheRunsCgroup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	h.run.CgroupPath = "/tego.slice"
	if err := h.Attach(f.run.CgroupID); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("Attach over a directory whose id is not the run's = %v, want ErrNotPrepared", err)
	}
	if f.kernel.attached != "" {
		t.Fatalf("attached %q after refusing", f.kernel.attached)
	}
}

// TestPrepareAdoptsExistingDescendants is §5 R11's other half: a cgroup created inside the run's scope before
// the tracepoint was attached is still in the run set once the run is armed.
func TestPrepareAdoptsExistingDescendants(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	nested := filepath.Join(f.run.CgroupMount, f.run.CgroupPath, "worker", "deeper")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("make a nested cgroup: %v", err)
	}
	h := f.prepareArmed(t)
	defer h.Close()

	if len(f.kernel.runs) != 3 {
		t.Fatalf("%d run-set rows, want the scope and its two descendants: %+v", len(f.kernel.runs), f.kernel.runs)
	}
	for id, val := range f.kernel.runs {
		if val.RunIdx != h.Slot() || val.Descendants != 1 {
			t.Fatalf("cgroup %d has %+v", id, val)
		}
	}
}

// TestPrepareUnwindsEveryStep is invariant I10: failing any kernel step leaves no row, no slot and no
// listener behind, and the error reaches the caller unchanged. The run-set row is Arm's step (ADR 0021 (2)):
// a failure there fails the run, and Close, which the runtime's unwind calls, releases what Prepare built.
func TestPrepareUnwindsEveryStep(t *testing.T) {
	t.Parallel()
	for _, step := range []string{"populate", "insertRun"} {
		t.Run(step, func(t *testing.T) {
			f := newFixture(t)
			f.kernel.failAt = step
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if err == nil {
				err = h.Arm()
				_ = h.Close()
			}
			if err == nil {
				t.Fatal("Prepare and Arm succeeded with a failing kernel step")
			}
			if !strings.Contains(err.Error(), step) {
				t.Fatalf("error does not name the failing step: %v", err)
			}
			if len(f.kernel.runs) != 0 {
				t.Fatalf("rows survived the unwind: %+v", f.kernel.runs)
			}
			if !f.kernel.closed {
				t.Fatal("the kernel state was not closed on the unwind")
			}
			// The slot must be free again for the next run.
			slots, err := openSlotTable(t, f.dir, "testhash")
			if err != nil {
				t.Fatalf("openSlotTable: %v", err)
			}
			if n, err := slots.held(); err != nil || n != 0 {
				t.Fatalf("held = %d, %v; a failed Prepare must free its slot", n, err)
			}
		})
	}
}

// TestPrepareFailingAbovePoolTrimsItsRings: a Prepare that placed its rings at a slot above the pool
// (ringPoolSlots) and then failed releases the slot and has those rings trimmed, as Detach does; the undo used to
// release the slot alone, leaving rings no run would trim.
func TestPrepareFailingAbovePoolTrimsItsRings(t *testing.T) {
	t.Parallel()
	var trimmed []string
	f := newFixture(t, func(o *Options) {
		o.carriedSlots = func(string) (map[uint32]bool, error) {
			carried := map[uint32]bool{}
			for s := uint32(0); s < ringPoolSlots; s++ {
				carried[s] = true
			}
			return carried, nil
		}
		o.trimRings = func(hash string) error {
			trimmed = append(trimmed, hash)
			return nil
		}
		// A step after the rings are placed fails: composing the inherited tier-1 state.
		o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
			return nil, errors.New("inherit failed")
		}
	})
	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded with a failing kernel step")
	}
	if len(trimmed) != 1 || trimmed[0] != "testhash" {
		t.Fatalf("trimRings calls %v, want one for testhash", trimmed)
	}
}

// TestDetachOrder pins enforce-cgroup-observe.md §5 R15 and §4: the cgroup links go first, then the rows, then the slot, and only a
// last launcher out unpins.
func TestDetachOrder(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Attach(f.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.kernel.calls = nil

	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	order := strings.Join(f.kernel.calls, ",")
	if !strings.HasPrefix(order, "detachCgroup,removeRun") {
		t.Fatalf("teardown order %q: links must go before rows (§5 R15)", order)
	}
	if !strings.Contains(order, "removeRules") {
		t.Fatalf("teardown order %q: verdict rows were not removed", order)
	}
	if !f.kernel.unpinned {
		t.Fatal("a sole launcher must unpin on the way out (§5 R14)")
	}
	if len(f.kernel.runs) != 0 {
		t.Fatalf("rows survived Detach: %+v", f.kernel.runs)
	}

	// Idempotent: Detach and Close may both run, twice.
	before := len(f.kernel.calls)
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach twice: %v", err)
	}
	if len(f.kernel.calls) != before {
		t.Fatalf("a second Detach touched the kernel: %v", f.kernel.calls[before:])
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close twice: %v", err)
	}
	slots, err := openSlotTable(t, f.dir, "testhash")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	if n, err := slots.held(); err != nil || n != 0 {
		t.Fatalf("held = %d, %v; Detach must free the slot", n, err)
	}
}

// TestDetachKeepsPinsWhileAnotherLauncherRuns is §5 R14's multi-run case: the departing launcher removes its
// own rows but leaves the shared pins for the one still running.
func TestDetachKeepsPinsWhileAnotherLauncherRuns(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()

	stop := holdLockInChild(t, f.dir, "testhash")
	defer stop()

	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if f.kernel.unpinned {
		t.Fatal("unpinned while another launcher of this build is running (§5 R14)")
	}
	if len(f.kernel.runs) != 0 {
		t.Fatal("this run's own rows must be removed regardless")
	}
}

// TestPrepareRejects covers every input Prepare refuses before it creates anything.
func TestPrepareRejects(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if _, err := f.backend.Prepare(context.Background(), nil, f.run); !errors.Is(err, ErrNoTable) {
		t.Fatalf("nil table = %v", err)
	}
	wrong := *f.table
	wrong.Tier = backend.TierLandlock
	if _, err := f.backend.Prepare(context.Background(), &wrong, f.run); !errors.Is(err, ErrTier) {
		t.Fatalf("wrong tier = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.backend.Prepare(ctx, f.table, f.run); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context = %v", err)
	}
	noCgroup := f.run
	noCgroup.CgroupID = 0
	if _, err := f.backend.Prepare(context.Background(), f.table, noCgroup); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("a run with no cgroup id = %v", err)
	}
}

// TestRingbufValidation is enforce-cgroup-observe.md §5 R16 and §6 E28: the size is checked before any map exists, and every rejected
// value says why.
func TestRingbufValidation(t *testing.T) {
	t.Parallel()
	page := int64(os.Getpagesize())
	cases := []struct {
		name string
		size int64
		ok   bool
	}{
		{"default 8MiB", 8 << 20, true},
		{"one page", page, true},
		{"two pages", 2 * page, true},
		{"three pages", 3 * page, false},
		{"3MiB", 3 << 20, false},
		{"not a page multiple", page + 1, false},
		{"zero", 0, false},
		{"negative", -4096, false},
		{"too large", 1 << 33, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateRingbuf(tc.size)
			if tc.ok {
				if err != nil {
					t.Fatalf("validateRingbuf(%d) = %v", tc.size, err)
				}
				if int64(got) != tc.size {
					t.Fatalf("= %d, want %d", got, tc.size)
				}
				return
			}
			if !errors.Is(err, ErrRingbufSize) {
				t.Fatalf("validateRingbuf(%d) = %v, want ErrRingbufSize", tc.size, err)
			}
		})
	}
}

// TestRingbufFromMachineConfig asserts the value really comes from the machine config and reaches Prepare.
func TestRingbufFromMachineConfig(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	got, err := b.RingbufBytes()
	if err != nil {
		t.Fatalf("RingbufBytes: %v", err)
	}
	if got == 0 || got&(got-1) != 0 {
		t.Fatalf("built-in ring buffer is %d bytes, which is not a power of two", got)
	}
	m := config.Builtin()
	m.Record.Ringbuf.Value = config.ByteSize(3 << 20)
	if _, err := New(Options{Machine: m}).RingbufBytes(); !errors.Is(err, ErrRingbufSize) {
		t.Fatalf("a 3MiB ring buffer was accepted")
	}
}

// TestCapabilitiesNarrowPerRun asserts a run whose contract names something this tier cannot decide reports
// it as missing rather than letting it look enforced.
func TestCapabilitiesNarrowPerRun(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.table.Net = append(f.table.Net, agent.NetRule{Raw: "unix:/run/pg.sock",
		Proto: agent.ProtoUnix, UnixPath: "/run/pg.sock", Verdict: agent.VerdictAllow})
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()

	set := h.Capabilities()
	// A unix entry is decided on every kernel: by connect_unix and sendmsg_unix from 6.7 and by the inherited
	// tier-1 path alongside them (§5 R7). The row used to be cleared here for a unix entry the inherited path
	// enforced, which recorded net.unix=false for sockets that were enforced.
	if !set[backend.CapUnixSockets] {
		t.Fatal("a run with a unix entry must report net.unix, which the kernel or tier 1 decides on every kernel (§5 R7)")
	}
	if set[backend.CapProtectedWriteTargets] {
		t.Error("a run on the fanotify listener claims the built-in deny_write targets, which only a plane mode decides race-free (ADR 0041 D7)")
	}
	if !set[backend.CapNetHostDeny] {
		t.Fatal("host:port denial is this tier's whole point")
	}
	if got := f.backend.Capabilities(); !got[backend.CapNetHostDeny] {
		t.Fatal("the tier's static column must still claim host:port denial")
	}
}

// TestCapabilitiesNameEntriesWhereThePlaneChecksNames: fs.deny_read.created_later (ADR 0043 C9) is true exactly
// where the plane's name check decides the run's slot, a plane mode with name rows (Prepare writes the header's flag
// for them or fails), at tier cgroup and tier bpflsm alike, and only for a table whose name-eligible entries all have
// their name entry (D7: none left out by a cap or a collision, RuleTable.NameLeftOut); never on the fanotify
// fallback, which refuses a name-matched open and, best effort, a mutation, nor for a table without name rows (no
// name entry), which the row would describe vacuously, nor for a handle without its table.
func TestCapabilitiesNameEntriesWhereThePlaneChecksNames(t *testing.T) {
	t.Parallel()
	named := &decide.PlaneRows{NameRows: []decide.PlaneNameRow{{Name: ".env", Prefix: true}}}
	whole := &agent.RuleTable{}
	leftOut := &agent.RuleTable{NameLeftOut: []agent.NameLeftOut{{Entry: agent.NameDenyRule{Literal: "secret.txt",
		Raw: "w/d9/*/secret.txt"}, Why: "the plane's 8 scope directories a run"}}}
	for _, tc := range []struct {
		name  string
		tier  backend.Tier
		mode  ebpfbindings.PlaneMode
		rows  *decide.PlaneRows
		table *agent.RuleTable
		want  bool
	}{
		{"cgroup lsm with name rows", backend.TierCgroup, ebpfbindings.PlaneLSM, named, whole, true},
		{"cgroup fmod_ret with name rows", backend.TierCgroup, ebpfbindings.PlaneFmodRet, named, whole, true},
		{"cgroup lsm without name rows", backend.TierCgroup, ebpfbindings.PlaneLSM, &decide.PlaneRows{}, whole, false},
		{"the fanotify fallback", backend.TierCgroup, "", nil, whole, false},
		{"the fanotify fallback after a mode's rows were compiled", backend.TierCgroup, "", named, whole, false},
		{"bpflsm with name rows", backend.TierBPFLSM, ebpfbindings.PlaneLSM, named, whole, true},
		{"bpflsm without name rows", backend.TierBPFLSM, ebpfbindings.PlaneLSM, &decide.PlaneRows{}, whole, false},
		{"cgroup lsm with an entry left out by a cap", backend.TierCgroup, ebpfbindings.PlaneLSM, named, leftOut, false},
		{"bpflsm with an entry left out by a cap", backend.TierBPFLSM, ebpfbindings.PlaneLSM, named, leftOut, false},
		{"bpflsm without its table", backend.TierBPFLSM, ebpfbindings.PlaneLSM, named, nil, false},
	} {
		h := &Handle{opts: Options{Tier: tc.tier}, planeMode: tc.mode, planeRows: tc.rows, table: tc.table}
		if got := h.Capabilities().Has(backend.CapReadDenyCreatedLater); got != tc.want {
			t.Errorf("%s: fs.deny_read.created_later %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestNoListenerWithoutFSRules asserts a contract with no fs rules creates no fanotify group at all, and that
// its run reports the two capabilities the group would have provided as absent.
func TestNoListenerWithoutFSRules(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Deliberate kernel-input counterfactual: no FS, exec or name rows. A real compile
	// carries implicit entries and its command grant; this test isolates R8.
	f.table.FS, f.table.Exec, f.table.NameDeny = nil, nil, nil
	f.table.Contract.Exec = nil
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()

	if h.fan != nil {
		t.Fatal("a contract with no fs rules must not open a fanotify group (§5 R8)")
	}
	set := h.Capabilities()
	if set[backend.CapReadDeny] || set[backend.CapExecDeny] {
		t.Fatal("without a listener, deny_read and exec denial are not provided")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.RunListener(ctx); err != nil {
		t.Fatalf("RunListener without a listener = %v, want nil", err)
	}
}

// TestInheritedTier1 asserts the composition seam: a tier-2 run still hands back tier 1's ruleset and filter,
// and reports none when the caller composed none.
func TestInheritedTier1(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(o *Options) {
		o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
			return fakeInherited{fd: 42}, nil
		}
	})
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if fd, ok := h.LandlockRuleset(); !ok || fd != 42 {
		t.Fatalf("LandlockRuleset = %d, %v", fd, ok)
	}
	if prog, ok := h.SeccompFilter(); !ok || len(prog) == 0 {
		t.Fatalf("SeccompFilter = %d instructions, %v", len(prog), ok)
	}

	plain := newFixture(t)
	ph, err := plain.backend.Prepare(context.Background(), plain.table, plain.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer ph.Close()
	if fd, ok := ph.LandlockRuleset(); ok || fd != -1 {
		t.Fatalf("with no Inherit, LandlockRuleset = %d, %v", fd, ok)
	}
	if prog, ok := ph.SeccompFilter(); ok || prog != nil {
		t.Fatalf("with no Inherit, SeccompFilter = %v, %v", prog, ok)
	}
}

// TestInheritFailureUnwinds asserts a failure in the composition seam leaves no kernel state behind either.
func TestInheritFailureUnwinds(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(o *Options) {
		o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
			return nil, errors.New("no landlock here")
		}
	})
	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded with a failing Inherit")
	}
	if len(f.kernel.runs) != 0 || !f.kernel.closed {
		t.Fatalf("state survived: runs=%+v closed=%v", f.kernel.runs, f.kernel.closed)
	}
}

// TestBackendIdentity asserts the two facts the selector relies on.
func TestBackendIdentity(t *testing.T) {
	t.Parallel()
	b := New(Options{})
	if b.Tier() != backend.TierCgroup {
		t.Fatalf("Tier = %s", b.Tier())
	}
	if !b.Capabilities()[backend.CapRecordExecOpenNet] {
		t.Fatal("tier 2 provides the eBPF record")
	}
}

// TestBuildHashWithoutObjects asserts a binary built without the compiled objects says so, with the fix, and
// creates nothing on the way (§7's load-failure row).
func TestBuildHashWithoutObjects(t *testing.T) {
	t.Parallel()
	if ebpfbindings.Available() {
		t.Skip("this binary carries the objects; the no-objects path is exercised in an untagged build")
	}
	b := New(Options{BPFFS: t.TempDir(), StateDir: t.TempDir()})
	_, err := b.Prepare(context.Background(), &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull},
		Run{ID: "r", CgroupID: 1, CgroupPath: "/x"})
	if !errors.Is(err, ErrProgramLoad) {
		t.Fatalf("Prepare without objects = %v, want ErrProgramLoad", err)
	}
	if !strings.Contains(err.Error(), "tegobpf") {
		t.Fatalf("the error does not name the fix: %v", err)
	}
}

// fakeInherited stands in for the tier-1 handle the composition root supplies.
type fakeInherited struct{ fd int }

func (f fakeInherited) LandlockRuleset() (int, bool) { return f.fd, true }
func (f fakeInherited) SeccompFilter() ([]bpf.RawInstruction, bool) {
	return []bpf.RawInstruction{{Op: 6}}, true
}

// TestPrepareReadsCarriedSlotsUnderTheSlotLock is ADR 0026 (6) against a launcher that dies in the gap: Prepare
// reads the run set's carried slots while it holds the slot table's lock, as purgeDeadSlots does. Read before the
// lock, a launcher that inserted its row and was killed before the lock was taken would have its slot look held
// by a dead owner and not carried, and be reclaimed while its orphans' row still carries it.
func TestPrepareReadsCarriedSlotsUnderTheSlotLock(t *testing.T) {
	t.Parallel()
	var dir string
	var locked, asked bool
	f := newFixture(t, func(o *Options) {
		o.carriedSlots = func(string) (map[uint32]bool, error) {
			asked = true
			tf, err := os.OpenFile(filepath.Join(dir, slotTableName+"-testhash"), os.O_RDWR, 0)
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil // not even created yet, so certainly not locked
			}
			if err != nil {
				return nil, err
			}
			defer func() { _ = tf.Close() }()
			err = unix.Flock(int(tf.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if err == nil {
				_ = unix.Flock(int(tf.Fd()), unix.LOCK_UN)
			}
			locked = errors.Is(err, unix.EWOULDBLOCK)
			return nil, nil
		}
	})
	dir = f.dir
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = h.Detach() })
	if !asked {
		t.Fatal("Prepare never read the carried slots")
	}
	if !locked {
		t.Fatal("Prepare read the carried slots without holding the slot table's lock")
	}
}
