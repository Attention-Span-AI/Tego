// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// newTestTable builds a slot table in a temporary directory with a controllable liveness oracle.
func newTestTable(t *testing.T, dir string, alive func(owner) bool) *slotTable {
	t.Helper()
	s, err := openSlotTable(t, dir, "testhash")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	if alive != nil {
		s.alive = alive
	}
	return s
}

// The table owns a raw directory descriptor, so its lifetime is the test's:
// neither garbage collection nor t.TempDir's removal closes it.
func TestSlotTestHelperClosesOwnedDirectory(t *testing.T) {
	dir := t.TempDir()
	count := func(tb *testing.T) int {
		tb.Helper()
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			tb.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && target == dir {
				n++
			}
		}
		return n
	}
	before := count(t)
	var table *slotTable
	t.Run("actual-helper", func(t *testing.T) {
		table = newTestTable(t, dir, nil)
		if got := count(t); got != before+1 {
			t.Fatalf("table owns %d directory descriptors, want %d", got, before+1)
		}
	})
	// Also release on failure, so this regression never leaks the descriptor it
	// detects when exercised against a helper without registered cleanup.
	if table != nil {
		defer func() { _ = table.close() }()
	}
	if after := count(t); after != before {
		t.Fatalf("owned directory descriptors after subtest = %d, want %d", after, before)
	}
}

// A direct helper caller also owns its raw directory until test cleanup. The
// descriptor count is matched by inode, so removing a pathname cannot hide it.
func TestDirectSlotTableHelperClosesOwnedDirectory(t *testing.T) {
	for _, mode := range []string{"automatic", "explicit-close", "release-before-close"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			owned, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			count := func() int {
				t.Helper()
				entries, err := os.ReadDir("/proc/self/fd")
				if err != nil {
					t.Fatal(err)
				}
				n := 0
				for _, entry := range entries {
					if st, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name())); err == nil && os.SameFile(owned, st) {
						n++
					}
				}
				return n
			}
			before := count()
			var table *slotTable
			// Release the exact descriptor even when the original helper fails this
			// test, without relying on garbage collection or removing its name.
			defer func() { _ = table.close() }()
			t.Run("owner", func(t *testing.T) {
				table, err = openSlotTable(t, dir, "direct-helper")
				if err != nil {
					t.Fatal(err)
				}
				if got := count(); got != before+1 {
					t.Fatalf("helper owns %d directory descriptors, want %d", got, before+1)
				}
				switch mode {
				case "explicit-close":
					if err := table.close(); err != nil {
						t.Fatal(err)
					}
				case "release-before-close":
					idx, err := table.acquire(nil)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := table.release(idx); err != nil {
							t.Errorf("release before directory cleanup: %v", err)
						}
					})
				}
			})
			if after := count(); after != before {
				t.Fatalf("owned directory descriptors after helper caller = %d, want %d", after, before)
			}
		})
	}
}

// TestSlotAcquireRelease covers the ordinary lifecycle: slots come out dense and ascending, a released slot
// is reused, and releasing twice is not an error (§8 I10).
func TestSlotAcquireRelease(t *testing.T) {
	t.Parallel()
	s := newTestTable(t, t.TempDir(), nil)

	var got []uint32
	for i := 0; i < 5; i++ {
		idx, err := s.acquire(nil)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		got = append(got, idx)
	}
	for i, idx := range got {
		if idx != uint32(i) {
			t.Fatalf("slot %d = %d, want a dense ascending allocation %v", i, idx, got)
		}
	}
	if n, err := s.held(); err != nil || n != 5 {
		t.Fatalf("held = %d, %v; want 5", n, err)
	}
	if err := s.release(2); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := s.release(2); err != nil {
		t.Fatalf("release twice: %v", err)
	}
	next, err := s.acquire(nil)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if next != 2 {
		t.Fatalf("reused slot = %d, want the freed 2", next)
	}
}

// TestSlotReclaimsDeadOwner covers the leak the design must not have: a launcher that is killed without
// running Detach leaves an occupied record, and the next acquire takes it back.
func TestSlotReclaimsDeadOwner(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dead := newTestTable(t, dir, nil)
	dead.self = owner{PID: 4294967295, StartTicks: 1} // a pid that cannot exist
	idx, err := dead.acquire(nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if idx != 0 {
		t.Fatalf("first slot = %d", idx)
	}

	live := newTestTable(t, dir, nil)
	got, err := live.acquire(nil)
	if err != nil {
		t.Fatalf("acquire after a dead owner: %v", err)
	}
	if got != 0 {
		t.Fatalf("reclaimed slot = %d, want 0", got)
	}
	if n, err := live.held(); err != nil || n != 1 {
		t.Fatalf("held = %d, %v; want only the live holder", n, err)
	}
}

// TestSlotACarriedSlotStaysHeld is ADR 0026 (6): a dead launcher's slot that a run-set row still carries (its
// orphaned processes' cgroup) is not reclaimed, nor is a free slot a row carries, because the new run would
// receive that row's samples and rows; the next slot is taken instead. heldBy tells a live holder from a dead one.
func TestSlotACarriedSlotStaysHeld(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dead := newTestTable(t, dir, nil)
	dead.self = owner{PID: 4294967295, StartTicks: 1} // a pid that cannot exist
	if idx, err := dead.acquire(nil); err != nil || idx != 0 {
		t.Fatalf("acquire = %d, %v", idx, err)
	}
	live := newTestTable(t, dir, nil)
	if held, err := live.heldBy(0); err != nil || held {
		t.Fatalf("heldBy(0) = %v, %v for a dead owner", held, err)
	}
	got, err := live.acquire(func() (map[uint32]bool, error) { return map[uint32]bool{0: true, 1: true}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("acquire past carried slots 0 and 1 = %d, want 2", got)
	}
	if held, err := live.heldBy(2); err != nil || !held {
		t.Fatalf("heldBy(2) = %v, %v for this live process", held, err)
	}
}

// TestSlotReclaimsReusedPID covers the subtler leak: the owner's pid exists again, but it is a different
// process, so its start time differs and the slot is still free.
func TestSlotReclaimsReusedPID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stale := newTestTable(t, dir, nil)
	stale.self = owner{PID: uint32(os.Getpid()), StartTicks: stale.self.StartTicks + 1}
	if _, err := stale.acquire(nil); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	live := newTestTable(t, dir, nil)
	got, err := live.acquire(nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if got != 0 {
		t.Fatalf("slot %d taken; a record whose owner's start time differs is free", got)
	}
}

// TestSlotOnlyOwnerReleases asserts one launcher cannot free another's slot, which is what keeps run_idx from
// being handed out twice while rows still reference it (§5 R12, §8 I5).
func TestSlotOnlyOwnerReleases(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mine := newTestTable(t, dir, nil)
	idx, err := mine.acquire(nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	other := newTestTable(t, dir, func(owner) bool { return true })
	other.self = owner{PID: mine.self.PID + 1, StartTicks: 7}
	if err := other.release(idx); err != nil {
		t.Fatalf("release by a non-owner: %v", err)
	}
	if n, err := mine.held(); err != nil || n != 1 {
		t.Fatalf("held = %d, %v; a non-owner must not have freed the slot", n, err)
	}
}

// TestSlotOwnersNeedTheInitialPidNamespace: a slot's owner is a pid read back in /proc, and the table is shared by
// every launcher on the host. A launcher in a pid namespace of its own (sudo unshare -pf --mount-proc tego run)
// read the host launcher's pid as another process, took its live slot for a dead one and reclaimed it, and two
// runs shared a run_idx. The slot table is refused outside the initial pid namespace, and so is a namespace link
// that cannot be read.
func TestSlotOwnersNeedTheInitialPidNamespace(t *testing.T) {
	t.Parallel()
	other := filepath.Join(t.TempDir(), "pid") // a file whose inode is not PROC_PID_INIT_INO
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := initialPidNamespace(other); !errors.Is(err, ErrPidNamespace) {
		t.Errorf("another pid namespace: %v, want ErrPidNamespace", err)
	}
	if err := initialPidNamespace(filepath.Join(t.TempDir(), "gone")); !errors.Is(err, ErrPidNamespace) {
		t.Errorf("an unreadable namespace link: %v, want ErrPidNamespace", err)
	}
	if err := initialPidNamespace(selfPidNamespace); err != nil {
		t.Skipf("this test runs outside the initial pid namespace: %v", err)
	}
	if _, err := selfOwner(); err != nil {
		t.Errorf("selfOwner in the initial pid namespace: %v", err)
	}
}

// TestSlotExhaustion covers enforce-cgroup-observe.md §6 E12: when every slot is held by a live launcher, allocation fails with the
// error the launcher turns into exit 125, and leaves nothing behind.
func TestSlotExhaustion(t *testing.T) {
	t.Parallel()
	s := newTestTable(t, t.TempDir(), func(owner) bool { return true })
	for i := 0; i < bpf.MaxSlots; i++ {
		if _, err := s.acquire(nil); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if _, err := s.acquire(nil); !errors.Is(err, ErrSlotsExhausted) {
		t.Fatalf("acquire beyond capacity = %v, want ErrSlotsExhausted", err)
	}
	if n, err := s.held(); err != nil || n != bpf.MaxSlots {
		t.Fatalf("held = %d, %v", n, err)
	}
}

// TestSlotConcurrentGoroutines asserts no two callers in one process get the same slot.
func TestSlotConcurrentGoroutines(t *testing.T) {
	t.Parallel()
	s := newTestTable(t, t.TempDir(), func(owner) bool { return true })
	const n = 64
	var (
		mu   sync.Mutex
		seen = map[uint32]bool{}
		wg   sync.WaitGroup
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			idx, err := s.acquire(nil)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[idx] {
				t.Errorf("slot %d handed out twice", idx)
			}
			seen[idx] = true
		}()
	}
	wg.Wait()
	if len(seen) != n {
		t.Fatalf("%d distinct slots for %d callers", len(seen), n)
	}
}

// TestSlotConcurrentProcesses is the case enforce-cgroup-observe.md §6 E21 names and a Go mutex cannot cover: two launcher processes
// allocating at the same instant. It re-executes this test binary as helpers that take slots, report them and
// then hold them until the parent lets them exit, so what is asserted is disjointness between *live* holders;
// reclaiming a dead holder's slots is TestSlotProcessDeathReclaims below.
func TestSlotConcurrentProcesses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const procs, each = 4, 16

	type helper struct {
		cmd *exec.Cmd
		in  io.WriteCloser
		out string
	}
	helpers := make([]helper, procs)
	for i := range helpers {
		out := filepath.Join(dir, "out-"+itoa(i))
		cmd := exec.Command(os.Args[0], "-test.run=TestSlotHelper", "-test.v=false")
		cmd.Env = append(os.Environ(), "TEGO_SLOT_DIR="+dir, "TEGO_SLOT_OUT="+out,
			"TEGO_SLOT_COUNT="+itoa(each), "TEGO_SLOT_HOLD=1")
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatalf("stdin pipe: %v", err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper %d: %v", i, err)
		}
		helpers[i] = helper{cmd: cmd, in: in, out: out}
	}
	t.Cleanup(func() {
		for _, h := range helpers {
			h.in.Close()
			_ = h.cmd.Wait()
		}
	})

	// Wait until every helper has taken its slots while all of them are still alive.
	deadline := time.Now().Add(60 * time.Second)
	reports := make([]string, procs)
	for i, h := range helpers {
		for {
			b, err := os.ReadFile(h.out)
			if err == nil && len(b) > 0 && b[len(b)-1] == '\n' {
				reports[i] = string(b)
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("helper %d never reported its slots", i)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	seen := map[string]int{}
	for i, report := range reports {
		lines := splitLines(report)
		if len(lines) != each {
			t.Fatalf("helper %d reported %d slots, want %d", i, len(lines), each)
		}
		for _, line := range lines {
			seen[line]++
		}
	}
	if len(seen) != procs*each {
		t.Fatalf("%d distinct slots across %d live processes, want %d", len(seen), procs, procs*each)
	}
	for slot, n := range seen {
		if n != 1 {
			t.Fatalf("slot %s handed out to %d live processes at once", slot, n)
		}
	}
}

// TestSlotProcessDeathReclaims asserts the other half of E21's contract: a launcher that exits without
// releasing frees its slots for the next process, so a crash leaks nothing permanently.
func TestSlotProcessDeathReclaims(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	cmd := exec.Command(os.Args[0], "-test.run=TestSlotHelper", "-test.v=false")
	cmd.Env = append(os.Environ(), "TEGO_SLOT_DIR="+dir, "TEGO_SLOT_OUT="+out, "TEGO_SLOT_COUNT=8")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v (%s)", err, b)
	}
	report, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read helper report: %v", err)
	}
	if n := len(splitLines(string(report))); n != 8 {
		t.Fatalf("helper took %d slots", n)
	}

	s := newTestTable(t, dir, nil)
	if n, err := s.held(); err != nil || n != 0 {
		t.Fatalf("held = %d, %v; a dead launcher's slots are free", n, err)
	}
	idx, err := s.acquire(nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if idx != 0 {
		t.Fatalf("reclaimed slot = %d, want 0", idx)
	}
}

// TestSlotHelper is the child half of the two process tests. It does nothing in a normal run.
func TestSlotHelper(t *testing.T) {
	dir := os.Getenv("TEGO_SLOT_DIR")
	if dir == "" {
		t.Skip("helper process only")
	}
	count, err := strconv.Atoi(os.Getenv("TEGO_SLOT_COUNT"))
	if err != nil {
		t.Fatalf("TEGO_SLOT_COUNT: %v", err)
	}
	s, err := openSlotTable(t, dir, "testhash")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	defer func() { _ = s.close() }()
	var report strings.Builder
	for i := 0; i < count; i++ {
		idx, err := s.acquire(nil)
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		report.WriteString("SLOT " + itoa(int(idx)) + "\n")
	}
	if err := os.WriteFile(os.Getenv("TEGO_SLOT_OUT"), []byte(report.String()), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if os.Getenv("TEGO_SLOT_HOLD") != "" {
		// Hold the slots until the parent closes stdin, so it can compare live holders.
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
}

// TestSlotTableIsPerBuild asserts two build hashes have disjoint slot spaces, which is what keeps an upgrade
// mid-run from handing one run's index to another build's run (enforce-cgroup-observe.md §6 E22).
func TestSlotTableIsPerBuild(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, err := openSlotTable(t, dir, "aaaa")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	defer func() { _ = a.close() }()
	b, err := openSlotTable(t, dir, "bbbb")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	defer func() { _ = b.close() }()
	if a.path == b.path {
		t.Fatalf("two builds share one slot table at %s", a.path)
	}
	ia, err := a.acquire(nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ib, err := b.acquire(nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if ia != 0 || ib != 0 {
		t.Fatalf("slots %d and %d; each build's space starts at zero", ia, ib)
	}
	if filepath.Dir(a.path) != dir {
		t.Fatalf("slot table is outside the runtime directory: %s", a.path)
	}
}

// TestSlotReleaseOutOfRange asserts a nonsense index is reported, never applied.
func TestSlotReleaseOutOfRange(t *testing.T) {
	t.Parallel()
	s := newTestTable(t, t.TempDir(), nil)
	if err := s.release(bpf.MaxSlots); !errors.Is(err, ErrSlotsExhausted) {
		t.Fatalf("release(MaxSlots) = %v", err)
	}
}

// TestSlotAcquireProbesNoOwnerPastTheFreeSlot pins that acquire stops asking whether owners are alive once it
// has a slot to hand out: every probe reads /proc under the table's exclusive flock, which every launcher's
// acquire, release and heldBy wait on, and a probe after the first free slot changes nothing.
func TestSlotAcquireProbesNoOwnerPastTheFreeSlot(t *testing.T) {
	t.Parallel()
	s := newTestTable(t, t.TempDir(), func(owner) bool { return true })
	const occupied = 100
	for i := 0; i < occupied; i++ {
		if _, err := s.acquire(nil); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if err := s.release(0); err != nil {
		t.Fatalf("release: %v", err)
	}
	probes := 0
	s.alive = func(owner) bool { probes++; return true }
	idx, err := s.acquire(nil)
	if err != nil || idx != 0 {
		t.Fatalf("acquire = %d, %v; want slot 0", idx, err)
	}
	if probes != 0 {
		t.Fatalf("acquire probed %d owners after it had found free slot 0, want 0", probes)
	}
}

// TestSlotAnOwnerUnreadableButNotGoneKeepsItsSlot: only ErrProcGone says a slot's owner died. A /proc read that
// fails otherwise (EMFILE, ENOMEM) or a stat line not parsed says nothing of it, so acquire does not reclaim the
// slot and heldBy reports it held: taken for dead, a live launcher's run_idx would go to a second run.
func TestSlotAnOwnerUnreadableButNotGoneKeepsItsSlot(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		err     error
		reclaim bool
	}{
		{"emfile", fmt.Errorf("cgroup: read /proc/7/stat: %w", unix.EMFILE), false},
		{"enomem", fmt.Errorf("cgroup: read /proc/7/stat: %w", unix.ENOMEM), false},
		{"format", fmt.Errorf("%w: short line", ErrProcFormat), false},
		{"gone", fmt.Errorf("%w: pid 7", ErrProcGone), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			other := newTestTable(t, dir, nil)
			other.self = owner{PID: 7, StartTicks: 1}
			if idx, err := other.acquire(nil); err != nil || idx != 0 {
				t.Fatalf("acquire = %d, %v", idx, err)
			}
			s := newTestTable(t, dir, func(o owner) bool {
				return o.aliveBy(func(int) (uint64, error) { return 0, tc.err })
			})
			held, err := s.heldBy(0)
			if err != nil || held == tc.reclaim {
				t.Fatalf("heldBy(0) = %v, %v; want %v", held, err, !tc.reclaim)
			}
			got, err := s.acquire(nil)
			if err != nil {
				t.Fatal(err)
			}
			if want := map[bool]uint32{true: 0, false: 1}[tc.reclaim]; got != want {
				t.Fatalf("acquire = slot %d, want %d", got, want)
			}
		})
	}
}

// TestSlotEpochAdvancesAndSurvivesRelease: each acquire of a slot hands out that slot's next epoch, never 0 and never
// one it handed out before, and release keeps the epoch in the record (ADR 0025 (1)); a reclaim from a dead owner
// advances it too.
func TestSlotEpochAdvancesAndSurvivesRelease(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := newTestTable(t, dir, nil)
	seen := map[uint32]bool{}
	for i := 0; i < 5; i++ {
		idx, gen, err := s.acquireGen(nil)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		if idx != 0 || gen == 0 || seen[gen] {
			t.Fatalf("acquire %d: slot %d gen %d, want slot 0 with a fresh non-zero epoch (seen %v)", i, idx, gen, seen)
		}
		seen[gen] = true
		if err := s.release(idx); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
	if held, err := s.held(); err != nil || held != 0 {
		t.Fatalf("held = %d, %v after releasing every slot; an epoch must not read as in use", held, err)
	}
	dead := newTestTable(t, dir, nil)
	dead.self = owner{PID: 4294967295, StartTicks: 1}
	if _, _, err := dead.acquireGen(nil); err != nil {
		t.Fatal(err)
	}
	_, gen, err := s.acquireGen(nil)
	if err != nil || gen == 0 || seen[gen] {
		t.Fatalf("reclaimed slot's gen %d, %v; want a fresh epoch", gen, err)
	}
}

// TestSlotEpochWrapSkipsZero: the epoch is 31 bits above the in-use flag and wraps to 1, never to 0, which a
// cleared slot header holds.
func TestSlotEpochWrapSkipsZero(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ in, want uint32 }{{slotEpochMax, 1}, {0, 1}, {7, 8}} {
		if got := nextSlotEpoch(c.in); got != c.want {
			t.Errorf("nextSlotEpoch(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// held reports how many slots are currently occupied by a live owner, for the tests' occupancy checks. It
// takes the same lock as an allocation.
func (s *slotTable) held() (int, error) {
	n := 0
	err := s.withTable(func(_ *os.File, records []byte) error {
		for i := 0; i < bpf.MaxSlots; i++ {
			rec := records[i*slotRecordSize : (i+1)*slotRecordSize]
			if binary.LittleEndian.Uint32(rec[4:8])&slotFlagInUse == 0 {
				continue
			}
			o := owner{PID: binary.LittleEndian.Uint32(rec[0:4]), StartTicks: binary.LittleEndian.Uint64(rec[8:16])}
			if s.alive(o) {
				n++
			}
		}
		return nil
	})
	return n, err
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
