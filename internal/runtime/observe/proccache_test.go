// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// writeProc writes one fake /proc/<pid> entry; startTicks is field 22 of stat.
func writeProc(t *testing.T, root string, pid, ppid int, comm, exe string, argv []string, startTicks uint64) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tail := []string{"S", strconv.Itoa(ppid)}
	for len(tail) < 17 {
		tail = append(tail, "0")
	}
	tail = append(tail, "1", "0", strconv.FormatUint(startTicks, 10)) // fields 20, 21, 22
	line := strconv.Itoa(pid) + " (" + comm + ") " + strings.Join(tail, " ") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/tego/run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if exe != "" {
		link := filepath.Join(dir, "exe")
		if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Symlink(exe, link); err != nil {
			t.Fatal(err)
		}
	}
}

// TestProcCacheKeepsNoCommandLine is the cache's bound. A /proc rebuild read the whole process, its cmdline among it
// (up to 1 MiB, internal/platform/proc), and kept the argv in the entry though nothing read it: the ledger's argv
// comes from the exec sample. An agent's processes that the recorder first meets by an open, forked children it never
// saw exec, held the launcher at up to 8 GiB at DefaultProcCacheSize. Sixteen such entries, 1 MB of cmdline each,
// must leave the cache holding well under one of them.
func TestProcCacheKeepsNoCommandLine(t *testing.T) {
	procRoot := t.TempDir()
	big := strings.Repeat("A", 100_000)
	argv := make([]string, 10) // ~1 MB, within ARG_MAX: ten arguments below MAX_ARG_STRLEN each
	for i := range argv {
		argv[i] = big
	}
	const n = 16
	for i := range n {
		writeProc(t, procRoot, 1000+i, 1, "a", "/usr/bin/a", argv, uint64(100+i))
	}
	var before, after goruntime.MemStats
	goruntime.GC()
	goruntime.ReadMemStats(&before)
	c := newProcCache(proc.NewAt(procRoot), "r-1", 0)
	for i := range n {
		if _, ok := c.lookup(1000+i, 0); !ok { // what handleOpen does for a child it never saw exec
			t.Fatalf("pid %d missed", 1000+i)
		}
	}
	goruntime.GC()
	goruntime.ReadMemStats(&after)
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	goruntime.KeepAlive(c)
	if held > 1<<20 {
		t.Errorf("%d cached processes hold %d KiB after a collection; at DefaultProcCacheSize (%d) that is %d MiB",
			n, held>>10, DefaultProcCacheSize, held/n*DefaultProcCacheSize>>20)
	}
}

// TestProcCacheRebuildsFromProc is docs/p0/enforce-cgroup-observe.md §6 E13: a recorder restarted mid-run has lost its
// process cache, and the next event for an uncached pid rebuilds the entry from /proc.
func TestProcCacheRebuildsFromProc(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 100, 1, "python3", "/usr/bin/python3.12", []string{"python3", "app.py"}, 900)
	c := newProcCache(proc.NewAt(root), "r-1", 0)

	e, ok := c.lookup(100, 0)
	if !ok {
		t.Fatal("first lookup missed")
	}
	wantID := "r-1/100/" + strconv.FormatUint(900*proc.NanosPerTick, 10)
	if e.ExecID != wantID {
		t.Errorf("exec id %q, want %q", e.ExecID, wantID)
	}
	if !e.FromProc {
		t.Error("an entry built from /proc must say so")
	}
	if c.rebuilds != 1 {
		t.Errorf("%d rebuilds", c.rebuilds)
	}
	if _, ok := c.lookup(100, 0); !ok || c.rebuilds != 1 {
		t.Errorf("second lookup rebuilt: %d", c.rebuilds)
	}
}

// TestProcCacheAdoptsTheExactStartTime is the tick-resolution reconciliation: /proc rounds a start
// time down to a USER_HZ tick, the kernel's own value is exact, and the two must name one process
// with one exec id. The id must not change when the exact time is adopted: events already written
// under the /proc-derived id, and the supervisor's exec lines, which only ever have the /proc value,
// would otherwise name the process differently from every event after it.
func TestProcCacheAdoptsTheExactStartTime(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 101, 1, "sh", "/bin/sh", []string{"sh"}, 900)
	c := newProcCache(proc.NewAt(root), "r-1", 0)
	seeded, ok := c.lookup(101, 0)
	if !ok {
		t.Fatal("seed lookup missed")
	}
	exact := 900*proc.NanosPerTick + 3_000_000 // 3 ms into the same tick
	e, ok := c.lookup(101, uint64(exact))
	if !ok {
		t.Fatal("lookup with the exact time missed")
	}
	if e.FromProc || e.StartBootNS != uint64(exact) {
		t.Error("the entry should have adopted the exact kernel time")
	}
	if want := "r-1/101/" + strconv.Itoa(900*proc.NanosPerTick); e.ExecID != want || seeded.ExecID != want {
		t.Errorf("exec id %q after adoption, %q before, want %q both times", e.ExecID, seeded.ExecID, want)
	}
	if c.rebuilds != 1 || c.reused != 0 {
		t.Errorf("rebuilds %d reused %d: the tick difference must not look like pid reuse", c.rebuilds, c.reused)
	}
}

// TestProcCachePidReuse is E14: a cache hit whose start time names a different process is a miss.
func TestProcCachePidReuse(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 102, 1, "old", "/bin/old", []string{"old"}, 900)
	c := newProcCache(proc.NewAt(root), "r-1", 0)
	first, _ := c.lookup(102, 0)

	// The pid is reused seconds later by a different binary.
	writeProc(t, root, 102, 1, "new", "/bin/new", []string{"new"}, 5000)
	second, ok := c.lookup(102, 5000*proc.NanosPerTick)
	if !ok {
		t.Fatal("lookup after reuse missed")
	}
	if second.ExecID == first.ExecID {
		t.Fatalf("the reused pid inherited the exec id %q", second.ExecID)
	}
	if second.StartBootNS != 5000*proc.NanosPerTick {
		t.Errorf("start %d, the old occupant's entry", second.StartBootNS)
	}
	if c.reused != 1 || c.rebuilds != 2 {
		t.Errorf("reused %d rebuilds %d", c.reused, c.rebuilds)
	}
}

func TestProcCacheGonePid(t *testing.T) {
	c := newProcCache(proc.NewAt(t.TempDir()), "r-1", 0)
	e, ok := c.lookup(4242, 0)
	if ok {
		t.Fatal("a pid with no /proc entry must miss")
	}
	if e.ExecID != ExecIDUnknown {
		t.Errorf("exec id %q, want %q", e.ExecID, ExecIDUnknown)
	}
	if c.gone != 1 {
		t.Errorf("gone %d", c.gone)
	}
	// With a start time from the sample the exec id is still derivable without /proc, at the tick the
	// id always carries.
	e, ok = c.lookup(4243, 7*proc.NanosPerTick+777)
	if ok || e.ExecID != "r-1/4243/"+strconv.Itoa(7*proc.NanosPerTick) {
		t.Errorf("entry %+v ok %v", e, ok)
	}
}

func TestProcCacheExecEventWins(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 103, 1, "sh", "/bin/sh", []string{"sh"}, 900)
	c := newProcCache(proc.NewAt(root), "r-1", 0)
	if _, ok := c.lookup(103, 0); !ok {
		t.Fatal("seed lookup missed")
	}
	rec := Record{Header: Header{PID: 103, PPID: 7}}
	rec.Exec = ExecBody{StartBootNS: 123456789, Comm: "python3", Path: "/usr/bin/python3.12", Argv: []string{"python3", "-m", "pytest"}}
	e := c.observeExec(103, &rec)
	// 123456789 ns is 12 whole ticks and change: the id carries the tick, like one built from /proc.
	if e.ExecID != "r-1/103/120000000" || e.FromProc {
		t.Fatalf("entry %+v", e)
	}
	got, ok := c.lookup(103, 123456789)
	if !ok || got.ExecID != e.ExecID {
		t.Errorf("the exec entry did not replace the /proc one: %+v", got)
	}
}

func TestProcCacheParentAndEviction(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 200, 1, "parent", "/bin/parent", []string{"parent"}, 100)
	c := newProcCache(proc.NewAt(root), "r-1", 0)
	parent, _ := c.lookup(200, 0)
	if got := c.parentExecID(200, 0); got != parent.ExecID {
		t.Errorf("parentExecID = %q", got)
	}
	// The exec sample's exact time of the parent names the entry /proc rounded down to its tick.
	if got := c.parentExecID(200, 100*proc.NanosPerTick+5); got != parent.ExecID {
		t.Errorf("parentExecID with the parent's exact start = %q", got)
	}
	// Another process of the pid is not the parent (§6 E14): the cached entry's id is not the one named; the
	// parent that started at the sample's time is named by that time.
	if got := c.parentExecID(200, 300*proc.NanosPerTick); got == parent.ExecID || got != c.execID(200, 300*proc.NanosPerTick) {
		t.Errorf("a parent that started later than the cached process was named %q", got)
	}
	if got := c.parentExecID(999, 0); got != "" {
		t.Errorf("an unknown parent must be empty, got %q", got)
	}
	if got := c.parentExecID(0, 0); got != "" {
		t.Errorf("pid 0 must be empty, got %q", got)
	}
	// An exit of another process of the pid leaves the entry; its own evicts it.
	c.evictExited(200, 300*proc.NanosPerTick)
	if c.len() != 1 {
		t.Errorf("the exit of another process of the pid evicted its entry")
	}
	c.evictExited(200, 100*proc.NanosPerTick+5)
	if c.len() != 0 {
		t.Errorf("evict left %d entries", c.len())
	}
	c.evictExited(200, 0) // idempotent
}

// TestProcCacheRebuildOfAnExitedProcess: a sample of a process that has exited and whose pid /proc already shows in
// its next process's hands gets the sample's own exec id, and the next process's entry is not taken for it (§6 E14).
func TestProcCacheRebuildOfAnExitedProcess(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 300, 1, "next", "/bin/next", []string{"next"}, 5000)
	c := newProcCache(proc.NewAt(root), "r-1", 0)
	e, ok := c.lookup(300, 100*proc.NanosPerTick)
	if ok || e.ExecID != "r-1/300/"+strconv.Itoa(100*proc.NanosPerTick) {
		t.Errorf("entry %+v ok %v, want the exited process's own id and a miss", e, ok)
	}
	if c.len() != 0 {
		t.Errorf("the next process's entry was cached for the exited one's sample")
	}
}

func TestProcCacheIsBounded(t *testing.T) {
	c := newProcCache(proc.NewAt(t.TempDir()), "r-1", 3)
	for pid := 1; pid <= 10; pid++ {
		c.put(pid, procEntry{ExecID: "e", StartBootNS: uint64(pid)})
	}
	if c.len() > 3 {
		t.Fatalf("cache grew to %d entries past its cap of 3", c.len())
	}
	// The least recently stored entry is the one dropped.
	if _, ok := c.peek(1); ok {
		t.Error("the least recently used entry should have been evicted first")
	}
	if _, ok := c.peek(10); !ok {
		t.Error("the newest entry should still be cached")
	}
}

// TestProcCacheEvictsABatchOfTheLeastUsed pins the eviction policy and the batching. The cap exists to
// survive a process storm, and a full scan per insert is worst under exactly that load: the goroutine
// doing it is the one that has to keep draining the ring buffer.
func TestProcCacheEvictsABatchOfTheLeastUsed(t *testing.T) {
	const max = 64
	c := newProcCache(nil, "r-test", max)
	for i := 1; i <= max; i++ {
		c.put(i, procEntry{ExecID: "e", StartBootNS: uint64(i)})
	}
	if c.len() != max {
		t.Fatalf("len %d, want the cache full at %d", c.len(), max)
	}

	// The insert that overflows drops a batch, not one entry, so the next max/evictFraction inserts
	// do no scanning at all.
	c.put(max+1, procEntry{ExecID: "e", StartBootNS: uint64(max + 1)})
	batch := max / evictFraction
	if want := max - batch + 1; c.len() != want {
		t.Fatalf("len %d after the overflowing insert, want %d (a batch of %d dropped)", c.len(), want, batch)
	}
	// The dropped entries are the least recently stored ones, and the newest is kept.
	for pid := 1; pid <= batch; pid++ {
		if _, ok := c.peek(pid); ok {
			t.Errorf("pid %d was used least recently and survived eviction", pid)
		}
	}
	for pid := batch + 1; pid <= max+1; pid++ {
		if _, ok := c.peek(pid); !ok {
			t.Errorf("pid %d was evicted although later entries exist", pid)
		}
	}

	// Filling back to the cap must not evict again until the cap is actually reached.
	for i := 0; i < batch-1; i++ {
		c.put(1000+i, procEntry{ExecID: "e", StartBootNS: uint64(1000 + i)})
	}
	if c.len() != max {
		t.Fatalf("len %d, want the cache back at its cap %d without an extra eviction", c.len(), max)
	}
}

// TestProcCacheCapKeepsTheLiveAncestors pins what the cap evicts: the entries used least recently, not the
// earliest started. The earliest started are the agent's root and its long-lived shells, alive and exec'ing
// children; parentExecID never rebuilds an evicted parent from /proc, so evicting them by start time left every
// later child exec with no parent in the ledger. A root that its children's execs keep naming, and a process
// whose actions keep finding it, survive a storm of short-lived entries that nobody uses again.
func TestProcCacheCapKeepsTheLiveAncestors(t *testing.T) {
	const max = 64
	c := newProcCache(proc.NewAt(t.TempDir()), "r-test", max)
	c.put(1, procEntry{ExecID: "root", StartBootNS: 1}) // the agent's root, started first
	c.put(2, procEntry{ExecID: "shell", StartBootNS: 2})
	for pid := 3; pid <= 4*max; pid++ {
		// A storm of children whose exit samples were lost: each exec names the root as its parent, and the
		// shell's own actions find it.
		if got := c.parentExecID(1, 0); got != "root" {
			t.Fatalf("pid %d: parentExecID(root) = %q, want root: the live root was evicted", pid, got)
		}
		if e, ok := c.lookup(2, 0); !ok || e.ExecID != "shell" {
			t.Fatalf("pid %d: lookup(shell) = %+v, %v: the live shell was evicted", pid, e, ok)
		}
		c.put(pid, procEntry{ExecID: "child", StartBootNS: uint64(pid)})
		if c.len() > max {
			t.Fatalf("cache grew to %d past its cap of %d", c.len(), max)
		}
	}
	if _, ok := c.peek(3); ok {
		t.Error("the least recently used child survived eviction")
	}
}

// TestProcCacheEvictionIsDeterministic covers the tie /proc makes ordinary: start times are reported at
// one USER_HZ tick, so many processes share one value and the choice must not depend on map order.
func TestProcCacheEvictionIsDeterministic(t *testing.T) {
	const max = 16
	var first []int
	for attempt := 0; attempt < 5; attempt++ {
		c := newProcCache(nil, "r-test", max)
		for i := 1; i <= max; i++ {
			c.put(i, procEntry{ExecID: "e", StartBootNS: 42}) // every entry the same tick
		}
		c.put(max+1, procEntry{ExecID: "e", StartBootNS: 42})
		var kept []int
		for pid := 1; pid <= max+1; pid++ {
			if _, ok := c.peek(pid); ok {
				kept = append(kept, pid)
			}
		}
		if attempt == 0 {
			first = kept
			continue
		}
		if len(kept) != len(first) {
			t.Fatalf("attempt %d kept %v, attempt 0 kept %v", attempt, kept, first)
		}
		for i := range kept {
			if kept[i] != first[i] {
				t.Fatalf("attempt %d kept %v, attempt 0 kept %v: eviction depends on map order", attempt, kept, first)
			}
		}
	}
}

// TestParentExecIDOfAForkOnlyParent: a parent that only forked (a subshell) has no cache entry, and its child's
// exec sample carries the parent's exact start time, which names it as it does at tier 1.
func TestParentExecIDOfAForkOnlyParent(t *testing.T) {
	c := newProcCache(proc.NewAt(t.TempDir()), "r-1", 0)
	want := string(proc.ExecID("r-1", 321, 5_000_000_000))
	if got := c.parentExecID(321, 5_000_000_000); got != want {
		t.Errorf("parentExecID = %q, want %q", got, want)
	}
	if got := c.parentExecID(321, 0); got != "" {
		t.Errorf("without a start time an unseen parent must stay unnamed, got %q", got)
	}
}

// TestProcCacheReadsAGonePidOnce: a process that exited behind the drain is read from /proc once, however
// many samples it left; a different start time of the same pid is another process and reads again.
func TestProcCacheReadsAGonePidOnce(t *testing.T) {
	c := newProcCache(proc.NewAt(t.TempDir()), "r-1", 0)
	const start = 7_000_000_000
	for i := 0; i < 5; i++ {
		e, ok := c.lookup(400, start)
		if ok || e.ExecID != string(proc.ExecID("r-1", 400, start)) {
			t.Fatalf("lookup %d = %+v, %v", i, e, ok)
		}
	}
	if c.rebuilds != 1 || c.gone != 1 {
		t.Errorf("rebuilds %d gone %d: a gone pid was re-read per sample", c.rebuilds, c.gone)
	}
	c.lookup(400, start+10*proc.NanosPerTick)
	if c.rebuilds != 2 {
		t.Errorf("a reused pid was served the previous occupant's result: rebuilds %d", c.rebuilds)
	}
	// A sample with no start time is never served from the memo.
	c.lookup(400, 0)
	c.lookup(400, 0)
	if c.rebuilds != 4 {
		t.Errorf("start 0 was memoised: rebuilds %d", c.rebuilds)
	}
}
