// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"cmp"
	"errors"
	"slices"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// DefaultProcCacheSize bounds the process cache. A run's process tree is small; the cap exists so a
// fork bomb inside the cgroup cannot grow userspace memory without limit while the pids controller
// is still deciding (docs/p0/enforce-cgroup-observe.md §6 E23's "bound memory" requirement).
const DefaultProcCacheSize = 8192

// ExecIDUnknown is the exec id of an action whose process could not be identified: the pid had
// already exited when /proc was read, and no exec event for it was ever seen (§7 "/proc read races
// an exited pid"). An event carrying it is recorded with attribution confidence unattributed.
const ExecIDUnknown = "unknown"

// procEntry is one process the recorder knows about: what attribution needs and nothing else, so an entry has
// a fixed size. It used to keep the process's path, comm and argv too, which nothing read (the ledger's come
// from the exec sample), and a /proc rebuild's argv was the whole cmdline, up to 1 MiB an entry: an agent's
// processes could hold the launcher at 8 GiB at DefaultProcCacheSize (§2.4).
type procEntry struct {
	ExecID      string
	StartBootNS uint64
	// FromProc marks a start time read from /proc, which has one USER_HZ tick of resolution; an
	// exec sample's task->start_boottime is exact and replaces it on first sight. The exec id does not
	// change when it does: proc.ExecID rounds both to the tick /proc reports.
	FromProc bool
	// used is the cache's clock when the entry was last stored or found: what the cap evicts by (put).
	used uint64
}

// procCache maps pid to process, filled from /proc the first time a pid is seen and from exec
// events after that (§2.4). It is owned by the single drain goroutine and takes no lock.
type procCache struct {
	fs    *proc.FS
	run   identity.RunID
	max   int
	byPID map[int]procEntry
	clock uint64 // advanced on every store and hit, so the least recently used entry has the smallest used

	// Counters for the run's log (Recorder.logProcCache), read after the drain goroutine has stopped.
	rebuilds uint64 // /proc reads caused by a cache miss
	gone     uint64 // pids that had already exited when /proc was read
	reused   uint64 // cache hits rejected because the start time named a different process

	// goneSeen remembers the last few (pid, start) whose /proc read found the process exited, with the id its
	// sample names, so a process that exited behind a backlogged drain costs one read, not one per sample.
	// Only a sample with a start time is remembered: the start names the process, so a reused pid is a
	// different key (§6 E14).
	goneSeen [goneSlots]goneEntry
	goneNext int
}

const goneSlots = 8

type goneEntry struct {
	pid   int
	start uint64
	e     procEntry
}

// newProcCache builds an empty cache. A nil fs reads the system's /proc.
func newProcCache(fs *proc.FS, run identity.RunID, max int) *procCache {
	if fs == nil {
		fs = proc.New()
	}
	if max <= 0 {
		max = DefaultProcCacheSize
	}
	return &procCache{fs: fs, run: run, max: max, byPID: make(map[int]procEntry)}
}

// lookup returns the process behind a pid. startBootNS is the sample's own idea of when the process
// started, 0 when the sample does not carry one; a cached entry whose start time names a different
// process is treated as a miss and rebuilt, which is what keeps a reused pid from inheriting the
// previous occupant's exec id (§6 E14). A pid that has already exited yields an entry with
// ExecIDUnknown and ok=false so the caller can degrade attribution.
func (c *procCache) lookup(pid int, startBootNS uint64) (procEntry, bool) {
	if e, hit := c.byPID[pid]; hit {
		switch {
		case startBootNS == 0, e.StartBootNS == startBootNS:
			return c.touch(pid, e), true
		case e.FromProc && proc.SameProcess(e.StartBootNS, startBootNS):
			// /proc rounded the same process down to a tick; keep the entry and its exec id, and adopt
			// the exact time so a later reuse check compares exact values.
			e.StartBootNS = startBootNS
			e.FromProc = false
			return c.touch(pid, e), true
		default:
			c.reused++
			delete(c.byPID, pid)
		}
	}
	return c.rebuild(pid, startBootNS)
}

// rebuild reads one pid's stat line out of /proc and caches it. The stat line is all an entry needs, and all
// it reads: bounded, where the process's cmdline is not (procEntry).
func (c *procCache) rebuild(pid int, startBootNS uint64) (procEntry, bool) {
	if startBootNS != 0 {
		for _, g := range c.goneSeen {
			if g.pid == pid && g.start == startBootNS {
				return g.e, false
			}
		}
	}
	c.rebuilds++
	st, err := c.fs.Stat(pid)
	if err != nil {
		e := procEntry{ExecID: ExecIDUnknown, StartBootNS: startBootNS}
		if startBootNS != 0 {
			e.ExecID = string(proc.ExecID(c.run, pid, startBootNS))
		}
		if errors.Is(err, proc.ErrGone) {
			c.gone++
			c.rememberGone(pid, startBootNS, e)
		}
		return e, false
	}
	start, fromProc := st.StartBootNS(), true
	switch {
	case startBootNS == 0:
	case proc.SameProcess(start, startBootNS):
		start, fromProc = startBootNS, false
	default:
		// /proc has the pid's next process: the sample's has exited, and taking /proc's for it would give its
		// actions the next one's exec id (§6 E14). Its own id is known from the sample; nothing is cached for it.
		c.gone++
		e := procEntry{ExecID: string(proc.ExecID(c.run, pid, startBootNS)), StartBootNS: startBootNS}
		c.rememberGone(pid, startBootNS, e)
		return e, false
	}
	e := procEntry{
		ExecID:      string(proc.ExecID(c.run, pid, start)),
		StartBootNS: start,
		FromProc:    fromProc,
	}
	c.put(pid, e)
	return e, true
}

// rememberGone stores a gone process's result in the next slot of a small ring; a sample with no start time is
// never remembered (see goneSeen).
func (c *procCache) rememberGone(pid int, start uint64, e procEntry) {
	if start == 0 {
		return
	}
	c.goneSeen[c.goneNext] = goneEntry{pid: pid, start: start, e: e}
	c.goneNext = (c.goneNext + 1) % goneSlots
}

// observeExec records what an exec sample says about a process, replacing whatever /proc guessed.
// The start time from the kernel is exact, so this is the authoritative entry.
func (c *procCache) observeExec(pid int, r *Record) procEntry {
	e := procEntry{
		ExecID:      string(proc.ExecID(c.run, pid, r.Exec.StartBootNS)),
		StartBootNS: r.Exec.StartBootNS,
	}
	c.put(pid, e)
	return e
}

// parentExecID is the exec id of a pid's parent, "" when the parent is not known. It is looked up
// without a /proc rebuild. start is the parent's start time as the exec sample read it: a cached entry of
// another process of that pid, one whose exit record was lost, is not the parent (§6 E14). With a start the
// parent's id is computed from it, cached or not: a parent that only forked (a subshell, a worker) has no
// entry, and its start time names it exactly, as it does at tier 1. 0 means the caller has none, and then a
// parent never seen is not reported, because guessing would attach the action to the wrong subtree.
func (c *procCache) parentExecID(ppid int, start uint64) string {
	if ppid <= 0 {
		return ""
	}
	if e, ok := c.byPID[ppid]; ok && (start == 0 || e.same(start)) {
		return c.touch(ppid, e).ExecID // a parent that execs children is in use, whatever it does itself
	}
	if start != 0 {
		return c.execID(ppid, start)
	}
	return ""
}

// touch stores e as just used, so the cap evicts it after every entry used less recently (put).
func (c *procCache) touch(pid int, e procEntry) procEntry {
	c.clock++
	e.used = c.clock
	c.byPID[pid] = e
	return e
}

// same reports whether an entry is the process that started at start: the exact time, or the tick /proc
// rounded it down to.
func (e procEntry) same(start uint64) bool {
	return e.StartBootNS == start || e.FromProc && proc.SameProcess(e.StartBootNS, start)
}

// peek looks a pid up in the cache without ever reading /proc: what an exit sample needs, since the
// process is on its way out and a /proc read would only race it (§7).
func (c *procCache) peek(pid int) (procEntry, bool) {
	e, ok := c.byPID[pid]
	return e, ok
}

// evictExited drops a pid's entry when it is the process that started at start, what an exit sample does, even
// under `record: off`, so the cache cannot grow for the lifetime of a long run (§6 E23). An entry of a later
// process of the pid, one the exit arrived behind, stays (§6 E14); start 0 evicts whatever the entry is.
func (c *procCache) evictExited(pid int, start uint64) {
	if e, ok := c.byPID[pid]; ok && (start == 0 || e.same(start)) {
		delete(c.byPID, pid)
	}
}

// execID is the exec id of the process pid names that started at start.
func (c *procCache) execID(pid int, start uint64) string {
	return string(proc.ExecID(c.run, pid, start))
}

// len is the number of cached processes.
func (c *procCache) len() int { return len(c.byPID) }

// evictFraction is how much of the cache one eviction pass clears: a full scan happens once per
// max/evictFraction inserts instead of once per insert, which is what makes the amortised cost of an
// insert constant rather than proportional to the cache.
const evictFraction = 8

// put stores an entry, making room first when the cache is at its cap by dropping the entries used least
// recently: stored, found by a lookup or named as an exec's parent longest ago. Those are the processes most
// likely to have exited without an exit event reaching us. The earliest-started are not: they are the agent's
// root and its long-lived shells and tool servers, and an evicted parent is never rebuilt for parentExecID,
// so evicting by start time cut every later exec of theirs off the process tree.
//
// It drops a batch rather than one. The cap exists to survive a process storm, and that is exactly
// when a scan per insert hurts: the drain goroutine that does this work is the same one that has to
// keep up with the ring buffer, so time spent here becomes dropped samples, which are gaps in the
// record under the load that produces the most to record. Eviction on exit normally keeps the cache
// far below its cap, so this path is reached only when exit samples are already being lost, which is
// the same overload.
func (c *procCache) put(pid int, e procEntry) {
	if _, present := c.byPID[pid]; !present && len(c.byPID) >= c.max {
		c.evictLeastUsed(max(1, c.max/evictFraction))
	}
	c.touch(pid, e)
}

// evictLeastUsed drops the n entries used least recently. The cache is bounded, so the sort is bounded work;
// doing it once per n inserts is the point.
func (c *procCache) evictLeastUsed(n int) {
	type aged struct {
		pid  int
		used uint64
	}
	all := make([]aged, 0, len(c.byPID))
	for p, v := range c.byPID {
		all = append(all, aged{pid: p, used: v.used})
	}
	// Ordered by last use, which the clock makes unique; by pid after it, so the choice never depends on map
	// order even for entries a test stores with the clock bypassed.
	slices.SortFunc(all, func(x, y aged) int {
		if x.used != y.used {
			return cmp.Compare(x.used, y.used)
		}
		return cmp.Compare(x.pid, y.pid)
	})
	if n > len(all) {
		n = len(all)
	}
	for _, a := range all[:n] {
		delete(c.byPID, a.pid)
	}
}
