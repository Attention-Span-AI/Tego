// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"sort"
	"strings"
)

// DefaultAggregateLimit bounds the aggregation table. A run that touches more distinct
// (exec id, rule) pairs than this flushes early rather than growing without limit; the flush is
// counted so the count in the ledger is still exact.
const DefaultAggregateLimit = 4096

// aggKey is one aggregation bucket: reads of one rule by one process (§5 R13).
type aggKey struct {
	ExecID string
	Rule   string
}

// aggEntry is the running count of one bucket.
type aggEntry struct {
	Count  uint64
	LastNS uint64
	// Path is the matched rule's path. A bucket no entry matched has none to name, and names the deepest
	// directory holding every file it counted (commonDir), the file itself while it counted one: it named the
	// first file it saw, so a count of two hundred reads read as reads of that one file (R13).
	Path   string
	PID    int
	TID    int
	Cgroup uint64
}

// aggregate is one flushed bucket, the shape the recorder turns into a single fs event.
type aggregate struct {
	aggKey
	aggEntry
}

// aggTable accumulates the reads that R13 does not record individually. It is owned by the drain
// goroutine and takes no lock.
//
// The buckets are indexed by exec id first because flushExec runs on every sched_process_exit sample,
// and a flat map would make each exit scan every bucket to find the handful belonging to one process.
// A workload that exits thousands of processes against a full table turns that into millions of map
// visits on the one goroutine that has to keep draining the ring buffer, and the cost surfaces as
// dropped samples: gaps in the record under exactly the load that produces the most to record.
type aggTable struct {
	m     map[string]map[string]aggEntry // exec id -> rule -> entry
	n     int                            // total buckets, so the cap check stays O(1)
	limit int
}

// newAggTable builds an empty table; limit <= 0 means DefaultAggregateLimit.
func newAggTable(limit int) *aggTable {
	if limit <= 0 {
		limit = DefaultAggregateLimit
	}
	return &aggTable{m: make(map[string]map[string]aggEntry), limit: limit}
}

// add counts one read and reports whether the table is now at its cap, which tells the caller to
// flush before the next add.
func (t *aggTable) add(k aggKey, e aggEntry) (full bool) {
	byRule, hasExec := t.m[k.ExecID]
	if !hasExec {
		byRule = map[string]aggEntry{}
		t.m[k.ExecID] = byRule
	}
	cur, ok := byRule[k.Rule]
	if !ok {
		cur = e
		cur.Count = 0
		t.n++
	}
	cur.Count++
	// LastNS takes the latest timestamp, not the latest arrival. The ring buffer preserves order
	// within one CPU and not across them, so a sample can arrive after one with a later timestamp;
	// assigning LastNS directly would drag the bucket's last-seen time backwards.
	if cur.LastNS == 0 || e.LastNS > cur.LastNS {
		cur.LastNS = e.LastNS
	}
	cur.PID, cur.TID, cur.Cgroup = e.PID, e.TID, e.Cgroup
	if ok && cur.Path != e.Path {
		cur.Path = commonDir(cur.Path, e.Path)
	}
	byRule[k.Rule] = cur
	return t.n >= t.limit
}

// commonDir is the deepest directory holding both a and b, compared on whole components; a itself when the two
// are one path. Both are absolute, as bpf_d_path and the declared entries are, so the answer is "/" at least.
func commonDir(a, b string) string {
	if a == b {
		return a
	}
	// end is the length of the common prefix that ends at a component boundary of both.
	end := 0
	for i := 0; i < len(a) && i < len(b) && a[i] == b[i]; i++ {
		if a[i] == '/' {
			end = i
		}
	}
	short, long := a, b
	if len(short) > len(long) {
		short, long = long, short
	}
	if strings.HasPrefix(long, short) && (short == "/" || long[len(short)] == '/') {
		return short // one is an ancestor of the other
	}
	if end == 0 {
		return "/"
	}
	return a[:end]
}

// flushExec removes and returns the buckets of one process, what sched_process_exit triggers so the
// count an exiting process leaves behind is final (R13). It touches only that process's own buckets,
// which is why the table is indexed by exec id.
func (t *aggTable) flushExec(execID string) []aggregate {
	byRule, ok := t.m[execID]
	if !ok {
		return nil
	}
	out := make([]aggregate, 0, len(byRule))
	for rule, v := range byRule {
		out = append(out, aggregate{aggKey: aggKey{ExecID: execID, Rule: rule}, aggEntry: v})
	}
	delete(t.m, execID)
	t.n -= len(out)
	return sorted(out)
}

// flushAll removes and returns every bucket, what the periodic tick and Stop do.
func (t *aggTable) flushAll() []aggregate {
	if t.n == 0 {
		return nil
	}
	out := make([]aggregate, 0, t.n)
	for execID, byRule := range t.m {
		for rule, v := range byRule {
			out = append(out, aggregate{aggKey: aggKey{ExecID: execID, Rule: rule}, aggEntry: v})
		}
	}
	t.m = make(map[string]map[string]aggEntry)
	t.n = 0
	return sorted(out)
}

// sorted orders a flush by exec id then rule so the ledger is byte-identical across runs of the same
// workload, which is what the golden fixtures compare.
func sorted(out []aggregate) []aggregate {
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExecID != out[j].ExecID {
			return out[i].ExecID < out[j].ExecID
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}
