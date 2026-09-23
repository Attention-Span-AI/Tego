// SPDX-License-Identifier: Apache-2.0

package observe

import "testing"

func TestAggTableCountsAndFlushes(t *testing.T) {
	tab := newAggTable(0)
	if tab.limit != DefaultAggregateLimit {
		t.Fatalf("max %d", tab.limit)
	}
	k1 := aggKey{ExecID: "run/1/10", Rule: "fs.write[./out]"}
	k2 := aggKey{ExecID: "run/1/10", Rule: RuleUnmatched}
	k3 := aggKey{ExecID: "run/2/20", Rule: RuleUnmatched}
	for i := 0; i < 5; i++ {
		tab.add(k1, aggEntry{LastNS: uint64(100 + i), Path: "/out", PID: 1})
	}
	tab.add(k2, aggEntry{LastNS: 50, Path: "/usr/lib", PID: 1})
	tab.add(k3, aggEntry{LastNS: 60, Path: "/usr/lib", PID: 2})

	out := tab.flushExec("run/1/10")
	if len(out) != 2 {
		t.Fatalf("flushExec returned %d buckets: %+v", len(out), out)
	}
	if out[0].Rule != "fs.write[./out]" || out[1].Rule != RuleUnmatched {
		t.Errorf("flush is not sorted by rule: %+v", out)
	}
	if out[0].Count != 5 || out[0].LastNS != 104 {
		t.Errorf("counts %+v", out[0])
	}
	if tab.len() != 1 {
		t.Errorf("flushExec left %d buckets", tab.len())
	}
	if again := tab.flushExec("run/1/10"); len(again) != 0 {
		t.Errorf("a second flush of the same process returned %d buckets", len(again))
	}
	all := tab.flushAll()
	if len(all) != 1 || all[0].ExecID != "run/2/20" || all[0].Count != 1 {
		t.Errorf("flushAll = %+v", all)
	}
	if tab.flushAll() != nil {
		t.Error("flushAll on an empty table must return nil")
	}
}

func TestAggTableReportsFull(t *testing.T) {
	tab := newAggTable(2)
	if full := tab.add(aggKey{ExecID: "a"}, aggEntry{LastNS: 1}); full {
		t.Error("one bucket of two is not full")
	}
	if full := tab.add(aggKey{ExecID: "b"}, aggEntry{LastNS: 1}); !full {
		t.Error("two buckets of two is full")
	}
	// A repeat of an existing key keeps reporting full without growing the table.
	if full := tab.add(aggKey{ExecID: "b"}, aggEntry{LastNS: 2}); !full || tab.len() != 2 {
		t.Errorf("full=%v len=%d", full, tab.len())
	}
}

// TestAggTableWindowSurvivesOutOfOrderSamples pins a bucket's last-seen time against the delivery
// order. The ring buffer preserves order within one CPU and not across them, so a sample timestamped
// earlier can arrive later. LastNS must be the latest timestamp, whichever
// order they turn up in; taking LastNS from the most recent arrival would drag the window's end
// backwards and understate how long the process was reading.
func TestAggTableWindowSurvivesOutOfOrderSamples(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []uint64
	}{
		{"in order", []uint64{100, 500}},
		{"out of order, as two CPUs can deliver", []uint64{500, 100}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tab := newAggTable(0)
			k := aggKey{ExecID: "run/1/10"}
			for _, ns := range tc.order {
				tab.add(k, aggEntry{LastNS: ns})
			}
			out := tab.flushAll()
			if out[0].LastNS != 500 || out[0].Count != 2 {
				t.Errorf("got %+v, want last 500 over 2 samples", out[0])
			}
		})
	}
}

// TestAggTableFlushExecTouchesOnlyThatProcess is the indexing guarantee: an exit flushes one process's
// buckets and leaves every other process's alone, without reading them.
//
// Also pins record-ledger.md E2: the aggregation window of an (exec, rule) closes when that exec ends.
func TestAggTableFlushExecTouchesOnlyThatProcess(t *testing.T) {
	tab := newAggTable(0)
	tab.add(aggKey{ExecID: "a", Rule: "fs.read[.]"}, aggEntry{LastNS: 1})
	tab.add(aggKey{ExecID: "a", Rule: "fs.write[./out]"}, aggEntry{LastNS: 2})
	tab.add(aggKey{ExecID: "b", Rule: "fs.read[.]"}, aggEntry{LastNS: 3})
	if tab.len() != 3 {
		t.Fatalf("len %d, want 3", tab.len())
	}
	out := tab.flushExec("a")
	if len(out) != 2 || out[0].ExecID != "a" || out[1].ExecID != "a" {
		t.Fatalf("flushExec(a) = %+v", out)
	}
	if tab.len() != 1 {
		t.Errorf("len %d after flushing a, want b's one bucket left", tab.len())
	}
	if rest := tab.flushAll(); len(rest) != 1 || rest[0].ExecID != "b" {
		t.Errorf("what remains is %+v, want b's bucket", rest)
	}
	if tab.len() != 0 {
		t.Errorf("len %d after flushAll", tab.len())
	}
	// An exec with no buckets is not an error and must not disturb the count.
	if out := tab.flushExec("never-seen"); out != nil || tab.len() != 0 {
		t.Errorf("flushExec on an unknown exec id returned %+v, len %d", out, tab.len())
	}
}

// TestAggTableNamesTheDirectoryItsReadsLieUnder is what an unmatched bucket's path says: with no entry to name, it
// named the first file it counted, so "count=200 path=os.py" read as two hundred reads of one file. It names the
// deepest directory holding every file it counted, which for a bucket of one file is that file.
func TestAggTableNamesTheDirectoryItsReadsLieUnder(t *testing.T) {
	tab := newAggTable(0)
	one := aggKey{ExecID: "run/1/10", Rule: RuleUnmatched}
	many := aggKey{ExecID: "run/2/20", Rule: RuleUnmatched}
	apart := aggKey{ExecID: "run/3/30", Rule: RuleUnmatched}
	tab.add(one, aggEntry{LastNS: 1, Path: "/usr/lib/python3.12/os.py"})
	tab.add(one, aggEntry{LastNS: 2, Path: "/usr/lib/python3.12/os.py"})
	for i, p := range []string{"/usr/lib/python3.12/os.py", "/usr/lib/python3.12/io.py",
		"/usr/lib/python3.12/json/__init__.py", "/usr/lib/python3.12/json/decoder.py"} {
		tab.add(many, aggEntry{LastNS: uint64(i + 1), Path: p})
	}
	tab.add(apart, aggEntry{LastNS: 1, Path: "/usr/lib/libc.so.6"})
	tab.add(apart, aggEntry{LastNS: 2, Path: "/etc/hosts"})
	want := map[string]string{"run/1/10": "/usr/lib/python3.12/os.py", "run/2/20": "/usr/lib/python3.12", "run/3/30": "/"}
	for _, a := range tab.flushAll() {
		if a.Path != want[a.ExecID] {
			t.Errorf("%s: %d reads named %q, want %q", a.ExecID, a.Count, a.Path, want[a.ExecID])
		}
	}
}

func TestCommonDir(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"/usr/lib/a.so", "/usr/lib/a.so", "/usr/lib/a.so"},
		{"/usr/lib/a.so", "/usr/lib/a.so.1", "/usr/lib"},
		{"/usr/lib", "/usr/lib/x/y", "/usr/lib"},
		{"/usr/libexec/x", "/usr/lib/x", "/usr"},
		{"/a", "/b", "/"},
		{"/", "/b", "/"},
	} {
		if got := commonDir(tc.a, tc.b); got != tc.want {
			t.Errorf("commonDir(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
		if got := commonDir(tc.b, tc.a); got != tc.want {
			t.Errorf("commonDir(%q, %q) = %q, want %q", tc.b, tc.a, got, tc.want)
		}
	}
}
