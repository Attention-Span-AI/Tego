// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// emitted is the one event l.emit sends to the sink for a call of tid pid: kind, and verdict when it is not "".
func emitted(t *testing.T, l *Loop, sink *testSink, pid int, kind record.Kind, verdict record.Verdict) *record.Event {
	t.Helper()
	before := len(sink.all())
	ev := l.event(notifFor(1, pid), kind, record.SourceSeccomp)
	ev.Verdict = verdict
	l.emit(ev, map[string]string{"x": "y"})
	got := sink.all()
	if len(got) != before+1 {
		t.Fatalf("%d events after one emit, want %d", len(got), before+1)
	}
	return got[len(got)-1]
}

// TestARefusedLineCarriesItsLineage: a refused line (an action refused, which the pipeline mirrors into a refused
// line, or a refused line itself) names the refused process and each ancestor with its start time (the reason
// channel's ownership, ADR 0063), nearest first; an allowed line carries none; a cached answer is used while the
// start time holds and read again when the pid was reused; and a process that is gone makes an unowned line.
func TestARefusedLineCarriesItsLineage(t *testing.T) {
	f := newFake()
	f.stats[300] = procStat{ppid: 200, start: 30}
	f.stats[200] = procStat{ppid: 100, start: 20}
	f.stats[100] = procStat{ppid: 1, start: 10}
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	const want = "300:30,200:20,100:10"
	if ev := emitted(t, l, sink, 300, record.KindFS, record.VerdictRefused); ev.Lineage != want {
		t.Fatalf("lineage %q on a refused action, want the process, its parent and the harness above it", ev.Lineage)
	}
	if ev := emitted(t, l, sink, 300, record.KindRefused, ""); ev.Lineage != want {
		t.Errorf("lineage %q on a refused line, want %q", ev.Lineage, want)
	}
	if ev := emitted(t, l, sink, 300, record.KindFS, record.VerdictAllow); ev.Lineage != "" {
		t.Errorf("an allowed line carries lineage %q", ev.Lineage)
	}
	// The parent changed under the same start time: the cache answers (one stat read revalidates it).
	f.mu.Lock()
	f.stats[200] = procStat{ppid: 1, start: 20}
	f.mu.Unlock()
	if ev := emitted(t, l, sink, 300, record.KindRefused, ""); ev.Lineage != want {
		t.Errorf("a cached lineage was walked again: %q", ev.Lineage)
	}
	// Pid 300 is reused by a new process: the start time differs, so it is walked again.
	f.mu.Lock()
	f.stats[300] = procStat{ppid: 200, start: 31}
	f.mu.Unlock()
	if ev := emitted(t, l, sink, 300, record.KindRefused, ""); ev.Lineage != "300:31,200:20" {
		t.Errorf("a reused pid kept the old lineage: %q", ev.Lineage)
	}
	// Gone: unowned.
	if ev := emitted(t, l, sink, 999, record.KindRefused, ""); ev.Lineage != "" {
		t.Errorf("an unreadable process has lineage %q", ev.Lineage)
	}
}

// TestLineageIsBounded: a chain deeper than lineageDepth is cut there, and a loop in the parents ends at the bound.
func TestLineageIsBounded(t *testing.T) {
	f := newFake()
	f.stats[500] = procStat{ppid: 501, start: 1}
	f.stats[501] = procStat{ppid: 500, start: 2}
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	got := l.lineageOf(500)
	n := 1
	for _, c := range got {
		if c == ',' {
			n++
		}
	}
	if n != lineageDepth {
		t.Errorf("%d identities in %q, want the bound %d", n, got, lineageDepth)
	}
}
