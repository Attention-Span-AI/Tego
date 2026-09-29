// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestExecQuietReadsNoArgv: under record: off an allowed exec writes no line, so its argv, up to 8192 pointers
// and 128 KiB read from the target while its exec is held, is not read at all; the verdict never depends on it.
// A refused exec, which is recorded, still reads it, as does every exec under record: full.
//
// Spec: docs/p0/supervisor.md R16.
func TestExecQuietReadsNoArgv(t *testing.T) {
	nr := nrFor(t, "execve")
	long := make([]string, 40)
	for i := range long {
		long[i] = "arg"
	}
	reads := func(mode agent.RecordMode, p string, argv []string) int {
		pol := searchPolicy()
		pol.Record = mode
		f := newFake()
		l, _ := newTestLoop(t, f, pol)
		before := f.memReads
		execAt(l, f, nr, 42, 0, p, argv...)
		return f.memReads - before
	}
	for _, tc := range []struct {
		name     string
		mode     agent.RecordMode
		path     string
		readArgv bool
	}{
		{"record: off, an allowed exec", agent.RecordOff, "/usr/bin/python3", false},
		{"record: off, a refused exec", agent.RecordOff, "/usr/local/bin/nmap", true},
		{"record: full, an allowed exec", agent.RecordFull, "/usr/bin/python3", true},
	} {
		short, many := reads(tc.mode, tc.path, []string{"x"}), reads(tc.mode, tc.path, long)
		if got := many > short; got != tc.readArgv {
			t.Errorf("%s: %d target reads with 40 args against %d with one: argv read=%v, want %v", tc.name, many, short, got, tc.readArgv)
		}
	}
}

// TestExecRecordOffUnreadablePathWritesNothing: under a contract with no exec: section an exec whose pathname
// is NULL, unreadable or empty is observed and continued. That is not a refusal, so record: off writes
// nothing for it, as emitFS drops the same case for a file operation. The exec was quiet only when allowed
// or a PATH-search candidate, and wrote `exec observed rule=args-unreadable`.
//
// Spec: docs/p0/record-ledger.md R12, docs/p0/supervisor.md R16.
func TestExecRecordOffUnreadablePathWritesNothing(t *testing.T) {
	nr := nrFor(t, "execve")
	for _, tc := range []struct {
		mode agent.RecordMode
		want int
	}{{agent.RecordOff, 0}, {agent.RecordSummary, 1}} {
		pol := contractPolicy(&agent.Contract{}, nil, nil)
		pol.Record = tc.mode
		f := newFake()
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(nr, 42, 0, 0, 0))
		if evs := sink.all(); len(evs) != tc.want {
			t.Errorf("record: %s: %d events for an exec with a NULL pathname, want %d: %+v", tc.mode, len(evs), tc.want, evs)
		}
	}
}
