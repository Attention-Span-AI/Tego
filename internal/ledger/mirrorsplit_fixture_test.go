// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mirrorSplitRef is the mirror-split fixture's run: one whose refused lines do not each follow their action.
var mirrorSplitRef = record.RunRef{ID: runID(fixedStart, "m1rr0r"), Agent: "retriever"}

// generateMirrorSplit writes spec/record/v1/fixtures/mirror-split.jsonl through the real Writer: a run of three refused
// connects whose refused lines do not each follow their action. Each mirror is built as the runtime's pipeline builds
// it (mirrorRefusals): a copy of its action's envelope (pid, tid, cgroup, source and the monotonic clock the producer
// stamped at capture), rule and reason, with a refused payload naming the operation and the target. The Writer appends
// lines in the order its callers hand them over and a run has more than one caller, so here a write of another process
// lands between the agent's refused connect and its mirror, and two refused connects under the same rule and reason,
// git's and the agent's, both land before either mirror. A reader that pairs a mirror only with the line just before
// it counts five refusals in this run; there are three.
func generateMirrorSplit(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 812_345_000_000, time.Millisecond)
	w, err := Open(dir, mirrorSplitRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	const git, child = 48251, 48281 // a git fetch and a python3 child the agent started
	// connect is a refused connect of process pid, stamped at its capture as a producer stamps it; mirror is the
	// refused line the pipeline writes for it.
	connect := func(pid int, dst, host string) *record.Event {
		e := f.action(record.KindNet, record.SourceSupervisor, pid, "unmatched", record.VerdictRefused,
			record.ReasonNetNotAllowed, record.Unattributed(), record.NetPayload{Proto: "tcp", Dst: dst, Host: host})
		e.PID, e.MonoNS = pid, clk.Mono()
		return e
	}
	mirror := func(a *record.Event) *record.Event {
		var p record.NetPayload
		if err := a.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		m := *a
		m.Kind, m.Verdict, m.Authority, m.Attr = record.KindRefused, "", "", nil
		m.ID, m.Prev, m.Seq = "", "", 0
		if err := m.SetPayload(record.RefusedPayload{Op: "connect", Target: p.Dst}); err != nil {
			t.Fatal(err)
		}
		return &m
	}
	example := connect(fxPID, "93.184.216.34:443", "example.com")
	f.emit(time.Millisecond, example)
	write := f.action(record.KindFS, record.SourceLandlock, child, "fs.write[./out]", record.VerdictAllow, "",
		record.Unattributed(), record.FSPayload{Op: record.FSOpen, Path: "/home/u/proj/out/data.json", Flags: 0x241})
	write.PID = child
	f.emit(time.Millisecond, write)
	f.emit(0, mirror(example))
	fetch := connect(git, "140.82.112.3:443", "github.com")
	again := connect(fxPID, "93.184.216.34:443", "example.com")
	f.emit(time.Millisecond, fetch)
	f.emit(0, again)
	f.emit(0, mirror(fetch))
	f.emit(0, mirror(again))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 1,
		Supervisor: record.Supervisor{Notifications: 3}}); err != nil {
		t.Fatal(err)
	}
}

// TestMirrorSplitFixtureFrozen regenerates mirror-split.jsonl and compares it byte for byte with the committed file;
// -update rewrites it, as TestFixturesFrozen does for the others.
func TestMirrorSplitFixtureFrozen(t *testing.T) {
	root := t.TempDir()
	generateMirrorSplit(t, filepath.Join(root, mirrorSplitRef.ID), &memAnchor{})
	got := readFile(t, filepath.Join(root, mirrorSplitRef.ID, EventsFile))
	path := filepath.Join(fixturesDir, "mirror-split.jsonl")
	if *updateFixtures {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mirror-split.jsonl: %v (run with -update to generate)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("mirror-split.jsonl differs from the generator output; run go test ./internal/ledger -run TestMirrorSplitFixtureFrozen -update")
	}
}
