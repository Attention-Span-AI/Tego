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

// generateLiveBlock writes spec/record/v1/fixtures/live-block.jsonl through the real Writer: a run at record_minor 21
// (MinorLiveBlock) whose contract allows curl and example.com:443. A person blocks the program live from the
// dashboard (a gap live-block-added line), the next curl is refused under live.block[exec:curl] with its refused
// mirror, a block of the destination added from the CLI refuses the next connect, both blocks are removed (two gap
// live-block-removed lines), the same exec and connect are then allowed under the contract's own entries, and an
// overlay the launcher could not read is one gap live-block-unreadable line. Its run_start carries launcher_uid and
// fs_reads, as every run_start at MinorRunIdentity and MinorHeldReads or later does.
func generateLiveBlock(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 912_345_000_000, time.Millisecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.Command = []string{"codex", "--no-daemon"}
	start.RecordMinor = record.MinorLiveBlock
	launcher := uint32(1000)
	start.LauncherUID = &launcher
	start.FSReads = &record.FSReads{Reads: record.FSReadsDirect, Why: record.FSReadsWhyNoneNested}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	at := fixedStart.Add(2 * time.Second).UTC()
	change := func(why, op, kind, value, by string, serial uint64) {
		rule := "live.block[" + kind + ":" + value + "]"
		f.emit(time.Millisecond, f.plain(record.KindGap, record.SourceSupervisor, 48211, 48211, record.GapPayload{
			What: record.GapEnforce, Why: why, LiveBlock: &record.LiveBlockChange{Op: op, Kind: kind, Value: value, Rule: rule,
				By: by, Serial: serial, At: at.Add(time.Duration(serial) * time.Second)}}))
	}
	curl := record.ExecPayload{Path: "/usr/bin/curl", Argv: []string{"curl", "-s", "https://example.com"}}
	dashboard, cli := "uid:1000 pid:51234 dashboard", "uid:1000 pid:51302 cli"
	change(record.GapLiveBlockAdded, "add", "exec", "curl", dashboard, 1)
	refusedExec := curl
	refusedExec.ExecID, refusedExec.Errno = f.execID(48240, 5_120_000_000), 13
	f.emit(time.Millisecond, f.action(record.KindExec, record.SourceSeccomp, fxTID, "live.block[exec:curl]", record.VerdictRefused,
		record.ReasonExecNotAllowed, record.Unattributed(), refusedExec))
	mirror := f.plain(record.KindRefused, record.SourceSeccomp, fxPID, fxTID, record.RefusedPayload{Op: "exec",
		Target: "/usr/bin/curl", Reason: record.ReasonExecNotAllowed, Rule: "live.block[exec:curl]"})
	mirror.Rule, mirror.Reason = "live.block[exec:curl]", record.ReasonExecNotAllowed
	f.emit(0, mirror)
	change(record.GapLiveBlockAdded, "add", "net", "example.com:443", cli, 2)
	f.emit(time.Millisecond, f.action(record.KindNet, record.SourceSupervisor, fxTID, "live.block[net:example.com:443]",
		record.VerdictRefused, record.ReasonNetNotAllowed, record.Unattributed(),
		record.NetPayload{Proto: "tcp", Dst: "93.184.216.34:443", Host: "example.com"}))
	netMirror := f.plain(record.KindRefused, record.SourceSupervisor, fxPID, fxTID, record.RefusedPayload{Op: "connect",
		Target: "93.184.216.34:443", Reason: record.ReasonNetNotAllowed, Rule: "live.block[net:example.com:443]"})
	netMirror.Rule, netMirror.Reason = "live.block[net:example.com:443]", record.ReasonNetNotAllowed
	f.emit(0, netMirror)
	change(record.GapLiveBlockRemoved, "remove", "exec", "curl", dashboard, 3)
	change(record.GapLiveBlockRemoved, "remove", "net", "example.com:443", cli, 4)
	allowedExec := curl
	allowedExec.ExecID = f.execID(48251, 5_220_000_000)
	f.emit(time.Millisecond, f.action(record.KindExec, record.SourceSeccomp, fxTID, "exec[/usr/bin/curl]", record.VerdictAllow,
		"", record.Unattributed(), allowedExec))
	f.emit(time.Millisecond, f.action(record.KindNet, record.SourceSupervisor, fxTID, "net[example.com:443]",
		record.VerdictAllow, "", record.Unattributed(), record.NetPayload{Proto: "tcp", Dst: "93.184.216.34:443", Host: "example.com"}))
	f.emit(time.Millisecond, f.plain(record.KindGap, record.SourceSupervisor, 48211, 48211,
		record.GapPayload{What: record.GapEnforce, Why: record.GapLiveBlockUnreadable}))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 4}}); err != nil {
		t.Fatal(err)
	}
}

// TestLiveBlockFixtureFrozen regenerates live-block.jsonl and compares it byte for byte with the committed file;
// -update rewrites it, as TestFixturesFrozen does for the others.
func TestLiveBlockFixtureFrozen(t *testing.T) {
	root := t.TempDir()
	generateLiveBlock(t, filepath.Join(root, testRef.ID), &memAnchor{})
	got := readFile(t, filepath.Join(root, testRef.ID, EventsFile))
	path := filepath.Join(fixturesDir, "live-block.jsonl")
	if *updateFixtures {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("live-block.jsonl: %v (run with -update to generate)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("live-block.jsonl differs from the generator output; run go test ./internal/ledger -run TestLiveBlockFixtureFrozen -update")
	}
}
