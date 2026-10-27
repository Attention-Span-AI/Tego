// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGateSumsReadAndWriteKindsOfOneEnd: the scores of every rule an action matches sum
// (ADR 0007, 2026-10-20), but an action the gate scores by both fs kinds (a read-write open, a rename's or hard link's
// source) kept the stronger of the two kinds' scores, the highest-rule reading the package rejected. Under
// `fs.read matches "*.env": 45` and `fs.write outside worktree: 45` with {allow: 50, ask: 80}, an O_RDWR open of
// /out/prod.env and its rename away were continued at 45; summed they score 90 and are refused. A move is one action
// over its two ends: a write rule matching both ends counts once, and a read rule on the
// source adds to a write rule on the destination, so renaming /work/prod.env out of the worktree, continued at 45
// while each end was its own action, is refused at 90 too.
func TestGateSumsReadAndWriteKindsOfOneEnd(t *testing.T) {
	const pathAddr, path2Addr = 0x10000, 0x11000
	fs := []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}, {Path: "/out", Kind: agent.FSWrite}}
	g, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "*.env", Score: 45}, {Predicate: gate.WriteOutsideWorktree, Score: 45}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		syscall  string
		from, to string
		flags    uint64
		refused  bool
	}{
		{"read-write open outside the worktree of a matching name", "openat", "/out/prod.env", "", unix.O_RDWR, true},
		{"read-only creating open outside the worktree of a matching name", "openat", "/out/prod.env", "", unix.O_RDONLY | unix.O_CREAT, true},
		{"write-only open outside the worktree of a matching name", "openat", "/out/prod.env", "", unix.O_WRONLY, false},
		{"read-write open in the worktree of a matching name", "openat", "/work/prod.env", "", unix.O_RDWR, false},
		{"read-write open outside the worktree of another name", "openat", "/out/notes", "", unix.O_RDWR, false},
		{"rename a matching name outside the worktree away", "renameat", "/out/prod.env", "/out/notes", 0, true},
		{"link a matching name outside the worktree", "linkat", "/out/prod.env", "/work/notes", 0, true},
		{"exchange a file with a matching name outside the worktree", "renameat2", "/out/notes", "/out/prod.env", unix.RENAME_EXCHANGE, true},
		{"rename a file onto a matching name outside the worktree", "renameat", "/out/notes", "/out/prod.env", 0, false},
		{"rename a matching name out of the worktree", "renameat", "/work/prod.env", "/out/notes", 0, true},
		{"link a matching name out of the worktree", "linkat", "/work/prod.env", "/out/notes", 0, true},
		{"rename another name out of the worktree", "renameat", "/work/notes", "/out/notes", 0, false},
		{"rename a matching name within the worktree", "renameat", "/work/prod.env", "/work/notes", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.from))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Workdir = "/work"
			pol.Rules.Gate = g
			l, sink := newTestLoop(t, f, pol)
			if tc.to == "" {
				l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, tc.flags))
			} else {
				f.put(path2Addr, cstr(tc.to))
				l.handle(notifFor(nrFor(t, tc.syscall), 42, argCWD, pathAddr, argCWD, path2Addr, tc.flags))
			}
			got, _ := f.lastResp()
			ev := sink.one(t)
			p := gateLineOf(t, ev)
			if !tc.refused {
				if got.Flags == 0 || ev.Verdict == record.VerdictRefused || p.Score == nil || *p.Score != 45 {
					t.Fatalf("response %+v line %+v %s; want continued at score 45", got, ev, ev.Payload)
				}
				return
			}
			if got.Flags != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response %+v; want the gate's refusal", got)
			}
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate || p.Score == nil || *p.Score != 90 || p.GateOutcome != "refused" {
				t.Fatalf("line %+v %s; want refused fs-gate at the summed score 90", ev, ev.Payload)
			}
		})
	}
	// The open deputy holds a read-write open whose kinds escalate only together (openMayEscalate).
	if !openMayEscalate(g, unix.O_RDWR) || openMayEscalate(g, unix.O_WRONLY) || openMayEscalate(g, unix.O_RDONLY) {
		t.Fatalf("openMayEscalate: rdwr %t wronly %t rdonly %t", openMayEscalate(g, unix.O_RDWR), openMayEscalate(g, unix.O_WRONLY), openMayEscalate(g, unix.O_RDONLY))
	}
	if d := scoreOpen(g, gate.Allow, "/out/prod.env", unix.O_RDWR, "/work"); d.Score != 90 || d.Verdict != gate.Refused {
		t.Fatalf("scoreOpen O_RDWR: %+v", d)
	}
}
