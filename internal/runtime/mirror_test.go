// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// refusedFS is a refused fs action on path.
func refusedFS(t *testing.T, path string) *record.Event {
	t.Helper()
	ev := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, Rule: "unmatched",
		Verdict: record.VerdictRefused, Authority: record.AuthorityRule, Reason: record.ReasonWriteOutsideContract}
	if err := ev.SetPayload(record.FSPayload{Op: record.FSOpen, Path: path}); err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestTheRefusedMirrorKeepsALongTarget: the mirror was copied from the action after the ledger's stages
// rewrote it in place, and splitBlobs had already moved a path over 4 KiB to path_blob, so the refused line
// named no target. It is built first now.
func TestTheRefusedMirrorKeepsALongTarget(t *testing.T) {
	const id = "r-00000000-000000000000a-mirror"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "mirror"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	pipe := newPipeline(NewQueue(4), ledger.Sink(w.Append), w.RedactStage, w.SplitBlobsStage,
		runStamp{PID: 1, TID: 1, Cgroup: 1}, nil, nil, slog.New(slog.DiscardHandler))
	long := "/tmp/" + strings.Repeat("d/", 2600) + "secret"
	pipe.handle(refusedFS(t, long))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	var mirror *record.Event
	for _, e := range events(t, dir) {
		if e.Kind == record.KindRefused {
			mirror = e
		}
	}
	if mirror == nil {
		t.Fatal("no refused line")
	}
	var p map[string]any
	if err := mirror.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	target, _ := p["target"].(string)
	blob, _ := p["target_blob"].(string)
	if target == "" && blob == "" {
		t.Fatalf("the refused line names no target: %v", p)
	}
}

// TestNoMirrorForADroppedAction: a mirror written after its action's line was refused by the ledger was a
// refusal with no action behind it.
func TestNoMirrorForADroppedAction(t *testing.T) {
	var got []record.Kind
	terminal := func(ev *record.Event) error {
		if ev.Kind == record.KindFS {
			return errors.New("the ledger refused the action")
		}
		got = append(got, ev.Kind)
		return nil
	}
	pipe := newPipeline(NewQueue(4), terminal, ledger.RedactStage, passthroughStage,
		runStamp{PID: 1, TID: 1, Cgroup: 1}, nil, nil, slog.New(slog.DiscardHandler))
	pipe.handle(refusedFS(t, "/etc/shadow"))
	if len(got) != 0 {
		t.Fatalf("lines written %v, want no mirror of a dropped action", got)
	}
}

// TestTheRefusedMirrorNamesTheCommandRule: an exec a command rule refused is mirrored with command_rule and
// command_match (ADR 0048 (8), record-ledger), so a reader of refused lines alone (status, hooks, last-refusal)
// sees which command rule refused. The mirror copied op and target only. An exec no command rule refused carries
// neither.
func TestTheRefusedMirrorNamesTheCommandRule(t *testing.T) {
	const id = "r-00000000-000000000000a-cmdrul"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "cmdrule"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	pipe := newPipeline(NewQueue(4), ledger.Sink(w.Append), w.RedactStage, w.SplitBlobsStage,
		runStamp{PID: 1, TID: 1, Cgroup: 1}, nil, nil, slog.New(slog.DiscardHandler))
	for _, p := range []record.ExecPayload{
		{Path: "/usr/bin/git", Argv: []string{"git", "push"}, ExecID: id + "/2/1",
			CommandRule: "git push", CommandList: "deny", CommandMatch: "definite", CommandVia: "name"},
		{Path: "/usr/bin/curl", Argv: []string{"curl"}, ExecID: id + "/3/1"},
		// A command rule allowed this exec and the gate refused it: the mirror names the gate's refusal, not the
		// command rule that admitted it. command_list allow is not copied.
		{Path: "/usr/bin/gitgate", Argv: []string{"git", "status"}, ExecID: id + "/4/1",
			CommandRule: "git status", CommandList: "allow", CommandMatch: "definite", CommandVia: "name"},
		// A sentinel refusal (the argv bound) writes no command_list, so a stale prefix rule is never mirrored.
		{Path: "/usr/bin/gitbound", Argv: []string{"git", "log"}, ExecID: id + "/5/1",
			CommandRule: "git log --oneline", CommandMatch: "definite"},
	} {
		rule := map[string]string{"/usr/bin/git": "exec.deny[git push]", "/usr/bin/gitgate": "gate.rules[0]",
			"/usr/bin/gitbound": "args-unreadable"}[p.Path]
		if rule == "" {
			rule = "unmatched"
		}
		ev := &record.Event{Kind: record.KindExec, Source: record.SourceSupervisor, Rule: rule,
			Verdict: record.VerdictRefused, Authority: record.AuthorityRule, Reason: record.ReasonExecNotAllowed}
		if err := ev.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		pipe.handle(ev)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	got := map[string]record.RefusedPayload{}
	for _, e := range events(t, dir) {
		if e.Kind == record.KindRefused {
			var p record.RefusedPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			got[p.Target] = p
		}
	}
	if p := got["/usr/bin/git"]; p.CommandRule != "git push" || p.CommandMatch != "definite" || p.Rule != "exec.deny[git push]" {
		t.Errorf("the mirror of an exec.deny refusal: %+v, want command_rule git push, definite", p)
	}
	if p, ok := got["/usr/bin/curl"]; !ok || p.CommandRule != "" || p.CommandMatch != "" {
		t.Errorf("an image refusal's mirror: %+v (present %v), want no command rule", p, ok)
	}
	if p, ok := got["/usr/bin/gitgate"]; !ok || p.CommandRule != "" || p.CommandMatch != "" {
		t.Errorf("a gate refusal's mirror of a command-allowed exec: %+v (present %v), want no command rule", p, ok)
	}
	if p, ok := got["/usr/bin/gitbound"]; !ok || p.CommandRule != "" || p.CommandMatch != "" {
		t.Errorf("a sentinel (args-unreadable) refusal's mirror: %+v (present %v), want no command rule", p, ok)
	}
}

// TestTheRefusedMirrorNamesTheMechanism: an action line that names the mechanism that refused it (a read the Landlock
// ruleset refused, ADR 0077; a decision plane's refusal and its mode) is mirrored with mechanism and decision_plane, so
// the reason file a harness reads says which mechanism refused; a line that names none mirrors none.
func TestTheRefusedMirrorNamesTheMechanism(t *testing.T) {
	const id = "r-00000000-000000000000a-mechnm"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "mechanism"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	pipe := newPipeline(NewQueue(4), ledger.Sink(w.Append), w.RedactStage, w.SplitBlobsStage,
		runStamp{PID: 1, TID: 1, Cgroup: 1}, nil, nil, slog.New(slog.DiscardHandler))
	for _, p := range []record.FSPayload{
		{Op: record.FSOpen, Path: "/h/.ssh/id", Mechanism: record.MechanismLandlock},
		{Op: record.FSOpen, Path: "/h/.env", Mechanism: record.MechanismPlane, DecisionPlane: record.DecisionPlaneLSM},
		{Op: record.FSOpen, Path: "/h/plain"},
	} {
		ev := &record.Event{Kind: record.KindFS, Source: record.SourceSeccomp, Rule: "fs.deny_read[/h]",
			Verdict: record.VerdictRefused, Authority: record.AuthorityRule, Reason: record.ReasonReadDenied}
		if err := ev.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		pipe.handle(ev)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	got := map[string]record.RefusedPayload{}
	for _, e := range events(t, dir) {
		var p record.RefusedPayload
		if e.Kind == record.KindRefused && e.DecodePayload(&p) == nil {
			got[p.Target] = p
		}
	}
	if p := got["/h/.ssh/id"]; p.Mechanism != record.MechanismLandlock || p.DecisionPlane != "" {
		t.Errorf("the mirror of a read Landlock refused: %+v, want mechanism landlock", p)
	}
	if p := got["/h/.env"]; p.Mechanism != record.MechanismPlane || p.DecisionPlane != record.DecisionPlaneLSM {
		t.Errorf("the mirror of a plane refusal: %+v, want mechanism plane, decision_plane lsm", p)
	}
	if p, ok := got["/h/plain"]; !ok || p.Mechanism != "" || p.DecisionPlane != "" {
		t.Errorf("the mirror of a line naming no mechanism: %+v (present %v), want none", p, ok)
	}
}

// A second writer can append well beyond the old four-line pairing window.
func TestRefusedPairWithCompetingWriter(t *testing.T) {
	const id = "r-00000000-000000000000a-pairxx"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "pair"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"sh"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	terminal := func(e *record.Event) error {
		if err := w.Append(e); err != nil {
			return err
		}
		if e.Kind == record.KindFS {
			for range 8 {
				g := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
				_ = g.SetPayload(record.GapPayload{What: "record", Why: "queue-full"})
				if err := w.Append(g); err != nil {
					return err
				}
			}
		}
		return nil
	}
	pipe := newPipeline(NewQueue(4), terminal, w.RedactStage, w.SplitBlobsStage, runStamp{PID: 1, TID: 1}, nil, nil, slog.New(slog.DiscardHandler), w.AppendBatch)
	pipe.handle(refusedFS(t, "/work/private"))
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	evs := events(t, dir)
	var action, mirror uint64
	for _, e := range evs {
		if e.Kind == record.KindFS {
			action = e.Seq
		}
		if e.Kind == record.KindRefused {
			mirror = e.Seq
		}
	}
	if mirror != action+1 {
		t.Fatalf("action at %d, mirror at %d: competing appends split the pair", action, mirror)
	}
}
