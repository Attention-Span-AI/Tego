// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// reasonReadsScene is one run through the real binary at tier landlock under record: summary: an agent (/bin/sh,
// harness auto, so generic) whose HOME is a fake home, the project, cats a key planted in that home's .ssh, which the
// contract's deny_read covers and the Landlock ruleset refuses, cats an allowed file, and copies its reason file. tego
// reads the built-in list's home from the passwd database, never HOME (identity-config R21), so the fake home's .ssh
// is declared: the same row the built-in ~/.ssh entry is for a real home. fsExtra is added to the fs: section and
// extra to the contract's top level. It returns the scene, the run's ledger and the key's path.
func reasonReadsScene(t *testing.T, fsExtra, extra string) (*askReadScene, []*record.Event, string) {
	t.Helper()
	bin := tegoBinary(t)
	var allow []string
	for _, name := range []string{"sh", "cat", "sleep"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("no %s: %v", name, err)
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{p, real} {
			if q := fmt.Sprintf("%q", q); !slices.Contains(allow, q) {
				allow = append(allow, q)
			}
		}
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: ireasonreads
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
  deny_read: [%q]
%sexec:
  allow: [%s]
env:
  pass: ["PATH"]
  set: {HOME: %q}
limits:
  pids: 64
record: summary
%s`, filepath.Join(project, ".ssh"), fsExtra, strings.Join(allow, ", "), project, extra)
	// The key exists before compile, so the deny_read entry has a target.
	key := filepath.Join(project, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("PRIVATE-"+heldReadsSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Dir(key))
	agentOwns(t, key)
	s := &askReadScene{bin: bin}
	s.f = newFixtureIn(t, project, contract, nil)
	if err := os.WriteFile(filepath.Join(project, "allowed.txt"), []byte("benign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.f.out, "res"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := (`#!/bin/sh
r=out/res
cat "$HOME/.ssh/id_ed25519" > $r/key.out 2> $r/key.err; echo $? > $r/key.rc
cat allowed.txt > $r/allowed.out 2> $r/allowed.err; echo $? > $r/allowed.rc
if [ -n "$TEGO_REASON" ]; then
  i=0
  while [ ! -s "$TEGO_REASON" ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done
  cat "$TEGO_REASON" > $r/reason.json 2> $r/reason.err
fi
echo done > $r/done
`)
	if err := os.WriteFile(filepath.Join(project, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwnsTree(t, s.f.out)
	agentOwns(t, filepath.Join(project, "agent.sh"))
	s.env = isolatedEnv(t, s.f)
	evs := s.runToEnd(t)
	if s.out("res/done") == "" {
		t.Fatalf("the agent did not run to its end: %q", s.out("res/key.err"))
	}
	// The read is refused as before, with Landlock's errno: nothing about the agent's view changes.
	if rc := strings.TrimSpace(s.out("res/key.rc")); rc == "0" || !strings.Contains(s.out("res/key.err"), "Permission denied") ||
		strings.Contains(s.out("res/key.out"), heldReadsSecret) {
		t.Fatalf("cat of the key: rc %s, stderr %q, stdout %q; want EACCES and no secret", rc, s.out("res/key.err"), s.out("res/key.out"))
	}
	if rc := strings.TrimSpace(s.out("res/allowed.rc")); rc != "0" {
		t.Fatalf("cat of an allowed file: rc %s, stderr %q", rc, s.out("res/allowed.err"))
	}
	return s, evs, key
}

// keyLines is the fs lines of evs whose path is key.
func keyLines(t *testing.T, evs []*record.Event, key string) []*record.Event {
	t.Helper()
	var out []*record.Event
	for _, e := range evs {
		var p record.FSPayload
		if e.Kind != record.KindFS || e.DecodePayload(&p) != nil || p.Path != key {
			continue
		}
		out = append(out, e)
	}
	return out
}

// reasonReadsStart is the ledger's run_start.
func reasonReadsStart(t *testing.T, evs []*record.Event) record.RunStartPayload {
	t.Helper()
	var p record.RunStartPayload
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart || evs[0].DecodePayload(&p) != nil {
		t.Fatalf("no run_start")
	}
	if p.RecordMinor < record.MinorReasonReads || p.ReadsNotified == nil {
		t.Fatalf("run_start record_minor %d, reads_notified %+v", p.RecordMinor, p.ReadsNotified)
	}
	return p
}

// TestIntegrationReasonReadsAtLandlock is ADR 0077's acceptance through the real binary: with a harness, reads not
// held and reason.reads: on (the default, auto, is the measured off), the agent's cat of a key in the fake home's
// ~/.ssh still gets EACCES from Landlock, and the run's ledger has exactly one line for it: refused read-denied under
// fs.deny_read[<home>/.ssh], mechanism landlock, which the reason file the agent reads holds (the rule is the declared
// fake home's .ssh, see reasonReadsScene). No allowed read is a line under summary.
func TestIntegrationReasonReadsAtLandlock(t *testing.T) {
	s, evs, key := reasonReadsScene(t, "", "reason:\n  reads: on\n")
	start := reasonReadsStart(t, evs)
	if !start.ReadsNotified.Notified || start.ReadsNotified.Why != record.ReadsNotifiedWhyReason {
		t.Errorf("reads_notified %+v, want notified, reason", start.ReadsNotified)
	}
	lines := keyLines(t, evs, key)
	if len(lines) != 1 {
		t.Fatalf("%d fs lines for the key, want exactly one: %v", len(lines), lines)
	}
	e := lines[0]
	var p record.FSPayload
	_ = e.DecodePayload(&p)
	if e.Verdict != record.VerdictRefused || e.Reason != record.ReasonReadDenied || e.Rule != "fs.deny_read["+filepath.Join(s.f.dir, ".ssh")+"]" ||
		p.Mechanism != record.MechanismLandlock || e.Source != record.SourceSeccomp {
		t.Errorf("the key's line: %s %s %s mechanism %q source %s; want refused read-denied fs.deny_read[<home>/.ssh] mechanism landlock",
			e.Verdict, e.Reason, e.Rule, p.Mechanism, e.Source)
	}
	for _, ev := range evs {
		var fp record.FSPayload
		if ev.Kind == record.KindFS && ev.DecodePayload(&fp) == nil && fp.Path == filepath.Join(s.f.dir, "allowed.txt") {
			t.Errorf("an allowed read has a line under record: summary: %s %s", ev.Verdict, ev.Rule)
		}
	}
	raw := s.out("res/reason.json")
	if os.Geteuid() == 0 {
		// A root launcher makes no runtime directory, so no TEGO_REASON (REASON-CHANNEL §2): the ledger's copy is the
		// same file.
		dirs := runDirs(t, s.f.root)
		b, _ := os.ReadFile(filepath.Join(dirs[len(dirs)-1], "last-refusal.json"))
		raw = string(b)
	}
	f, err := reason.Decode(strings.NewReader(raw))
	if err != nil || !slices.ContainsFunc(f.Recent, func(r reason.Entry) bool {
		return r.Target == key && r.Reason == record.ReasonReadDenied && r.Rule == e.Rule && r.Mechanism == record.MechanismLandlock
	}) {
		t.Errorf("the reason file read inside the run: %q (%q, %v), want the key's refusal, mechanism landlock, among its recent ones", raw, s.out("res/reason.err"), err)
	}
}

// TestIntegrationReasonReadsOffAtLandlock: with the default (reason.reads: auto, the measured off) or reason.reads: off
// the run is what it was before ADR 0077: the cat still gets EACCES, and under record: summary the refusal is
// Landlock's alone and no line; run_start says why.
func TestIntegrationReasonReadsOffAtLandlock(t *testing.T) {
	for _, tc := range []struct{ name, extra string }{{"default", ""}, {"off", "reason:\n  reads: off\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			_, evs, key := reasonReadsScene(t, "", tc.extra)
			start := reasonReadsStart(t, evs)
			if start.ReadsNotified.Notified || start.ReadsNotified.Why != record.ReadsNotifiedWhyReasonOff {
				t.Errorf("reads_notified %+v, want not notified, reason-off", start.ReadsNotified)
			}
			if lines := keyLines(t, evs, key); len(lines) != 0 {
				t.Errorf("%d fs lines for the key, want none", len(lines))
			}
		})
	}
}

// TestIntegrationReasonReadsUnderHeldReads: where the run holds its reads (fs.reads: held), reason.reads: on adds no
// second notify arm and no second line: the held floor's refusal of the key is its one line (ADR 0069, ADR 0077).
func TestIntegrationReasonReadsUnderHeldReads(t *testing.T) {
	_, evs, key := reasonReadsScene(t, "  reads: held\n", "reason:\n  reads: on\n")
	start := reasonReadsStart(t, evs)
	if !start.ReadsNotified.Notified || start.ReadsNotified.Why != record.ReadsNotifiedWhyHeld {
		t.Errorf("reads_notified %+v, want notified, held", start.ReadsNotified)
	}
	lines := keyLines(t, evs, key)
	if len(lines) != 1 || lines[0].Verdict != record.VerdictRefused || lines[0].Reason != record.ReasonReadDenied {
		t.Fatalf("fs lines for the key %v, want exactly one read-denied refusal", lines)
	}
}
