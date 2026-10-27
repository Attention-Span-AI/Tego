// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// harnessRunStart is the run's run_start.harness, and the index of the first reason-unavailable gap (-1 for none).
func harnessRunStart(t *testing.T, evs []*record.Event) (*record.HarnessStart, int) {
	t.Helper()
	var p record.RunStartPayload
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart || evs[0].DecodePayload(&p) != nil {
		t.Fatal("no run_start")
	}
	gap := -1
	for i, e := range evs {
		var g record.GapPayload
		if gap < 0 && e.Kind == record.KindGap && e.DecodePayload(&g) == nil && g.What == record.GapRecord && g.Why == GapReasonUnavailable {
			gap = i
		}
	}
	return p.Harness, gap
}

// TestIntegrationHarnessFilesAreReadOnlyAndHookStateWritable is agent-contract.md R27's acceptance (4) at tier
// landlock through the real runner.run: a fake provisioner gives the run a settings file and names it and hook-state/
// to the agent; the shell agent writes hook-state/x, and its writes to the settings file and to last-refusal.json fail
// EACCES (Landlock: neither lies under a write grant). run_start says what was provisioned, with the grant.
func TestIntegrationHarnessFilesAreReadOnlyAndHookStateWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory, so it provisions nothing (TestIntegrationHarnessWithNoRuntimeDirectory)")
	}
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
	f := newFixture(t, "version: 0\nname: iharness\ncommand: [/bin/sh]\ntier: landlock\nharness: generic\nenv:\n  pass: [PATH, HOME]\nlimits:\n  pids: 64\n")
	deps := f.deps(t, nil)
	p := &fakeProvisioner{fn: func(run harness.Run) harness.Provision {
		settings := filepath.Join(run.RuntimeDir, "settings.json")
		return harness.Provision{
			Env:   []string{"TEGO_T_SETTINGS=" + settings, "TEGO_T_STATE=" + run.StateDir},
			Files: []harness.File{{Dir: harness.Runtime, Name: "settings.json", Bytes: []byte("{}\n")}},
			Hook:  &harness.Hook{Argv: []string{run.TegoExe, "hook", "generic"}},
		}
	}}
	deps.Harness = func(harness.Name) Provisioner { return p }
	out := filepath.Join(t.TempDir(), "stdout")
	o, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	deps.Stdio.Out = o
	// Each refused write must be EACCES ("Permission denied"), not a missing file or another errno.
	script := `echo ok > "$TEGO_T_STATE/x" || exit 3; [ "$(cat "$TEGO_T_STATE/x")" = ok ] || exit 4; ` +
		`[ "$(cat "$TEGO_T_SETTINGS")" = "{}" ] || exit 5; ` +
		`e=$( { echo y > "$TEGO_T_SETTINGS"; } 2>&1 ) && exit 6; case "$e" in *"Permission denied"*) ;; *) echo "settings: $e"; exit 7;; esac; ` +
		`e=$( { echo y > "$TEGO_REASON"; } 2>&1 ) && exit 8; case "$e" in *"Permission denied"*) ;; *) echo "reason: $e"; exit 9;; esac; ` +
		`echo done`
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", script}, deps)
	_ = o.Close()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, _ := os.ReadFile(out)
	if res.ExitCode != 0 || strings.TrimSpace(string(b)) != "done" {
		t.Fatalf("exit %d, stdout %q: 3-4 hook-state not writable, 5 settings unreadable, 6-9 a write that was not refused EACCES", res.ExitCode, b)
	}
	h, gap := harnessRunStart(t, events(t, runDirs(t, f.root)[0]))
	if h == nil || !h.Provisioned || h.Name != "generic" || len(h.Files) != 1 || !strings.HasSuffix(h.Files[0], "/settings.json") ||
		!strings.HasSuffix(h.StateDir, "/hook-state") || gap >= 0 {
		t.Fatalf("run_start.harness %+v, reason-unavailable gap at %d; want provisioned and no gap", h, gap)
	}
}

// TestIntegrationHarnessWithNoRuntimeDirectory is acceptance (7) through the real runner.run: with no XDG_RUNTIME_DIR
// (or as root, whose launcher makes no runtime directory) nothing is provisioned, run_start says reason-unavailable,
// and the gap what=record why=reason-unavailable is written after run_start. harness: none writes neither.
func TestIntegrationHarnessWithNoRuntimeDirectory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	for _, h := range []string{"auto", "none"} {
		f := newFixture(t, "version: 0\nname: iharnessnodir\ncommand: [/bin/true]\nharness: "+h+"\nlimits:\n  pids: 64\n")
		deps := f.deps(t, nil)
		p := &fakeProvisioner{p: harness.Provision{Files: []harness.File{{Dir: harness.Runtime, Name: "x", Bytes: []byte("x")}}}}
		deps.Harness = func(harness.Name) Provisioner { return p }
		res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("%s: Run: %+v %v", h, res, err)
		}
		start, gap := harnessRunStart(t, events(t, runDirs(t, f.root)[0]))
		if len(p.runs) != 0 {
			t.Errorf("%s: the provisioner was asked with no runtime directory", h)
		}
		if h == "none" {
			if start != nil || gap >= 0 {
				t.Errorf("none: run_start.harness %+v, gap at %d; want neither", start, gap)
			}
			continue
		}
		if start == nil || start.Provisioned || start.Why != record.HarnessWhyReasonUnavailable || start.Name != "generic" || gap < 1 {
			t.Errorf("auto: run_start.harness %+v, gap at %d; want generic, reason-unavailable, and the gap after run_start", start, gap)
		}
	}
}
