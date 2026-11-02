// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationAdjustableFenceLiftAndRestore is ADR 0125 end to end through the real binary: an Adjustable run
// whose fence takes a deny_read folder out of the kernel layers starts with Tego's live layer refusing it, under
// live.fence[read:...]; a lift written to the run's overlay with a MAC under its key (as runact.Lift and `tego lift`
// do; the engine never imports the dashboard, ADR 0100 (1a)) lets the agent read it, recorded under
// the same rule; a restore refuses it again. Run as a user the run lands at tier landlock, which a product launcher
// refuses for Adjustable, so the tegotesthooks binary is told TEGO_TEST_LIVE_ANY_TIER=1; as root (VM_RUN) it lands
// at tier cgroup and needs no hook.
func TestIntegrationAdjustableFenceLiftAndRestore(t *testing.T) {
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
			if !slices.Contains(allow, fmt.Sprintf("%q", q)) {
				allow = append(allow, fmt.Sprintf("%q", q))
			}
		}
	}
	vault, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin, secret: filepath.Join(vault, "token")}
	if err := os.WriteFile(s.secret, []byte(realSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	// An exec fence entry that takes a program out of exec.deny under an exec.allow folder: once lifted, the folder
	// rule is what the kernel layers match, and its line must still name the fence entry (ADR 0125 decision 9).
	tools, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(tools, "hello")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	allow = append(allow, fmt.Sprintf("%q", tools+"/"))
	contract := fmt.Sprintf(`version: 0
name: ifence
command: ["/bin/sh"]
fs:
  write: ["./out/"]
  deny_read: [%q]
exec:
  allow: [%s]
  deny: [%q]
net: {}
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: full
live:
  mode: adjustable
  fence:
    read: [%q]
    exec: [%q]
`, vault, strings.Join(allow, ", "), filepath.Base(tool), vault, tool)
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.f = newFixtureIn(t, project, contract, nil)
	script := "#!/bin/sh\n" +
		"while [ ! -e out/stop ]; do\n" +
		"  if cat \"" + s.secret + "\" > out/got 2> out/err; then echo ok > out/state; else echo refused > out/state; fi\n" +
		"  if \"" + tool + "\" > out/xout 2>&1; then echo ok > out/xstate; else echo refused > out/xstate; fi\n" +
		"  sleep 0.1\n" +
		"done\n"
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, s.secret)
	agentOwns(t, s.secret, filepath.Join(s.f.dir, "agent.sh"))
	s.env = append(isolatedEnv(t, s.f), "TEGO_TEST_LIVE_ANY_TIER=1")

	run, dir := s.start(t)
	id := filepath.Base(dir)
	state := func(want string) {
		t.Helper()
		for _, f := range []string{"state", "xstate"} {
			ok := false
			for deadline := time.Now().Add(10 * time.Second); !ok && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
				if strings.TrimSpace(s.out(f)) == want {
					// Twice in a row: an action already under way when the change landed may still say the old state.
					time.Sleep(300 * time.Millisecond)
					ok = strings.TrimSpace(s.out(f)) == want
				}
			}
			if !ok {
				t.Fatalf("the agent's %s never became %q (now %q)", f, want, s.out(f))
			}
		}
	}
	state("refused")
	if _, err := os.Stat(filepath.Join(dir, "live-key")); err != nil {
		t.Fatalf("the Adjustable run has no live key: %v", err)
	}

	fenceChange(t, dir, id, liveblock.KindRead, vault, true)
	fenceChange(t, dir, id, liveblock.KindExec, tool, true)
	state("ok")
	// Each loop truncates out/got before cat writes it, so one read can fall between the two: poll for the secret.
	got := s.out("got")
	for deadline := time.Now().Add(5 * time.Second); got != realSecret && time.Now().Before(deadline); got = s.out("got") {
		time.Sleep(20 * time.Millisecond)
	}
	if got != realSecret {
		t.Fatalf("the lifted read gave %q", got)
	}
	fenceChange(t, dir, id, liveblock.KindRead, vault, false)
	fenceChange(t, dir, id, liveblock.KindExec, tool, false)
	state("refused")
	if err := os.WriteFile(filepath.Join(s.f.out, "stop"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	evs := s.finish(t, run, dir)

	start := runStartPayload(t, evs)
	// The tier the run landed at: cgroup as root with the BPF objects built in (VM_BPF=yes), landlock otherwise.
	t.Logf("run_start tier %s, euid %d", start.Tier, os.Geteuid())
	if start.LiveMode != record.LiveModeAdjustable || start.LiveFence == nil || len(start.LiveFence.Entries) != 2 {
		t.Fatalf("run_start live_mode %q, live_fence %+v", start.LiveMode, start.LiveFence)
	}
	rule, xrule := "live.fence[read:"+vault+"]", "live.fence[exec:"+tool+"]"
	var whys []string
	refused, allowed, xrefused, xallowed := 0, 0, 0, 0
	for _, e := range evs {
		switch e.Kind {
		case record.KindGap:
			var p record.GapPayload
			if e.DecodePayload(&p) == nil && p.LiveBlock != nil {
				whys = append(whys, p.Why)
				if p.LiveBlock.Rule != rule && p.LiveBlock.Rule != xrule {
					t.Errorf("gap %s under %q, want %q or %q", p.Why, p.LiveBlock.Rule, rule, xrule)
				}
			}
		case record.KindExec:
			var p record.ExecPayload
			if e.DecodePayload(&p) != nil || p.Path != tool {
				continue
			}
			switch {
			case e.Verdict == record.VerdictRefused && e.Rule == xrule:
				xrefused++
			case e.Verdict == record.VerdictAllow && e.Rule == xrule:
				xallowed++
			case e.Verdict == record.VerdictAllow:
				t.Errorf("an exec of the fenced program allowed under %q, want %q", e.Rule, xrule)
			}
		case record.KindFS:
			var p record.FSPayload
			if e.DecodePayload(&p) != nil || p.Path != s.secret {
				continue
			}
			switch {
			case e.Verdict == record.VerdictRefused && e.Rule == rule:
				refused++
			case e.Verdict == record.VerdictAllow && e.Rule == rule:
				allowed++
			case e.Verdict == record.VerdictAllow:
				t.Errorf("a read of the fenced file allowed under %q, want %q", e.Rule, rule)
			}
		}
	}
	if want := []string{record.GapLiveRuleLifted, record.GapLiveRuleLifted, record.GapLiveRuleRestored, record.GapLiveRuleRestored}; !slices.Equal(whys, want) {
		t.Fatalf("live lines %q, want %q", whys, want)
	}
	if refused == 0 || allowed == 0 {
		t.Fatalf("%d reads refused and %d allowed under %s: want both", refused, allowed, rule)
	}
	if xrefused == 0 || xallowed == 0 {
		t.Fatalf("%d execs refused and %d allowed under %s: want both", xrefused, xallowed, xrule)
	}
}

// fenceChange writes a lift (with no end, under a MAC with the run's key) or a restore of kind on value into the run's
// live overlay, as runact.Lift and runact.Restore do once their checks pass.
func fenceChange(t *testing.T, dir, run string, kind liveblock.Kind, value string, lift bool) {
	t.Helper()
	v, err := liveblock.Normalize(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	key, err := liveblock.ReadKey(dir)
	if err != nil {
		t.Fatalf("the run's key: %v", err)
	}
	if _, err := liveblock.Update(context.Background(), dir, run, func(o *liveblock.Overlay) (bool, error) {
		var err error
		if lift {
			_, err = o.Lift(kind, v, liveblock.By("cli"), time.Now(), time.Time{}, key)
		} else {
			_, err = o.Restore(kind, v, liveblock.By("cli"), time.Now())
		}
		return err == nil, err
	}); err != nil {
		t.Fatalf("lift %v of %s %s: %v", lift, kind, value, err)
	}
}
