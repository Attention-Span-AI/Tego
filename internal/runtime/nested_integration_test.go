// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationANestedRunFailsAtStartAndLeavesTheOuterRunAlone, end to end: a
// `tego run` started by the agent of a run exits 125 at startup, before its own agent runs, and the outer
// run's supervisor goes on deciding the outer agent's syscalls as before — a write inside fs.write, an exec
// the contract allows, and a write outside it refused and recorded — to the outer run's own exit 0.
//
// A run cannot start inside a run: the kernel allows one seccomp listener per filter chain, so a nested run can never
// install its own. The launcher says so before anything else (cli.refuseNestedRun): its cgroup path shows the outer
// run, it names that run and exits 125 without holding itself undumpable, loading anything or starting a process. Until
// the hold came (C209) the nested launcher went on to its tier probe, whose NEW_LISTENER the kernel refuses (EBUSY: the
// enforced case) or to the clone3 the outer filter refuses (--observe inside --observe); an undumpable launcher there
// is refused its first file operation by the outer supervisor, which cannot read it, so the person would read
// "permission denied" (gate 20). Those later refusals stay behind the first for a nested launcher whose cgroup path
// does not show a run.
//
// Either way no process of the nested run exists and nothing of it reaches the outer run's Loop.
func TestIntegrationANestedRunFailsAtStartAndLeavesTheOuterRunAlone(t *testing.T) {
	for _, tc := range []struct {
		name         string
		outer, inner []string
		want         string // what the nested launcher's refusal names
	}{
		{"enforced", nil, nil, "a run cannot start inside a run"},
		{"observe in observe", []string{"--observe"}, []string{"--observe"}, "a run cannot start inside a run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nestedRun(t, tc.outer, tc.inner, tc.want)
		})
	}
}

func nestedRun(t *testing.T, outerFlags, innerFlags []string, want string) {
	// The nested launcher is a copy the dropped agent of a root run can reach and execute.
	bin := reachableCopy(t, tegoBinary(t), "tego")
	f := newFixture(t, strings.Replace(
		contractFor("inest", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/true", "/usr/bin/true", bin}),
		"  pass: [\"PATH\", \"HOME\"]", "  pass: [\"PATH\"]", 1))
	cfg := writeMachineConfig(t, f)

	// The nested launcher's own machine config names a ledger root inside the outer run's fs.write, and its
	// chain anchor and own log live there too, so the only thing that can stop it is what this test is about.
	innerLedger := filepath.Join(f.out, "ledger")
	innerHome := filepath.Join(f.out, "home")
	for _, d := range []string{innerLedger, innerHome} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	innerCfg := filepath.Join(f.dir, "inner-config.yaml")
	if err := os.WriteFile(innerCfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", innerLedger)), 0o600); err != nil {
		t.Fatal(err)
	}
	innerContract := filepath.Join(f.dir, "inner.yaml")
	if err := os.WriteFile(innerContract, []byte(`version: 0
name: inner
command: ["/bin/sh"]
exec:
  allow: ["/bin/sh"]
record: summary
`), 0o644); err != nil {
		t.Fatal(err)
	}
	innerRan := filepath.Join(f.out, "inner-ran")
	// A directory outside fs.write that the agent's uid owns, so only the outer run's enforcement refuses a
	// write there.
	other := filepath.Join(f.dir, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	refusedTarget := filepath.Join(other, "refused-after")
	script := filepath.Join(f.dir, "nest.sh")
	body := fmt.Sprintf(`#!/bin/sh
export TEGO_CONFIG=%q TEGO_TEST_CHAIN_ANCHOR=%q TEGO_TEST_OWN_LOG_HOME=%q HOME=%q
echo before > %q/before
%q run %s %q -- /bin/sh -c 'echo ran > %s'
echo "inner=$?"
echo after > %q/after
/bin/true && echo "exec-after ok"
if echo nope > %q; then echo "refused-after=0"; else echo "refused-after=1"; fi
`, innerCfg, filepath.Join(innerHome, "chain.log"), innerHome, innerHome, f.out, bin, strings.Join(innerFlags, " "),
		innerContract, innerRan, f.out, refusedTarget)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script, innerCfg, innerLedger, innerHome, other)

	args := append(append([]string{"run"}, outerFlags...), filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sh", script)
	cmd := exec.Command(bin, args...)
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("the outer run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, line := range []string{"inner=125", "exec-after ok"} {
		if !strings.Contains(out, line) {
			t.Errorf("the outer agent did not report %q:\n%s\nstderr:\n%s", line, out, stderr.String())
		}
	}
	t.Logf("the outer run's stderr, the nested launcher's refusal among it:\n%s", stderr.String())
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("the nested launcher's refusal does not name %q:\n%s", want, stderr.String())
	}
	if _, err := os.Stat(innerRan); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the nested run's agent ran (%v)", err)
	}
	for _, name := range []string{"before", "after"} {
		if _, err := os.Stat(filepath.Join(f.out, name)); err != nil {
			t.Errorf("the outer agent's write of %s inside fs.write: %v", name, err)
		}
	}

	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories under the outer ledger root %v, want the outer run's alone", dirs)
	}
	evs := events(t, dirs[0])
	end := runEndOf(t, dirs[0])
	if end.Reason != record.RunEndExit || end.ExitCode != 0 {
		t.Fatalf("the outer run ended %s %d, want exit 0", end.Reason, end.ExitCode)
	}
	if len(outerFlags) == 0 {
		// An enforced outer run refuses the write outside fs.write after the nested attempt, and records it.
		if _, err := os.Stat(refusedTarget); !strings.Contains(out, "refused-after=1") || !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the write outside fs.write after the nested attempt was not refused (%v):\n%s", err, out)
		}
		var found bool
		for _, e := range evs {
			if e.Kind == record.KindRefused && bytes.Contains(e.Payload, []byte("refused-after")) {
				found = true
			}
		}
		if !found {
			t.Errorf("no refused line for %s after the nested attempt: %v", refusedTarget, kinds(evs))
		}
	}
	// The nested run left no run of its own that started.
	if ents, _ := os.ReadDir(innerLedger); len(ents) != 0 {
		for _, e := range ents {
			if hasRunStart(filepath.Join(innerLedger, e.Name())) {
				t.Errorf("the nested run started a run: %s", e.Name())
			}
		}
	}
}
