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

// TestIntegrationANestedRunFailsAtStartAndLeavesTheOuterRunAlone is supervisor.md R20/E16 end to end: a
// `tego run` started by the agent of a run exits 125 at startup, before its own agent runs, and the outer
// run's supervisor goes on deciding the outer agent's syscalls as before — a write inside fs.write, an exec
// the contract allows, and a write outside it refused and recorded — to the outer run's own exit 0.
//
// The kernel allows one seccomp listener per filter chain, so a nested run can never install its own. Where
// the nested launcher meets that depends on how it is started, and each case is a subtest:
//
//   - enforced (tier auto or pinned): its selection probes tier 1 first, and doctor's seccomp self-test's
//     NEW_LISTENER fails EBUSY, so the nested run is refused as tier-unavailable, naming EBUSY;
//   - --observe inside an --observe run: no probe runs, and the nested launcher stops at the first step the
//     outer run's placement or filter refuses: as the user, its clone3, which the outer filter refuses (the
//     clone3 arm) before its child could ask for a listener; as a root run's dropped agent, placing its scope,
//     since the agent runs outside its user's delegated subtree.
//
// Either way no process of the nested run exists and nothing of it reaches the outer run's Loop.
func TestIntegrationANestedRunFailsAtStartAndLeavesTheOuterRunAlone(t *testing.T) {
	for _, tc := range []struct {
		name         string
		outer, inner []string
		want         string // what the nested launcher's refusal names; "" when that depends on the host
	}{
		{"enforced", nil, nil, "device or resource busy"},
		{"observe in observe", []string{"--observe"}, []string{"--observe"}, ""},
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
