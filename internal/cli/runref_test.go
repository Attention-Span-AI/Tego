// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestABareRunIDIsNeverTheCwdDirectory is R25's run argument: a bare run id names the run under the ledger
// root, as status and stop resolve it, even when the current directory holds a directory of that name. The
// agent knows its run id (TEGO_RUN_ID) and can write the project, so a ./<id>/ it planted there used to win
// over the real record in events, drift, measure and events --verify run from the project. ./<id> still
// names the local directory.
func TestABareRunIDIsNeverTheCwdDirectory(t *testing.T) {
	id, _ := verifiedRun(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	// A decoy with no events.jsonl: resolving to it is "no such run" (2) or a ledger that does not verify.
	if err := os.Mkdir(filepath.Join(cwd, id), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"events", id}, {"drift", id}, {"measure", id}, {"learn", id}, {"events", id, "--verify"}} {
		if code, out, errs := run(t, args...); code != identity.ExitOK {
			t.Errorf("%v with a decoy ./%s: exit %d, want 0 from the ledger root\nstdout %s\nstderr %s",
				args, id, code, out, errs)
		}
	}
	if code, _, errs := run(t, "events", "./"+id); code != identity.ExitUsage || !strings.Contains(errs, "no such run") {
		t.Errorf("events ./<id>: exit %d, want 2 for the local directory holding no record\nstderr %s", code, errs)
	}
}

// TestStatusOrdersRunsByMintTimeAcrossHosts: newest and oldest are the runs' mint times, never their host
// prefix. A ledger root holding two host8 prefixes (a machine-id change, a shared home) sorted by the whole
// id put every run of the higher prefix after every run of the lower, so bare status kept showing the last
// run from before a reinstall and --all was grouped by host.
func TestStatusOrdersRunsByMintTimeAcrossHosts(t *testing.T) {
	root := gcRoot(t)
	now := time.Now()
	old := endedRunOnHost(t, root, [32]byte{0xff, 0xff, 0xff, 0xff}, now.Add(-2*time.Hour))
	mid := endedRunOnHost(t, root, [32]byte{}, now.Add(-time.Hour))
	newest := endedRunOnHost(t, root, [32]byte{0x7f}, now)
	code, out, errs := run(t, "status", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got statusListJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Runs) != 1 || got.Runs[0].Run != newest {
		t.Fatalf("bare status: %+v %v, want only %s (%s)", got.Runs, err, newest, out)
	}
	_, out, _ = run(t, "status", "--all", "--json")
	got = statusListJSON{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, r := range got.Runs {
		order = append(order, r.Run)
	}
	if want := []string{old, mid, newest}; !slices.Equal(order, want) {
		t.Errorf("status --all order %v, want oldest first %v", order, want)
	}
}

// TestCompileJSONEnvListsAreNeverNull is agent-contract R12's --json shape: with no env: section env_deny is
// [] and env_set {}, as every other list is, where both were null; env_pass stays null, meaning the agent
// inherits the environment, and [] is a contract that passes nothing.
func TestCompileJSONEnvListsAreNeverNull(t *testing.T) {
	code, out, errs := run(t, "compile", filepath.Join("testdata", "minimal.yaml"), "--json", "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	for _, want := range []string{`"env_pass":null`, `"env_deny":[]`, `"env_set":{}`} {
		if !strings.Contains(out, want) {
			t.Errorf("--json lacks %s:\n%s", want, out)
		}
	}
}

// TestDriftAggregateLoadsTheConfigOnceAndSkipsOtherAgents:--aggregate resolves the machine config once
// per invocation (R24), printing a config warning once however many runs it sums, and never recompiles the
// contract of another agent's run. It recompiled every run under the root before comparing agents, and
// printed each warning and each other agent's "no longer loads" line once per run.
func TestDriftAggregateLoadsTheConfigOnceAndSkipsOtherAgents(t *testing.T) {
	root := gcRoot(t)
	cfg := os.Getenv("TEGO_CONFIG")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\nprivileged_binary: /nowhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var mine []string
	for i := range 3 {
		mine = append(mine, endedRunAs(t, root, [32]byte{}, "tester", now.Add(time.Duration(i-5)*time.Minute)))
	}
	other := endedRunAs(t, root, [32]byte{}, "someone-else", now)
	for _, id := range append(slices.Clone(mine), other) {
		if err := os.WriteFile(filepath.Join(root, id, ledger.ContractFile), []byte("{not: [a contract\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := run(t, "drift", mine[0], "--aggregate")
	if code == identity.ExitError || code == identity.ExitUsage {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if n := strings.Count(errs, "privileged_binary is honoured"); n != 1 {
		t.Errorf("the config warning printed %d times, want once:\n%s", n, errs)
	}
	if strings.Contains(errs, other) {
		t.Errorf("another agent's run was recompiled:\n%s", errs)
	}
	if n := strings.Count(errs, "no longer loads"); n != len(mine) {
		t.Errorf("%d \"no longer loads\" lines, want one per run of this agent (%d):\n%s", n, len(mine), errs)
	}
}
