// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// envWithout is env without the entries that set name.
func envWithout(env []string, name string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// TestIntegrationTestBuildFailsClosedWithoutAnAnchor is identity-config.md R27: the binary this package builds
// (-tags tegotesthooks) anchors where TEGO_TEST_CHAIN_ANCHOR says and, given none, anchors nowhere: `events
// --verify` and `run` refuse, naming the variable, instead of reading and extending the invoking user's own
// ~/.tego/chain.log. 2026-10-06: an integration test took os.Environ() before the call that set the variable, and
// 61 test runs were appended to the developer's anchor with their ledgers in directories since removed.
func TestIntegrationTestBuildFailsClosedWithoutAnAnchor(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("ianchor", []string{"/bin/true"}, []string{"/bin/true"}))
	cfg := writeMachineConfig(t, f)
	with := append(os.Environ(), "TEGO_CONFIG="+cfg)
	without := envWithout(with, "TEGO_TEST_CHAIN_ANCHOR")
	if len(without) != len(with)-1 {
		t.Fatalf("writeMachineConfig did not set TEGO_TEST_CHAIN_ANCHOR in the environment")
	}

	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/true")
	run.Dir, run.Env = f.dir, with
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run with an anchor: %v\n%s", err, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v", dirs)
	}

	// Verifying the run reads the anchor: with none named it must say so, and must not fall back to the real one.
	verify := exec.Command(bin, "events", filepath.Base(dirs[0]), "--verify")
	verify.Env = without
	out, err := verify.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "TEGO_TEST_CHAIN_ANCHOR is not set") {
		t.Fatalf("events --verify without an anchor: err %v\n%s\nwant a refusal naming TEGO_TEST_CHAIN_ANCHOR", err, out)
	}

	// The run itself refuses before it makes a run directory (the guard above holds, or this would extend the
	// invoking user's chain.log by one line).
	again := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/true")
	again.Dir, again.Env = f.dir, without
	out, err = again.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "chain anchor: ") || !strings.Contains(string(out), "TEGO_TEST_CHAIN_ANCHOR is not set") {
		t.Fatalf("tego run without an anchor: err %v\n%s\nwant a refusal naming the chain anchor", err, out)
	}
	if got := runDirs(t, f.root); len(got) != 1 {
		t.Errorf("the refused run left a directory: %v", got)
	}
}

// TestIntegrationTestBuildRefusesTheRealLedgerRoot is identity-config.md R27's ledger half: the binary this package
// builds refuses a machine config whose ledger_root is inside the invoking user's own ~/.tego, before `run` sweeps
// or `gc` expires anything there, so a harness without a ledger_root of its own, or with the built-in one, never
// ends or anchors a run of the developer's. Both commands get the anchor and own-log variables here, so the
// ledger root is the only thing that can refuse them. The `run` names a contract that does not exist and `gc`
// is a dry run: should the refusal ever be lost, neither writes the developer's ledger.
func TestIntegrationTestBuildRefusesTheRealLedgerRoot(t *testing.T) {
	bin := tegoBinary(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "machine.yaml")
	// "~/" expands against the passwd home, as it does for a harness that left ledger_root out.
	if err := os.WriteFile(cfg, []byte("ledger_root: ~/.tego/runs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(dir, "own", "chain.log")
	env := append(os.Environ(), "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+anchor,
		"TEGO_TEST_OWN_LOG_HOME="+filepath.Join(dir, "own", "home"))
	for _, args := range [][]string{
		{"run", filepath.Join(dir, "no-such-contract.yaml"), "--", "/bin/true"},
		{"gc", "--dry-run"},
	} {
		cmd := exec.Command(bin, args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "ledger_root") || !strings.Contains(string(out), "tegotesthooks") {
			t.Errorf("tego %s with the ledger root in the real ~/.tego: err %v\n%s\nwant a refusal naming ledger_root", args[0], err, out)
		}
	}
	if _, err := os.Stat(anchor); err == nil {
		t.Errorf("a refused command made the anchor %s", anchor)
	}
}
