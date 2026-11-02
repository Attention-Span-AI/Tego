// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestIntegrationInitPresetRunsAtTierLandlock is the end-to-end acceptance, unprivileged at tier
// landlock: `tego init --preset no-secrets,no-prod,repo-only-writes --write src --allow-host 127.0.0.1:<port>
// --command ...` in a fresh project, then `tego run agent.yaml` as written, with the probe of
// TestIntegrationPresetsAtTierLandlock as the agent. The write outside src/ and the unlisted connect are refused, the
// write in src/ and the listed connect are not, a variable outside no-secrets' allow-list is absent, and each
// refusal's ledger line names its rule.
func TestIntegrationInitPresetRunsAtTierLandlock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the agent runs as the invoking user, who cannot reach the test's 0700 directories; the unprivileged run covers init")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("the probe connects with bash's /dev/tcp: no /bin/bash")
	}
	bin := buildTegoBinary(t)
	w := t.TempDir()
	if err := os.Chmod(w, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(w, "home")
	own := filepath.Join(home, ".tego")
	ledger := filepath.Join(own, "runs")
	if err := os.MkdirAll(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(own, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(own, "machine.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledger)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.TegoEnv(t, w, "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(own, "chain.log"), "HOME="+home,
		"TEGO_PRESET_PROBE_SECRET=planted")
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")

	listed, listedHits := listen(t)
	unlisted, unlistedHits := listen(t)
	proj := filepath.Join(w, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "probe.sh"), []byte(presetProbe), 0o755); err != nil {
		t.Fatal(err)
	}
	initCmd := exec.Command(bin, "init", "--preset", "no-secrets,no-prod,repo-only-writes", "--write", "src",
		"--allow-host", fmt.Sprintf("127.0.0.1:%d", listed), "--command", fmt.Sprintf("/bin/bash ./probe.sh %d %d", listed, unlisted), proj)
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil || strings.Contains(string(out), "warning") {
		t.Fatalf("tego init: %v\n%s", err, out)
	}
	run := exec.Command(bin, "run", "agent.yaml")
	run.Dir, run.Env = proj, env
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}

	result, err := os.ReadFile(filepath.Join(proj, "src", "result.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(result), "write-src=ok\nwrite-outside=refused\nlisted=ok\nunlisted=refused\n"; got != want {
		t.Errorf("the agent saw\n%s\nwant\n%s", got, want)
	}
	if listedHits.Load() == 0 || unlistedHits.Load() != 0 {
		t.Errorf("connections: listed %d, unlisted %d", listedHits.Load(), unlistedHits.Load())
	}
	agentEnv, err := os.ReadFile(filepath.Join(proj, "src", "env.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if e := "\n" + string(agentEnv); strings.Contains(e, "\nTEGO_PRESET_PROBE_SECRET=") || !strings.Contains(e, "\nPATH=") {
		t.Errorf("the agent's environment, with the planted variable or without PATH:\n%s", agentEnv)
	}
	runs, err := filepath.Glob(filepath.Join(ledger, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledger runs %v (%v), want one", runs, err)
	}
	var write, connect bool
	for _, l := range refusals(t, runs[0]) {
		if l.Rule == "" {
			t.Errorf("a refusal names no rule: %s", l.line)
		}
		write = write || strings.Contains(l.line, filepath.Join(proj, "outside.txt"))
		connect = connect || strings.Contains(l.line, fmt.Sprintf("127.0.0.1:%d", unlisted))
	}
	if !write || !connect {
		t.Errorf("refused lines for the write outside src/ %v and the unlisted connect %v, want both", write, connect)
	}
}

// TestIntegrationInitPresetInsideARun: `tego init --preset repo-only-writes --write src/new <dir>` run as the agent of
// a run at tier landlock sets the project up as it does outside one: src/new/ and .tego/tmp/ are made, agent.yaml is
// written and init exits 0. The run's filter answers openat2 with ENOSYS (enforce-landlock R10), and init's folders
// were made with openat2 alone, so init failed there with "function not implemented" (125), leaving .tego/ behind.
func TestIntegrationInitPresetInsideARun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the agent runs as the invoking user, who cannot reach the test's 0700 directories; the unprivileged run covers init")
	}
	bin := buildTegoBinary(t)
	w := t.TempDir()
	if err := os.Chmod(w, 0o700); err != nil { // the machine config's directory must not be group-writable (umask 002)
		t.Fatal(err)
	}
	home := filepath.Join(w, "home")
	own := filepath.Join(home, ".tego")
	ledger := filepath.Join(own, "runs")
	if err := os.MkdirAll(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(own, 0o700); err != nil {
		t.Fatal(err)
	}
	// The machine config is outside ~/.tego, which a run's agent may not read (R10), and the inner init reads it.
	cfgDir := filepath.Join(w, "cfg")
	if err := os.Mkdir(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(cfgDir, "machine.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledger)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.TegoEnv(t, w, "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(own, "chain.log"), "HOME="+home)
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")

	inner, outer := filepath.Join(w, "inner"), filepath.Join(w, "outer")
	for _, d := range []string{filepath.Join(inner, "src"), outer} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	contract := fmt.Sprintf(`version: 0
name: outer
command: [%q, "init", "--preset", "repo-only-writes", "--write", "src/new", %q]
tier: landlock
fs:
  write: [%q, "/dev/null"]
`, bin, inner, inner+"/")
	if err := os.WriteFile(filepath.Join(outer, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(bin, "run", "agent.yaml")
	run.Dir, run.Env = outer, env
	out, err := run.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "created src/new/") {
		t.Fatalf("tego init inside tego run: %v\n%s", err, out)
	}
	for _, d := range []string{"src/new", ".tego/tmp"} {
		if fi, err := os.Lstat(filepath.Join(inner, filepath.FromSlash(d))); err != nil || !fi.IsDir() {
			t.Errorf("%s/ not made in %s: %v\n%s", d, inner, err, out)
		}
	}
	if _, err := os.Lstat(filepath.Join(inner, "agent.yaml")); err != nil {
		t.Errorf("agent.yaml not written: %v\n%s", err, out)
	}
}
