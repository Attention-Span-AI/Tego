// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// presetProbe is the agent of TestIntegrationPresetsAtTierLandlock: it writes its environment and each attempt's
// outcome under src/, the one folder the contract names. $1 is the listed port, $2 an unlisted one.
const presetProbe = `#!/bin/bash
env >src/env.txt
if echo inside >src/inside.txt 2>/dev/null; then echo write-src=ok; else echo write-src=refused; fi >>src/result.txt
if echo outside >outside.txt 2>/dev/null; then echo write-outside=ok; else echo write-outside=refused; fi >>src/result.txt
if (echo hi >/dev/tcp/127.0.0.1/$1) 2>/dev/null; then echo listed=ok; else echo listed=refused; fi >>src/result.txt
if (echo hi >/dev/tcp/127.0.0.1/$2) 2>/dev/null; then echo unlisted=ok; else echo unlisted=refused; fi >>src/result.txt
exit 0
`

// TestIntegrationPresetsAtTierLandlock is ADR 0068's end-to-end acceptance, unprivileged at tier landlock: a contract
// extending all three presets, with fs.write [./src/] and net.allow [127.0.0.1:<port>] of its own, runs an agent
// that writes inside and outside src/, connects to the listed port and to an unlisted one, and records its
// environment. The write outside src/ and the unlisted connect are refused, the write in src/ and the listed connect
// are not, a variable outside no-secrets' allow-list is absent from the agent's environment while PATH is there,
// and each refusal's ledger line names the rule that refused it.
func TestIntegrationPresetsAtTierLandlock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the agent runs as the invoking user, who cannot reach the test's 0700 directories; the unprivileged run covers the presets")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("the probe connects with bash's /dev/tcp: no /bin/bash")
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
	if err := os.MkdirAll(filepath.Join(proj, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "probe.sh"), []byte(presetProbe), 0o755); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: presets
extends: [tego/no-secrets, tego/no-prod, tego/repo-only-writes]
command: ["/bin/bash", "./probe.sh"]
tier: landlock
record: full
fs:
  write: ["./src/"]
net:
  allow: ["127.0.0.1:%d"]
limits:
  pids: 64
`, listed)
	if err := os.WriteFile(filepath.Join(proj, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(bin, "run", "agent.yaml", "--", "/bin/bash", "./probe.sh", fmt.Sprint(listed), fmt.Sprint(unlisted))
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
	if _, err := os.Stat(filepath.Join(proj, "outside.txt")); err == nil {
		t.Error("outside.txt was written")
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
	// run_start says which presets the run merged, each built in, with the sha256 of the bytes this binary serves
	// (ADR 0066 D6): a preset's rules version is its name, pin included, and that sum.
	got := runStartProfiles(t, runs[0])
	want := ""
	for _, name := range []string{"tego/no-secrets", "tego/no-prod", "tego/repo-only-writes"} {
		_, data, err := presets.Source{}.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		want += fmt.Sprintf("%s builtin %x\n", name, sha256.Sum256(data))
	}
	if got != want {
		t.Errorf("run_start.profiles:\n%s\nwant\n%s", got, want)
	}

	// Each refusal is named by the rule that refused it: outside every write entry and every allow entry, the rule
	// is unmatched, with the reason saying which section (SEMANTICS §3).
	var write, connect bool
	for _, l := range refusals(t, runs[0]) {
		if l.Rule == "" {
			t.Errorf("a refusal names no rule: %s", l.line)
		}
		switch {
		case strings.Contains(l.line, filepath.Join(proj, "outside.txt")):
			write = true
			if l.Rule != "unmatched" || l.Reason != "write-outside-contract" {
				t.Errorf("the write outside src/: rule %q, reason %q", l.Rule, l.Reason)
			}
		case strings.Contains(l.line, fmt.Sprintf("127.0.0.1:%d", unlisted)):
			connect = true
			if l.Rule != "unmatched" || l.Reason != "net-not-allowed" {
				t.Errorf("the unlisted connect: rule %q, reason %q", l.Rule, l.Reason)
			}
		}
	}
	if !write || !connect {
		t.Errorf("refused lines for the write outside src/ %v and the unlisted connect %v, want both", write, connect)
	}
}

// buildTegoBinary builds cmd/tego with tegotesthooks (its chain anchor and own log go where testutil.TegoEnv says).
func buildTegoBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tego")
	cmd := exec.Command("go", "build", "-tags", "tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return bin
}

// listen accepts on a loopback port until the test ends and counts the connections it accepted.
func listen(t *testing.T) (int, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &hits
}

// runStartProfiles is the run_start line's profiles, one "name source sha256" line each.
func runStartProfiles(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		var l struct {
			Kind     string `json:"kind"`
			Profiles []struct {
				Name, Source, SHA256 string
			} `json:"profiles"`
		}
		if json.Unmarshal([]byte(line), &l) != nil || l.Kind != "run_start" {
			continue
		}
		var b strings.Builder
		for _, p := range l.Profiles {
			fmt.Fprintf(&b, "%s %s %s\n", p.Name, p.Source, p.SHA256)
		}
		return b.String()
	}
	t.Fatalf("%s: no run_start line", path)
	return ""
}

// refusal is one ledger line recording a refusal, with the rule and the reason it names.
type refusal struct {
	Rule, Reason string
	line         string
}

// refusals is every line of a run's ledger that records a refusal.
func refusals(t *testing.T, path string) []refusal {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var out []refusal
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 1<<16), 4<<20)
	for sc.Scan() {
		var l struct {
			Kind    string `json:"kind"`
			Verdict string `json:"verdict"`
			Rule    string `json:"rule"`
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if l.Kind == "refused" || l.Verdict == "refused" {
			out = append(out, refusal{Rule: l.Rule, Reason: l.Reason, line: sc.Text()})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
