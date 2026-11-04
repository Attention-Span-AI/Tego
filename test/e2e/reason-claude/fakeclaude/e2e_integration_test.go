// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The end-to-end files run.sh and this twin share (test/e2e/reason-claude/README.md, "End to end").
const (
	e2eContract = "../contract.yaml"
	e2eTestdata = "../testdata"
	e2eGolden   = "../testdata/next-request.golden"
	e2eGit      = "../../../poc/interactive-claude/git"
)

// TestReasonEndToEndThroughTheStandIn is the CI twin of run.sh: scenarios a, c, d and e, each one
// `tego run` at tier landlock of this stand-in, built as a binary named claude so that tego provisions its hook, under
// the contract run.sh gives the real Claude Code, against the same model-stub scripts, with no network but the
// forwarder and a dummy key. report.py e2e then holds the stub's log and the run's ledger to the checks run.sh makes
// and to testdata/next-request.golden, which the real binary wrote: a change in the hook, the provision or the
// stand-in that moves the next request away from what Claude Code 2.1.310 sent fails here, on every CI run. On top,
// every refusal of the run is in the next request as reason.Text renders it from the ledger line.
func TestReasonEndToEndThroughTheStandIn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the launcher makes no runtime directory, so no harness is provisioned (reason-unavailable)")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed; the model stub and report.py are Python programs")
	}
	bins := t.TempDir()
	tego := filepath.Join(bins, "tego")
	claude := filepath.Join(bins, "cc", "claude")
	for _, b := range [][]string{
		{"build", "-tags", "tegotesthooks", "-o", tego, "github.com/attention-span-ai/tego/cmd/tego"},
		{"build", "-o", claude, "."},
	} {
		cmd := exec.Command("go", b...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %s: %v: %s", strings.Join(b, " "), err, out)
		}
	}
	doctorCfg := filepath.Join(bins, "cfg", "machine.yaml")
	if err := os.MkdirAll(filepath.Dir(doctorCfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(doctorCfg, []byte("version: 0\nledger_root: "+filepath.Join(bins, "cfg", "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doctor := exec.Command(tego, "doctor", "--require", "landlock")
	doctor.Env = testutil.TegoEnv(t, bins, "TEGO_CONFIG="+doctorCfg)
	testutil.RequireTier(t, doctor, "landlock")

	for _, s := range []string{"a", "c", "d", "e"} {
		t.Run(s, func(t *testing.T) { e2eScenario(t, py, tego, claude, s) })
	}
}

// e2eScenario is run.sh's layout and claude_p for scenario s, with the stand-in in place of claude.
func e2eScenario(t *testing.T, py, tego, claude, s string) {
	root := t.TempDir()
	ws, home, outside := filepath.Join(root, "ws"), filepath.Join(root, "home"), filepath.Join(root, "outside")
	cfgDir := filepath.Join(root, "cfg") // tego denies the agent this directory: nothing the agent reads is under it
	for _, d := range []string{filepath.Join(ws, "work"), filepath.Join(ws, "bin"), filepath.Join(ws, ".claude-state", "tmp"),
		filepath.Join(home, ".claude"), outside, filepath.Join(cfgDir, "runs"), filepath.Join(root, "stub")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	git, err := os.ReadFile(e2eGit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "bin", "git"), git, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(cfgDir, "machine.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nstop_grace: 3s\n", filepath.Join(cfgDir, "runs"))), 0o600); err != nil {
		t.Fatal(err)
	}
	fill := func(name string) string {
		b, err := os.ReadFile(filepath.Join(e2eTestdata, name))
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(root, name)
		if err := os.WriteFile(out, []byte(strings.NewReplacer("@W@", ws, "@OUT@", outside).Replace(string(b))), 0o644); err != nil {
			t.Fatal(err)
		}
		return out
	}
	stubScript, script := fill("stub-"+s+".json"), fill("fakeclaude-"+s+".json")
	cert, key := writeCert(t, filepath.Join(root, "stub"))
	base, stubLog := startStub(t, filepath.Join(root, "stub"), cert, key, stubScript)

	tmpl, err := os.ReadFile(e2eContract)
	if err != nil {
		t.Fatal(err)
	}
	contract := strings.NewReplacer("@STUB_PORT@", base[strings.LastIndex(base, ":")+1:], "@ROOT@", root,
		"@DENY_READ@", fmt.Sprintf("  deny_read: [%q]", filepath.Join(home, ".claude"))).Replace(string(tmpl))
	contractPath := filepath.Join(root, "agent.yaml")
	if err := os.WriteFile(contractPath, []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}

	result := filepath.Join(ws, "work", "result.json")
	run := exec.Command(tego, "run", contractPath, "--", "claude", "-p", "--permission-mode", "bypassPermissions",
		"--script", script, "--result", result, "Carry out the scripted steps.")
	run.Dir = ws
	// Keep durable state beside the private machine config. The test-owned short runtime
	// holds %R and the provisioned settings, outside the agent-denied config directory (RESULTS.md R4).
	run.Env = testutil.TegoEnv(t, root, "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(cfgDir, "chain.log"),
		"TEGO_TEST_OWN_LOG_HOME="+filepath.Join(cfgDir, "home"), "HOME="+home, "LANG=C.UTF-8", "SSL_CERT_FILE="+cert,
		"PATH="+filepath.Join(ws, "bin")+":"+filepath.Dir(claude)+":/usr/bin:/bin", "ANTHROPIC_API_KEY=dummy-not-a-key",
		"CLAUDE_CODE_SIMPLE=", "CLAUDE_CODE_SAFE_MODE=", "XDG_RUNTIME_DIR="+testutil.ShortRuntimeDir(t))
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run of the stand-in: %v\n%s", err, out)
	}
	ledgers, err := filepath.Glob(filepath.Join(cfgDir, "runs", "*", "events.jsonl"))
	if err != nil || len(ledgers) != 1 {
		t.Fatalf("ledger runs %v (%v), want one", ledgers, err)
	}

	report := exec.Command(py, "-I", "../report.py", "e2e", stubLog, "--ledger", ledgers[0], "--scenario", s,
		"--sub", ws+"=@W@", "--sub", outside+"=@OUT@", "--sub", root+"=@ROOT@", "--isolation", filepath.Join(home, ".claude"),
		"--golden", e2eGolden)
	out, err := report.CombinedOutput()
	if err != nil {
		t.Errorf("report.py e2e %s: %v\n%s", s, err, out)
	}
	t.Logf("report.py e2e %s:\n%s", s, out)

	var sum Summary
	if b, err := os.ReadFile(result); err != nil || json.Unmarshal(b, &sum) != nil {
		t.Fatalf("the stand-in's result %s: %v", result, err)
	}
	for _, r := range sum.Requests {
		if r.Agrees != nil && !*r.Agrees {
			t.Errorf("request %d: the stub's reply named tools the stand-in's script did not run", r.N)
		}
	}
	next := e2eTailText(t, stubLog, 2)
	for _, r := range e2eRefused(t, ledgers[0]) {
		if want := reason.Text(record.Reason(r.Reason), r.Op, r.Target, r.Rule); !strings.Contains(next, want) {
			t.Errorf("the next request does not carry the ledger's refusal as reason.Text renders it:\n%s\nin\n%s", want, next)
		}
	}
}

// e2eRefusal is what reason.Text reads from a refused line.
type e2eRefusal struct {
	Reason string `json:"reason"`
	Op     string `json:"op"`
	Target string `json:"target"`
	Rule   string `json:"rule"`
}

// e2eRefused is every refused line of the ledger at path.
func e2eRefused(t *testing.T, path string) []e2eRefusal {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []e2eRefusal
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e struct {
			Kind string `json:"kind"`
			e2eRefusal
		}
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		if e.Kind == "refused" {
			out = append(out, e.e2eRefusal)
		}
	}
	return out
}

// e2eTailText is every string of the stub's "tail" for the request of turn: the messages after its last assistant
// message (the tool results and the system message of hook notes), joined by newlines.
func e2eTailText(t *testing.T, logPath string, turn int) string {
	t.Helper()
	fh, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 1<<16), 4<<20)
	for sc.Scan() {
		var l struct {
			Turn *int `json:"turn"`
			Tail []map[string]any
		}
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		if l.Turn == nil || *l.Turn != turn {
			continue
		}
		var b strings.Builder
		for _, blk := range l.Tail {
			for _, k := range []string{"text", "content"} {
				if v, ok := blk[k].(string); ok {
					b.WriteString(v + "\n")
				}
			}
		}
		return b.String()
	}
	t.Fatalf("the stub logged no request for turn %d", turn)
	return ""
}
