// SPDX-License-Identifier: Apache-2.0

//go:build integration

package claudecode

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// The model stub and the stand-in Claude Code, from this package's directory.
const (
	modelStub     = "../../../test/workloads/model-stub/server.py"
	fakeClaudePkg = "github.com/attention-span-ai/tego/test/e2e/reason-claude/fakeclaude"
)

// provEnv is a tier-landlock tego environment of the test's own: its machine config, ledger root and chain anchor
// under w, HOME at w/home, with a ~/.claude of its own that the test watches.
type provEnv struct {
	bin, claude, w, home, ledger, proj, ccfg string
	env                                      []string
}

func newProvEnv(t *testing.T) *provEnv {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("as root the launcher makes no runtime directory, so no harness is provisioned (reason-unavailable)")
	}
	e := &provEnv{bin: buildTego(t), w: t.TempDir()}
	if err := os.Chmod(e.w, 0o700); err != nil {
		t.Fatal(err)
	}
	e.claude = filepath.Join(e.w, "bin", "claude") // named claude, so harness auto resolves to claude-code
	build := exec.Command("go", "build", "-o", e.claude, fakeClaudePkg)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build fakeclaude: %v: %s", err, out)
	}
	e.home, e.ccfg, e.proj = filepath.Join(e.w, "home"), filepath.Join(e.w, "ccfg"), filepath.Join(e.w, "proj")
	own := filepath.Join(e.w, "own")
	e.ledger = filepath.Join(own, "runs")
	for _, d := range []string{e.ledger, filepath.Join(e.home, ".claude"), e.ccfg, filepath.Join(e.proj, ".claude"), filepath.Join(e.proj, "out")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for p, body := range map[string]string{
		filepath.Join(e.home, ".claude", "settings.json"):         `{"model":"the user's own"}`,
		filepath.Join(e.ccfg, "settings.json"):                    `{"model":"CLAUDE_CONFIG_DIR's"}`,
		filepath.Join(e.proj, ".claude", "settings.local.json"):   `{"model":"the project's"}`,
		filepath.Join(own, "machine.yaml"):                        fmt.Sprintf("version: 0\nledger_root: %s\n", e.ledger),
		filepath.Join(e.home, ".claude", "projects", "keep", "x"): "history",
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e.env = testutil.TegoEnv(t, e.w, "TEGO_CONFIG="+filepath.Join(own, "machine.yaml"),
		"TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(own, "chain.log"), "HOME="+e.home, "CLAUDE_CONFIG_DIR="+e.ccfg)
	doctor := exec.Command(e.bin, "doctor", "--require", "landlock")
	doctor.Env = e.env
	testutil.RequireTier(t, doctor, "landlock")
	return e
}

// snapshot is every entry under the directories Claude Code keeps its configuration in, with mode, size, mtime and
// a hash of each file's content.
func (e *provEnv) snapshot(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, root := range []string{e.home, e.ccfg, filepath.Join(e.proj, ".claude")} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			st, err := os.Lstat(p)
			if err != nil {
				return err
			}
			line := fmt.Sprintf("%s %v %d %d", p, st.Mode(), st.Size(), st.ModTime().UnixNano())
			if st.Mode().IsRegular() {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				line += fmt.Sprintf(" %x", sha256.Sum256(b))
			}
			out = append(out, line)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestProvisionedClaudeHearsOfItsRefusal is acceptance (5) and (6): `tego run` of a deny-list contract at tier
// landlock whose command is claude (the stand-in, built by the test) provisions the settings file; the stand-in
// parses --settings, makes the scripted write outside the workspace, which the run refuses, and runs every hook the
// file lists with the documented payloads; its next request to the model carries the refusal's text, rule and
// target, and the ledger's only refused lines are that write's. ~/.claude, CLAUDE_CONFIG_DIR and the project's
// .claude/ are the same before and after. The hook finds the run with no XDG_RUNTIME_DIR in the agent's
// environment (env.pass leaves it out), under the test's own runtime base: the --reason the settings file names is
// $TEGO_REASON (ADR 0063 (5)).
func TestProvisionedClaudeHearsOfItsRefusal(t *testing.T) {
	e := newProvEnv(t)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed; the model stub is a Python program")
	}
	outside := filepath.Join(e.w, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "escape.txt")
	script := filepath.Join(e.w, "script.json")
	stubScript := filepath.Join(e.w, "stub-script.json")
	writeJSON(t, script, map[string]any{"prompt": "Write the file.", "turns": []any{
		map[string]any{"calls": []any{map[string]any{"write": target, "content": "x\n"}}},
	}})
	writeJSON(t, stubScript, []any{
		[]any{map[string]any{"type": "tool_use", "name": "Write", "input": map[string]any{"file_path": target, "content": "x\n"}}},
		[]any{map[string]any{"type": "text", "text": "SCENARIO-DONE"}},
	})
	cert, key := provCert(t, e.w)
	base, stubLog := provStub(t, py, e.w, cert, key, stubScript)

	contract := fmt.Sprintf(`version: 0
name: claudeprov
command: [%q]
tier: landlock
record: full
capture: off
fs:
  write: ["./out/"]
net:
  allow: [%q]
env:
  pass: ["PATH", "HOME", "CLAUDE_CONFIG_DIR", "ANTHROPIC_BASE_URL", "SSL_CERT_FILE", "ANTHROPIC_API_KEY"]
limits:
  pids: 128
`, e.claude, strings.TrimPrefix(base, "https://"))
	if err := os.WriteFile(filepath.Join(e.proj, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	before := e.snapshot(t)
	result := filepath.Join(e.proj, "out", "result.json")
	run := exec.Command(e.bin, "run", "agent.yaml", "--", e.claude, "-p", "--script", script, "--result", result, "--cwd", e.proj)
	run.Dir = e.proj
	run.Env = append(slices.Clone(e.env), "ANTHROPIC_BASE_URL="+base, "SSL_CERT_FILE="+cert, "ANTHROPIC_API_KEY=dummy-not-a-key")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	if after := e.snapshot(t); !slices.Equal(before, after) {
		t.Errorf("Claude Code's configuration changed:\nbefore %q\nafter  %q", before, after)
	}

	// The stand-in ran every hook the settings file lists, tego's exec-form argv each time, and each exited 0.
	var res struct {
		Hooks []struct {
			Event, Command string
			Exit           int
			Started        bool
		} `json:"hooks"`
		Ended string `json:"ended"`
	}
	b, err := os.ReadFile(result)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	ran := map[string]bool{}
	for _, h := range res.Hooks {
		if !strings.HasPrefix(h.Command, e.bin+" hook claude-code --reason ") || h.Exit != 0 || !h.Started {
			t.Errorf("hook run %+v", h)
		}
		ran[h.Event] = true
	}
	for _, ev := range hookEvents {
		if ev != EventPostToolUse && !ran[ev] { // the one call fails, so PostToolUseFailure fires and PostToolUse does not
			t.Errorf("no %s hook ran: %s", ev, b)
		}
	}

	runs, err := filepath.Glob(filepath.Join(e.ledger, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledger runs %v (%v), want one", runs, err)
	}
	if h := runStartHarness(t, runs[0]); h.Name != Harness || !h.Provisioned || len(h.Files) != 1 || filepath.Base(h.Files[0]) != SettingsFile {
		t.Errorf("run_start harness %+v, want claude-code provisioned with %s", h, SettingsFile)
	}
	refused := refusedLines(t, runs[0])
	if len(refused) == 0 {
		t.Fatalf("no refused line: the write to %s was not refused", target)
	}
	var first struct {
		Path string `json:"path"`
		Rule string `json:"rule"`
	}
	// The stand-in writes as Claude Code 2.1.310 does, through a descriptor of the target's directory
	// (/proc/self/fd/N/escape.txt.tmp.<pid>.<hex>), and unlinks the temporary file after the failure.
	viaFD := regexp.MustCompile(`"/proc/self/fd/\d+/escape\.txt\.tmp\.\d+\.[0-9a-f]+"`)
	for _, l := range refused {
		if !strings.Contains(l, outside) && !viaFD.MatchString(l) {
			t.Errorf("a refusal the hook or the provision caused: %s", l)
		}
	}
	if err := json.Unmarshal([]byte(refused[0]), &first); err != nil || first.Rule == "" || first.Path == "" {
		t.Fatalf("refused line %s: %v", refused[0], err)
	}
	// The request after the refused write carries the refusal, as the hook rendered it.
	next := stubUserText(t, stubLog, 1)
	for _, want := range []string{"Tego refused", first.Path, "(rule " + first.Rule + ")"} {
		if !strings.Contains(next, want) {
			t.Errorf("the next request does not carry %q:\n%s", want, next)
		}
	}
}

// TestProvisionRefusesADeniedSettingsPath is acceptance (3)'s deny_read case end to end: claude --settings <a path
// the run's deny_read covers> is refused before run_start with exit 125 and the fix, and nothing is run.
func TestProvisionRefusesADeniedSettingsPath(t *testing.T) {
	e := newProvEnv(t)
	secret := filepath.Join(e.home, "secret")
	if err := os.Mkdir(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(secret, "s.json")
	if err := os.WriteFile(settings, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf("version: 0\nname: claudedenied\ncommand: [%q]\ntier: landlock\nfs:\n  write: [\"./out/\"]\n  deny_read: [%q]\n",
		e.claude, secret+"/")
	if err := os.WriteFile(filepath.Join(e.proj, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(e.proj, "out", "ran")
	run := exec.Command(e.bin, "run", "agent.yaml", "--", e.claude, "--settings", settings, "--result", marker)
	run.Dir, run.Env = e.proj, e.env
	out, err := run.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 125 || !strings.Contains(string(out), fixPath) {
		t.Fatalf("tego run: %v, want exit 125 naming %q\n%s", err, fixPath, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("the agent ran: %v", err)
	}
}

// TestProvisionAllowListIsGranted is acceptance (7) with this build's provisioner and harness grants: an
// allow-list contract whose rules do not name the hook keeps the provision, since the launcher grants the hook's exact
// argv (ADR 0064): run_start says provisioned, its harness.hook granted, runtime_grants names the grant, and no
// harness-hook-refused warning is given. Before the grant this provision was dropped hook-not-granted.
func TestProvisionAllowListIsGranted(t *testing.T) {
	e := newProvEnv(t)
	contract := fmt.Sprintf("version: 0\nname: claudeallow\ncommand: [%q]\ntier: landlock\nfs:\n  write: [\"./out/\"]\nexec:\n  allow: [%q]\n",
		e.claude, e.claude)
	if err := os.WriteFile(filepath.Join(e.proj, "agent.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	// With no ANTHROPIC_BASE_URL the stand-in exits 1 before any request; the run is here for its run_start.
	run := exec.Command(e.bin, "run", "agent.yaml", "--", e.claude, "-p", "hi")
	run.Dir, run.Env = e.proj, e.env
	out, _ := run.CombinedOutput()
	if strings.Contains(string(out), "harness-hook-refused") {
		t.Errorf("a harness-hook-refused warning for a hook the launcher grants:\n%s", out)
	}
	runs, err := filepath.Glob(filepath.Join(e.ledger, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledger runs %v (%v), want one\n%s", runs, err, out)
	}
	h := runStartHarness(t, runs[0])
	if h.Name != Harness || !h.Provisioned || h.Why != "" || len(h.Files) != 1 || h.Hook == nil || !h.Hook.Granted ||
		len(h.Hook.Argv) == 0 || h.Hook.Argv[0] != e.bin {
		t.Errorf("run_start harness %+v (hook %+v), want claude-code provisioned with its hook granted to %s", h, h.Hook, e.bin)
	}
	b, err := os.ReadFile(runs[0])
	if err != nil {
		t.Fatal(err)
	}
	if grant := `"exec.harness-hook[` + e.bin + `]"`; !strings.Contains(string(b), grant) {
		t.Errorf("the ledger names no %s runtime grant", grant)
	}
}

// harnessStart is run_start's harness (pkg/spec/record HarnessStart).
type harnessStart struct {
	Name        string   `json:"name"`
	Provisioned bool     `json:"provisioned"`
	Why         string   `json:"why"`
	Files       []string `json:"files"`
	Hook        *struct {
		Argv    []string `json:"argv"`
		Granted bool     `json:"granted"`
	} `json:"hook"`
}

// runStartHarness is the harness of the run_start line of a run's ledger.
func runStartHarness(t *testing.T, path string) harnessStart {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		var line struct {
			Kind    string        `json:"kind"`
			Harness *harnessStart `json:"harness"`
			Payload struct {
				Harness *harnessStart `json:"harness"`
			} `json:"payload"`
		}
		if json.Unmarshal([]byte(l), &line) != nil || line.Kind != "run_start" {
			continue
		}
		if line.Harness != nil {
			return *line.Harness
		}
		if line.Payload.Harness != nil {
			return *line.Payload.Harness
		}
		t.Fatalf("run_start has no harness: %s", l)
	}
	t.Fatalf("%s has no run_start", path)
	return harnessStart{}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// provCert makes a self-signed certificate for 127.0.0.1 that the stub serves and the stand-in trusts through
// SSL_CERT_FILE.
func provCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// provStub runs the model stub with script on a free port and returns its base URL and its content log.
func provStub(t *testing.T, py, dir, cert, key, script string) (baseURL, logPath string) {
	t.Helper()
	logPath, ready := filepath.Join(dir, "stub.log"), filepath.Join(dir, "stub.port")
	cmd := exec.Command(py, "-I", modelStub, "--cert", cert, "--key", key, "--ready", ready, "--script", script, "--log", logPath, "--log-content")
	cmd.Env = testutil.TegoEnv(t, dir)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for range 200 {
		if b, err := os.ReadFile(ready); err == nil && len(b) > 0 {
			return "https://127.0.0.1:" + strings.TrimSpace(string(b)), logPath
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the model stub did not start: %s", stderr.String())
	return "", ""
}

// stubUserText is every string of the stub's request for turn (the request after turn's tool calls): its last user
// message and every message after the last assistant one (the system message of hook notes), joined by newlines.
func stubUserText(t *testing.T, logPath string, turn int) string {
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
			User any  `json:"user"`
			Tail any  `json:"tail"` // every message after the last assistant one: the system message of hook notes too
		}
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		if l.Turn != nil && *l.Turn == turn {
			var b strings.Builder
			var walk func(any)
			walk = func(v any) {
				switch x := v.(type) {
				case string:
					b.WriteString(x + "\n")
				case []any:
					for _, y := range x {
						walk(y)
					}
				case map[string]any:
					for _, y := range x {
						walk(y)
					}
				}
			}
			walk(l.User)
			walk(l.Tail)
			return b.String()
		}
	}
	t.Fatalf("the stub logged no request for turn %d", turn)
	return ""
}
