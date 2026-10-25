// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

const (
	stubServer = "../../../workloads/model-stub/server.py"
	reportPy   = "../report.py"
	goldenDir  = "../golden"
	markerText = "stand-in hook:"
)

// writeCert makes a self-signed certificate for 127.0.0.1 that the model stub serves and fakeclaude trusts through
// SSL_CERT_FILE, as a harness trusts the stub in the kill tests.
func writeCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// startStub runs test/workloads/model-stub/server.py on a free port with the given script and returns its base URL and
// log path.
func startStub(t *testing.T, dir, certPath, keyPath, script string) (baseURL, logPath string) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed; the model stub is a Python program")
	}
	logPath = filepath.Join(dir, "stub.log")
	ready := filepath.Join(dir, "stub.port")
	cmd := exec.Command(py, "-I", stubServer, "--cert", certPath, "--key", keyPath, "--ready", ready,
		"--script", script, "--log", logPath, "--log-content")
	cmd.Env = testutil.TegoEnv(t, dir)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 200; i++ {
		if b, err := os.ReadFile(ready); err == nil && len(b) > 0 {
			return "https://127.0.0.1:" + strings.TrimSpace(string(b)), logPath
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the model stub did not start: %s", stderr.String())
	return "", ""
}

type scenario struct {
	name     string // file stem: script<suffix>.json, stub-script<suffix>.json, golden/shape<suffix>.json
	suffix   string
	hooks    map[string]string
	args     []string
	reminder []string // report.py --expect-reminder
	feedback []string // report.py --expect-feedback
	noRem    bool
	files    []string // regular files the scripted writes must have made
	final    string   // what fakeclaude prints last: the stub's final text, or its default "done" after a Stop continuation
}

var scenarios = []scenario{
	{
		name: "sequential", suffix: "",
		hooks: map[string]string{EvSessionStart: "context", EvPostToolUse: "context", EvPostToolUseFailure: "context",
			EvPostToolBatch: "context", EvStop: "exit2-once"},
		reminder: []string{markerText + " this is a fixed additionalContext (SessionStart)=1", "(PostToolUse)=2", "(PostToolUseFailure)=1", "(PostToolBatch)=3"},
		feedback: []string{"stand-in hook: keep going=1"},
		files:    []string{"note.txt"},
		final:    "done", // the Stop hook's exit 2 asks for one more answer, which the stub scripts no turn for
	},
	{
		name: "parallel", suffix: "-parallel",
		hooks:    map[string]string{EvPostToolUse: "context", EvPostToolBatch: "context"},
		reminder: []string{"(PostToolUse)=4", "(PostToolBatch)=2"},
		files:    []string{"a.txt", "b.txt"},
		final:    "SCENARIO-DONE: a parallel batch and a read.",
	},
	{
		// Bare mode runs no hook at all (RESULTS.md R2): neither the context nor the exit-2 feedback reaches the
		// model, and the Stop hook does not ask for one more answer.
		name: "bare", suffix: "-bare",
		hooks: map[string]string{EvSessionStart: "context", EvPostToolUse: "exit2", EvPostToolUseFailure: "exit2",
			EvPostToolBatch: "context", EvStop: "exit2-once"},
		args:     []string{"--bare"},
		noRem:    true,
		feedback: []string{"stand-in hook: exit 2 reason=0", "stand-in hook: keep going=0"},
		files:    []string{"note.txt"},
		final:    "SCENARIO-DONE: two steps taken in a bare session.",
	},
}

// TestHooksGoldenIsTheHookSetTheShapeGoldenWasMadeWith holds golden/hooks<suffix>.json: the hook settings a
// scenario's shape golden was made with, the stand-in's command written @HOOK@. A different hook set gives different
// counts (the shape golden counts what the hooks wrote, and without the Stop hook's exit 2 there is no last request),
// so the reason end-to-end run uses the real binary with these hooks and the test binary that `go test -c` builds for @HOOK@
// (it serves the __hook__ modes), and compares it with golden/shape<suffix>.json.
func TestHooksGoldenIsTheHookSetTheShapeGoldenWasMadeWith(t *testing.T) {
	for _, sc := range scenarios {
		var buf bytes.Buffer
		if err := json.Indent(&buf, []byte(settingsFor(t, sc.hooks, "@HOOK@")), "", "  "); err != nil {
			t.Fatal(err)
		}
		buf.WriteByte('\n')
		path := filepath.Join(goldenDir, "hooks"+sc.suffix+".json")
		if *update {
			if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test -tags integration -run %s -update)", err, t.Name())
		}
		if !bytes.Equal(want, buf.Bytes()) {
			t.Errorf("%s differs from the hooks scenario %q uses:\n got: %s\nwant: %s", path, sc.name, buf.Bytes(), want)
		}
	}
}

// TestAgainstTheModelStub runs fakeclaude as a separate process against the real model stub over TLS, with the
// stand-in hooks, and holds the stub's log to report.py and to the request-shape golden that the end-to-end run holds the
// real Claude Code to.
func TestAgainstTheModelStub(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			dir := t.TempDir()
			work := filepath.Join(dir, "work")
			if err := os.Mkdir(work, 0o755); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join("..", "stub-script"+sc.suffix+".json"))
			if err != nil {
				t.Fatal(err)
			}
			stubScript := filepath.Join(dir, "stub-script.json")
			if err := os.WriteFile(stubScript, []byte(strings.ReplaceAll(string(raw), "@W@", work)), 0o644); err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := writeCert(t, dir)
			base, stubLog := startStub(t, dir, certPath, keyPath, stubScript)

			hookLog := filepath.Join(dir, "hooks.log")
			result := filepath.Join(dir, "result.json")
			args := append([]string{"__fakeclaude__", "--script", filepath.Join("..", "script"+sc.suffix+".json"),
				"--result", result, "--cwd", work, "--settings", settingsJSON(t, sc.hooks)}, sc.args...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = testutil.TegoEnv(t, dir, "ANTHROPIC_BASE_URL="+base, "SSL_CERT_FILE="+certPath,
				"ANTHROPIC_API_KEY=dummy-not-a-key", "FAKECLAUDE_HOOK_LOG="+hookLog, "CLAUDE_CODE_SIMPLE=", "HOME="+dir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("fakeclaude: %v\n%s", err, out)
			}
			if strings.TrimSpace(string(out)) != sc.final {
				t.Errorf("stdout is %q, want the final text %q", out, sc.final)
			}
			for _, f := range sc.files {
				if fi, err := os.Stat(filepath.Join(work, f)); err != nil || !fi.Mode().IsRegular() {
					t.Errorf("%s was not written by the scripted call: %v", f, err)
				}
			}
			if ents, _ := os.ReadDir(work); len(ents) != len(sc.files) {
				t.Errorf("work holds %v; a temporary file was left", ents)
			}

			golden := filepath.Join(goldenDir, "shape"+sc.suffix+".json")
			if *update {
				shape := exec.Command(py, "-I", reportPy, "shape", stubLog, "--marker", markerText)
				b, err := shape.Output()
				if err != nil {
					t.Fatalf("report.py shape: %v", err)
				}
				if err := os.MkdirAll(goldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			rargs := []string{"-I", reportPy, "check", stubLog, "--result", result, "--marker", markerText, "--shape", golden}
			for _, r := range sc.reminder {
				rargs = append(rargs, "--expect-reminder", r)
			}
			for _, f := range sc.feedback {
				rargs = append(rargs, "--expect-feedback", f)
			}
			if sc.noRem {
				rargs = append(rargs, "--no-reminders")
			}
			if b, err := exec.Command(py, rargs...).CombinedOutput(); err != nil {
				t.Errorf("report.py: %v\n%s", err, b)
			}

			var sum Summary
			b, err := os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &sum); err != nil {
				t.Fatal(err)
			}
			if sum.Ended != "end_turn" || sum.Bare != (sc.name == "bare") {
				t.Errorf("summary: ended %q bare %v", sum.Ended, sum.Bare)
			}
		})
	}
}
