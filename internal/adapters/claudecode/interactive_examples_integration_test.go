// SPDX-License-Identifier: Apache-2.0

//go:build integration

package claudecode

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// Exercise the shipped filesystem/env/exec policy, rather than a similar
// stand-in contract. Only the model transport is redirected to the local stub;
// no login, external model request or credential is needed.
func TestInteractiveClaudeExamplesRunTool(t *testing.T) {
	for _, example := range []string{"examples/agents/claude-code-interactive.yaml", "examples/demo/contracts/claude-code.yaml"} {
		t.Run(example, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("root does not provision the Claude harness")
			}
			root, err := os.MkdirTemp(os.TempDir(), "cc-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			e := newProvEnvAt(t, root)
			// The project can be arbitrarily deep; only the invoking runtime
			// base affects %R. A short test-owned base avoids sweeping the
			// invoking user's runtime; the PID socket leaf is never shortened.
			e.proj = filepath.Join(e.w, strings.Repeat("long-project-", 6))
			var envBase []string
			for _, kv := range e.env {
				if !strings.HasPrefix(kv, "XDG_RUNTIME_DIR=") {
					envBase = append(envBase, kv)
				}
			}
			e.env = append(envBase, "XDG_RUNTIME_DIR="+testutil.ShortRuntimeDir(t))
			py, err := exec.LookPath("python3")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join("../../..", example))
			if err != nil {
				t.Fatal(err)
			}
			body := strings.ReplaceAll(string(raw), "@@STAGE@@/claude-code", e.proj)
			body = strings.ReplaceAll(body, "/path/to/project", e.proj)
			var contract map[string]any
			if err := yaml.Unmarshal([]byte(body), &contract); err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{filepath.Join(e.proj, ".claude-state/tmp")} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			script, stubScript := filepath.Join(e.w, "script.json"), filepath.Join(e.w, "stub-script.json")
			command := "printf TOOL_OK > tool.txt"
			writeJSON(t, script, map[string]any{"prompt": "Run the tool.", "turns": []any{map[string]any{"calls": []any{map[string]any{"bash": command}}}}})
			writeJSON(t, stubScript, []any{
				[]any{map[string]any{"type": "tool_use", "name": "Bash", "input": map[string]any{"command": command}}},
				[]any{map[string]any{"type": "text", "text": "DONE"}},
			})
			cert, key := provCert(t, e.w)
			base, log := provStub(t, py, e.w, cert, key, stubScript)
			net := contract["net"].(map[string]any)
			net["allow"] = []string{"unix:/var/run/nscd/socket", strings.TrimPrefix(base, "https://")}
			env := contract["env"].(map[string]any)
			env["pass"] = append(env["pass"].([]any), "ANTHROPIC_BASE_URL", "SSL_CERT_FILE")
			contract["tier"] = "landlock"
			data, err := yaml.Marshal(contract)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.w, "interactive.yaml") // outside the writable project
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			result := filepath.Join(e.proj, "result.json")
			run := exec.Command(e.bin, "run", path, "--", e.claude, "--session-socket", "-p", "--script", script, "--result", result, "--cwd", e.proj)
			run.Dir = e.proj
			run.Env = append(e.env, "PATH="+filepath.Dir(e.claude)+":"+os.Getenv("PATH"), "ANTHROPIC_BASE_URL="+base, "SSL_CERT_FILE="+cert, "ANTHROPIC_API_KEY=dummy-not-a-key")
			out, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("run: %v\n%s", err, out)
			}
			if !regexp.MustCompile(`/tego/r-[^/]+/hook-state/cc-socks/[0-9]+\.sock`).Match(out) {
				t.Fatalf("no actual PID socket in the private run runtime:\n%s", out)
			}
			got, err := os.ReadFile(filepath.Join(e.proj, "tool.txt"))
			if err != nil || string(got) != "TOOL_OK" {
				t.Fatalf("tool result %q, %v", got, err)
			}
			raw, err = os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			var res struct {
				Turns []struct {
					Calls []struct {
						Tool string `json:"tool"`
						OK   bool   `json:"ok"`
					} `json:"calls"`
				} `json:"turns"`
			}
			if err := json.Unmarshal(raw, &res); err != nil {
				t.Fatal(err)
			}
			if len(res.Turns) != 1 || len(res.Turns[0].Calls) != 1 || !res.Turns[0].Calls[0].OK || res.Turns[0].Calls[0].Tool != "Bash" {
				t.Fatalf("tool call did not complete: %s", raw)
			}
			if text := stubUserText(t, log, 1); text == "" {
				t.Fatal("the model received no tool result")
			}

			// An app changing its environment after launch still cannot use
			// Claude's shared fallback: the run grants only its private state.
			contract["harness"] = "claude-code"
			data, err = yaml.Marshal(contract)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			bad := exec.Command(e.bin, "run", path, "--", "/bin/bash", "-c",
				`export XDG_RUNTIME_DIR="$1"; exec "$2" --settings "$TEGO_CLAUDE_SETTINGS" --session-socket -p --script "$3"`,
				"fallback", e.proj, e.claude, script)
			bad.Dir, bad.Env = e.proj, run.Env
			out, err = bad.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "/tmp/cc-socks-") || !strings.Contains(string(out), "permission denied") {
				t.Fatalf("shared fallback was not refused: %v\n%s", err, out)
			}
			env["set"].(map[string]any)["XDG_RUNTIME_DIR"] = e.proj
			data, err = yaml.Marshal(contract)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			long := exec.Command(e.bin, run.Args[1:]...)
			long.Dir, long.Env = run.Dir, run.Env
			out, err = long.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "maximum 103") || strings.Contains(string(out), "fakeclaude session socket:") {
				t.Fatalf("overlong explicit directory was not refused before agent start: %v\n%s", err, out)
			}
			env["set"].(map[string]any)["XDG_RUNTIME_DIR"] = "%R"
			data, err = yaml.Marshal(contract)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			baseDir := filepath.Join(e.w, "overlong-invoking-runtime")
			if err := os.MkdirAll(baseDir, 0o700); err != nil {
				t.Fatal(err)
			}
			long = exec.Command(e.bin, run.Args[1:]...)
			long.Dir = run.Dir
			for _, kv := range run.Env {
				if !strings.HasPrefix(kv, "XDG_RUNTIME_DIR=") {
					long.Env = append(long.Env, kv)
				}
			}
			long.Env = append(long.Env, "XDG_RUNTIME_DIR="+baseDir)
			out, err = long.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "maximum 103") || strings.Contains(string(out), "fakeclaude session socket:") {
				t.Fatalf("overlong %%R expansion was not refused before agent start: %v\n%s", err, out)
			}

			t.Logf("%s: private session bind/connect and Bash tool completed (%s)", example, filepath.Join(e.proj, "tool.txt"))
		})
	}
}
