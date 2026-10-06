// SPDX-License-Identifier: Apache-2.0

package evaluate_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestExternalModule exercises Go's actual internal import boundary. An external
// test package within this repository still has permission to import internal,
// which concealed the broken compatibility path for ordinary module consumers.
func TestExternalModule(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mod := fmt.Sprintf("module example.com/tego-consumer\n\ngo 1.27\n\nrequire github.com/attention-span-ai/tego v0.0.0\nreplace github.com/attention-span-ai/tego => %q\n", root)
	source := `package main
import (
 "github.com/attention-span-ai/tego/pkg/policy/evaluate"
 "github.com/attention-span-ai/tego/pkg/spec/agent"
 "github.com/attention-span-ai/tego/pkg/spec/backend"
)
func main() {
 rt := &agent.RuleTable{Contract: &agent.Contract{}}
 action := agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.1", Port: 443, Proto: agent.ProtoTCP}
 got := evaluate.Evaluate(rt, action, backend.TierLandlock)
 if got.Verdict != agent.VerdictAllow { panic("unexpected verdict") }
 if rt.Evaluate(action, backend.TierLandlock) != got { panic("legacy model diverged") }
 evaluate.FSDecider(rt, "/tmp/x", true)
 evaluate.ListenerOpenRefused(rt, "/tmp/x")
 evaluate.ExecReadGrant(rt, "/tmp/x")
 if evaluate.Canonical(rt, "/tmp/x") != "/tmp/x" { panic("canonical path changed") }
 table := &agent.TestTable{}
 evaluate.Run(table, rt, "/", backend.TierLandlock)
 table.Run(rt, "/", backend.TierLandlock)
}
`
	for name, body := range map[string]string{"go.mod": mod, "main.go": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(t.Context(), "go", "run", "-mod=mod", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("external consumer: %v\n%s", err, output)
	}
}
