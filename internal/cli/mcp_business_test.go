// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestBusinessRulesNeverBuildLegacyCLIService(t *testing.T) {
	c := &agent.Contract{MCP: []agent.MCPServer{{Name: "square", Command: []string{"worker"}, BusinessRules: &agent.BusinessRules{}}}}
	var stderr bytes.Buffer
	sources, code := mcpRelayFor(&agent.RuleTable{Contract: c}, nil, "tego run", &stderr)
	if len(sources) != 0 || code != identity.ExitLauncher || !strings.Contains(stderr.String(), agent.BusinessRulesUnavailable) {
		t.Fatalf("CLI built unsafe service: %v %d %s", sources, code, &stderr)
	}
	servers := relayedServers(c)
	if len(servers) != 1 || !servers[0].BusinessRules {
		t.Fatalf("source marker lost: %+v", servers)
	}
}

// TestBusinessRulesRunRefusesBeforeSetup uses a successfully compiled declaration,
// even in a build that cannot select bpflsm. No host capability is needed to refuse.
func TestBusinessRulesRunRefusesBeforeSetup(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "runs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\ngc_interval: 1s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	buildsTiers(t, backend.TierBPFLSM)
	const bundle = `{"adapter":"square.refund.v1","rules":[{"codes":["USD"],"id":"currencies","kind":"currencies"},{"currency":"USD","id":"refund-cap","kind":"per_call","limit":"10000"}],"server":"square","version":1}`
	path := filepath.Join(base, "agent.yaml")
	yaml := fmt.Sprintf(`version: 0
name: business
command: [true]
tier: bpflsm
record: full
capture: off
mcp:
  - name: square
    command: [/opt/tego/workers/square/node, /opt/tego/workers/square/server.js]
    tools: {allow: [make_api_request]}
    business_rules:
      version: 1
      topology: trusted-stdio-worker-v1
      worker_digest: '%s'
      bundle_sha256: '%x'
      bundle_json: '%s'
`, strings.Repeat("1", 64), sha256.Sum256([]byte(bundle)), bundle)
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	oldProbe, oldSweep, oldAnchor, oldCapture := probeMachine, sweepLive, anchorPath, captureFor
	t.Cleanup(func() { probeMachine, sweepLive, anchorPath, captureFor = oldProbe, oldSweep, oldAnchor, oldCapture })
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		t.Error("backend selection ran before business refusal")
		return nil, errors.New("unexpected backend selection")
	}
	sweepLive = func(context.Context, string, ...tegoruntime.SweepOption) (tegoruntime.SweepResult, error) {
		t.Error("orphan sweep ran before business refusal")
		return tegoruntime.SweepResult{}, nil
	}
	anchorCalls := 0
	anchor := filepath.Join(base, "chain.log")
	anchorPath = func(*config.Machine) (string, error) { anchorCalls++; return anchor, nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		t.Error("capture construction ran before business refusal")
		return nil, nil
	}
	// Establish successful compilation independently of runRun's refusal diagnostic.
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	rt, _, _, code := compileForRun(t.Context(), runOptions{contract: path, offline: true}, m, &stderr)
	if rt == nil || code != identity.ExitOK || !rt.BusinessRulesConfigured() {
		t.Fatalf("compile: %d %s", code, &stderr)
	}
	anchorCalls = 0
	stderr.Reset()
	code = runRun(t.Context(), runOptions{contract: path, offline: true}, &stderr)
	if code != identity.ExitLauncher || !strings.Contains(stderr.String(), agent.BusinessRulesUnavailable) {
		t.Fatalf("run: %d %s", code, &stderr)
	}
	// State restoration, directory setup and compilation resolve the anchor name;
	// none may open the anchor for append as the later probe does.
	if anchorCalls != 3 {
		t.Errorf("anchor resolved %d times, want precompile setup and compilation only", anchorCalls)
	}
	if _, err := os.Stat(anchor); !os.IsNotExist(err) {
		t.Errorf("anchor probe touched disk: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("cleanup/retention touched records: %v", entries)
	}
}
