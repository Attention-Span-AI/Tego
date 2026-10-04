// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Listing edits must not stop Compile recognizing a variable the actual
// forwarder still overrides, or make a foreign variable runtime-owned.
func TestForwarderListingDoesNotRedefineReservedVariables(t *testing.T) {
	original := identity.ForwarderVarNames
	t.Cleanup(func() { identity.ForwarderVarNames = original })
	identity.ForwarderVarNames[0] = "FOREIGN_ROUTING_VAR"
	if !identity.ForwarderVar(identity.EnvAnthropicBaseURL) || identity.ForwarderVar("FOREIGN_ROUTING_VAR") {
		t.Error("editing the listing changed runtime-owned variables")
	}
	root := t.TempDir()
	c, _, err := agent.LoadBytes(filepath.Join(root, "agent.yaml"), []byte("version: 0\nname: agent\ncommand: [/bin/true]\ntier: landlock\ncapture: forwarder\nfs: {deny_read: []}\nenv: {pass: [ANTHROPIC_BASE_URL]}\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "runs")
	rt, ds, err := agent.Compile(c, m, agent.WithHome(root), agent.WithCwd(root), agent.WithMountInfo(""))
	if err != nil {
		t.Fatalf("compile: %v (%v)", err, ds)
	}
	if slices.Contains(rt.Env, identity.EnvAnthropicBaseURL) {
		t.Error("listing edit kept the forwarder-owned variable in env.pass")
	}
	if !slices.ContainsFunc(ds, func(d agent.Diagnostic) bool { return d.Code == agent.CodeEnvRuntimeReserved }) {
		t.Error("listing edit suppressed the forwarder override diagnostic")
	}
}
