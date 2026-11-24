// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/mcprelay"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// C208: the relay and the forwarder hold a Locked run to its contract, and only the launcher knows the run's mode. These
// pin that it hands the mode over: a relay or forwarder built without it is Locked (their own tests), so a missing line
// here would make an Adjustable run's live switches silently stop working, and a wrong one would make a Locked run's open.

func relayContract() *agent.Contract {
	return &agent.Contract{MCP: []agent.MCPServer{{Name: "files", Command: []string{"server"}, Tools: &agent.MCPTools{Deny: []string{"delete_file"}}}}}
}

func TestMCPRelayGetsTheRunsMode(t *testing.T) {
	for _, c := range []struct {
		name string
		rt   *agent.RuleTable
		want bool
	}{
		{"no live section: Locked", &agent.RuleTable{Contract: relayContract()}, false},
		{"live.mode locked", &agent.RuleTable{Contract: relayContract(), Live: &agent.LiveTable{Mode: agent.LiveLocked}}, false},
		{"live.mode adjustable", &agent.RuleTable{Contract: relayContract(), Live: &agent.LiveTable{Mode: agent.LiveAdjustable}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var stderr bytes.Buffer
			sources, code := mcpRelayFor(c.rt, nil, "tego run", &stderr)
			if code != 0 || len(sources) != 1 {
				t.Fatalf("sources %v, code %d: %s", sources, code, &stderr)
			}
			s, ok := sources[0].(*mcprelay.Service)
			if !ok {
				t.Fatalf("source %T", sources[0])
			}
			defer func() { _ = s.Stop() }()
			if s.Adjustable() != c.want {
				t.Fatalf("Adjustable %v, want %v", s.Adjustable(), c.want)
			}
		})
	}
}

// TestForwarderFactoryHandsOverTheRunsMode: forwarderFactory builds forwarder.Options in a closure that cannot be run here
// without the machine's own log, so its literal is read: it names Adjustable, from the run's table.
func TestForwarderFactoryHandsOverTheRunsMode(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "capture.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Options" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "forwarder" {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Adjustable" {
				call, ok := kv.Value.(*ast.CallExpr)
				if !ok {
					continue
				}
				if s, ok := call.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Adjustable" {
					if x, ok := s.X.(*ast.Ident); ok && x.Name == "rt" {
						found = true
					}
				}
			}
		}
		return true
	})
	if !found {
		t.Fatal("forwarderFactory's forwarder.Options does not say Adjustable: rt.Adjustable(): a Locked forwarder would ignore an Adjustable run's live routes")
	}
}
