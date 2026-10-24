// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scope

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestContractLoadsInEngine hands a generated contract to the engine's own loader (spec/agent/v0, unknown
// fields refused), so a contract Maze writes is one the engine reads. Linux only: pkg/spec/agent doesn't build
// on macOS.
func TestContractLoadsInEngine(t *testing.T) {
	root, home := project(t)
	c, err := Compile(Input{Root: root, Home: home, Name: "demo", Rules: sampleRules(), LookPath: installed})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "claude.yaml")
	if err := os.WriteFile(path, c.Contract, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ds, err := agent.Load(path, nil); err != nil {
		t.Fatalf("the engine refused the contract: %v\n%v\n%s", err, ds, c.Contract)
	}
}
