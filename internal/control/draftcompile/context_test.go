// SPDX-License-Identifier: Apache-2.0
package draftcompile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestChildPreservesUnknownMachineBaseline(t *testing.T) {
	home := t.TempDir()
	missing := filepath.Join(home, "missing-machine.yaml")
	m, _, err := config.LoadSources(config.Sources{EnvFile: missing}, home, os.Getuid(), config.TrustWarn)
	if err != nil || m.BaselineKnown() {
		t.Fatalf("unknown fixture: %v", err)
	}
	// A snapshot-only caller has no source reloader. Its UNKNOWN observation must
	// survive the child boundary rather than becoming an empty known baseline.
	m.Sources = nil
	r, err := Check(context.Background(), Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(home, "agent.yaml"), Cwd: home, Home: home, PATH: "/usr/bin:/bin"}, Text: []byte("version: 0\nname: unknown\ncommand: [sh]\n")})
	if err == nil {
		t.Fatalf("UNKNOWN machine compiled after transport: %+v", r)
	}
}
