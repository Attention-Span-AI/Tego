// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestRecordedRulesRequireCompleteCurrentConfig(t *testing.T) {
	for _, state := range []string{"empty", "configured", "unknown"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			contents := "{}\n"
			if state == "configured" {
				contents = "baseline: {exec: {deny: ['true']}}\n"
			}
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if state == "unknown" {
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			m, _, err := config.LoadSources(config.Sources{User: path}, dir, os.Getuid(), config.TrustWarn)
			if err != nil {
				t.Fatal(err)
			}
			m.LedgerRoot.Value = filepath.Join(dir, "ledger")
			text := []byte("version: 0\nname: recorded\ncommand: [/bin/true]\ncapture: off\n")
			if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), text, 0o600); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(text)
			var got Contract
			loadCopy(context.Background(), &got, dir, record.RunStartPayload{ContractHash: hex.EncodeToString(hash[:]), Cwd: dir}, Options{Machine: m}, nil, nil)
			if state == "unknown" {
				if got.Compiled != nil || got.Text == "" || !strings.Contains(got.Err, "baseline UNKNOWN") || !strings.Contains(got.Err, path) {
					t.Fatalf("degraded rules view stated rules or lost readable text/cause: %+v", got)
				}
			} else if got.Err != "" || got.Compiled == nil || got.Compiled.Baseline != nil || !strings.Contains(got.Table, "baseline UNKNOWN: this record") {
				t.Fatalf("historical view borrowed current baseline or failed ordinary input: %+v", got)
			}
		})
	}
}

func TestBaselineAppliedOnceAcrossRulesViewReplay(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "baseline-tool"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("baseline: {env: {deny: [TOKEN]}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, _, err := config.LoadSources(config.Sources{User: cfg}, dir, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	m.LedgerRoot.Value = filepath.Join(dir, "runs")
	c, _, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), []byte("version: 0\nname: recorded\ncommand: [baseline-tool]\ncapture: off\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, ds, err := agent.Compile(c, m, agent.WithHome(dir), agent.WithPATH(bin), agent.WithOwnBinaries(""), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("%v %v", err, ds)
	}
	p := record.RunStartPayload{Tier: "landlock", Cwd: dir}
	if err := rt.RecordBaseline(&p, m, backend.TierLandlock, "", false, true); err != nil {
		t.Fatal(err)
	}
	sourceBytes, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), sourceBytes, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	t.Run("current-comparison-keeps-caller-path", func(t *testing.T) {
		caller := config.CallerContext{UID: os.Getuid(), Home: dir, Cwd: dir, PATH: bin}
		view := InForceView{Source: filepath.Join(dir, "agent.yaml")}
		view.compareBaseline(t.Context(), p, Options{Machine: m, Caller: &caller, PATH: bin}, source{matches: true, text: sourceBytes})
		if view.NextEffectiveHash != p.EffectiveHash || !strings.Contains(view.BaselineCheck, "same effective contract bytes") {
			t.Fatalf("baseline comparison lost frozen caller PATH: %+v", view)
		}
	})
	retry := 0
	for _, state := range []string{"original", "edited", "deleted"} {
		if state == "edited" {
			if err := os.WriteFile(cfg, []byte("baseline: {env: {deny: [OTHER]}}\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if state == "deleted" {
			if err := os.Remove(cfg); err != nil {
				t.Fatal(err)
			}
		}
		var got Contract
		loadCopy(context.Background(), &got, dir, p, Options{Machine: m}, nil, func(string) string { retry++; return bin })
		if got.Err != "" || got.Compiled == nil {
			t.Fatalf("%s: %s", state, got.Err)
		}
		if got.Compiled.EffectiveHash != rt.EffectiveHash || len(got.Compiled.Baseline.Entries) != 1 || len(got.Compiled.EffectiveContract.Env.Deny) != 1 || strings.Contains(got.Table, "baseline UNKNOWN") {
			t.Fatalf("%s: insertion changed: %s", state, got.Table)
		}
	}
	if retry != 3 {
		t.Fatalf("PATH retry called %d times, want 3", retry)
	}
}
