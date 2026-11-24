// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileBaselineDualHashAndEffectiveOutput(t *testing.T) {
	gcRoot(t)
	configPath := os.Getenv("TEGO_CONFIG")
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("baseline: {env: {deny: [PROD_TOKEN]}}\n"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("version: 0\nname: baseline-output\ncommand: [/bin/true]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, merged, errs := run(t, "rules", "check", path, "--merged")
	if code != 0 || strings.Contains(merged, "PROD_TOKEN") {
		t.Fatalf("source: %d %s %s", code, merged, errs)
	}
	code, effective, errs := run(t, "rules", "check", path, "--effective")
	if code != 0 || !strings.Contains(effective, "PROD_TOKEN") {
		t.Fatalf("effective: %d %s %s", code, effective, errs)
	}
	code, out, errs := run(t, "rules", "check", path, "--json")
	if code != 0 {
		t.Fatalf("json: %d %s", code, errs)
	}
	var table struct {
		ContractHash  string         `json:"contract_hash"`
		EffectiveHash string         `json:"effective_hash"`
		Baseline      *TableBaseline `json:"baseline"`
	}
	if err := json.Unmarshal([]byte(out), &table); err != nil {
		t.Fatal(err)
	}
	if len(table.ContractHash) != 64 || len(table.EffectiveHash) != 64 || table.ContractHash == table.EffectiveHash {
		t.Fatalf("hashes: %+v", table)
	}
	if b := table.Baseline; b == nil || !b.Applied || len(b.Entries) != 1 || b.Entries[0].Value != "PROD_TOKEN" || len(b.Entries[0].Sources) != 1 || len(b.Entries[0].Coverage) != 5 || len(b.Entries[0].Rules) != 1 {
		t.Fatalf("missing baseline sources/rules/modeled coverage: %+v", b)
	}
	code, _, _ = run(t, "rules", "check", path, "--effective", "--merged")
	if code != 2 {
		t.Fatalf("conflicting print flags=%d", code)
	}
}

func TestCompileEmptyBaselineOmitsEffectiveHash(t *testing.T) {
	for _, baseline := range []string{"", "baseline: {}\n", "baseline: {env: {deny: []}}\n"} {
		t.Run(strings.TrimSpace(baseline), func(t *testing.T) {
			gcRoot(t)
			p := os.Getenv("TEGO_CONFIG")
			f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(baseline); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "agent.yaml")
			if err := os.WriteFile(path, []byte("version: 0\nname: empty-baseline-output\ncommand: [/bin/true]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, "rules", "check", path, "--json")
			if code != 0 {
				t.Fatalf("compile: %d %s", code, errs)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(out), &fields); err != nil {
				t.Fatal(err)
			}
			if _, ok := fields["effective_hash"]; ok {
				t.Fatalf("empty baseline changes ordinary JSON: %s", out)
			}
			if _, ok := fields["baseline"]; ok {
				t.Fatalf("empty baseline carries metadata: %s", out)
			}
		})
	}
}
