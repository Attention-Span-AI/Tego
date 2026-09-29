// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestDriftAggregateCompilesEachContractOnce: --aggregate recompiled every run's contract copy, although
// runs of one agent almost always share the contract, the cwd and the command; Compile does bounded
// directory listings and link resolution for each deny-write search, so that was per-run filesystem work.
// One compile per distinct (contract, cwd, run command) now, and a different contract still gets its own.
func TestDriftAggregateCompilesEachContractOnce(t *testing.T) {
	root := gcRoot(t)
	cfg := os.Getenv("TEGO_CONFIG")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const same = "version: 0\nname: tester\ncommand: [\"true\"]\n"
	const other = "version: 0\nname: tester\ncommand: [\"true\"]\nexec:\n  allow: [\"/bin/sh\"]\n"
	now := time.Now()
	var ids []string
	for i, contract := range []string{same, same, same, other} {
		id := endedRunAs(t, root, [32]byte{}, "tester", now.Add(time.Duration(i-5)*time.Minute))
		if err := os.WriteFile(filepath.Join(root, id, ledger.ContractFile), []byte(contract), 0o600); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	compiles := 0
	prev := compileTable
	compileTable = func(c *agent.Contract, m *config.Machine, opts ...agent.CompileOption) (*agent.RuleTable, []agent.Diagnostic, error) {
		compiles++
		return prev(c, m, opts...)
	}
	defer func() { compileTable = prev }()
	code, out, errs := run(t, "drift", ids[0], "--aggregate")
	if code == identity.ExitError || code == identity.ExitUsage {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if compiles != 2 {
		t.Errorf("%d compiles over 4 runs of 2 distinct contracts, want 2\nstdout %s\nstderr %s", compiles, out, errs)
	}
}
