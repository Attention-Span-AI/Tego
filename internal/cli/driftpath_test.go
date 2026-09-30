// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"testing"
)

// TestDriftUnderAnotherPATHIsNotADriftFinding: run_start does not record the run's PATH, so a reader whose
// PATH lacks a bare exec.allow entry cannot recompile the contract. Its declared entries are then unknown,
// and the rules the run used read as unknown, not as undeclared: nothing about the run's world changed.
func TestDriftUnderAnotherPATHIsNotADriftFinding(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no jq, which driftContract allows
	dir := runWithContract(t, driftContract)
	rep, err := driftReport(context.Background(), dir, &machineOnce{stderr: io.Discard}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DeclaredUnknown {
		t.Fatal("a contract that does not recompile here did not mark the report's declared entries unknown")
	}
	// The fixture's own refusal is a finding whatever the PATH; what must not be one is an undeclared rule.
	// The fixture's recorded hash is not driftContract's, so the hash comparison is cleared as well.
	rep.Exec, rep.FS, rep.Net, rep.MCP, rep.Other = nil, nil, nil, nil, nil
	rep.HashChanged, rep.UnusedMCP = false, nil // mcp[postgres] is the contract's own text, unused whatever the PATH
	if rep.Drifted() {
		t.Errorf("the report drifted with no rule left but unknown ones: undone %v unused mcp %v", rep.Undone, rep.UnusedMCP)
	}
}
