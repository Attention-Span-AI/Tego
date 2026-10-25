// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRevisionIsShownAndKept is agent-contract.md R28: tego compile prints a contract's revision on its own line and
// as revision in --json, and the run directory's contract.yaml keeps it, so the copy reloads to the same revision
// and hash with its extends sealed.
func TestRevisionIsShownAndKept(t *testing.T) {
	f, _ := newCopyFixture(t)
	writeTestFile(t, f.contract, copyContract+"revision: 2026.10.25+1\n")
	t.Chdir(f.project) // the contract's relative entries resolve against the directory compile runs in
	code, out, errs := run(t, "compile", f.contract, "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	if !strings.Contains(out, "\nrevision  2026.10.25+1\n") {
		t.Fatalf("the table has no revision line:\n%s", out)
	}
	code, out, errs = run(t, "compile", f.contract, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	var tbl Table
	if err := json.Unmarshal([]byte(out), &tbl); err != nil || tbl.Revision != "2026.10.25+1" {
		t.Fatalf("--json revision %q (%v):\n%s", tbl.Revision, err, out)
	}

	rt := compileLikeRun(t, f)
	b, err := contractCopy(rt)
	if err != nil {
		t.Fatal(err)
	}
	c, ds, err := loadContractCopy(writeCopy(t, b), hex.EncodeToString(rt.Hash[:]), dirProfiles{})
	if err != nil || c.Revision != "2026.10.25+1" {
		t.Fatalf("the copy reloads with revision %v (%v %v):\n%s", c, err, ds, b)
	}
	if h, err := c.Hash(); err != nil || h != rt.Hash {
		t.Fatalf("reloaded hash %x (%v), want %x", h, err, rt.Hash)
	}

	// A contract with no revision prints no line and writes no key.
	writeTestFile(t, f.contract, copyContract)
	if _, out, _ = run(t, "compile", f.contract, "--offline"); strings.Contains(out, "revision") {
		t.Fatalf("a contract with no revision prints one:\n%s", out)
	}
	if _, out, _ = run(t, "compile", f.contract, "--offline", "--json"); strings.Contains(out, `"revision"`) {
		t.Fatalf("a contract with no revision writes one in --json:\n%s", out)
	}
}
