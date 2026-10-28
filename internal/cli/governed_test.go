// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// governedCaller makes the commands see their caller inside a run (or, with err, unable to tell) for the test.
func governedCaller(t *testing.T, err error) {
	t.Helper()
	old := selfInRun
	selfInRun = func() (bool, error) { return true, err }
	t.Cleanup(func() { selfInRun = old })
}

// TestUnblockRefusedInsideARun: a caller inside a run cannot lift a live block (an agent lifting what
// governs it), and the overlay keeps it; adding a block to its own run, which only takes away, is still done. A caller that cannot
// be shown outside every run is refused the same way.
func TestUnblockRefusedInsideARun(t *testing.T) {
	dir, id, _ := liveRun(t)
	if code, _, errs := run(t, "block", id, "exec", "curl"); code != identity.ExitOK {
		t.Fatalf("block: exit %d %s", code, errs)
	}
	governedCaller(t, nil)
	callerRun(t, id, nil)
	code, out, errs := run(t, "unblock", id, "exec", "curl")
	if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "a governed agent cannot change its own governance") ||
		!strings.Contains(errs, "[governed]") || !strings.Contains(errs, "outside any tego run") {
		t.Errorf("unblock inside a run: exit %d stdout %q stderr %q", code, out, errs)
	}
	if o, err := liveblock.Read(dir, id); err != nil || len(o.Blocks) != 1 {
		t.Fatalf("the block was lifted from inside the run: %+v %v", o, err)
	}
	if code, _, errs := run(t, "block", id, "net", "example.com:443"); code != identity.ExitOK {
		t.Errorf("a block from inside the run (a narrowing): exit %d %s", code, errs)
	}
	governedCaller(t, errors.New("runscope: this process is in cgroup namespace 4026532000, not the initial one"))
	if code, _, errs := run(t, "unblock", id, "exec", "curl"); code != identity.ExitFinding || !strings.Contains(errs, "cannot be shown to be outside every tego run") {
		t.Errorf("unblock from an unknown cgroup: exit %d stderr %q", code, errs)
	}
}

// TestRuleWideningRefusedInsideARun: tego rule --allow (a widening) from inside a run writes nothing;
// --block (a narrowing) is written, and --dry-run still prints the diff.
func TestRuleWideningRefusedInsideARun(t *testing.T) {
	dir, contract := refusedWriteRun(t)
	governedCaller(t, nil)
	if code, out, errs := run(t, "rule", dir, "1", "--allow", "--dry-run"); code != identity.ExitOK || !strings.Contains(out, "+    - ./log.txt") {
		t.Fatalf("a dry run inside a run: exit %d %q %s", code, out, errs)
	}
	code, _, errs := run(t, "rule", dir, "1", "--allow")
	if code != identity.ExitFinding || !strings.Contains(errs, "a governed agent cannot change its own governance") {
		t.Errorf("--allow inside a run: exit %d stderr %q", code, errs)
	}
	if b, _ := os.ReadFile(contract); string(b) != ruleContract {
		t.Fatalf("--allow inside a run wrote the contract:\n%s", b)
	}
	if _, err := os.Stat(contract + ".bak"); err == nil {
		t.Error("--allow inside a run left a .bak")
	}
	// Asking where the write was refused lets the next run do more (a yes lets it through): refused too.
	if code, _, errs := run(t, "rule", dir, "1", "--ask"); code != identity.ExitFinding || !strings.Contains(errs, "[governed]") {
		t.Errorf("--ask of a refused write inside a run: exit %d %s", code, errs)
	}
	// A narrowing (block a read that was allowed) is written from inside a run.
	readDir, readContract, _ := ruleRun(t)
	if code, _, errs := run(t, "rule", readDir, "1", "--block"); code != identity.ExitOK {
		t.Fatalf("--block inside a run: exit %d %s", code, errs)
	}
	if b, _ := os.ReadFile(readContract); !strings.Contains(string(b), "deny_read:") {
		t.Errorf("--block inside a run wrote nothing:\n%s", b)
	}
}

// refusedWriteRun is ruleRun with line #1 a write to proj/log.txt the contract refused, so --allow widens.
func refusedWriteRun(t *testing.T) (dir, contract string) {
	t.Helper()
	root := resolvedTemp(t)
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(filepath.Join(proj, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	contract = filepath.Join(root, "agent.yaml")
	if err := os.WriteFile(contract, []byte(ruleContract), 0o600); err != nil {
		t.Fatal(err)
	}
	start := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
		ContractSource: &record.ContractSource{Path: contract}})
	refused := ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "open", Target: filepath.Join(proj, "log.txt")},
		func(e *record.Event) {
			e.Seq, e.Source, e.Rule, e.Reason = 1, record.SourceSeccomp, "unmatched", record.ReasonWriteOutsideContract
			e.Prev = strings.Repeat("a", 64)
		})
	var buf bytes.Buffer
	for _, e := range []*record.Event{start, refused} {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	dir = filepath.Join(resolvedTemp(t), "r-fixture")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, contract
}
