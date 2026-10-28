// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRunPassesAdjustableToTheLauncher: since the launcher seeds the fence's refusals, `tego run` of an
// Adjustable contract reaches the runtime, which refuses to start where it cannot (runtime.ErrLiveStart); `tego adopt`
// of one is still refused with exit 125 [live-unavailable] before anything starts (ADR 0125 decision 6). A table with no
// live: key is never refused.
func TestRunPassesAdjustableToTheLauncher(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	// The project is a folder of its own: inside base, which holds the run's config and ledger, compile would refuse
	// the fence's read entry as reaching Tego's own state.
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(filepath.Join(work, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "secrets", "a"), []byte("TOPSECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// compile resolves a relative path against the working folder, so ./secrets is work's.
	t.Chdir(work)
	// A read fence entry needs an exec.allow list ([live-fence-entry]), so the contract names cat.
	const body = "version: 0\nname: fenced\ntier: auto\ncommand: [cat, secrets/a]\nenv: {pass: [PATH]}\n" +
		"exec: {allow: [cat]}\nfs: {deny_read: [./secrets/]}\n"
	prevAnchor, prevRun := anchorPath, startRun
	t.Cleanup(func() { anchorPath, startRun = prevAnchor, prevRun })
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	started := 0
	var handed *agent.RuleTable
	startRun = func(_ context.Context, tbl *agent.RuleTable, _ []string, _ tegoruntime.Deps) (tegoruntime.Result, error) {
		started++
		handed = tbl
		return tegoruntime.Result{}, tegoruntime.ErrDeps
	}
	run := func(contract string) (int, string) {
		p := filepath.Join(work, "agent.yaml")
		if err := os.WriteFile(p, []byte(contract), 0o600); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		code := runRun(context.Background(), runOptions{contract: p, offline: true}, &stderr)
		return code, stderr.String()
	}
	code, out := run(body + "live: {mode: adjustable, fence: {read: [./secrets]}}\n")
	if strings.Contains(out, "["+codeLiveUnavailable+"]") {
		t.Fatalf("exit %d: a run of an Adjustable contract is refused before the launcher:\n%s", code, out)
	}
	if started != 1 {
		t.Fatalf("exit %d: the runtime was started %d times for an Adjustable contract, want once:\n%s", code, started, out)
	}
	// The launcher gets the table compile made: its mode and its fence, the read entry resolved, as the launcher seeds them.
	wantRead := filepath.Join(work, "secrets")
	if handed == nil || handed.Live == nil {
		t.Fatalf("the runtime was handed no live table (%v)", handed)
	}
	if l := handed.Live; l.Mode != agent.LiveAdjustable || len(l.Entries) != 1 || l.Entries[0].Kind != agent.LiveKindRead ||
		l.Entries[0].Value != wantRead || l.SHA256 == "" {
		t.Fatalf("the runtime was handed the live table %+v, want an Adjustable one whose fence is read:%s", *l, wantRead)
	}
	var adopted bytes.Buffer
	if code := refuseAdjustableRun(&agent.RuleTable{Contract: &agent.Contract{Name: "fenced"},
		Live: &agent.LiveTable{Mode: agent.LiveAdjustable}}, "x", true, &adopted); code != identity.ExitLauncher ||
		!strings.Contains(adopted.String(), "["+codeLiveUnavailable+"]") || !strings.Contains(adopted.String(), "live.mode: locked") {
		t.Fatalf("an adoption of an Adjustable table: exit %d, want 125 [%s]:\n%s", code, codeLiveUnavailable, adopted.String())
	}
	var none bytes.Buffer
	if code := refuseAdjustableRun(&agent.RuleTable{Contract: &agent.Contract{Name: "fenced"}}, "x", false, &none); code != 0 || none.Len() != 0 {
		t.Fatalf("a table with no live: key is refused (%d): %s", code, none.String())
	}
}
