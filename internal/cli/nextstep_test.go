// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRuleOnAWatchedRunPointsToLearn: a run whose record names no contract file (a tego watch run) has no
// file for tego rule to change; it says so and points to tego learn, exit 1 [usage], not 125 [io].
func TestRuleOnAWatchedRunPointsToLearn(t *testing.T) {
	start := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "observe", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: t.TempDir(), Kernel: "6", StopGrace: "1s"})
	read := ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: "/etc/hostname"}, func(e *record.Event) {
		e.Seq, e.Source, e.Rule, e.Verdict, e.Authority = 1, record.SourceSeccomp, "unmatched", record.VerdictAllow, record.AuthorityRule
		e.Prev = strings.Repeat("a", 64)
		e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
	})
	var buf bytes.Buffer
	for _, e := range []*record.Event{start, read} {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	dir := filepath.Join(resolvedTemp(t), "r-watched")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "rule", dir, "1", "--block")
	if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "names no contract file") ||
		!strings.Contains(errs, "tego learn r-watched --out agent.yaml") || !strings.Contains(errs, "[usage]") {
		t.Errorf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestInitSaysToSetTheCommand: the starter runs python3 agent.py; in a project without one, plain tego init
// says to set command: first, and with one it says the run is ready.
func TestInitSaysToSetTheCommand(t *testing.T) {
	dir := t.TempDir()
	if code, out, errs := run(t, "init", dir); code != identity.ExitOK || errs != "" ||
		!strings.Contains(out, "next: set command: in agent.yaml to your agent's command line") {
		t.Errorf("without agent.py: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.py"), []byte("print('hi')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := run(t, "init", dir); code != identity.ExitOK || errs != "" ||
		!strings.Contains(out, "next: tego compile agent.yaml; tego run agent.yaml (it runs python3 agent.py)") {
		t.Errorf("with agent.py: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
}
