// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestParityCLIAndDashboard: `tego rule` and the dashboard's rule service (internal/control/rules) give the same
// verdict on the same change of the same run's contract, over six fixtures: a contract
// that extends a profile (F2), a tier-auto contract with fs.ask_read at the run's tier (F3), a pinned tier, a program
// named by a basename only the run's exec directories hold (F17), an entry the compiler refuses, and a widening
// change. Both write paths now compile through internal/nextrun; this holds the context each one fills.
//
// This file is one of the internal/cli tests allowed to import the dashboard (.golangci.yml
// engine-never-imports-control): the parity it checks spans both binaries.
func TestParityCLIAndDashboard(t *testing.T) {
	root := resolvedTemp(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(root, "proj")
	profiles := filepath.Join(root, "profiles")
	bin := filepath.Join(root, "bin")
	ledgerRoot := filepath.Join(root, "runs")
	for _, d := range []string{filepath.Join(proj, "docs"), filepath.Join(profiles, "base"), bin, ledgerRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(profiles, "base", "mini.yaml"): "net:\n  allow: [\"api.example.com:443\"]\n",
		filepath.Join(proj, "secret.txt"):            "s3cret",
	}
	for p, b := range files {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "parity-tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+ledgerRoot+"\nprofiles: "+profiles+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigVar, cfg)
	m, err := (&machineOnce{stderr: io.Discard}).get()
	if err != nil {
		t.Fatal(err)
	}
	if m.Profiles.Value != profiles {
		t.Fatalf("the machine's profiles are %q, not the fixture's", m.Profiles.Value)
	}
	head := "version: 0\nname: parity\ncommand: [\"sh\"]\n"
	cases := []struct {
		name, text, action, line string
		ok                       bool
	}{
		{"extends a profile", head + "extends: base/mini\nexec:\n  allow: [sh]\n", "--block", "1", true},
		{"auto with ask_read", head + "tier: auto\nexec:\n  allow: [sh]\nfs:\n  ask_read: [\"./docs/\"]\n", "--block", "1", true},
		{"pinned tier", head + "tier: landlock\nexec:\n  allow: [sh]\n", "--block", "1", true},
		{"basename off PATH", head + "tier: landlock\nexec:\n  allow: [sh, parity-tool]\n", "--block", "1", true},
		{"a broken entry", head + "tier: landlock\nexec:\n  allow: [sh, no-such-program-tego-parity]\n", "--block", "1", false},
		// Line #2 is the exec of a program the contract does not allow: --allow widens exec.allow by it.
		{"a widened entry", head + "tier: landlock\nexec:\n  allow: [sh]\n", "--allow", "2", true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			contract := filepath.Join(proj, "agent-"+string(rune('a'+i))+".yaml")
			if err := os.WriteFile(contract, []byte(c.text), 0o644); err != nil {
				t.Fatal(err)
			}
			id := "r-0000abcd-000000000000" + string(rune('a'+i)) + "-parity"
			parityRun(t, filepath.Join(ledgerRoot, id), id, contract, proj, filepath.Join(bin, "parity-tool"))
			code, _, errs := run(t, "rule", filepath.Join(ledgerRoot, id), c.line, c.action, "--dry-run")
			cliOK := code == identity.ExitOK
			s := &rules.Service{Ledger: ledgerRoot, Machine: m, Home: m.Home, PATH: os.Getenv("PATH")}
			p, err := s.ActOn(t.Context(), rules.ActReq{Run: id, Seq: map[string]uint64{"1": 1, "2": 2}[c.line], Action: strings.TrimPrefix(c.action, "--")})
			if err != nil {
				t.Fatal(err)
			}
			dashOK := p.PickErr == ""
			if cliOK != dashOK {
				t.Fatalf("tego rule ok=%v (%s), dashboard ok=%v (%s)", cliOK, errs, dashOK, p.PickErr)
			}
			if cliOK != c.ok {
				t.Errorf("both said ok=%v, want %v: %s %s", cliOK, c.ok, errs, p.PickErr)
			}
			if b, _ := os.ReadFile(contract); string(b) != c.text {
				t.Errorf("a plan wrote the contract:\n%s", b)
			}
		})
	}
}

// parityRun writes the run directory dir of a run of contract at tier landlock from proj whose line #1 is a read of
// proj/secret.txt and whose line #2 is a refused exec of tool: tool's folder is on no PATH but the run's.
func parityRun(t *testing.T, dir, run, contract, proj, tool string) {
	t.Helper()
	start := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
		ContractSource: &record.ContractSource{Path: contract}})
	read := ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: filepath.Join(proj, "secret.txt")},
		func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Authority = record.SourceSeccomp, "unmatched", record.VerdictAllow, record.AuthorityRule
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		})
	exec := ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: tool, Argv: []string{"parity-tool"}, ExecID: "x/1/1"},
		func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Authority = record.SourceSeccomp, "unmatched", record.VerdictRefused, record.AuthorityRule
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		})
	var buf bytes.Buffer
	for n, e := range []*record.Event{start, read, exec} {
		e.Run, e.Seq = run, uint64(n)
		if n > 0 {
			e.Prev = strings.Repeat("a", 64)
		}
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
