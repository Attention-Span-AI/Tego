// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// saveParityRun is an ended run in cwd that wrote under cwd/out, connected to an address and started a program: a
// draft from it has an fs.write entry, an address in net.allow and an exec entry.
func saveParityRun(t *testing.T, root, anchor, cwd string) string {
	t.Helper()
	rid, err := identity.NewRunID([32]byte{}, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "bot"}, ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"sh", "bot.sh"}, Cwd: cwd, Tier: "landlock", Capture: "off",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true}}); err != nil {
		t.Fatal(err)
	}
	add := func(kind record.Kind, p any) {
		e := &record.Event{Kind: kind, Source: record.SourceSupervisor, PID: 1, TID: 1, Verdict: record.VerdictAllow, Rule: "unmatched",
			Attr: record.Unattributed(), Authority: record.AuthorityRule}
		if err := e.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	add(record.KindFS, record.FSPayload{Op: record.FSOpen, Path: filepath.Join(cwd, "out", "x.txt"), Flags: 0x241})
	add(record.KindNet, record.NetPayload{Dst: "104.20.23.154:443", Proto: "tcp"})
	add(record.KindExec, record.ExecPayload{Path: "/bin/sh", Argv: []string{"sh", "bot.sh"}, ExecID: "x/1/1"})
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestLearnSaveAndTheDashboardSaveTheSameFile: `tego learn <run> --save <name>` and the dashboard's New contract from
// the same run, saved to the user registry (rules.Service.CreateNew with Registry, the real compile of the machine
// config), write the same file in the same place, refused reads on and off, for names YAML would read as a number,
// a bool or a null as well. The one difference is the header's "leaks:" line: learn judges leaks with its own rule
// (leak.go) and says so there, while the dashboard leaves leaks to the run's verdict (rulesview.Withhold), so its
// draft has no such line. For a run that leaked the two can also allow different addresses; this run leaked
// nothing.
//
// This file is one of the internal/cli tests allowed to import the dashboard (.golangci.yml
// engine-never-imports-control): the parity it checks spans both binaries.
func TestLearnSaveAndTheDashboardSaveTheSameFile(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(filepath.Join(project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	id := saveParityRun(t, root, anchor, project)
	m, err := (&machineOnce{stderr: io.Discard}).get()
	if err != nil {
		t.Fatal(err)
	}
	s := &rules.Service{Ledger: root, Anchor: anchor, Machine: m, Home: m.Home, PATH: os.Getenv("PATH")}
	for _, c := range []struct {
		name  string
		reads bool
	}{{"same", true}, {"quiet", false}, {"123", true}, {"null", true}, {"true", false}, {"1e3", true}} {
		t.Run(c.name, func(t *testing.T) {
			args := []string{"learn", id, "--save", c.name}
			if !c.reads {
				args = append(args, "--reads", "off")
			}
			code, _, errs := run(t, args...)
			file := filepath.Join(reg, "agents", c.name+".yaml")
			cli, err := os.ReadFile(file)
			if code != identity.ExitOK || err != nil {
				t.Fatalf("tego learn --save %s: exit %d, %v\n%s", c.name, code, err, errs)
			}
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}

			req := rules.NewReq{Dir: project, Name: c.name, FromRun: id, Registry: true, Reads: c.reads}
			p, err := s.PlanNew(t.Context(), req)
			if err != nil || len(p.Problems) > 0 || !p.OK || p.File != file {
				t.Fatalf("the dashboard's plan: %v, problems %q, ok %v, file %s, diagnostics %q", err, p.Problems, p.OK, p.File, p.Diagnostics)
			}
			cr, err := s.CreateNew(t.Context(), req, p.Base)
			if err != nil || cr.Path != file || !cr.Registry {
				t.Fatalf("the dashboard's save: %+v, %v", cr, err)
			}
			dash, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}

			var leaks []string
			kept := strings.SplitAfter(string(cli), "\n")
			for i := 0; i < len(kept); i++ {
				if strings.HasPrefix(kept[i], "#   - leaks: ") {
					leaks = append(leaks, kept[i])
					kept = append(kept[:i], kept[i+1:]...)
					i--
				}
			}
			if len(leaks) != 1 {
				t.Errorf("the CLI's file has %d leaks lines, not one:\n%s", len(leaks), cli)
			}
			if want := strings.Join(kept, ""); string(dash) != want {
				t.Errorf("the two files differ past the leaks line:\n--- tego learn --save\n%s\n--- dashboard\n%s", want, dash)
			}
			if !strings.Contains(string(dash), "\nname: \""+c.name+"\"\n") || strings.Contains(string(dash), "reads: on") != c.reads {
				t.Errorf("the saved file's name or reason block:\n%s", dash)
			}
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
		})
	}
}
