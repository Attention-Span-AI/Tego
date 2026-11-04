// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestRulesUsesDashboardView(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root, proj := filepath.Join(base, "runs"), filepath.Join(base, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	text := []byte("version: 0\nname: demo\ncommand: [/bin/true]\ncapture: off\nenv:\n  set:\n    APP_KEY: DO-NOT-DISPLAY-SECRET\n")
	path := filepath.Join(proj, "agent.yaml")
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(path, text, nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	const id = "r-12345678-0000000000000-abcdef"
	dir := filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Cwd: proj, Command: []string{"/bin/true"}, ContractHash: fmt.Sprintf("%x", hash), ContractSource: &record.ContractSource{Path: path}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.ContractFile), canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	old := anchorPath
	anchorPath = func() (string, error) { return ledger.DefaultAnchorPath(dir), nil }
	t.Cleanup(func() { anchorPath = old })
	m, _, err := loadMachine()
	if err != nil {
		t.Fatal(err)
	}
	want := rulesview.InForce(context.Background(), root, id, rulesview.Options{Machine: m, Anchor: ledger.DefaultAnchorPath(dir), Profiles: profilesrc.Chain(m)})
	for _, args := range [][]string{{"rules", id, "--json"}, {"rules", "--json", "abcdef"}, {"rules", "--last", "--json"}} {
		code, out, errs := run(t, user, args...)
		if code != 0 {
			t.Fatalf("%q: %d %s %s", args, code, out, errs)
		}
		var got struct {
			V int `json:"v"`
			*rulesview.InForceView
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if got.V != 1 || !reflect.DeepEqual(got.View, want.View) || got.Positions != want.Positions {
			t.Fatalf("different dashboard view: %s", out)
		}
		if strings.Contains(out, "DO-NOT-DISPLAY-SECRET") {
			t.Fatal("rules exposed an env.set value")
		}
	}
	code, out, errs := run(t, user, "rules", id)
	if code != 0 || !strings.Contains(out, "Rules for run "+id) || !strings.Contains(out, "Next: tego receipt "+id) || strings.Contains(out, "DO-NOT-DISPLAY-SECRET") {
		t.Fatalf("text: %d %s %s", code, out, errs)
	}
	// Pin the complete human text deliberately; paths and the run's measured duration are not part of this view.
	out = strings.ReplaceAll(out, base, "$PROJECT")
	golden := filepath.Join("testdata", "rules.golden")
	if os.Getenv("TEGO_UPDATE_RULES_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(golden)
	if err != nil || string(b) != out {
		t.Fatalf("rules golden differs (%v):\n%s", err, out)
	}
	for _, args := range [][]string{{"rules"}, {"rules", "--last", id}, {"rules", ""}, {"rules", "abc"}, {"rules", "unknown"}} {
		if code, _, _ := run(t, user, args...); code != 2 {
			t.Fatalf("%q: %d", args, code)
		}
	}
	// Interrupted startup can leave a directory, or an empty events file, newer than this complete run.
	const abandoned = "r-12345678-0000000000001-abcdef"
	abandonedDir := filepath.Join(root, abandoned)
	if err := os.Mkdir(abandonedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, empty := range []bool{false, true} {
		if empty {
			if err := os.WriteFile(filepath.Join(abandonedDir, ledger.EventsFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if code, out, errs := run(t, user, "rules", "--last", "--json"); code != 0 || !strings.Contains(out, `"run":"`+id+`"`) {
			t.Errorf("abandoned (empty=%v): %d %s %s", empty, code, out, errs)
		}
	}
	// A present but unusable record must fail, rather than silently fall back to the older run.
	for _, mode := range []os.FileMode{0o600, 0o000} {
		if err := os.WriteFile(filepath.Join(abandonedDir, ledger.EventsFile), []byte("broken\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(abandonedDir, ledger.EventsFile), mode); err != nil {
			t.Fatal(err)
		}
		if code, out, errs := run(t, user, "rules", "--last"); code != 125 || out != "" || !strings.Contains(errs, abandoned) {
			t.Errorf("unusable record (mode=%o): %d %s %s", mode, code, out, errs)
		}
	}
	if err := os.Chmod(filepath.Join(abandonedDir, ledger.EventsFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte("broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, user, "rules", id); code != 125 {
		t.Fatalf("corrupt: %d", code)
	}
}

func TestRulesLastWithOnlyAbandonedRuns(t *testing.T) {
	root := t.TempDir()
	id := "r-12345678-0000000000001-abcdef"
	dir := filepath.Join(root, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, empty := range []bool{false, true} {
		if empty {
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := rulesRunID(root, "", true); !errors.Is(err, errRulesNoRuns) || got != "" {
			t.Errorf("only abandoned (empty=%v): %q %v", empty, got, err)
		}
		if got, err := rulesRunID(root, id, false); got != id || err != nil {
			t.Errorf("explicit selector should still reach the incomplete record: %q %v", got, err)
		}
	}
}

func TestRulesEscapesTerminalTextAndSourceCommand(t *testing.T) {
	v := &rulesview.InForceView{Run: "r", Source: "/p/a'$(exit 9)\x1b", Pending: &rulesview.Pending{}, View: rulesview.InForce(context.Background(), "", "invalid", rulesview.Options{Machine: config.Builtin()}).View}
	v.View.Agent = "evil\x1b[2J"
	var out bytes.Buffer
	if err := writeRules(&out, v); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatalf("raw control: %q", out.String())
	}
}

func TestRulesEmptyLedgerNamesFirstRun(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "runs")
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	for _, present := range []bool{false, true} {
		if present {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, args := range [][]string{{"rules", "--last"}, {"rules", "--last", "--json"}} {
			code, out, errs := run(t, user, args...)
			if code != 125 || out != "" || !strings.Contains(errs, "there are no runs yet") || !strings.Contains(errs, "[not-found]") ||
				!strings.Contains(errs, "tego init --preset no-secrets,repo-only-writes --write ./out, then tego run agent.yaml") {
				t.Fatalf("empty ledger (present=%v), %q: %d %q %q", present, args, code, out, errs)
			}
		}
	}
}
