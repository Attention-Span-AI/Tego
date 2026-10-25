// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestLoadCompilesAtTheRunsContractPath: the copy under the ledger root compiles as the run compiled the contract,
// at its own path: the table names that path and denies the ledger root, and no ledger-readable warning appears.
func TestLoadCompilesAtTheRunsContractPath(t *testing.T) {
	base := t.TempDir()
	root, proj, home := filepath.Join(base, "state", "ledger"), filepath.Join(base, "proj"), filepath.Join(base, "home")
	run := "r-aaaaaaaa-0000000000001-cleanx"
	dir := filepath.Join(root, run)
	for _, d := range []string{dir, filepath.Join(proj, "out"), home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	contract := "version: 0\nname: demo\ncommand: [sh]\ncapture: off\nfs:\n  write: [./out/]\n"
	sum := sha256.Sum256([]byte(contract))
	ts := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	start := fmt.Sprintf(`{"v":1,"seq":0,"id":"%064x","prev":"","ts":"%s","mono_ns":1,"run":"%s","agent":"demo","pid":10,"tid":10,"cgroup":1,"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}}`+"\n",
		1, ts, run, proj, hex.EncodeToString(sum[:]), filepath.Join(proj, "agent.yaml"))
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(start), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &config.Machine{Home: home}
	m.LedgerRoot.Value = root
	c := Load(context.Background(), root, run, Options{Machine: m})
	if c.Err != "" || !c.HashMatches {
		t.Fatalf("load: err %q, hash matches %v, diagnostics %s", c.Err, c.HashMatches, c.Diagnostics)
	}
	if strings.Contains(c.Diagnostics, "ledger-readable") {
		t.Errorf("a false ledger-readable warning:\n%s", c.Diagnostics)
	}
	if !strings.Contains(c.Table, "contract  "+filepath.Join(proj, "agent.yaml")) {
		t.Errorf("the table does not name the run's contract path:\n%s", c.Table)
	}
	if !hasDeny(c.Table, root) {
		t.Errorf("the table does not deny tego's own records:\n%s", c.Table)
	}
}

// hasDeny reports whether the printed table has a deny_read row for path.
func hasDeny(table, path string) bool {
	for l := range strings.Lines(table) {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "deny_read" && f[1] == path {
			return true
		}
	}
	return false
}

// TestDriftFindsACommandOffTheDashboardsPATH: the contract names its command by basename and the program lives in a
// directory the dashboard's PATH lacks, as ~/.local/bin is to a service. The run found it, so the recompile must too:
// the entries are declared (not "Not in the contract") and the page does not say the contract was not recompiled.
func TestDriftFindsACommandOffTheDashboardsPATH(t *testing.T) {
	base := t.TempDir()
	root, proj, home, bin := filepath.Join(base, "ledger"), filepath.Join(base, "proj"), filepath.Join(base, "home"), filepath.Join(base, "elsewhere", "bin")
	run := "r-aaaaaaaa-0000000000002-offpth"
	dir := filepath.Join(root, run)
	for _, d := range []string{dir, proj, home, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "mytool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	contract := "version: 0\nname: demo\ncommand: [mytool]\ncapture: off\nnet:\n  allow: [\"unix:/var/run/x/socket\", \"127.0.0.1:8803\"]\n"
	sum := sha256.Sum256([]byte(contract))
	ts := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	line := func(seq int, rest string) string {
		return fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"demo","pid":10,"tid":10,"cgroup":1,%s}`+"\n", seq, seq+1, ts, seq+1, run, rest)
	}
	events := line(0, fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["mytool"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}`,
		proj, hex.EncodeToString(sum[:]), filepath.Join(proj, "agent.yaml"))) +
		line(1, fmt.Sprintf(`"kind":"exec","source":"seccomp","rule":"exec[mytool]","verdict":"allow","authority":"rule","argv":["mytool"],"exec_id":"%s/10/1","path":"%s"`, run, filepath.Join(bin, "mytool")))
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &config.Machine{Home: home}
	m.LedgerRoot.Value = root
	d := Drift(context.Background(), root, run, Options{Machine: m})
	if d.Err != "" || d.Unknown {
		t.Fatalf("drift: err %q, contract not recompiled: %v (%s)", d.Err, d.Unknown, d.Contract)
	}
	var sawNet, sawExec bool
	for _, r := range d.Rows {
		if !r.Declared {
			t.Errorf("row %q is not declared, but the contract names it", r.Rule)
		}
		sawNet = sawNet || r.Rule == "net[127.0.0.1:8803]" && r.Unused
		sawExec = sawExec || r.Rule == "exec[mytool]" && !r.Unused
	}
	if !sawNet || !sawExec {
		t.Errorf("rows %+v: want the unused net entry and the used exec entry", d.Rows)
	}
}

// TestExplainLabels: a default decision reads as a short label per list, never the list itself.
func TestExplainLabels(t *testing.T) {
	l := Lists{OK: true, Net: []string{"tcp://chatgpt.com:443", "unix:/var/run/nscd/socket"}}
	for _, c := range [][4]string{
		{"net", "connect", "refused", "Host not in policy"},
		{"exec", "exec", "refused", "Program not in policy"},
		{"fs", "open", "", "Open by default"},
		{"refused", "mkdir", "refused", "Outside writable folders"},
	} {
		if got := l.Explain(c[0], c[1], c[2]); got != c[3] {
			t.Errorf("Explain(%s, %s, %s) = %q, want %q", c[0], c[1], c[2], got, c[3])
		}
	}
}

// TestDriftCountsFromTheContractTextWhenItCannotCompile: the demo's with/ folder was deleted after the run, so the
// copy no longer compiles ("parent ... does not exist", path-missing). The tab still counts every entry the copy
// declares (one used, one never used) and marks the note, instead of "unknown here" for every row.
func TestDriftCountsFromTheContractTextWhenItCannotCompile(t *testing.T) {
	base := t.TempDir()
	root, proj, home := filepath.Join(base, "ledger"), filepath.Join(base, "gone", "proj"), filepath.Join(base, "home")
	run := "r-aaaaaaaa-0000000000004-nocomp"
	dir := filepath.Join(root, run)
	for _, d := range []string{dir, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	contract := "version: 0\nname: demo\ncommand: [sh]\ncapture: off\nfs:\n  write: [./src/, ./tmp/]\nnet:\n  allow: [\"tcp://chatgpt.com:443\", \"127.0.0.1:8803\"]\nexec:\n  allow: [sh, git]\n"
	sum := sha256.Sum256([]byte(contract))
	ts := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	line := func(seq int, rest string) string {
		return fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"demo","pid":10,"tid":10,"cgroup":1,%s}`+"\n", seq, seq+1, ts, seq+1, run, rest)
	}
	events := line(0, fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}`,
		proj, hex.EncodeToString(sum[:]), filepath.Join(proj, "with", "agent.yaml"))) +
		line(1, `"kind":"fs","source":"landlock","rule":"fs.write[./src/]","verdict":"allow","op":"write","path":"/x/src/a"`) +
		line(2, `"kind":"net","source":"seccomp","rule":"net[tcp://chatgpt.com:443]","verdict":"allow","op":"connect","dst":"1.2.3.4:443"`) +
		line(3, `"kind":"exec","source":"seccomp","rule":"exec[sh]","verdict":"allow","authority":"rule","argv":["sh"],"exec_id":"x/10/1","path":"/usr/bin/sh"`)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &config.Machine{Home: home}
	m.LedgerRoot.Value = root
	d := Drift(context.Background(), root, run, Options{Machine: m})
	if d.Err != "" || !d.Unknown || !d.FromText {
		t.Fatalf("err %q, unknown %v, from text %v (contract note %q)", d.Err, d.Unknown, d.FromText, d.Contract)
	}
	got := map[string]DriftRow{}
	for _, r := range d.Rows {
		got[r.Rule] = r
	}
	for rule, unused := range map[string]bool{"fs.write[./src/]": false, "fs.write[./tmp/]": true, "net[tcp://chatgpt.com:443]": false,
		"net[127.0.0.1:8803]": true, "exec[sh]": false, "exec[git]": true} {
		r, ok := got[rule]
		if !ok || !r.Declared || r.Unused != unused {
			t.Errorf("row %q = %+v (present %v), want declared, unused %v", rule, r, ok, unused)
		}
	}
	if d.Declared != 6 || d.Unused != 3 {
		t.Errorf("declared %d unused %d, want 6 and 3", d.Declared, d.Unused)
	}
}
