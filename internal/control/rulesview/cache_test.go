// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// cacheRun is an ended-looking run (no lock held) under a new ledger root with a compiling contract copy, one write
// and one connection, and a chain anchor beside the root. It returns the root, the run, the anchor and a function
// that appends a line given its seq and its kind's members.
func cacheRun(t *testing.T) (root, run, anchor, home string, add func(seq int, rest string)) {
	t.Helper()
	base := t.TempDir()
	root, proj, home := filepath.Join(base, "state", "ledger"), filepath.Join(base, "proj"), filepath.Join(base, "home")
	run = "r-aaaaaaaa-0000000000009-cachex"
	dir := filepath.Join(root, run)
	for _, d := range []string{dir, filepath.Join(proj, "out"), home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	anchor = filepath.Join(base, "state", "chain.log")
	if err := os.WriteFile(anchor, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	contract := "version: 0\nname: demo\ncommand: [sh]\ncapture: off\nfs:\n  write: [./out/]\nnet:\n  allow: [\"127.0.0.1:8803\"]\n"
	sum := sha256.Sum256([]byte(contract))
	ts := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	line := func(seq int, rest string) string {
		return fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"demo","pid":10,"tid":10,"cgroup":1,%s}`+"\n", seq, seq+1, ts, seq+1, run, rest)
	}
	events := line(0, fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}`,
		proj, hex.EncodeToString(sum[:]), filepath.Join(proj, "agent.yaml"))) +
		line(1, fmt.Sprintf(`"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow","op":"write","path":"%s"`, filepath.Join(proj, "out", "a")))
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	add = func(seq int, rest string) {
		t.Helper()
		f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString(line(seq, rest)); err != nil {
			t.Fatal(err)
		}
	}
	return root, run, anchor, home, add
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

// TestLearnKeptPerRunVersion: the Least privilege tab is computed once while the run and the anchor are the same,
// and is the uncached proposal again after an append and after the anchor grows.
func TestLearnKeptPerRunVersion(t *testing.T) {
	root, run, anchor, _, add := cacheRun(t)
	ctx := context.Background()
	before := learned.Computes()
	a := Learn(ctx, root, anchor, run)
	if a.Err != "" {
		t.Fatal(a.Err)
	}
	if b := Learn(ctx, root, anchor, run); b != a || learned.Computes() != before+1 {
		t.Fatalf("second view: same %v, computed %d times", b == a, learned.Computes()-before)
	}
	add(2, `"kind":"net","source":"seccomp","rule":"net[127.0.0.1:8803]","verdict":"allow","op":"connect","dst":"127.0.0.1:8803"`)
	c := Learn(ctx, root, anchor, run)
	if c == a || c.Text == a.Text || !reflect.DeepEqual(c, learnRun(ctx, root, anchor, run)) {
		t.Fatalf("after an append: stale %v, text moved %v\n%s", c == a, c.Text != a.Text, c.Text)
	}
	appendTo(t, anchor, "b\n")
	if d := Learn(ctx, root, anchor, run); d == c || learned.Computes() != before+3 {
		t.Fatalf("after the anchor grew: stale %v, computed %d times", d == c, learned.Computes()-before)
	}
	if Learn(ctx, root, anchor, "not-a-run").Err == "" {
		t.Error("a request that names no run got a proposal")
	}
}

// TestDriftKeptPerRunVersion: the Unused permissions tab is computed once while the run, its contract copy, the
// anchor and the machine config are the same, and is the uncached report again after each of them changes.
func TestDriftKeptPerRunVersion(t *testing.T) {
	root, run, anchor, home, add := cacheRun(t)
	ctx := context.Background()
	m := &config.Machine{Home: home}
	m.LedgerRoot.Value = root
	o := Options{Machine: m, Anchor: anchor}
	before := drifted.Computes()
	a := Drift(ctx, root, run, o)
	if a.Err != "" || a.Unknown || a.Declared != 2 || a.Unused != 1 {
		t.Fatalf("drift: %+v", a)
	}
	if b := Drift(ctx, root, run, o); b != a || drifted.Computes() != before+1 {
		t.Fatalf("second view: same %v, computed %d times", b == a, drifted.Computes()-before)
	}
	fresh := func(name string, n int64) *Drifted {
		t.Helper()
		d := Drift(ctx, root, run, o)
		if want := driftRun(ctx, root, run, o); !reflect.DeepEqual(d, want) {
			t.Fatalf("%s: cached %+v, uncached %+v", name, d, want)
		}
		if drifted.Computes() != before+n {
			t.Fatalf("%s: computed %d times, want %d", name, drifted.Computes()-before, n)
		}
		return d
	}
	add(2, `"kind":"net","source":"seccomp","rule":"net[127.0.0.1:8803]","verdict":"allow","op":"connect","dst":"127.0.0.1:8803"`)
	if d := fresh("after an append", 2); d.Unused != 0 {
		t.Errorf("after the connection: unused %d, want 0", d.Unused)
	}
	copyPath := filepath.Join(root, run, "contract.yaml")
	appendTo(t, copyPath, "exec:\n  allow: [sh, cat]\n")
	if d := fresh("after a contract.yaml edit", 3); d.Declared == a.Declared {
		t.Errorf("after the edit: declared %d, as before", d.Declared)
	}
	appendTo(t, anchor, "b\n")
	fresh("after the anchor grew", 4)
	o.Machine = &config.Machine{Home: home + "/other"}
	o.Machine.LedgerRoot.Value = root
	fresh("after the machine config changed", 5)
}
