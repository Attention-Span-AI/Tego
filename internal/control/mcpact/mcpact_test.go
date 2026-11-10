// SPDX-License-Identifier: Apache-2.0

package mcpact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
)

const run = "r-aaaaaaaa-0000000000003-mcpxxx"

const contract = `version: 0
name: t
command: [python3]
mcp:
  - name: files
    command: [python3, /opt/fake-mcp/server.py]
    tools:
      deny: [delete_file]
      ask: [write_file]
  - name: open
    command: [python3, /opt/other.py]
    tools: {}
  - name: plain
    url: http://127.0.0.1:1/mcp
`

// fixture is a ledger root with one run: its contract copy, a run_start line (capabilities.ask as given), and the run
// lock held by this process (a live run), released at the end of the test.
func fixture(t *testing.T, broker bool) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, run)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	ask := "false"
	if broker {
		ask = "true"
	}
	start := `{"v":1,"seq":0,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:00Z","mono_ns":1,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"run_start","source":"supervisor","capabilities":{"ask":` + ask + `}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(start), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	s := New(root)
	s.governed = func() (bool, error) { return false, nil }
	return s, dir
}

const zeros = "0000000000000000000000000000000000000000000000000000000000000001"

func TestStateDecisions(t *testing.T) {
	s, dir := fixture(t, false)
	if err := mcptools.WriteSeen(dir, mcptools.Seen{"files": {"read_file", "write_file", "delete_file"}}); err != nil {
		t.Fatal(err)
	}
	st, err := s.State(run)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running || st.Broker || len(st.Servers) != 3 {
		t.Fatalf("state %+v", st)
	}
	files := st.Servers[0]
	if !files.Relayed || files.Transport != "stdio" || len(files.Tools) != 3 {
		t.Fatalf("files %+v", files)
	}
	want := map[string]string{"delete_file": "deny", "read_file": "allow", "write_file": "ask"}
	for _, tl := range files.Tools {
		if tl.Decision != want[tl.Name] || tl.Contract != want[tl.Name] || tl.Live {
			t.Errorf("%s: %+v", tl.Name, tl)
		}
	}
	if !st.Servers[1].Relayed || st.Servers[2].Relayed || st.Servers[2].Transport != "http" {
		t.Errorf("open %+v plain %+v", st.Servers[1], st.Servers[2])
	}
}

func TestAckOnlyForLoosening(t *testing.T) {
	s, dir := fixture(t, true)
	ctx := context.Background()
	// Tightening: no acknowledgement needed.
	p, err := s.Set(ctx, run, "files", "read_file", "deny", "")
	if err != nil || !p.Changed || p.Loosens {
		t.Fatalf("tighten: %+v %v", p, err)
	}
	// Loosening without the preview's acknowledgement: refused, nothing written.
	before := mcptools.Stat(dir)
	if _, err := s.Set(ctx, run, "files", "delete_file", "allow", ""); !errors.Is(err, ErrAck) {
		t.Fatalf("loosen without ack: %v", err)
	}
	if _, err := s.Set(ctx, run, "files", "delete_file", "allow", "forged"); !errors.Is(err, ErrAck) {
		t.Fatalf("loosen with a forged ack: %v", err)
	}
	if mcptools.Stat(dir) != before {
		t.Fatal("a refused loosening wrote the overlay")
	}
	plan, err := s.Plan(run, "files", "delete_file", "allow")
	if err != nil || !plan.Loosens || plan.Ack == "" {
		t.Fatalf("plan %+v %v", plan, err)
	}
	// An ack for another change is not this one's.
	if _, err := s.Set(ctx, run, "files", "write_file", "allow", plan.Ack); !errors.Is(err, ErrAck) {
		t.Fatalf("an ack reused for another tool: %v", err)
	}
	// The overlay moving after the preview makes the ack stale.
	if _, err := s.Set(ctx, run, "files", "write_file", "deny", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(ctx, run, "files", "delete_file", "allow", plan.Ack); !errors.Is(err, ErrAck) {
		t.Fatalf("a stale ack: %v", err)
	}
	plan, _ = s.Plan(run, "files", "delete_file", "allow")
	if p, err := s.Set(ctx, run, "files", "delete_file", "allow", plan.Ack); err != nil || !p.Changed {
		t.Fatalf("loosen with ack: %+v %v", p, err)
	}
	o, err := mcptools.Read(dir, run)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := o.Lookup("files", "delete_file"); !ok || e.Decision != "allow" {
		t.Fatalf("overlay %+v", o)
	}
	// A reset that tightens (allow back to the contract's deny) needs none.
	if p, err := s.Reset(ctx, run, "files", "delete_file", ""); err != nil || !p.Changed || p.To != "deny" {
		t.Fatalf("reset: %+v %v", p, err)
	}
}

// TestLooseningDecidedUnderTheLock: a change that does not loosen on the preview's read, with another writer's Deny
// landing before the writers' lock, is decided again on what the lock sees: it loosens now, it has no acknowledgement,
// and the Deny stands.
func TestLooseningDecidedUnderTheLock(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		change func(*Service) (*Plan, error)
	}{
		{"set allow on allow", func(s *Service) (*Plan, error) { return s.Set(ctx, run, "open", "read_file", "allow", "") }},
		{"set ask on allow", func(s *Service) (*Plan, error) { return s.Set(ctx, run, "open", "read_file", "ask", "") }},
		{"reset with no switch", func(s *Service) (*Plan, error) { return s.Reset(ctx, run, "open", "read_file", "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := fixture(t, true)
			s.beforeLock = func() {
				if _, err := mcptools.Update(ctx, dir, run, func(o *mcptools.Overlay) (bool, error) {
					return o.Set("open", "read_file", mcptools.Deny, "uid:1 pid:3 cli", s.now())
				}); err != nil {
					t.Fatal(err)
				}
			}
			p, err := tc.change(s)
			if !errors.Is(err, ErrAck) {
				t.Fatalf("a loosening made under the lock without an ack: %+v %v", p, err)
			}
			if p == nil || !p.Loosens || p.From.Decision != mcptool.Deny {
				t.Fatalf("plan %+v", p)
			}
			o, err := mcptools.Read(dir, run)
			if err != nil {
				t.Fatal(err)
			}
			if e, ok := o.Lookup("open", "read_file"); !ok || e.Decision != mcptools.Deny {
				t.Fatalf("the Deny did not stand: %+v", o)
			}
		})
	}
}

// TestLooseningUnderTheLockIsRefusedInsideARun: the same change from inside a run is ErrGoverned, not a missing ack.
func TestLooseningUnderTheLockIsRefusedInsideARun(t *testing.T) {
	ctx := context.Background()
	s, dir := fixture(t, true)
	calls := 0
	s.governed = func() (bool, error) { calls++; return true, nil }
	s.beforeLock = func() {
		if _, err := mcptools.Update(ctx, dir, run, func(o *mcptools.Overlay) (bool, error) {
			return o.Set("open", "read_file", mcptools.Deny, "uid:1 pid:3 cli", s.now())
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Set(ctx, run, "open", "read_file", "ask", ""); !errors.Is(err, ErrGoverned) || calls != 1 {
		t.Fatalf("%v, %d governed checks", err, calls)
	}
}

func TestRefusals(t *testing.T) {
	s, _ := fixture(t, false)
	ctx := context.Background()
	if _, err := s.Set(ctx, run, "files", "read_file", "ask", ""); !errors.Is(err, ErrNoBroker) {
		t.Errorf("ask with no broker: %v", err)
	}
	if _, err := s.Set(ctx, run, "plain", "x", "deny", ""); !errors.Is(err, ErrNotRelayed) {
		t.Errorf("unrelayed server: %v", err)
	}
	if _, err := s.Set(ctx, run, "nope", "x", "deny", ""); !errors.Is(err, ErrNoServer) {
		t.Errorf("undeclared server: %v", err)
	}
	if _, err := s.Set(ctx, "r-bad", "files", "x", "deny", ""); !errors.Is(err, ErrBadRun) {
		t.Errorf("bad run: %v", err)
	}
	s.governed = func() (bool, error) { return true, nil }
	p, _ := s.Plan(run, "files", "delete_file", "allow")
	if _, err := s.Set(ctx, run, "files", "delete_file", "allow", p.Ack); !errors.Is(err, ErrGoverned) {
		t.Errorf("loosening from inside a run: %v", err)
	}
	if _, err := s.Set(ctx, run, "files", "read_file", "deny", ""); err != nil {
		t.Errorf("tightening from inside a run: %v", err)
	}
}

// TestServersRefusesAListKeyBesideAMergeKey: yaml.v3 panicked on a key that is a list beside a merge key in the run's
// contract copy (config.GuardYAML), at the top or in an mcp entry.
func TestServersRefusesAListKeyBesideAMergeKey(t *testing.T) {
	for _, text := range []string{"{<<,[]}", "mcp: [{<<: {}, []: 0}]\n"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := servers(dir); err == nil {
			t.Errorf("%q: no error", text)
		}
	}
}
