// SPDX-License-Identifier: Apache-2.0

package mcpact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
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

// fixture is a ledger root with one Adjustable run (ADR 0125), whose switches may loosen past its contract: its
// contract copy, a run_start line (capabilities.ask as given), and the run lock held by this process (a live run),
// released at the end of the test.
func fixture(t *testing.T, broker bool) (*Service, string) {
	t.Helper()
	return fixtureMode(t, broker, adjustable)
}

// adjustable is a run_start's live mode and fence (an empty one) at record minor 26: an Adjustable run.
const adjustable = `,"record_minor":26,"live_mode":"adjustable","live_fence":{"sha256":"` + zeros + `","entries":[]}`

// fixtureMode is fixture with live as the run_start's live fields: "" is a Locked run (no live_mode, the default).
func fixtureMode(t *testing.T, broker bool, live string) (*Service, string) {
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
	start := `{"v":1,"seq":0,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:00Z","mono_ns":1,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"run_start","source":"supervisor","capabilities":{"ask":` + ask + `}` + live + `}` + "\n"
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

// TestLockedRunRefusesLoosening: on a Locked run (ADR 0125, ADR 0126 §4) a switch to a decision looser than the
// contract's is refused ErrLocked, in Plan and in Set with the acknowledgement an Adjustable run would need, with no
// acknowledgement minted and nothing written: neither the overlay nor the run's ledger (a writer's refusal is not a
// ledger line, as a refused lift is not; ADR 0125 decision 5). A switch that tightens, and a reset back to the
// contract (as an unblock), are taken.
func TestLockedRunRefusesLoosening(t *testing.T) {
	ctx := context.Background()
	s, dir := fixtureMode(t, true, "")
	events := filepath.Join(dir, ledger.EventsFile)
	ledgerBefore, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	overlayBefore := mcptools.Stat(dir)
	for _, c := range []struct{ server, tool, decision string }{
		{"files", "delete_file", "allow"}, // deny -> allow
		{"files", "delete_file", "ask"},   // deny -> ask
		{"files", "write_file", "allow"},  // ask -> allow
	} {
		p, err := s.Plan(run, c.server, c.tool, c.decision)
		if !errors.Is(err, ErrLocked) || !errors.Is(err, liveblock.ErrLocked) || p == nil || p.Ack != "" || !p.Loosens {
			t.Fatalf("Plan %v: %+v %v, want ErrLocked with no acknowledgement", c, p, err)
		}
		if err.Error() != "the run is Locked: it keeps to its contract while it runs, so nothing loosens until its next run" {
			t.Fatalf("Plan %v: words %q", c, err)
		}
		if _, err := s.Set(ctx, run, c.server, c.tool, c.decision, "forged"); !errors.Is(err, ErrLocked) {
			t.Fatalf("Set %v: %v, want ErrLocked", c, err)
		}
	}
	if mcptools.Stat(dir) != overlayBefore {
		t.Fatal("a refused switch wrote the overlay")
	}
	if b, err := os.ReadFile(events); err != nil || string(b) != string(ledgerBefore) {
		t.Fatalf("a refused switch changed the run's ledger: %v", err)
	}
	// Tightening is taken on a Locked run, and so is a switch that leaves the contract's own decision.
	if p, err := s.Set(ctx, run, "files", "read_file", "deny", ""); err != nil || !p.Changed {
		t.Fatalf("tighten: %+v %v", p, err)
	}
	if p, err := s.Set(ctx, run, "files", "write_file", "deny", ""); err != nil || !p.Changed {
		t.Fatalf("tighten ask to deny: %+v %v", p, err)
	}
	// Back to the contract: a loosening of now, never past the contract, so it needs its acknowledgement only.
	p, err := s.PlanReset(run, "files", "read_file")
	if err != nil || !p.Loosens || p.Ack == "" {
		t.Fatalf("plan reset: %+v %v", p, err)
	}
	if p, err := s.Reset(ctx, run, "files", "read_file", p.Ack); err != nil || !p.Changed || p.To != mcptool.Allow {
		t.Fatalf("reset: %+v %v", p, err)
	}
	p, err = s.Plan(run, "files", "write_file", "ask")
	if err != nil || p.Ack == "" {
		t.Fatalf("plan ask back to the contract: %+v %v", p, err)
	}
	if p, err := s.Set(ctx, run, "files", "write_file", "ask", p.Ack); err != nil || !p.Changed {
		t.Fatalf("set ask back to the contract: %+v %v", p, err)
	}
}

// TestLockedRunAcrossAnUnreadableStart: a run whose run_start cannot be read is refused a loosening, never as ErrLocked
// (its mode is not known, acceptance 2B, 2026-11-11): with no ledger yet as still starting (ErrStarting), and with an
// undecodable first line or one that is not run_start as not readable (ErrStartUnreadable, the review's S1: waiting
// does not change it). One whose revision predates the modes is Locked to it, the claim that promises least. A
// tightening is still taken.
func TestLockedRunAcrossAnUnreadableStart(t *testing.T) {
	for name, text := range map[string]string{
		"no ledger":           "",
		"not json":            "{\n",
		"not a run_start":     `{"v":1,"seq":0,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:00Z","mono_ns":1,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"gap","source":"supervisor","what":"record","why":"x"}` + "\n",
		"adjustable below 26": `{"v":1,"seq":0,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:00Z","mono_ns":1,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"run_start","source":"supervisor","record_minor":25,"live_mode":"adjustable","live_fence":{"sha256":"` + zeros + `","entries":[]}}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			s, dir := fixture(t, true)
			events := filepath.Join(dir, ledger.EventsFile)
			if text == "" {
				if err := os.Remove(events); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(events, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			want := map[string]error{"no ledger": ErrStarting, "not json": ErrStartUnreadable,
				"not a run_start": ErrStartUnreadable, "adjustable below 26": ErrLocked}[name]
			if _, err := s.Set(context.Background(), run, "files", "delete_file", "allow", "x"); !errors.Is(err, want) ||
				(want != ErrLocked && errors.Is(err, ErrLocked)) || (want == ErrStartUnreadable && errors.Is(err, ErrStarting)) {
				t.Fatalf("%v, want %v", err, want)
			}
			if _, err := s.Set(context.Background(), run, "files", "read_file", "deny", ""); err != nil {
				t.Fatalf("a tightening: %v", err)
			}
		})
	}
}

// TestEndedRunRefusesLoosening: a run no launcher holds is refused a switch past the contract ErrNotRunning, Locked or
// Adjustable, in the preview as well as in Set, with no acknowledgement minted: the Locked check never takes a free
// lock for a go-ahead.
func TestEndedRunRefusesLoosening(t *testing.T) {
	for name, live := range map[string]string{"Locked": "", "Adjustable": adjustable} {
		t.Run(name, func(t *testing.T) {
			s, dir := fixtureMode(t, true, live)
			ended := filepath.Join(filepath.Dir(dir), "r-aaaaaaaa-0000000000004-mcpend")
			if err := os.MkdirAll(ended, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{"contract.yaml", "events.jsonl"} {
				b, err := os.ReadFile(filepath.Join(dir, f))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(ended, f), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			endedRun := filepath.Base(ended)
			p, err := s.Plan(endedRun, "files", "delete_file", "allow")
			if !errors.Is(err, ErrNotRunning) || (p != nil && p.Ack != "") {
				t.Fatalf("Plan: %+v %v, want ErrNotRunning with no acknowledgement", p, err)
			}
			if _, err := s.Set(context.Background(), endedRun, "files", "delete_file", "allow", "x"); !errors.Is(err, ErrNotRunning) {
				t.Fatalf("Set: %v, want ErrNotRunning", err)
			}
			if _, err := os.Stat(filepath.Join(ended, mcptools.FileName)); err == nil {
				t.Fatal("a refused switch wrote the overlay")
			}
		})
	}
}

// TestAdjustableRunLoosens: the same switch on an Adjustable run is taken with its acknowledgement.
func TestAdjustableRunLoosens(t *testing.T) {
	s, _ := fixture(t, true)
	p, err := s.Plan(run, "files", "delete_file", "allow")
	if err != nil || p.Ack == "" {
		t.Fatalf("plan: %+v %v", p, err)
	}
	if p, err := s.Set(context.Background(), run, "files", "delete_file", "allow", p.Ack); err != nil || !p.Changed {
		t.Fatalf("set: %+v %v", p, err)
	}
}
