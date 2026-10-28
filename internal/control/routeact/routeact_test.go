// SPDX-License-Identifier: Apache-2.0

package routeact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/modelroutes"
)

const run = "r-aaaaaaaa-0000000000003-route0"

const contract = `version: 0
name: t
command: [python3]
capture: forwarder
models:
  - provider: anthropic
    host: api.anthropic.com
    port: 443
    routes:
      - name: corp
        host: llm-proxy.corp.example
        port: 8443
      - name: local
        host: 127.0.0.1
        port: 11434
        tls: false
  - provider: openai
    host: api.openai.com
    port: 443
`

const zeros = "0000000000000000000000000000000000000000000000000000000000000001"

const endpoint = "api.anthropic.com:443"

// fixture is a ledger root with one run: its contract copy, a run_start, two requests (one direct, one by corp) and a
// change line, and the run lock held by this process (a live run).
func fixture(t *testing.T) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, run)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	ls := `{"v":1,"seq":0,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:00Z","mono_ns":1,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"run_start","source":"supervisor","record_minor":27}` + "\n" +
		`{"v":1,"seq":1,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:01Z","mono_ns":2,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"ssl_request","source":"forwarder","endpoint":"anthropic","method":"POST","path":"/v1/messages","host":"api.anthropic.com","size":1,"route":{"name":"direct","authority":"api.anthropic.com:443"}}` + "\n" +
		`{"v":1,"seq":2,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:02Z","mono_ns":3,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"gap","source":"forwarder","what":"enforce","why":"model-route-changed","model_route":{"model":"api.anthropic.com:443","route":"corp","authority":"llm-proxy.corp.example:8443","by":"uid:1 pid:2 cli","serial":1,"at":"2026-10-27T12:00:02Z"}}` + "\n" +
		`{"v":1,"seq":3,"id":"` + zeros + `","prev":"","ts":"2026-10-27T12:00:03Z","mono_ns":4,"run":"` + run + `","agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"ssl_request","source":"forwarder","endpoint":"anthropic","method":"POST","path":"/v1/messages","host":"api.anthropic.com","size":1,"route":{"name":"corp","authority":"llm-proxy.corp.example:8443"}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ls), 0o600); err != nil {
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

func TestState(t *testing.T) {
	s, _ := fixture(t)
	st, err := s.State(run)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running || len(st.Models) != 2 {
		t.Fatalf("state %+v", st)
	}
	a := st.Models[0]
	if a.Endpoint != endpoint || a.Route != "direct" || a.SendsTo != endpoint || !a.Routed() || len(a.Options) != 3 {
		t.Fatalf("anthropic %+v", a)
	}
	if !a.Options[0].Current || a.Options[0].Requests != 1 || a.Options[1].Requests != 1 || a.Options[1].Authority != "llm-proxy.corp.example:8443" ||
		a.Options[2].TLS || len(a.Changes) != 1 || a.Changes[0].Route != "corp" {
		t.Fatalf("anthropic options %+v changes %+v", a.Options, a.Changes)
	}
	if st.Models[1].Routed() {
		t.Fatalf("openai %+v", st.Models[1])
	}
	if !s.HasRoutes(run) || s.HasRoutes("r-bad") {
		t.Fatal("HasRoutes")
	}
}

func TestAckOnlyForWidening(t *testing.T) {
	s, dir := fixture(t)
	ctx := context.Background()
	before := modelroutes.Stat(dir)
	for _, ack := range []string{"", "forged"} {
		if _, err := s.Set(ctx, run, endpoint, "corp", ack); !errors.Is(err, ErrAck) {
			t.Fatalf("widen with ack %q: %v", ack, err)
		}
	}
	if modelroutes.Stat(dir) != before {
		t.Fatal("a refused widening wrote the overlay")
	}
	plan, err := s.Plan(run, endpoint, "corp")
	if err != nil || !plan.Widens || plan.Ack == "" || plan.From.Name != "direct" || plan.To.Authority != "llm-proxy.corp.example:8443" {
		t.Fatalf("plan %+v %v", plan, err)
	}
	if _, err := s.Set(ctx, run, endpoint, "local", plan.Ack); !errors.Is(err, ErrAck) {
		t.Fatalf("an ack reused for another route: %v", err)
	}
	if p, err := s.Set(ctx, run, endpoint, "corp", plan.Ack); err != nil || !p.Changed {
		t.Fatalf("widen with ack: %+v %v", p, err)
	}
	o, err := modelroutes.Read(dir, run)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := o.Lookup(endpoint); !ok || e.Route != "corp" {
		t.Fatalf("overlay %+v", o)
	}
	// The overlay moved since this preview: stale.
	stale, _ := s.Plan(run, endpoint, "local")
	if _, err := s.Clear(ctx, run, endpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(ctx, run, endpoint, "local", stale.Ack); !errors.Is(err, ErrAck) {
		t.Fatalf("a stale ack: %v", err)
	}
	// A revert needs none.
	if p, _ := s.Plan(run, endpoint, "direct"); p.Widens || p.Ack != "" {
		t.Fatalf("revert plan %+v", p)
	}
	st, _ := s.State(run)
	if st.Models[0].Route != "direct" {
		t.Fatalf("after clear %+v", st.Models[0])
	}
}

func TestRefusals(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	if _, err := s.Set(ctx, run, endpoint, "evil", ""); !errors.Is(err, ErrNoRoute) {
		t.Errorf("undeclared route: %v", err)
	}
	if _, err := s.Set(ctx, run, "api.openai.com:443", "corp", ""); !errors.Is(err, ErrNoRoute) {
		t.Errorf("a route of another endpoint: %v", err)
	}
	if _, err := s.Set(ctx, run, "api.example.com:443", "direct", ""); !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("undeclared endpoint: %v", err)
	}
	if _, err := s.Set(ctx, "r-bad", endpoint, "direct", ""); !errors.Is(err, ErrBadRun) {
		t.Errorf("bad run: %v", err)
	}
	s.governed = func() (bool, error) { return true, nil }
	p, _ := s.Plan(run, endpoint, "corp")
	if _, err := s.Set(ctx, run, endpoint, "corp", p.Ack); !errors.Is(err, ErrGoverned) {
		t.Errorf("widening from inside a run: %v", err)
	}
	if _, err := s.Clear(ctx, run, endpoint); !errors.Is(err, ErrGoverned) {
		t.Errorf("a revert from inside a run: %v", err)
	}
}

func TestEndedRun(t *testing.T) {
	s, dir := fixture(t)
	other := filepath.Join(filepath.Dir(dir), "r-aaaaaaaa-0000000000004-route1")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "contract.yaml"))
	if err := os.WriteFile(filepath.Join(other, "contract.yaml"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Plan("r-aaaaaaaa-0000000000004-route1", endpoint, "corp")
	if _, err := s.Set(context.Background(), "r-aaaaaaaa-0000000000004-route1", endpoint, "corp", p.Ack); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("an ended run: %v", err)
	}
}

// TestWideningDecidedUnderTheLock: a change previewed as no widening (the endpoint already on corp) that a clear turns
// into one before the writers' lock is refused for want of an acknowledgement, and the overlay keeps the clear.
func TestWideningDecidedUnderTheLock(t *testing.T) {
	s, dir := fixture(t)
	ctx := context.Background()
	plan, err := s.Plan(run, endpoint, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(ctx, run, endpoint, "corp", plan.Ack); err != nil {
		t.Fatal(err)
	}
	s.beforeLock = func() {
		if _, err := modelroutes.Update(ctx, dir, run, func(o *modelroutes.Overlay) (bool, error) {
			return o.Clear(endpoint, "uid:1 pid:3 cli", s.now())
		}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Set(ctx, run, endpoint, "corp", "")
	if !errors.Is(err, ErrAck) {
		t.Fatalf("a widening made under the lock without an ack: %+v %v", p, err)
	}
	if p == nil || !p.Widens || p.From.Name != "direct" {
		t.Fatalf("plan %+v", p)
	}
	o, err := modelroutes.Read(dir, run)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Lookup(endpoint); ok {
		t.Fatalf("overlay %+v", o)
	}
}
