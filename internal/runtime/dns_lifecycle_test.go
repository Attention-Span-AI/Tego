// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsPreparedBackend struct {
	tierBackend
	table *agent.RuleTable
}

func TestDNSBrokerReadinessWithoutConfiguredBroker(t *testing.T) {
	for _, r := range []*runner{nil, {}, {dnsBrokerStarted: true}} {
		if r.dnsBrokerReady() {
			t.Fatal("absent broker advertised ready")
		}
	}
}

func (b *dnsPreparedBackend) Prepare(_ context.Context, rt *agent.RuleTable, _ enforce.RunRef) (api.Handle, error) {
	b.table = rt
	return tier1Handle{}, nil
}

func dnsRuntimeQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 53, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dnsRuntimeClient is the binary dnsRuntimeExchange runs as the dropped uid when the test is root, "" otherwise:
// a copy of this test binary that uid can execute (CI's root suites run it through sudo from the runner's home,
// which another uid cannot enter), with TMPDIR at /tmp for the rest of the test. The client inherits it, so its
// TestMain makes its temporary parent where that uid can write; under this process's own parent, which is root's
// 0700, it exited 1 before reaching the broker (R5).
func dnsRuntimeClient(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		return ""
	}
	t.Setenv("TMPDIR", "/tmp")
	return testutil.ExecutableForAnyUID(t)
}

// The root suite uses a real dropped client, rather than teaching the broker to
// accept launcher credentials. Its process stays in the same fixture cgroup.
// A client failure carries the client's own stderr, so the caller's Fatalf says why.
func dnsRuntimeExchange(t *testing.T, client, dir string, raw []byte) ([]byte, error) {
	t.Helper()
	if client == "" {
		return dnsbroker.Exchange(context.Background(), dir, os.Getpid(), raw)
	}
	cmd := exec.Command(client, "-test.run=^TestDNSRuntimeClientHelper$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	cmd.Env = append(os.Environ(), "TEGO_DNS_RUNTIME_HELPER=1", "TEGO_DNS_RUNTIME_DIR="+dir, "TEGO_DNS_RUNTIME_PID="+strconv.Itoa(os.Getpid()), "TEGO_DNS_RUNTIME_QUERY="+hex.EncodeToString(raw))
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func TestDNSRuntimeClientHelper(t *testing.T) {
	if os.Getenv("TEGO_DNS_RUNTIME_HELPER") != "1" {
		return
	}
	raw, err := hex.DecodeString(os.Getenv("TEGO_DNS_RUNTIME_QUERY"))
	pid, _ := strconv.Atoi(os.Getenv("TEGO_DNS_RUNTIME_PID"))
	if err == nil {
		raw, err = dnsbroker.Exchange(context.Background(), os.Getenv("TEGO_DNS_RUNTIME_DIR"), pid, raw)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "DNS runtime client:", err)
		os.Exit(2)
	}
	fmt.Println(hex.EncodeToString(raw))
	os.Exit(0)
}

func TestDNSRuntimeExactGrantActualQueryLedgerAndShutdown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Setenv("SUDO_UID", "65534")
		t.Setenv("SUDO_GID", "65534")
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			buf := make([]byte, dnsbroker.MaxPacket)
			n, from, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			calls.Add(1)
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			q.Response, q.RecursionAvailable = true, true
			q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 17}}}}
			out, _ := q.Pack()
			_, _ = u.WriteToUDP(out, from)
		}
	})
	t.Cleanup(func() { u.Close(); wg.Wait() })
	m := config.Builtin()
	m.Resolver.Value = config.ResolverMode{Servers: []netip.AddrPort{u.LocalAddr().(*net.UDPAddr).AddrPort()}}
	cache := 2
	contract := &agent.Contract{Name: "dns-test", Net: &agent.NetSection{DNS: &agent.DNSPolicy{Mode: "broker", Allow: []string{"allowed.example"}, Types: []string{"A"}, Cache: &cache}}}
	settings, queries, err := agent.CompileDNSPolicy(contract)
	if err != nil {
		t.Fatal(err)
	}
	original := &agent.RuleTable{Contract: contract, DNS: settings, DNSQueries: queries, Record: agent.RecordSummary, Tier: backend.TierLandlock, Set: map[string]string{dnsBrokerDirEnv: "/forged-set", dnsBrokerPIDEnv: "2"}}
	const id = "r-00000000-000000000000a-dnsxyz"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: contract.Name}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(record.RunEndPayload{Reason: record.RunEndError})
	cg, err := unifiedAskCgroup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if cg == "/" { // A root cgroup is never a governed run; test its refusal, not a broad grant.
		cg = "/private-nonmember-fixture"
	}
	b := &dnsPreparedBackend{tierBackend: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}}
	g, ctx := newGroup(context.Background())
	r := &runner{rt: original, dir: dir, id: identity.RunID(id), agentID: identity.AgentID(contract.Name), writer: w, started: make(chan struct{}), group: g,
		deps: Deps{Config: m, Enforce: b, Clock: systemClock{}}, log: slog.New(slog.DiscardHandler), cg: cgroup.Cgroup{Path: "/sys/fs/cgroup" + cg, ID: 1}, cgm: &fakeCgroups{}}
	t.Cleanup(func() { g.Cancel(); r.stopDNSBroker(); _ = g.Wait() })
	if err = r.setupDNSBroker(); err != nil {
		t.Fatal(err)
	}
	if r.dnsBrokerReady() {
		t.Fatal("unscheduled broker advertised ready")
	}
	if r.rt == original || len(original.Net) != 0 || len(original.FS) != len(r.rt.FS) || len(r.rt.Net) != 1 {
		t.Fatal("caller table or directory-read grants mutated")
	}
	controlledEnv := r.dnsBrokerEnv(buildEnv(r.rt, []string{dnsBrokerDirEnv + "=/inherited", dnsBrokerPIDEnv + "=3"}))
	for _, name := range []string{dnsBrokerDirEnv, dnsBrokerPIDEnv} {
		var found []string
		for _, value := range controlledEnv {
			if strings.HasPrefix(value, name+"=") {
				found = append(found, value)
			}
		}
		want := name + "=" + filepath.Dir(r.dnsBroker.Endpoint())
		if name == dnsBrokerPIDEnv {
			want = name + "=" + strconv.Itoa(os.Getpid())
		}
		if !slices.Equal(found, []string{want}) {
			t.Fatalf("runtime authority not final: %v want %q", found, want)
		}
	}
	if filepath.Dir(r.dnsBroker.Endpoint()) == r.dir || len(r.dnsBroker.Endpoint()) >= 108 {
		t.Fatal("runtime endpoint is not short and separate from ledger")
	}
	grant := r.rt.Net[0]
	if grant.UnixPath != r.dnsBroker.Endpoint() || grant.Proto != agent.ProtoUnix || !agent.IsRuntimeRule(grant.RuleName()) || grant.Verdict != agent.VerdictAllow {
		t.Fatalf("wrong owned grant %+v", grant)
	}
	if err = r.prepareEnforcement(ctx); err != nil {
		t.Fatal(err)
	}
	if len(b.table.Net) != 1 || b.table.Net[0].UnixPath != grant.UnixPath {
		t.Fatal("backend did not receive already-bound exact endpoint")
	}
	if got := r.runResolvers(); len(got) != 0 {
		t.Fatalf("broker mode granted agent resolver transport %v", got)
	}
	client := dnsRuntimeClient(t)
	if _, err = dnsRuntimeExchange(t, client, filepath.Dir(r.dnsBroker.Endpoint()), dnsRuntimeQuery(t, "allowed.example.", dnsmessage.TypeA)); err == nil || calls.Load() != 0 {
		t.Fatal("broker authorized before run_start")
	}
	if err = r.startDNSBroker(ctx); err != nil {
		t.Fatal(err)
	}
	if !r.dnsBrokerReady() {
		t.Fatal("scheduled live broker not ready")
	}
	if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"cooperating-client"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	close(r.started)
	if cg == "/private-nonmember-fixture" {
		if _, err = dnsRuntimeExchange(t, client, filepath.Dir(r.dnsBroker.Endpoint()), dnsRuntimeQuery(t, "allowed.example.", dnsmessage.TypeA)); err == nil || calls.Load() != 0 {
			t.Fatal("root cgroup was accepted as governed")
		}
	} else {
		for i, name := range []string{"allowed.example.", "allowed.example.", "forbidden.example."} {
			raw, err := dnsRuntimeExchange(t, client, filepath.Dir(r.dnsBroker.Endpoint()), dnsRuntimeQuery(t, name, dnsmessage.TypeA))
			if err != nil {
				t.Fatalf("query err=%v detail=%q worker=%v", err, r.detail, g.Err())
			}
			var response dnsmessage.Message
			if err = response.Unpack(raw); err != nil {
				t.Fatal(err)
			}
			want := dnsmessage.RCodeSuccess
			if i == 2 {
				want = dnsmessage.RCodeRefused
			}
			if response.RCode != want {
				t.Fatalf("response=%v want=%v", response.RCode, want)
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("cache/refusal dispatched %d", calls.Load())
		}
	}
	result := r.shutdown(context.Background())
	if result.RecordErr != nil {
		t.Fatal(result.RecordErr)
	}
	if r.dnsBrokerReady() {
		t.Fatal("shutdown broker remained ready")
	}
	if _, err = os.Lstat(r.dnsBroker.Endpoint()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("endpoint survived shutdown: %v", err)
	}
	if rep, err := ledger.VerifyRunDir(context.Background(), dir, nil); err != nil || !rep.Ended {
		t.Fatalf("ledger=%+v %v", rep, err)
	}
	if cg != "/private-nonmember-fixture" {
		var decisions, completions, refusals int
		for _, ev := range events(t, dir) {
			if ev.Kind != record.KindNet {
				continue
			}
			var p dnsPayload
			if err = json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatal(err)
			}
			if p.Proto != agent.ProtoUnix || p.Dst != "unix:"+grant.UnixPath || p.Mechanism != "dns-broker" || p.DNSName == "" || ev.PID <= 0 || ev.TID != 0 {
				t.Fatalf("invented/missing metadata %+v %+v", ev, p)
			}
			if p.DNSPhase == dnsbroker.PhaseCompletion {
				completions++
			} else {
				decisions++
			}
			if ev.Verdict == record.VerdictRefused {
				refusals++
			}
		}
		if decisions != 3 || completions != 2 || refusals != 1 {
			t.Fatalf("decision/completion/refusal=%d/%d/%d", decisions, completions, refusals)
		}
	}
}

func TestDNSRuntimeReservedEnvironmentAndMembership(t *testing.T) {
	env := []string{"A=1", dnsBrokerDirEnv + "=/foreign", dnsBrokerPIDEnv + "=2", dnsBrokerDirEnv + "=/second", dnsBrokerPIDEnv}
	r := &runner{}
	if got := r.dnsBrokerEnv(env); !slices.Equal(got, []string{"A=1"}) {
		t.Fatalf("disabled broker kept forged env %v", got)
	}
	if !slices.Equal(env, []string{"A=1", dnsBrokerDirEnv + "=/foreign", dnsBrokerPIDEnv + "=2", dnsBrokerDirEnv + "=/second", dnsBrokerPIDEnv}) {
		t.Fatal("input env mutated")
	}
	r.started = make(chan struct{})
	close(r.started)
	for _, path := range []string{"", "/sys/fs/cgroup", "/sys/fs/cgroup/private-other-run"} {
		r.cg.Path = path
		if r.dnsPeerAuthorize(dnsbroker.Peer{PID: os.Getpid()}) == nil {
			t.Fatalf("outside process admitted to %q", path)
		}
	}
	if r.dnsPeerAuthorize(dnsbroker.Peer{PID: -1}) == nil {
		t.Fatal("invalid PID admitted")
	}
}

func TestDNSRuntimeLedgerFailureAndRecordOff(t *testing.T) {
	const id = "r-00000000-000000000000a-dnsxyz"
	w, err := ledger.Open(filepath.Join(t.TempDir(), id), record.RunRef{ID: id, Agent: "dns-test"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	// The actual transport's constructor/close is exercised above; this inert
	// non-nil pointer suffices only for the record-off early-return assertion.
	r := &runner{rt: &agent.RuleTable{Record: agent.RecordOff}, writer: w, dnsBroker: &dnsbroker.Broker{}}
	if err = r.emitDNS(dnsbroker.Event{Allowed: true, Phase: dnsbroker.PhaseDecision}); err != nil {
		t.Fatalf("off telemetry blocked query: %v", err)
	}
	// Refusal construction needs an actual endpoint, including a closed writer.
	cache := 0
	p, q, err := agent.CompileDNSPolicy(&agent.Contract{Net: &agent.NetSection{DNS: &agent.DNSPolicy{Mode: "broker", Cache: &cache}}})
	if err != nil {
		t.Fatal(err)
	}
	r.rt.DNS, r.rt.DNSQueries = p, q
	r.dir = t.TempDir()
	r.deps = Deps{Config: config.Builtin(), Clock: fixedClock{at: time.Now()}}
	r.deps.Config.Resolver.Value = config.ResolverMode{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}}
	r.log, r.cgm = slog.New(slog.DiscardHandler), &fakeCgroups{}
	r.cg.Path = "/private-dns-fixture"
	if os.Geteuid() == 0 {
		t.Setenv("SUDO_UID", "65534")
		t.Setenv("SUDO_GID", "65534")
	}
	if err = r.setupDNSBroker(); err != nil {
		t.Fatal(err)
	}
	defer r.stopDNSBroker()
	err = r.emitDNS(dnsbroker.Event{Allowed: false, Phase: dnsbroker.PhaseDecision, Name: "denied.example.", Type: 1, Rule: agent.UnmatchedRule, Peer: dnsbroker.Peer{PID: os.Getpid()}})
	if !errors.Is(err, ledger.ErrClosed) || r.terminal != identity.ReasonError || r.cgm.(*fakeCgroups).killed != 1 {
		t.Fatalf("lost refusal err=%v terminal=%q", err, r.terminal)
	}
}
