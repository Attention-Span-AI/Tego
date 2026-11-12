// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// exampleComAnswer is what example.com resolved to in the guest on 2026-11-10 (internal/check/learn's exampleCom).
var exampleComAnswer = []netip.Addr{netip.MustParseAddr("104.20.23.154"), netip.MustParseAddr("172.66.147.243"),
	netip.MustParseAddr("2606:4700:10::6814:179a"), netip.MustParseAddr("2606:4700:10::ac42:93f3")}

// tableResolver answers from a table, a name it does not hold as DNS's "no such host"; a name in hang never answers
// until its context ends.
type tableResolver struct {
	table map[string][]netip.Addr
	hang  map[string]bool
}

func (r tableResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	if r.hang[host] {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	if a, ok := r.table[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// withLearnResolver makes tego learn look names up through r for the test.
func withLearnResolver(t *testing.T, r agent.Resolver) {
	t.Helper()
	prev := learnResolver
	learnResolver = r
	t.Cleanup(func() { learnResolver = prev })
}

// u2404Run writes into root the network lines of the guest's watched run of 2026-11-10 (internal/check/learn's
// u2404Watch, its lines #130 to #145: the nscd socket, the resolver, the netlink socket, the address-sorting UDP
// connects to the four addresses example.com resolved to, and the one TCP connect, to 104.20.23.154) as a run in
// project, and returns its id.
func u2404Run(t *testing.T, root, project string) string {
	t.Helper()
	return learnWriteRun(t, root, project, func(w *ledger.Writer) {
		for _, l := range []struct{ proto, dst, rule, host string }{
			{"unix", "unix:/var/run/nscd/socket", "unmatched", ""}, {"unix", "unix:/var/run/nscd/socket", "unmatched", ""},
			{"udp", "127.0.0.53:53", "net.resolver", "127.0.0.53"},
			{"raw", "family(16)", "unmatched", ""},
			{"udp", "104.20.23.154:443", "unmatched", ""}, {"udp", "unspec", "unmatched", ""}, {"udp", "172.66.147.243:443", "unmatched", ""},
			{"udp", "[2606:4700:10::6814:179a]:443", "unmatched", ""}, {"udp", "unspec", "unmatched", ""},
			{"udp", "[2606:4700:10::ac42:93f3]:443", "unmatched", ""},
			{"tcp", "104.20.23.154:443", "unmatched", ""},
		} {
			e := ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: l.proto, Dst: l.dst, Host: l.host}, func(e *record.Event) {
				e.Source, e.Rule, e.Verdict, e.Authority, e.Attr = record.SourceSupervisor, l.rule, record.VerdictObserved, record.AuthorityRule, record.Unattributed()
			})
			if err := w.Append(e); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// compileSaved compiles the registry entry at path as the next run's start does, with names resolved through r.
func compileSaved(t *testing.T, path string, r agent.Resolver) *agent.RuleTable {
	t.Helper()
	m := hintMachine(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(path, data, profileSources(m))
	if err != nil {
		t.Fatal(err)
	}
	rt, ds, err := agent.Compile(c, m, append(learnCompileOptions(t.Context(), m), agent.WithResolver(r))...)
	if err != nil {
		t.Fatalf("compile %s: %v %v", path, err, ds)
	}
	return rt
}

// admits reports whether a rule of rt allows a connect to ap over proto, by the rule's own semantics: its protocol and
// port, the addresses compile resolved its name to, and the resolved-address check (agent-contract R18) the
// supervisor makes of an address a name stands for (RuleTable.ResolvedDenied).
func admits(rt *agent.RuleTable, proto string, ap netip.AddrPort) (string, bool) {
	for _, r := range rt.Net {
		if !agent.IsIPProtocol(r.Proto) || !agent.ProtocolMatches(r.Proto, proto) || r.Port != int(ap.Port()) || !slices.Contains(r.IPs, ap.Addr()) {
			continue
		}
		if r.FiltersResolved() {
			if _, denied := rt.ResolvedDenied(r, ap.Addr()); denied {
				continue
			}
		}
		return r.Raw, true
	}
	return "", false
}

// TestLearnAllowHostNextRunAllowsTheOtherAddress: the guest's watched run reached example.com at 104.20.23.154; its
// next run picked 172.66.147.243 from the same answer and was refused, under a contract learned without a name. Saved
// with --allow-host example.com, the contract allows example.com by name, and its next run is allowed
// 172.66.147.243 by the rule's own semantics.
func TestLearnAllowHostNextRunAllowsTheOtherAddress(t *testing.T) {
	root, _, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "myagent")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := u2404Run(t, root, project)
	resolver := tableResolver{table: map[string][]netip.Addr{"example.com": exampleComAnswer}}
	withLearnResolver(t, resolver)
	hintsAt(t, false, "on")
	other := netip.MustParseAddrPort("172.66.147.243:443")

	// Before: learned by address, the next run is refused the other address.
	if code, _, errs := run(t, "learn", id, "--save", "before"); code != identity.ExitOK {
		t.Fatalf("--save before: exit %d\n%s", code, errs)
	}
	if rule, ok := admits(compileSaved(t, filepath.Join(reg, "agents", "before.yaml"), resolver), "tcp", other); ok {
		t.Fatalf("a contract learned by address admits %s (rule %s); the guest's run was refused it", other, rule)
	}

	code, out, errs := run(t, "learn", id, "--save", "myagent", "--allow-host", "example.com")
	if code != identity.ExitOK || out != "" {
		t.Fatalf("--allow-host example.com: exit %d, stdout %q\n%s", code, out, errs)
	}
	if want := "tego learn: example.com resolves here now to 4 addresses; what the run reached at 4 of them is now allowed by that name: " +
		"tcp 104.20.23.154:443, udp 104.20.23.154:443, udp 172.66.147.243:443, udp [2606:4700:10::6814:179a]:443 and 1 more.\n"; !strings.Contains(errs, want) {
		t.Errorf("stderr lacks %q:\n%s", want, errs)
	}
	if strings.Contains(errs, "allowed by address, not by name") || strings.Contains(errs, "net.allow has entries that are addresses") {
		t.Errorf("stderr still says addresses are allowed:\n%s", errs)
	}
	path := filepath.Join(reg, "agents", "myagent.yaml")
	rt := compileSaved(t, path, resolver)
	rule, ok := admits(rt, "tcp", other)
	if !ok || rule != "tcp://example.com:443" {
		data, _ := os.ReadFile(path)
		t.Fatalf("the next run is not allowed %s by tcp://example.com:443 (got %q):\n%s", other, rule, data)
	}
	if rule, ok := admits(rt, "udp", netip.MustParseAddrPort("[2606:4700:10::ac42:93f3]:443")); !ok || rule != "udp://example.com:443" {
		t.Errorf("the UDP probes are not allowed by udp://example.com:443: %q", rule)
	}
	if !strings.HasSuffix(errs, "\nnext: run your agent under it:\n  cd "+project+" && tego run myagent\n") {
		t.Errorf("the hint is not the run step:\n%s", errs)
	}
}

// alma98Run writes into root the AlmaLinux 9.8 guest's watched run of 2026-11-10 (internal/check/learn's
// alma98Watch): two queries to NetworkManager's resolver 10.0.2.3, which the engine named net.resolver, then pypi.org
// reached at two of its addresses over TCP and probed over UDP; with lookupOnly, the queries alone (getent hosts).
func alma98Run(t *testing.T, root, project string, lookupOnly bool) string {
	t.Helper()
	lines := []struct{ proto, dst, rule, host string }{
		{"udp", "10.0.2.3:53", "net.resolver", "10.0.2.3"}, {"udp", "10.0.2.3:53", "net.resolver", "10.0.2.3"},
	}
	if !lookupOnly {
		lines = append(lines, []struct{ proto, dst, rule, host string }{
			{"udp", "151.101.192.223:443", "unmatched", ""}, {"udp", "151.101.64.223:443", "unmatched", ""},
			{"tcp", "151.101.192.223:443", "unmatched", ""}, {"tcp", "151.101.64.223:443", "unmatched", ""},
		}...)
	}
	return learnWriteRun(t, root, project, func(w *ledger.Writer) {
		for _, l := range lines {
			e := ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: l.proto, Dst: l.dst, Host: l.host}, func(e *record.Event) {
				e.Source, e.Rule, e.Verdict, e.Authority, e.Attr = record.SourceSupervisor, l.rule, record.VerdictObserved, record.AuthorityRule, record.Unattributed()
			})
			if err := w.Append(e); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// TestLearnDoesNotAskToNameTheMachinesResolver: on AlmaLinux 9.8 the resolver is 10.0.2.3, not on loopback. learn
// leaves udp://10.0.2.3:53 out of the saved contract, and no line counts it as an address to name: --save prints no
// addresses: line and no warning, and neither learn's nor the watch's next: line offers --allow-host for a run that
// only looked a name up. The run on the host it was learned on still reaches its resolver: the contract compiled,
// decided as a run decides it (decide.EvaluateIn, in the env compile --test reads as a run reads it at start), allows
// the query as net.resolver, and the contract keeps a TCP or UDP entry, beside which Landlock grants port 53
// (enforce-landlock R6, TestLearnedLookupContractGetsPort53). A run whose resolver is another one, or whose contract
// sets net.dns.mode off, is refused that address, which the entry learn used to keep admitted. The run that only
// looked a name up has no other TCP or UDP entry, so its contract keeps the resolver as the address it is.
func TestLearnDoesNotAskToNameTheMachinesResolver(t *testing.T) {
	root, _, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "svc")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	pypi := []netip.Addr{netip.MustParseAddr("151.101.192.223"), netip.MustParseAddr("151.101.0.223"),
		netip.MustParseAddr("151.101.128.223"), netip.MustParseAddr("151.101.64.223")}
	resolver := tableResolver{table: map[string][]netip.Addr{"pypi.org": pypi}}
	withLearnResolver(t, resolver)
	hintsAt(t, false, "on")
	resolverAt := netip.MustParseAddrPort("10.0.2.3:53")

	id := alma98Run(t, root, project, false)
	code, out, errs := run(t, "learn", id, "--save", "svc", "--allow-host", "pypi.org")
	if code != identity.ExitOK || out != "" {
		t.Fatalf("--save svc --allow-host pypi.org: exit %d, stdout %q\n%s", code, out, errs)
	}
	for _, not := range []string{"  addresses:", "allowed by address, not by name", "net.allow has entries that are addresses", "10.0.2.3"} {
		if strings.Contains(errs, not) {
			t.Errorf("stderr counts the machine's resolver as an address to name (%q):\n%s", not, errs)
		}
	}
	path := filepath.Join(reg, "agents", "svc.yaml")
	rt := compileSaved(t, path, resolver)
	if rule, ok := admits(rt, "udp", resolverAt); ok {
		data, _ := os.ReadFile(path)
		t.Errorf("the saved contract admits the machine's resolver %s by an entry (%q):\n%s", resolverAt, rule, data)
	}
	resolverDecisions(t, rt, resolverAt, "")
	if !hasIPRule(rt) {
		t.Error("the saved contract has no TCP or UDP rule, so Landlock would grant no port 53")
	}
	if rule, ok := admits(rt, "tcp", netip.MustParseAddrPort("151.101.0.223:443")); !ok || rule != "tcp://pypi.org:443" {
		t.Errorf("the saved contract does not admit pypi.org by name: %q", rule)
	}

	dns := alma98Run(t, root, project, true)
	short := shortOf(dns)
	code, _, errs = run(t, "learn", short)
	if code != identity.ExitOK || strings.Contains(errs, "--allow-host") || strings.Contains(errs, "allowed by address") {
		t.Errorf("a run that only looked a name up: exit %d\n%s", code, errs)
	}
	// Saved, its one entry is the resolver's address, kept so that Landlock grants port 53, and its next run's lookups
	// reach the resolver over UDP and TCP.
	if code, _, errs := run(t, "learn", short, "--save", "lookup"); code != identity.ExitOK {
		t.Fatalf("a run that only looked a name up, --save lookup: exit %d\n%s", code, errs)
	}
	lookup := filepath.Join(reg, "agents", "lookup.yaml")
	lrt := compileSaved(t, lookup, resolver)
	if len(lrt.Net) != 1 || lrt.Net[0].Raw != "udp://10.0.2.3:53" || !hasIPRule(lrt) {
		data, _ := os.ReadFile(lookup)
		t.Errorf("a run that only looked a name up: the saved contract's net rules are %+v, want udp://10.0.2.3:53 alone:\n%s", lrt.Net, data)
	}
	resolverDecisions(t, lrt, resolverAt, "udp://10.0.2.3:53")
	// A name that stands only for the resolver is refused, and nothing is written.
	routerResolver := tableResolver{table: map[string][]netip.Addr{"router.lan": {netip.MustParseAddr("10.0.2.3")}}}
	withLearnResolver(t, routerResolver)
	code, _, errs = run(t, "learn", short, "--save", "dnsname", "--allow-host", "router.lan")
	if code != identity.ExitFinding || !strings.Contains(errs, "only as the machine's resolver") {
		t.Errorf("--allow-host router.lan, a name for the resolver alone: exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(reg, "agents", "dnsname.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("--allow-host router.lan wrote a contract: %v", err)
	}
	withLearnResolver(t, resolver)
	sum := &endSummary{root: root, machine: hintMachine(t)}
	if runAddresses(t.Context(), sum, tegoruntime.Result{RunID: dns}) {
		t.Error("runAddresses counts the machine's resolver as an address")
	}
	hintsAt(t, true, "on")
	if text, command := watchNext(t.Context(), os.Stderr, tegoruntime.Result{RunID: dns}, sum, "", project); text == watchNameHint ||
		strings.Contains(command, "--allow-host") {
		t.Errorf("the watch hint for a run that only looked a name up offers --allow-host: %q %q", text, command)
	}
}

// resolverDecisions checks how runs under rt decide a query to at, the resolver of the host the contract was learned
// on, at every tier that decides connects: allowed as net.resolver while the run's resolver is at (the machine
// config's resolver list, read as a run reads it at start). When the run's resolver is another one or the contract
// sets net.dns.mode off, it is refused where no net.allow entry names at on that protocol, and allowed by entry
// where the contract kept one for it.
func resolverDecisions(t *testing.T, rt *agent.RuleTable, at netip.AddrPort, entry string) {
	t.Helper()
	machine := func(servers ...netip.AddrPort) *config.Machine {
		m := hintMachine(t)
		m.Resolver.Value = config.ResolverMode{Servers: servers}
		return m
	}
	off := *rt
	off.DNS.Mode = "off"
	for _, proto := range []string{"udp", "tcp"} {
		a := agent.Action{Kind: agent.ActionNetConnect, Host: at.Addr().String(), Port: int(at.Port()), Proto: proto}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			if got := decide.EvaluateIn(rt, a, tier, testEnv(rt, machine(at))); got.Verdict != agent.VerdictAllow || got.Rule != agent.ResolverRule {
				t.Errorf("%s %s at tier %s, the run's resolver: %s %q, want allow %q", proto, at, tier, got.Verdict, got.Rule, agent.ResolverRule)
			}
			other := decide.EvaluateIn(rt, a, tier, testEnv(rt, machine(netip.MustParseAddrPort("192.168.1.1:53"))))
			dnsOff := decide.EvaluateIn(&off, a, tier, testEnv(&off, machine(at)))
			byEntry := strings.HasPrefix(entry, proto+"://") // a udp:// entry admits no TCP connect
			for what, got := range map[string]agent.EvalResult{"another resolver": other, "net.dns.mode off": dnsOff} {
				switch {
				case !byEntry && got.Verdict == agent.VerdictAllow:
					t.Errorf("%s %s at tier %s, %s: allowed by %q, want refused", proto, at, tier, what, got.Rule)
				case byEntry && (got.Verdict != agent.VerdictAllow || got.Rule != "net["+entry+"]"):
					t.Errorf("%s %s at tier %s, %s: %s %q, want allowed by the kept entry %s", proto, at, tier, what, got.Verdict, got.Rule, entry)
				}
			}
		}
	}
}

// hasIPRule is whether rt has a TCP or UDP rule: the condition on which Landlock grants the resolver port 53 for TCP,
// and for UDP at ABI 10 (internal/runtime/enforce/landlock netRules, R6).
func hasIPRule(rt *agent.RuleTable) bool {
	return slices.ContainsFunc(rt.Net, func(r agent.NetRule) bool { return agent.IsIPProtocol(r.Proto) })
}

// treeSum is a digest of every file under dir, by name, mode and bytes: what was written there.
func treeSum(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s %v\n", p, fi.Mode())
		if fi.Mode().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h.Write(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// TestLearnAllowHostRefusesWritingNothing: a name that does not answer in time, does not resolve, covers no address
// the run reached, or answers with a private address the run did not reach makes learn write nothing, print no
// proposal and exit 1, with the reason in one line each; and no next: line.
func TestLearnAllowHostRefusesWritingNothing(t *testing.T) {
	root, _, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "myagent")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := u2404Run(t, root, project)
	withLearnResolver(t, tableResolver{
		table: map[string][]netip.Addr{
			"example.com":   exampleComAnswer,
			"wrong.example": {netip.MustParseAddr("104.18.6.192"), netip.MustParseAddr("104.18.7.192")},
			"split.example": {netip.MustParseAddr("104.20.23.154"), netip.MustParseAddr("10.0.0.5")},
			"empty.example": {},
		},
		hang: map[string]bool{"slow.example": true},
	})
	hintsAt(t, false, "on")
	out := filepath.Join(resolvedTemp(t), "p.yaml")
	for _, tc := range []struct {
		host, want string
	}{
		// A run's start gives a name more time than learn does (agent.DefaultDNSTimeout), so a name that did not answer
		// here in time may still start one: only DNS's own "no such host" or "no addresses" says it would not.
		{"slow.example", "tego learn: slow.example did not resolve here within 2s; nothing was written. [allow-host]"},
		{"gone.example", "tego learn: gone.example did not resolve here (no such host); nothing was written. A run under this name would not start either. [allow-host]"},
		{"empty.example", "tego learn: empty.example did not resolve here (no addresses); nothing was written. A run under this name would not start either. [allow-host]"},
		{"wrong.example", "tego learn: wrong.example resolves here now to 104.18.6.192, 104.18.7.192; none is an address the run reached, so the name may be wrong, or its addresses changed since the run (it started "},
		{"split.example", "tego learn: split.example resolves here now to 104.20.23.154, 10.0.0.5, among them the private address 10.0.0.5, which the run did not reach"},
	} {
		before := treeSum(t, reg)
		for _, mode := range [][]string{{"--save", "x"}, {"--out", out}, nil} {
			args := append([]string{"learn", id, "--allow-host", "example.com", "--allow-host", tc.host}, mode...)
			code, stdout, errs := run(t, args...)
			if code != identity.ExitFinding || stdout != "" || !strings.Contains(errs, tc.want) {
				t.Errorf("%q: exit %d, stdout %q, stderr:\n%s\nwant exit 1, no stdout, and %q", args, code, stdout, errs, tc.want)
			}
			// The next: line is the command that works: the same, without the name refused (acceptance B, 2026-11-11).
			if got := lastHint(t, errs); !strings.HasPrefix(got, "tego learn ") || !strings.HasSuffix(got, strings.Join(mode, " ")+" --allow-host example.com") ||
				strings.Contains(got, tc.host) {
				t.Errorf("%q: next %q, want tego learn <run> %s --allow-host example.com", args, got, strings.Join(mode, " "))
			}
			// One refusal, the one the case is about: a name that did not resolve stops learn there, and is not judged
			// again as a name that covers nothing.
			if n := strings.Count(errs, "["+codeAllowHost+"]"); n != 1 {
				t.Errorf("%q: %d refusals, want 1:\n%s", args, n, errs)
			}
			if _, err := os.Lstat(out); err == nil {
				t.Errorf("%q wrote %s", args, out)
			}
		}
		if treeSum(t, reg) != before {
			t.Errorf("%s: the registry changed", tc.host)
		}
	}
}

// TestLearnAllowHostMachineDeniedRange: on a machine whose config denies 104.20.0.0/16 to names
// (denied_resolved_addresses), compile drops 104.20.23.154 from example.com's answer, so learn keeps what the run reached
// there as an address and says the name allows only the rest; the saved contract, compiled with that machine, admits
// every destination the run reached. A machine config that does not load leaves those ranges unknown, so --allow-host
// writes nothing.
func TestLearnAllowHostMachineDeniedRange(t *testing.T) {
	root, _, reg := saveHarness(t, "")
	cfg := filepath.Join(filepath.Dir(root), "tego.yaml")
	base, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, cfg, string(base)+"denied_resolved_addresses: [104.20.0.0/16]\n")
	project := filepath.Join(resolvedTemp(t), "myagent")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := u2404Run(t, root, project)
	resolver := tableResolver{table: map[string][]netip.Addr{"example.com": exampleComAnswer}}
	withLearnResolver(t, resolver)
	hintsAt(t, false, "on")

	code, _, errs := run(t, "learn", id, "--save", "named", "--allow-host", "example.com")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{
		"tego learn: example.com resolves here now to 4 addresses; what the run reached at 3 of them is now allowed by that name: " +
			"udp 172.66.147.243:443, udp [2606:4700:10::6814:179a]:443, udp [2606:4700:10::ac42:93f3]:443.\n",
		"tego learn: warning: 2 addresses the run reached are still allowed by address, not by name: tcp 104.20.23.154:443, udp 104.20.23.154:443.",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	rt := compileSaved(t, filepath.Join(reg, "agents", "named.yaml"), resolver)
	for _, d := range []struct{ proto, dst string }{
		{"tcp", "104.20.23.154:443"}, {"udp", "104.20.23.154:443"}, {"udp", "172.66.147.243:443"},
		{"udp", "[2606:4700:10::6814:179a]:443"}, {"udp", "[2606:4700:10::ac42:93f3]:443"},
	} {
		if rule, ok := admits(rt, d.proto, netip.MustParseAddrPort(d.dst)); !ok {
			data, _ := os.ReadFile(filepath.Join(reg, "agents", "named.yaml"))
			t.Errorf("the saved contract does not admit %s %s, which the run reached (%q):\n%s", d.proto, d.dst, rule, data)
		}
	}

	prev := machineGuard
	machineGuard = func(*config.Machine) error { return errors.New("refused for the test") }
	t.Cleanup(func() { machineGuard = prev })
	before := treeSum(t, reg)
	code, stdout, errs := run(t, "learn", filepath.Join(root, id), "--allow-host", "example.com")
	if code != identity.ExitLauncher || stdout != "" || !strings.Contains(errs, "tego learn: --allow-host: machine config: ") ||
		!strings.Contains(errs, "nothing was written") {
		t.Errorf("a machine config that does not load: exit %d, stdout %q\n%s", code, stdout, errs)
	}
	if treeSum(t, reg) != before {
		t.Error("the registry changed")
	}
}

// TestLearnAllowHostUsage: --allow-host takes a host name, or a host name and a port, at most eight of them; an
// address, a pattern, port 0 or a ninth name is a usage error (exit 2), and nothing is looked up.
func TestLearnAllowHostUsage(t *testing.T) {
	root, _, _ := saveHarness(t, "")
	id := u2404Run(t, root, resolvedTemp(t))
	withLearnResolver(t, tableResolver{})
	hintsAt(t, false, "on")
	nine := []string{"learn", id}
	for i := range agent.DefaultDNSParallel + 1 {
		nine = append(nine, "--allow-host", fmt.Sprintf("h%d.example", i))
	}
	for _, args := range [][]string{
		{"learn", id, "--allow-host", "1.2.3.4"}, {"learn", id, "--allow-host", "104.20.23.154:443"},
		{"learn", id, "--allow-host", "[2606:4700:10::6814:179a]:443"}, {"learn", id, "--allow-host", "*.example.com"},
		{"learn", id, "--allow-host", "example.com:0"}, {"learn", id, "--allow-host", "exa mple.com"}, {"learn", id, "--allow-host", ""},
		{"learn", id, "--allow-host", "tcp://example.com:443"}, nine,
	} {
		code, stdout, errs := run(t, args...)
		if code != identity.ExitUsage || stdout != "" || !strings.Contains(errs, "--allow-host") || strings.Contains(errs, "next:") {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want a usage error naming --allow-host", args[2:], code, stdout, errs)
		}
	}
}

// TestLearnNamesAllowHostWhereAddressesRemain: a proposal that allows addresses says on stderr which ones, and that
// --allow-host names them, and its next: line to save it names --allow-host with the host in angle brackets, which
// only the person knows; a watch's next: line does the same when its run reached addresses. A proposal with no address
// says neither.
func TestLearnNamesAllowHostWhereAddressesRemain(t *testing.T) {
	root, _, _ := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "myagent")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := u2404Run(t, root, project)
	short := shortOf(id)
	withLearnResolver(t, tableResolver{table: map[string][]netip.Addr{"one.example": {netip.MustParseAddr("104.20.23.154")}}})
	hintsAt(t, false, "on")

	code, _, errs := run(t, "learn", short)
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{
		"tego learn: warning: 5 addresses the run reached are allowed by address, not by name: tcp 104.20.23.154:443, udp 104.20.23.154:443, " +
			"udp 172.66.147.243:443, udp [2606:4700:10::6814:179a]:443 and 1 more. Name each with --allow-host <host>, or a later run can be refused.\n",
		"\nnext: " + learnNameHint + "\n  tego learn " + short + " --save myagent --allow-host <host>\n",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	// One name that covers one address: the rest are still addresses, and the hint keeps the name given.
	code, _, errs = run(t, "learn", short, "--allow-host", "one.example:443")
	if code != identity.ExitOK || !strings.Contains(errs, "tego learn: warning: 3 addresses the run reached are still allowed by address, not by name: "+
		"udp 172.66.147.243:443, udp [2606:4700:10::6814:179a]:443, udp [2606:4700:10::ac42:93f3]:443.") ||
		!strings.HasSuffix(errs, "  tego learn "+short+" --save myagent --allow-host one.example:443 --allow-host <host>\n") {
		t.Errorf("one name of several: exit %d\n%s", code, errs)
	}

	sum := &endSummary{root: root, machine: hintMachine(t)}
	text, command := watchHint(tegoruntime.Result{RunID: id}, sum, "", project, true)
	if text != watchNameHint || command != "tego learn "+short+" --save myagent --allow-host <host>" {
		t.Errorf("watch hint for a run that reached addresses: %q %q", text, command)
	}
	if !runAddresses(t.Context(), sum, tegoruntime.Result{RunID: id}) {
		t.Error("runAddresses does not see the run's addresses")
	}
	plain := learnWriteRun(t, root, project, func(w *ledger.Writer) { learnWrite(t, w, filepath.Join(project, "a.txt")) })
	if runAddresses(t.Context(), sum, tegoruntime.Result{RunID: plain}) {
		t.Error("runAddresses sees addresses in a run that reached none")
	}
	code, _, errs = run(t, "learn", plain)
	if code != identity.ExitOK || strings.Contains(errs, "--allow-host") {
		t.Errorf("a proposal with no address names --allow-host: exit %d\n%s", code, errs)
	}
}

// TestWatchNextReadsTheRecordOnlyForItsHint: whether the run reached addresses is a second read of the whole record,
// up to summaryBudget, so a watch makes it only when its next: line is printed and names the learn step: never for a
// bounded watch, a run whose record was off or not completed, or where hints are off.
func TestWatchNextReadsTheRecordOnlyForItsHint(t *testing.T) {
	root, _, _ := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "myagent")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	m := hintMachine(t)
	reads := 0
	prev := watchAddresses
	watchAddresses = func(context.Context, *endSummary, tegoruntime.Result) bool { reads++; return true }
	t.Cleanup(func() { watchAddresses = prev })
	res := tegoruntime.Result{RunID: "20261110T000000Z-1234-abcdef"}
	for _, tc := range []struct {
		name, boundary, hints string
		res                   tegoruntime.Result
		sum                   *endSummary
	}{
		{"bounded", "c.yaml", "on", res, &endSummary{root: root, machine: m}},
		{"record off", "", "on", res, &endSummary{root: root, machine: m, recordOff: true}},
		{"record error", "", "on", tegoruntime.Result{RunID: res.RunID, RecordErr: errors.New("chain")}, &endSummary{root: root, machine: m}},
		{"no summary", "", "on", res, nil},
		{"hints off", "", "off", res, &endSummary{root: root, machine: m}},
	} {
		hintsAt(t, true, tc.hints)
		reads = 0
		watchNext(t.Context(), os.Stderr, tc.res, tc.sum, tc.boundary, project)
		if reads != 0 {
			t.Errorf("%s: the record was read again %d times for no hint", tc.name, reads)
		}
	}
	hintsAt(t, true, "on")
	reads = 0
	if text, command := watchNext(t.Context(), os.Stderr, res, &endSummary{root: root, machine: m}, "", project); reads != 1 ||
		text != watchNameHint || !strings.HasSuffix(command, " --allow-host <host>") {
		t.Errorf("a record-only watch: %d reads, hint %q %q", reads, text, command)
	}
}

// TestLearnSaveRecordsRefusedReads (the project lead's decision of 2026-11-10): a contract --save writes records each
// read it refuses (reason: {reads: on}), and one stderr line says what that costs; --reads off leaves it out. The
// printed proposal and --out keep today's default unless --reads on is given.
func TestLearnSaveRecordsRefusedReads(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := readsRun(t, root, anchor, project, recordsOnly, false)
	hintsAt(t, false, "on")
	const reason = "\nreason:\n"
	cost := "  reads: it records each read it refuses, at tier landlock too (reason.reads: on): " + agent.ReasonReadCost + ", " +
		agent.ReasonReadWorkload + "; --reads off leaves it out.\n"

	code, printed, errs := run(t, "learn", id)
	if code != identity.ExitOK || strings.Contains(printed, reason) {
		t.Fatalf("the printed proposal changed: exit %d\n%s\n%s", code, printed, errs)
	}
	if !strings.HasSuffix(errs, "\nnext: "+learnSaveHint+"\n  tego learn "+shortOf(id)+" --save bot\n") {
		t.Errorf("the hint does not say a saved contract records refused reads:\n%s", errs)
	}
	code, withReads, _ := run(t, "learn", id, "--reads", "on")
	if code != identity.ExitOK || !strings.Contains(withReads, reason+"  # A read this contract refuses is recorded") {
		t.Fatalf("--reads on: exit %d\n%s", code, withReads)
	}

	code, _, errs = run(t, "learn", id, "--save", "bot")
	saved, _ := os.ReadFile(filepath.Join(reg, "agents", "bot.yaml"))
	if want := strings.Replace(withReads, "\nname: \"learned-bot\"\n", "\nname: \"bot\"\n", 1); code != identity.ExitOK || string(saved) != want {
		t.Errorf("--save: exit %d, the file is not the --reads on proposal:\n%s\nstderr:\n%s", code, saved, errs)
	}
	if !strings.Contains(errs, cost) {
		t.Errorf("--save does not say what refused reads cost; want %q in:\n%s", cost, errs)
	}

	code, _, errs = run(t, "learn", id, "--save", "bot-off", "--reads", "off")
	saved, _ = os.ReadFile(filepath.Join(reg, "agents", "bot-off.yaml"))
	if code != identity.ExitOK || strings.Contains(string(saved), reason) || strings.Contains(errs, "  reads: ") {
		t.Errorf("--reads off: exit %d\n%s\nstderr:\n%s", code, saved, errs)
	}
	code, _, errs = run(t, "learn", id, "--reads", "off") // bot is taken now, so the hint proposes <name>
	if code != identity.ExitOK || !strings.HasSuffix(errs, "\nnext: save it as a contract:\n  tego learn "+shortOf(id)+" --save <name> --reads off\n") {
		t.Errorf("--reads off printed: its hint does not keep it:\n%s", errs)
	}

	out := filepath.Join(resolvedTemp(t), "p.yaml")
	if code, _, errs := run(t, "learn", id, "--out", out); code != identity.ExitOK {
		t.Fatalf("--out: exit %d\n%s", code, errs)
	}
	if data, _ := os.ReadFile(out); strings.Contains(string(data), reason) {
		t.Errorf("--out changed its default:\n%s", data)
	}
}
