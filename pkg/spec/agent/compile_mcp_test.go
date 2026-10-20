// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// mcpHTTPContract is a contract with one stdio and two HTTP MCP servers under a net: section.
const mcpHTTPContract = `version: 0
name: t
command: ["python"]
fs:
  write: ["./out/"]
mcp:
  - name: postgres
    command: ["mcp-postgres"]
  - name: search
    url: "https://mcp.internal/mcp"
  - name: local
    url: "http://127.0.0.1:3001/mcp"
net:
  allow: ["api.anthropic.com:443"]
`

// TestMCPHTTPServerCompilesNetRule: a declared HTTP MCP server compiles to the net rule its URL's host and port
// need (FEATURES I5, agent-contract.md R16a), named for the server, after the author's own entries, resolved as a net.allow entry is;
// a stdio server compiles to its exec grant and no net rule.
func TestMCPHTTPServerCompilesNetRule(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load(mcpHTTPContract))
	if hasCode(ds, CodeSchema) || hasCode(ds, CodeContradiction) {
		t.Fatalf("diagnostics: %s", render(ds))
	}
	if len(rt.Net) != 3 {
		t.Fatalf("net rules %+v, want the declared one and one per HTTP server", rt.Net)
	}
	search, local := rt.Net[1], rt.Net[2]
	if search.MCP != "search" || search.Host != "mcp.internal" || search.Port != 443 || search.Proto != ProtoTCP ||
		search.Static || len(search.IPs) != 1 || search.IPs[0] != netip.MustParseAddr("10.0.0.5") || search.Verdict != VerdictAllow ||
		search.RuleName() != "mcp[search]" {
		t.Errorf("search: %+v (%s)", search, search.RuleName())
	}
	if local.MCP != "local" || local.Port != 3001 || local.Proto != ProtoTCP || !local.Static || len(local.IPs) != 1 || local.RuleName() != "mcp[local]" {
		t.Errorf("local: %+v (%s)", local, local.RuleName())
	}
	if pos := local.Pos; pos.Line != 12 {
		t.Errorf("local's rule points at line %d, want the url's, 12", pos.Line)
	}
	if r := findExec(rt, "mcp-postgres"); r == nil || r.Source != "mcp:postgres" {
		t.Errorf("the stdio server's exec grant: %+v", r)
	}
	for _, r := range rt.Exec {
		if strings.Contains(r.Source, "mcp:search") || strings.Contains(r.Source, "mcp:local") {
			t.Errorf("an HTTP server got an exec grant: %+v", r)
		}
	}
}

// TestMCPHTTPServerWithoutNetSection: with no net: section every destination is admitted already (SEMANTICS §1), so
// nothing is derived and the table stays unrestricted.
func TestMCPHTTPServerWithoutNetSection(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load(strings.Replace(mcpHTTPContract, "net:\n  allow: [\"api.anthropic.com:443\"]\n", "", 1)))
	if !rt.NetUnrestricted() || len(rt.Net) != 0 {
		t.Fatalf("unrestricted %v, net %+v", rt.NetUnrestricted(), rt.Net)
	}
}

// TestMCPHTTPServerAlreadyAllowedOrAsked: an endpoint net.allow already lists is the author's entry, and a
// redundant-rule warning says the server would have derived it; one net.ask lists stays asked, never allowed by a
// derived rule, and a warning says so.
func TestMCPHTTPServerAlreadyAllowedOrAsked(t *testing.T) {
	f := newFixture(t)
	src := strings.Replace(mcpHTTPContract, `allow: ["api.anthropic.com:443"]`,
		`allow: ["api.anthropic.com:443", "mcp.internal:443"]`+"\n  ask: [\"tcp://127.0.0.1:3001\"]", 1)
	rt, ds := f.compile(f.load(src))
	for _, r := range rt.Net {
		if r.MCP != "" {
			t.Errorf("a rule derived for an endpoint the author declared: %+v", r)
		}
	}
	if len(rt.NetAsk) != 1 || rt.NetAsk[0].RuleName() != "net[tcp://127.0.0.1:3001]" {
		t.Errorf("net.ask: %+v", rt.NetAsk)
	}
	var redundant, asked bool
	for _, d := range ds {
		redundant = redundant || d.Code == CodeRedundantRule && strings.Contains(d.Message, `mcp "search"`)
		asked = asked || d.Severity == "warning" && strings.Contains(d.Message, `mcp "local"`) && strings.Contains(d.Message, "net.ask")
	}
	if !redundant || !asked {
		t.Fatalf("diagnostics: %s", render(ds))
	}
}

// TestMCPHTTPServerDerivesTCPOnly: both HTTP transports are TCP (an http:// URL never speaks QUIC, and HTTP/3 is
// not admitted for an https:// one, R16a), so the derived rule admits a TCP connect to the URL's port and refuses
// a UDP datagram to it.
func TestMCPHTTPServerDerivesTCPOnly(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load(mcpHTTPContract))
	for _, c := range []struct {
		host  string
		port  int
		proto string
		want  Verdict
	}{
		{"127.0.0.1", 3001, ProtoTCP, VerdictAllow},
		{"127.0.0.1", 3001, ProtoUDP, VerdictRefused},
		{"10.0.0.5", 443, ProtoTCP, VerdictAllow},
		{"10.0.0.5", 443, ProtoUDP, VerdictRefused},
	} {
		got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: c.host, Port: c.port, Proto: c.proto}, rt.Tier)
		if got.Verdict != c.want {
			t.Errorf("%s %s:%d: %s %s, want %s", c.proto, c.host, c.port, got.Verdict, got.Rule, c.want)
		}
	}
}

// TestMCPHTTPServerUnderAWiderAsk: a net.ask entry that would decide a connect the server's derived rule admits (a
// CIDR holding the URL's address, a literal address its name resolved to, a name whose kept answer holds the
// address the URL's name resolved to, the server's own host on its port even where the two lookups answered
// differently) keeps it asked: no allow is derived and a warning says so. Evaluate does not model an approval and
// answers such a connect unmatched, which is where the run's supervisor asks (supervisor R11, ask_connect.go),
// rather than allow mcp[<name>].
func TestMCPHTTPServerUnderAWiderAsk(t *testing.T) {
	for _, c := range []struct{ name, ask string }{
		{"cidrs", `["tcp://10.0.0.0/8:443", "tcp://127.0.0.0/8:3001"]`},
		{"an address", `["tcp://10.0.0.5:443", "tcp://127.0.0.1:3001"]`},
		{"a name", `["tcp://alias.internal:443", "tcp://127.0.0.0/8:3001"]`},
		{"its own name", `["tcp://mcp.internal:443", "tcp://127.0.0.0/8:3001"]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.resolver.table["alias.internal"] = []netip.Addr{netip.MustParseAddr("10.0.0.5")}
			if c.name == "its own name" {
				// net.ask is resolved before the mcp urls: its lookup of the server's name answers an address
				// the url's lookup (10.0.0.5) does not hold, so only the name decides.
				f.resolver.next = map[string][][]netip.Addr{"mcp.internal": {{netip.MustParseAddr("10.9.9.9")}}}
			}
			src := strings.Replace(mcpHTTPContract, `allow: ["api.anthropic.com:443"]`,
				`allow: ["api.anthropic.com:443"]`+"\n  ask: "+c.ask, 1)
			rt, ds := f.compile(f.load(src))
			for _, r := range rt.Net {
				if r.MCP != "" {
					t.Errorf("an allow derived under an ask that covers it: %+v", r)
				}
			}
			for _, srv := range []string{"search", "local"} {
				if !strings.Contains(render(ds), `mcp "`+srv+`"`) {
					t.Errorf("no warning names mcp %q:\n%s", srv, render(ds))
				}
			}
			for _, a := range []Action{
				{Kind: ActionNetConnect, Host: "10.0.0.5", Port: 443, Proto: ProtoTCP},
				{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 3001, Proto: ProtoTCP},
			} {
				if got := rt.Evaluate(a, rt.Tier); got.Verdict != VerdictRefused || got.Rule != UnmatchedRule {
					t.Errorf("%s:%d: %s %s, want refused %s (asked at run time)", a.Host, a.Port, got.Verdict, got.Rule, UnmatchedRule)
				}
			}
		})
	}
}

// TestMCPHTTPServerBesideAnAskThatNeverAsks: an address R18 dropped from a net.ask name is one that entry never
// asks for (dns.NewSet keeps only an entry's IPs, so the supervisor's ask lookup finds nothing there), so it does
// not keep a server's url from deriving its rule: the literal-address server is admitted by mcp[local], as it is
// with no ask at all, rather than refused unmatched and unasked.
func TestMCPHTTPServerBesideAnAskThatNeverAsks(t *testing.T) {
	f := newFixture(t)
	f.resolver.table["loop.internal"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	src := strings.Replace(mcpHTTPContract, `allow: ["api.anthropic.com:443"]`,
		`allow: ["api.anthropic.com:443"]`+"\n  ask: [\"tcp://loop.internal:3001\"]", 1)
	rt, ds := f.compile(f.load(src))
	if a := rt.NetAsk[0]; len(a.IPs) != 0 || !slices.Contains(a.Denied, netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("the ask entry kept loopback: %+v", a)
	}
	if strings.Contains(render(ds), `mcp "local" url`) {
		t.Errorf("a warning says an ask decides mcp \"local\":\n%s", render(ds))
	}
	if !strings.Contains(render(ds), "net.ask tcp://loop.internal:3001: host loop.internal resolved to 127.0.0.1") {
		t.Errorf("the resolved-denied warning does not name the net.ask entry:\n%s", render(ds))
	}
	a := Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 3001, Proto: ProtoTCP}
	if got := rt.Evaluate(a, rt.Tier); got.Verdict != VerdictAllow || got.Rule != MCPRule("local") {
		t.Errorf("127.0.0.1:3001: %s %s, want allow %s", got.Verdict, got.Rule, MCPRule("local"))
	}
}

// TestMCPHTTPServerWhoseDroppedAddressAnAskHolds: an address R18 dropped from the server's own name is one its
// derived rule refuses by name (net.denied_resolved[...], supervisor R7), and that refusal comes before any ask,
// so a net.ask entry holding it keeps the server asked: no allow is derived, and the warning says the ask decides.
// The resolved-denied warning names the url as the mcp entry it is, not as a net.allow entry.
func TestMCPHTTPServerWhoseDroppedAddressAnAskHolds(t *testing.T) {
	f := newFixture(t)
	f.resolver.table["mcp.loop"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	src := strings.Replace(mcpHTTPContract, `"http://127.0.0.1:3001/mcp"`, `"https://mcp.loop:3001/mcp"`, 1)
	src = strings.Replace(src, `allow: ["api.anthropic.com:443"]`,
		`allow: ["api.anthropic.com:443"]`+"\n  ask: [\"tcp://127.0.0.0/8:3001\"]", 1)
	rt, ds := f.compile(f.load(src))
	for _, r := range rt.Net {
		if r.MCP == "local" {
			t.Errorf("an allow derived whose dropped address an ask holds: %+v", r)
		}
	}
	if !strings.Contains(render(ds), `mcp "local" url tcp://mcp.loop:3001 is decided by net.ask`) {
		t.Errorf("no warning says the ask decides mcp \"local\":\n%s", render(ds))
	}
	if strings.Contains(render(ds), "net.allow tcp://mcp.loop:3001") {
		t.Errorf("a warning calls the server's url a net.allow entry:\n%s", render(ds))
	}
}

// TestMCPHTTPServerPartlyUnderAnAsk: an ask holding only some of the addresses the server's name resolved to still
// derives nothing (a derived rule would admit the asked ones first, now or after a refresh), and the warning says
// the others are refused, naming them, rather than that every connect to the server asks.
func TestMCPHTTPServerPartlyUnderAnAsk(t *testing.T) {
	f := newFixture(t)
	f.resolver.table["mcp.corp"] = []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("52.1.1.1")}
	src := strings.Replace(mcpHTTPContract, `"https://mcp.internal/mcp"`, `"https://mcp.corp/mcp"`, 1)
	src = strings.Replace(src, `allow: ["api.anthropic.com:443"]`,
		`allow: ["api.anthropic.com:443"]`+"\n  ask: [\"tcp://10.0.0.0/8:443\"]", 1)
	rt, ds := f.compile(f.load(src))
	for _, r := range rt.Net {
		if r.MCP == "search" {
			t.Errorf("an allow derived under an ask that holds one of its addresses: %+v", r)
		}
	}
	if !strings.Contains(render(ds), "that no ask entry holds is refused unless another net.allow entry admits it: 52.1.1.1 [") {
		t.Errorf("the warning does not say the address no ask holds is refused:\n%s", render(ds))
	}
	a := Action{Kind: ActionNetConnect, Host: "52.1.1.1", Port: 443, Proto: ProtoTCP}
	if got := rt.Evaluate(a, rt.Tier); got.Verdict != VerdictRefused {
		t.Errorf("52.1.1.1:443: %s %s, want refused", got.Verdict, got.Rule)
	}
}

// TestMCPHTTPServerWhoseKeptAddressNoAskHolds: a server whose name resolved to a public address and a loopback one
// R18 dropped, under an ask holding the loopback one, derives no rule, so the public address is refused: no
// diagnostic says the url's other addresses still admit (R18's text for a rule that is derived), and the ask's
// warning names the refused address.
func TestMCPHTTPServerWhoseKeptAddressNoAskHolds(t *testing.T) {
	f := newFixture(t)
	f.resolver.table["mcp.mix"] = []netip.Addr{netip.MustParseAddr("52.1.1.1"), netip.MustParseAddr("127.0.0.1")}
	src := strings.Replace(mcpHTTPContract, `"http://127.0.0.1:3001/mcp"`, `"https://mcp.mix/mcp"`, 1)
	src = strings.Replace(src, `allow: ["api.anthropic.com:443"]`,
		`allow: ["api.anthropic.com:443"]`+"\n  ask: [\"tcp://127.0.0.0/8:443\"]", 1)
	rt, ds := f.compile(f.load(src))
	for _, r := range rt.Net {
		if r.MCP == "local" {
			t.Errorf("an allow derived whose dropped address an ask holds: %+v", r)
		}
	}
	for _, line := range strings.Split(render(ds), "\n") {
		if strings.Contains(line, "mcp.mix") && strings.Contains(line, "still admit") {
			t.Errorf("a warning says an address of a url that derives no rule admits: %s", line)
		}
	}
	if !strings.Contains(render(ds), "that no ask entry holds is refused unless another net.allow entry admits it: 52.1.1.1 [") {
		t.Errorf("the warning does not name the refused address:\n%s", render(ds))
	}
	a := Action{Kind: ActionNetConnect, Host: "52.1.1.1", Port: 443, Proto: ProtoTCP}
	if got := rt.Evaluate(a, rt.Tier); got.Verdict != VerdictRefused {
		t.Errorf("52.1.1.1:443: %s %s, want refused", got.Verdict, got.Rule)
	}
}

// TestMCPHTTPServerUnderAnAskOnItsNameThatKeptNothing: an ask naming the server's host on its port derives no rule,
// but where R18 dropped every address the name resolved to, that ask holds none (dns.NewSet keeps an entry's kept
// addresses only), so a connect to the address is refused and never asked: the warning says so, naming it and its
// class, and never that connecting asks first.
func TestMCPHTTPServerUnderAnAskOnItsNameThatKeptNothing(t *testing.T) {
	f := newFixture(t)
	f.resolver.table["mcp.loop"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	src := strings.Replace(mcpHTTPContract, `"http://127.0.0.1:3001/mcp"`, `"https://mcp.loop:3001/mcp"`, 1)
	src = strings.Replace(src, `allow: ["api.anthropic.com:443"]`,
		`allow: ["api.anthropic.com:443"]`+"\n  ask: [\"tcp://mcp.loop:3001\"]", 1)
	rt, ds := f.compile(f.load(src))
	for _, r := range rt.Net {
		if r.MCP == "local" {
			t.Errorf("an allow derived under an ask on the server's name: %+v", r)
		}
	}
	if strings.Contains(render(ds), "connecting to it asks first") {
		t.Errorf("a warning says a connect no ask holds asks first:\n%s", render(ds))
	}
	if !strings.Contains(render(ds), "that no ask entry holds is refused unless another net.allow entry admits it: 127.0.0.1 (loopback, which a host name never admits) [") {
		t.Errorf("the warning does not name the refused address and its class:\n%s", render(ds))
	}
	if !strings.Contains(render(ds), "declare the address itself (for example 127.0.0.1:3001)") {
		t.Errorf("the fix does not say how to have the dropped address asked:\n%s", render(ds))
	}
	a := Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 3001, Proto: ProtoTCP}
	if got := rt.Evaluate(a, rt.Tier); got.Verdict != VerdictRefused {
		t.Errorf("127.0.0.1:3001: %s %s, want refused", got.Verdict, got.Rule)
	}
}

// TestMCPHTTPServerBesideAnUnrelatedAsk: an ask on another port, by address or by the server's own name, or
// holding no address of the server's, derives the rule as usual. (An ask on another protocol cannot load: net.ask
// takes tcp:// and unix: destinations only.)
func TestMCPHTTPServerBesideAnUnrelatedAsk(t *testing.T) {
	f := newFixture(t)
	src := strings.Replace(mcpHTTPContract, `allow: ["api.anthropic.com:443"]`,
		`allow: ["api.anthropic.com:443"]`+"\n  ask: [\"tcp://10.0.0.0/8:8443\", \"tcp://192.168.0.0/16:3001\", \"tcp://mcp.internal:8443\"]", 1)
	rt, ds := f.compile(f.load(src))
	var derived int
	for _, r := range rt.Net {
		if r.MCP != "" {
			derived++
		}
	}
	if derived != 2 {
		t.Fatalf("derived %d rules, want 2: %+v\n%s", derived, rt.Net, render(ds))
	}
}

// TestMCPServerValidation: a server is a command or a URL, never both or neither; the URL is http or https with a
// host and carries no credentials, query or fragment; one origin is one server; and a model endpoint is not one.
func TestMCPServerValidation(t *testing.T) {
	for _, c := range []struct{ name, entry, want string }{
		{"neither", `{name: x}`, "no command and no url"},
		{"both", `{name: x, command: ["mcp-postgres"], url: "http://a:1/"}`, "both a command and a url"},
		{"scheme", `{name: x, url: "ws://a/"}`, "http or https"},
		{"no host", `{name: x, url: "http:///mcp"}`, "no host"},
		{"userinfo", `{name: x, url: "https://u:p@a/mcp"}`, "credentials"},
		{"query", `{name: x, url: "https://a/mcp?key=1"}`, "query"},
		{"fragment", `{name: x, url: "https://a/mcp#f"}`, "fragment"},
		{"port", `{name: x, url: "https://a:0/mcp"}`, "port"},
		{"relative", `{name: x, url: "/mcp"}`, "http or https"},
		{"same origin", `{name: x, url: "https://mcp.internal:443/a"}, {name: y, url: "https://MCP.internal/b"}`, "same origin"},
		{"model endpoint", `{name: x, url: "https://api.anthropic.com/mcp"}`, "models"},
		// Every models[] entry is read, not the first on the URL's host: this one is at another port.
		{"model endpoint after another port", `{name: x, url: "https://api.anthropic.com/mcp"}`, "is the models[] endpoint"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			models := "[{provider: anthropic, host: api.anthropic.com, port: 443}]"
			if c.name == "model endpoint after another port" {
				models = "[{provider: anthropic, host: api.anthropic.com, port: 8443}, {provider: anthropic, host: api.anthropic.com, port: 443}]"
			}
			src := "version: 0\nname: t\ncommand: [\"python\"]\nmodels: " + models + "\nmcp: [" + c.entry + "]\n"
			path := filepath.Join(f.project, "agent.yaml")
			if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			_, ds, err := Load(path, f.profiles())
			if err == nil {
				t.Fatalf("%s loaded", c.entry)
			}
			if !strings.Contains(render(ds), c.want) {
				t.Fatalf("diagnostics lack %q:\n%s", c.want, render(ds))
			}
		})
	}
}
