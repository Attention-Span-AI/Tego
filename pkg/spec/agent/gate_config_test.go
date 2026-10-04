// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"gopkg.in/yaml.v3"
)

func gateContract(t *testing.T, src string) *Contract {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(src), &n); err != nil {
		t.Fatal(err)
	}
	return &Contract{Gate: *n.Content[0]}
}

func TestGateConfigStrictClosedDSLAndBounds(t *testing.T) {
	for _, src := range []string{
		"null", "[]", "{unknown: true}", "{rules: null}", "{thresholds: null}",
		"{rules: [], rules: []}", "{thresholds: {allow: 5, allow: 6}}", "{thresholds: {deny: 90}}",
		"{thresholds: {allow: 80, ask: 50}}", "{thresholds: {allow: '50'}}", "{thresholds: {ask: null}}",
		// Below allow allows, so allow 0 would ask every unmatched action (gate R1, ADR 0007).
		"{thresholds: {allow: 0, ask: 80}}", "{thresholds: {allow: 0}}",
		"{rules: [{shell expression x: 90}]}", "{rules: [{fs.write outside worktree: true}]}",
		"{rules: [{fs.write outside worktree: -1}]}", "{rules: [{fs.write outside worktree: 101}]}",
		"{rules: [{fs.write outside worktree: 10, net to undeclared host: 20}]}",
		"{rules: [{'exec matches **': 90}]}", "{rules: [{'net to udp://host:443': 90}]}",
		"{rules: [{'net to 10.0.0.0/8:443': 90}]}", "{rules: ['exec matches rm']}",
		// A pathname first word never matches (gate R2): accepted, it never fired.
		"{rules: [{'exec matches \"/usr/bin/curl *\"': 90}]}", "{rules: [{'exec matches /bin/rm -rf': 90}]}",
	} {
		if _, err := CompileGateConfig(gateContract(t, src)); err == nil {
			t.Fatalf("accepted %q", src)
		}
	}
	if _, err := CompileGateConfig(gateContract(t, "rules: ["+strings.Repeat("{fs.write outside worktree: 1},", 257)+"]")); err == nil {
		t.Fatal("unbounded rules accepted")
	}
	p, err := CompileGateConfig(gateContract(t, "rules:\n - exec matches \"rm -rf\": 95\n - net to undeclared host: 70\n"))
	if err != nil || p == nil || !p.Has(gate.Exec) || !p.MayAsk(gate.Net) || p.MayAsk(gate.Exec) {
		t.Fatalf("compiled policy %+v %v", p, err)
	}
	if d := p.Evaluate(gate.Allow, gate.Action{Kind: gate.Exec, Complete: true, Executable: "/bin/rm", Args: []string{"fake", "-rf", "/work"}}); d.Verdict != gate.Refused || d.Score != 95 {
		t.Fatalf("closed DSL result %+v", d)
	}
}

// TestGateConfigRefusesAReadPatternNoCleanPathMatches at compile: `fs.read matches
// "./secrets/*"`, written as the contract's own fs entries are (./work), was accepted with no warning and never fired,
// since the path from the worktree it is matched against is clean. Compile refuses it and names the spelling that
// fires. A `~/` pattern expands against a home spelled with a trailing '/' to a clean pattern, so it is accepted.
func TestGateConfigRefusesAReadPatternNoCleanPathMatches(t *testing.T) {
	for src, fix := range map[string]string{
		`{rules: [{'fs.read matches "./secrets/*"': 90}]}`:     `write "secrets/*"`,
		`{rules: [{'fs.read matches "secrets//key"': 90}]}`:    `write "secrets/key"`,
		`{rules: [{'fs.read matches "/home/u/.ssh/*/"': 90}]}`: `write "/home/u/.ssh/*"`,
		`{rules: [{'fs.read matches "x/s[^x]k"': 90}]}`:        "can match '/'",
	} {
		if _, err := CompileGateConfig(gateContract(t, src)); err == nil || !strings.Contains(err.Error(), fix) {
			t.Errorf("%s: err %v, want a refusal naming %s", src, err, fix)
		}
	}
	p, err := compileGateConfig(gateContract(t, `{rules: [{'fs.read matches "~/.ssh/*"': 90}]}`), "/home/u/")
	if err != nil {
		t.Fatalf("~/.ssh/* under home /home/u/: %v", err)
	}
	if d := p.Evaluate(gate.Allow, gate.Action{Kind: gate.FSRead, Complete: true, Path: "/home/u/.ssh/id", Worktree: "/w"}); d.Score != 90 {
		t.Fatalf("read of /home/u/.ssh/id under ~/.ssh/*: %+v", d)
	}
}

// TestGatePredicateFixNamesWhatIsWrong: the schema check of a gate rule
// told every refusal to "use one of the five documented gate predicates", so a refused read pattern, whose predicate
// is right, was told to change its predicate. Only an unknown predicate gets that fix; a refused argument is told to
// rewrite the argument as the message says, which names the spelling to write where it has one.
func TestGatePredicateFixNamesWhatIsWrong(t *testing.T) {
	const predicates = "use one of the five documented gate predicates"
	for key, want := range map[string]string{
		"fs.reed matches *.env":                                predicates,
		"shell expression x":                                   predicates,
		`fs.read matches "./work/secrets/*"`:                   "rewrite the argument",
		`fs.read matches "a\\/x"`:                              "rewrite the argument",
		`fs.read matches "a*["`:                                "rewrite the argument",
		`exec matches "/usr/bin/curl *"`:                       "rewrite the argument",
		"net to udp://host:443":                                "rewrite the argument",
		"exec matches " + strings.Repeat("x", gate.MaxText+32): "rewrite the argument",
		"fs.write outside worktree":                            "",
		`fs.read matches "work/secrets/*"`:                     "",
		`net to undeclared host`:                               "",
		`exec matches "rm -rf"`:                                "",
		`fs.read matches "/home/u/.ssh/id_*"`:                  "",
		`fs.read matches "../shared/secrets"`:                  "",
		`fs.read matches "[^/]*.env"`:                          "",
		`fs.read matches "/*"`:                                 "",
		`net to 10.0.0.1:443`:                                  "",
		`fs.read matches "work/[^y/]z/secret"`:                 "",
	} {
		msg, fix := checkGatePredicate(key)
		if want == "" {
			if msg != "" || fix != "" {
				t.Errorf("%s: refused %q (fix %q), want accepted", key, msg, fix)
			}
			continue
		}
		if msg == "" || !strings.Contains(fix, want) {
			t.Errorf("%s: %q, fix %q; want a fix holding %q", key, msg, fix, want)
		}
	}
}

// TestCompileRefusesAReadPatternBeyondTheWorktreesAncestors at compile:
// the compile that builds the run's RuleTable captures its worktree, so a relative read pattern needing more leading
// ".." than that worktree has ancestors, which never fires in the run, is refused there and names the absolute
// pattern the agent's path resolves to; one the worktree can reach compiles and scores.
func TestCompileRefusesAReadPatternBeyondTheWorktreesAncestors(t *testing.T) {
	f := commandFixture(t)
	contract := func(pattern string) *Contract {
		return f.load("version: 0\nname: p\ncommand: [static-tool]\ntier: landlock\ngate:\n  rules:\n    - fs.read matches \"" + pattern + "\": 90\n")
	}
	depth := strings.Count(filepath.Clean(f.project), string(filepath.Separator))
	far := strings.Repeat("../", depth+1) + "secrets/*"
	rt, ds, err := Compile(contract(far), f.machine, f.opts()...)
	found := false
	for _, d := range ds {
		if d.IsError() && d.Code == CodeSchema && strings.Contains(d.Message, `write "/secrets/*"`) && strings.Contains(d.Fix, `leading ".."`) {
			found = true
		}
	}
	if err == nil || rt != nil || !found {
		t.Fatalf("compile of %q in %s (depth %d): rt %v err %v, want a refusal naming /secrets/*:\n%s", far, f.project, depth, rt != nil, err, render(ds))
	}
	near := strings.Repeat("../", depth) + "secrets/*"
	rt, ds, err = Compile(contract(near), f.machine, f.opts()...)
	if err != nil || rt == nil || rt.Gate == nil {
		t.Fatalf("compile of %q in %s: %v\n%s", near, f.project, err, render(ds))
	}
	if d := rt.Gate.Evaluate(gate.Allow, gate.Action{Kind: gate.FSRead, Complete: true, Path: "/secrets/k", Worktree: rt.Workdir}); d.Score != 90 {
		t.Fatalf("read of /secrets/k under %q from %s: %+v, want score 90", near, rt.Workdir, d)
	}
}

func TestGateConfigDefaultsEnableOnlySafeApprovalBroker(t *testing.T) {
	for _, tc := range []struct {
		src    string
		broker bool
	}{{"{}", false}, {"rules: [{fs.write outside worktree: 90}]", false}, {"rules: [{fs.read matches *.env: 70}]", true}, {"rules: [{fs.read matches *.env: 49}]", false}, {"rules: [{fs.read matches *.env: 50}]", true}, {"rules: [{fs.read matches *.env: 30}, {fs.write outside worktree: 30}]", true}, {"rules: [{exec matches rm: 70}]", false}, {"rules: [{net to host.example:443: 70}]", true}} {
		c := gateContract(t, tc.src)
		cfg, err := CompileAskConfig(c)
		if err != nil || (cfg != nil) != tc.broker {
			t.Fatalf("broker for %s cfg%+v err%v", tc.src, cfg, err)
		}
		if cfg != nil && (cfg.Hold != AskHoldConnect || cfg.MaxPending != 64) {
			t.Fatalf("gate default %+v", cfg)
		}
	}
}

func TestGateHostnameBindingsAndUnsafeRequestHold(t *testing.T) {
	for _, tc := range []struct {
		declaration, rule string
		refused           bool
	}{
		{"", "net to undeclared.example:443", true},
		{"net:\n  allow: [\"declared.example:443\"]\n", "net to declared.example:443", false},
		{"net:\n  ask: [\"tcp://declared.example:443\"]\n", "net to declared.example:443", false},
		{"", "net to 93.184.216.34:443", false},
	} {
		c := &Contract{}
		if e := yaml.Unmarshal([]byte("gate:\n  rules:\n    - \""+tc.rule+"\": 90\n"+tc.declaration), c); e != nil {
			t.Fatal(e)
		}
		var ds diags
		validateGate(&ds, c, func(string) Pos { return Pos{} })
		hasError := false
		for _, d := range ds.list {
			if d.IsError() {
				hasError = true
			}
		}
		if hasError != tc.refused {
			t.Fatalf("%s binding errors%t want%t: %v", tc.rule, hasError, tc.refused, ds.list)
		}
	}
}

func TestGateRowsEscalateAfterFloorAndPrintEffectiveProgram(t *testing.T) {
	c := gateContract(t, "rules:\n - exec matches \"static-tool --delete\": 90\n - fs.write outside worktree: 70\n")
	p, e := CompileGateConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	rt := &RuleTable{Contract: &Contract{Name: "gate-test"}, Gate: p, Workdir: "/work", Reach: []backend.Tier{backend.TierLandlock}}
	table := &TestTable{Rows: []TestRow{{Kind: ActionExec, Action: "exec", Argv: []string{"/bin/static-tool", "--delete"}, Expect: VerdictRefused, Rule: "gate.rules[0]"}, {Kind: ActionFSWrite, Action: "fs.write", Path: "/outside/file", Expect: VerdictAsk, Rule: "gate.rules[1]"}}}
	floor := func(*RuleTable, Action, backend.Tier) EvalResult {
		return EvalResult{Verdict: VerdictAllow, Rule: "static-floor"}
	}
	rows := table.RunBy(floor, rt, "/work")
	for _, row := range rows {
		if !row.Pass || row.Got.Score == nil {
			t.Fatalf("gate row%+v", row)
		}
	}
	denied := func(*RuleTable, Action, backend.Tier) EvalResult {
		return EvalResult{Verdict: VerdictRefused, Rule: "protected-floor"}
	}
	for _, row := range table.RunBy(denied, rt, "/work") {
		if row.Got.Rule != "protected-floor" || row.Got.Score != nil || row.Got.Verdict != VerdictRefused {
			t.Fatalf("floor reduced%+v", row)
		}
	}
	var out bytes.Buffer
	if e := PrintRuleTable(&out, rt); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "gate.rules[0]") || !strings.Contains(out.String(), "allow <50, ask 50..80, refused >80 (scores sum, saturating at 100;") {
		t.Fatalf("missing effective program%s", out.String())
	}
}

// TestNetGateWithoutNetSectionWarns is ADR 0041 D6's compile warning: a `net` gate under a contract with no
// net: section is the run's only network control. Its IP connects and sends are then relayed by the
// supervisor (the run's whole IP egress moves into the relay regime), and the unix connects and datagrams it
// scores are continued best effort (D1), so compile says so; a contract with a net: section does not get
// the warning, and neither does a gate that scores no net action.
func TestNetGateWithoutNetSectionWarns(t *testing.T) {
	for _, tc := range []struct {
		src  string
		warn bool
	}{
		{"gate:\n  rules:\n    - \"net to 93.184.216.34:443\": 90\n", true},
		{"gate:\n  rules:\n    - net to undeclared host: 90\n", true},
		{"gate:\n  rules:\n    - \"net to 93.184.216.34:443\": 90\nnet:\n  allow: [\"93.184.216.34:443\"]\n", false},
		{"gate:\n  rules:\n    - fs.write outside worktree: 90\n", false},
	} {
		c := &Contract{}
		if e := yaml.Unmarshal([]byte(tc.src), c); e != nil {
			t.Fatal(e)
		}
		var ds diags
		validateGate(&ds, c, func(string) Pos { return Pos{} })
		warned := false
		for _, d := range ds.list {
			if d.IsError() {
				t.Fatalf("%q: error %v", tc.src, d)
			}
			if d.Code == CodeUnenforced && strings.Contains(d.Message, "no net: section") {
				warned = true
			}
		}
		if warned != tc.warn {
			t.Fatalf("%q: no-net: warning %t, want %t: %v", tc.src, warned, tc.warn, ds.list)
		}
	}
}

// TestGateRowReadsThisHostAsTheRunDoes: a table row's destination is scored as the run scores it, so a `net to` rule on
// this host answers every spelling an address gives of itself, and a group or broadcast row. What only the running host
// can tell, that a LAN address is its own, compile --test cannot: gate.md R3 states that row's answer.
func TestGateRowReadsThisHostAsTheRunDoes(t *testing.T) {
	p, e := CompileGateConfig(gateContract(t, "rules:\n - net to 127.0.0.1:5000: 100\n - 'net to [::1]:5001': 100\n"))
	if e != nil {
		t.Fatal(e)
	}
	rt := &RuleTable{Contract: &Contract{Name: "gate-host"}, Gate: p, Workdir: "/work"}
	floor := EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}
	for _, tc := range []struct {
		host    string
		port    int
		refused bool
	}{
		{"127.0.0.1", 5000, true},
		{"127.0.0.2", 5000, true},
		{"::1", 5000, true},
		{"::ffff:127.0.0.1", 5000, true},
		{"localhost", 5000, true},
		{"224.0.0.1", 5000, true},
		{"255.255.255.255", 5000, true},
		{"127.0.0.1", 5001, true},
		{"::1", 5001, true},
		{"127.0.0.1", 5002, false},
		{"203.0.113.7", 5000, false},
		{"192.0.2.10", 5000, false}, // a LAN address: the run refuses it when it is this host's own
	} {
		got := EvaluateGateRow(rt, Action{Kind: ActionNetConnect, Host: tc.host, Port: tc.port}, floor)
		if refused := got.Verdict == VerdictRefused; refused != tc.refused {
			t.Errorf("%s:%d = %+v, want refused %v", tc.host, tc.port, got, tc.refused)
		}
	}
}

// A table row reads its destination as decide's evalNet reads it: no proto is TCP, and a path with no host is a
// unix socket. EvaluateGateRow matched hostname aliases against the row's raw proto, so a row with none skipped
// every tcp:// entry (net.ask's only form, R22) and its `net to <host>` gate rule: compile --test answered allow
// for a connect by address the run's gateNet, which sees the socket's real proto, refuses net-gate. A unix row with
// no proto was not unsupported either, so a gate ask there was answered ask where the
// run refuses it as unsupported (performAskConnect).
func TestGateRowReadsTheRowsDefaultProtocol(t *testing.T) {
	c := gateContract(t, "rules:\n - net to api.example.com:443: 100\n - net to undeclared host: 70\n")
	p, e := CompileGateConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	entry := NetRule{Raw: "tcp://api.example.com:443", Proto: ProtoTCP, Host: "api.example.com", Port: 443, IPs: []netip.Addr{netip.MustParseAddr("1.2.3.4")}, Verdict: VerdictAllow}
	rt := &RuleTable{Contract: &Contract{Name: "gate-proto"}, Gate: p, Workdir: "/work", Net: []NetRule{entry}}
	floor := EvalResult{Verdict: VerdictAllow, Rule: entry.RuleName()}
	for _, proto := range []string{"", "tcp", "TCP"} {
		got := EvaluateGateRow(rt, Action{Kind: ActionNetConnect, Host: "1.2.3.4", Port: 443, Proto: proto}, floor)
		if got.Verdict != VerdictRefused || got.Rule != "gate.rules[0]" || got.Reason != record.ReasonNetGate {
			t.Errorf("proto %q: 1.2.3.4:443 = %+v, want refused gate.rules[0] through the tcp:// entry's alias", proto, got)
		}
	}
	if got := EvaluateGateRow(rt, Action{Kind: ActionNetConnect, Host: "1.2.3.4", Port: 443, Proto: "udp"}, floor); got.Rule == "gate.rules[0]" {
		t.Errorf("udp 1.2.3.4:443 = %+v: a tcp:// entry names no UDP destination", got)
	}
	unmatched := EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}
	got := EvaluateGateRow(rt, Action{Kind: ActionNetConnect, Path: "unix:/tmp/x.sock"}, unmatched)
	if got.Verdict != VerdictRefused || got.Rule != "gate.rules[1]" || !got.CompletionUnsupported || got.Reason != record.ReasonNetGate {
		t.Errorf("unix row = %+v, want refused gate.rules[1], completion unsupported", got)
	}
}
