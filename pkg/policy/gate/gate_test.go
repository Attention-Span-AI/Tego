// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/thishost"
)

func TestGateThresholdsSumAndFloorCannotBeLowered(t *testing.T) {
	p, err := New([]Rule{{NetUndeclared, "", 40}, {NetTo, "host.example:443", 40}, {NetTo, "host.example:443", 40}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host     string
		declared bool
		score    int
		want     Verdict
	}{{"other.example", true, 0, Allow}, {"other.example", false, 40, Allow}, {"HOST.EXAMPLE.", true, 80, Ask}, {"host.example", false, 100, Refused}} {
		for _, floor := range []Verdict{Allow, Ask, Refused} {
			d := p.Evaluate(floor, Action{Kind: Net, Complete: true, Host: tc.host, Port: 443, Declared: tc.declared})
			want := max(floor, tc.want)
			if d.Verdict != want || floor != Refused && d.Score != tc.score {
				t.Fatalf("host%s floor%d result%+v want%d score%d", tc.host, floor, d, want, tc.score)
			}
		}
	}
}

// TestGateThresholdBoundaries is ADR 0007's `thresholds: {allow: 50, ask: 80}  # below 50 allow; 50 to
// 80 ask; above 80` refused: a score of exactly the allow threshold asks, exactly the ask threshold
// still asks, one past it refuses. Every predicate kind classifies alike, and MayAsk/MayEscalate (what compile
// warns about and what the supervisor holds) agree with Evaluate at each boundary.
func TestGateThresholdBoundaries(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  Verdict
	}{{0, Allow}, {1, Allow}, {49, Allow}, {50, Ask}, {51, Ask}, {79, Ask}, {80, Ask}, {81, Refused}, {100, Refused}} {
		for _, r := range []struct {
			rule Rule
			a    Action
		}{
			{Rule{NetUndeclared, "", tc.score}, Action{Kind: Net, Complete: true}},
			{Rule{WriteOutsideWorktree, "", tc.score}, Action{Kind: FSWrite, Complete: true, Path: "/else/f", Worktree: "/work"}},
			{Rule{ReadMatches, "*.env", tc.score}, Action{Kind: FSRead, Complete: true, Path: "/work/.env", Worktree: "/work"}},
			{Rule{ExecMatches, "rm *", tc.score}, Action{Kind: Exec, Complete: true, Executable: "/bin/rm", Args: []string{"rm", "x"}}},
		} {
			p, err := New([]Rule{r.rule}, 50, 80)
			if err != nil {
				t.Fatal(err)
			}
			if d := p.Evaluate(Allow, r.a); d.Verdict != tc.want || d.Score != tc.score {
				t.Fatalf("score %d kind %d: %+v, want verdict %d", tc.score, r.a.Kind, d, tc.want)
			}
			if p.MayEscalate(r.a.Kind) != (tc.want != Allow) || p.MayAsk(r.a.Kind) != (tc.want == Ask) {
				t.Fatalf("score %d kind %d: MayEscalate %t MayAsk %t disagree with verdict %d", tc.score, r.a.Kind, p.MayEscalate(r.a.Kind), p.MayAsk(r.a.Kind), tc.want)
			}
		}
	}
	// The allow band is "below allow": allow 0 would ask every unmatched action (score 0), which is allowed,
	// so thresholds need 1 <= allow < ask <= 100; allow 1 is what allow 0 meant before (any positive score asks).
	for _, th := range [][2]int{{0, 80}, {-1, 80}, {50, 50}, {80, 50}, {50, 101}} {
		if _, err := New(nil, th[0], th[1]); err == nil || !strings.Contains(err.Error(), "1 <= allow < ask <= 100") {
			t.Errorf("thresholds %v: err %v, want the 1 <= allow < ask <= 100 refusal", th, err)
		}
	}
	p, err := New([]Rule{{NetUndeclared, "", 1}, {NetTo, "h.example:443", 0}}, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		a    Action
		want Verdict
	}{{Action{Kind: Net, Complete: true, Host: "h.example", Port: 443, Declared: true}, Allow}, {Action{Kind: Net, Complete: true, Host: "o.example", Port: 443}, Ask}} {
		if d := p.Evaluate(Allow, tc.a); d.Verdict != tc.want {
			t.Fatalf("allow 1: %+v gave %+v, want %d", tc.a, d, tc.want)
		}
	}
}

// TestGateScoresSumNotHighest is the recorded departure from "an action's score is the highest rule it
// matches" (ADR 0007): the matching rules' scores sum, saturated at 100, which is never
// lower than the highest and so never allows what the highest-rule reading would ask or refuse. Each case's
// highest/highestWant columns are what the highest-rule reading would answer.
func TestGateScoresSumNotHighest(t *testing.T) {
	p, err := New([]Rule{
		{ReadMatches, "*.env", 30}, {ReadMatches, "prod*", 20}, {ReadMatches, "*.pem", 49}, {ReadMatches, "key*", 1},
		{ReadMatches, "*.der", 60}, {ReadMatches, "cert*", 60}, {ReadMatches, "*.bak", 40},
	}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		sum, highest      int
		want, highestWant Verdict
	}{
		{"x.env", 30, 30, Allow, Allow},     // one rule: both readings agree
		{"prod.env", 50, 30, Ask, Allow},    // 30+20 reaches allow exactly and asks; the highest (30) allows
		{"prod.pem", 69, 49, Ask, Allow},    // 20+49
		{"keyfile.pem", 50, 49, Ask, Allow}, // 1+49: a score-1 rule tips 49 into the ask band
		{"prod.bak", 60, 40, Ask, Allow},    // 20+40
		{"cert.der", 100, 60, Refused, Ask}, // 60+60 saturates at 100 and refuses; the highest asks
		{"cert.pem", 100, 60, Refused, Ask}, // 60+49
		{"other.txt", 0, 0, Allow, Allow},   // unmatched: allowed
	} {
		d := p.Evaluate(Allow, Action{Kind: FSRead, Complete: true, Path: "/w/" + tc.name, Worktree: "/w"})
		if d.Score != tc.sum || d.Verdict != tc.want {
			t.Errorf("%s: %+v, want score %d verdict %d", tc.name, d, tc.sum, tc.want)
		}
		if tc.sum < tc.highest || tc.want < tc.highestWant {
			t.Errorf("%s: the sum reading answered below the highest-rule reading", tc.name)
		}
	}
	// The subset-sum MayAsk/MayEscalate see combinations: two 30s reach the ask band only together.
	q, err := New([]Rule{{ReadMatches, "*.env", 30}, {ReadMatches, "a*", 30}, {WriteOutsideWorktree, "", 49}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if !q.MayAsk(FSRead) || !q.MayEscalate(FSRead) || q.MayEscalate(FSWrite) || q.MayAsk(FSWrite) {
		t.Fatalf("MayAsk/MayEscalate: read %t/%t write %t/%t", q.MayAsk(FSRead), q.MayEscalate(FSRead), q.MayAsk(FSWrite), q.MayEscalate(FSWrite))
	}
}

// TestGateReadingWriteSumsBothKinds is the sum across kinds: an FSWrite action that also
// reads its file (Reads: a read-write open, a rename's or hard link's source) is scored by the read and the write
// predicates together, each rule once, their scores summed as one action's are. Under the highest-rule reading the
// two kinds' 30s allowed it; summed they reach the ask band, and MayAskReadWrite/MayEscalateReadWrite see the
// combination neither kind reaches alone.
func TestGateReadingWriteSumsBothKinds(t *testing.T) {
	p, err := New([]Rule{{ReadMatches, "*.env", 30}, {WriteOutsideWorktree, "", 30}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	out := Action{Kind: FSWrite, Complete: true, Path: "/elsewhere/prod.env", Worktree: "/w"}
	for _, tc := range []struct {
		a     Action
		score int
		want  Verdict
	}{
		{out, 30, Allow}, // the write predicates alone
		{Action{Kind: FSRead, Complete: true, Path: out.Path, Worktree: "/w"}, 30, Allow}, // the read ones alone
		{Action{Kind: FSWrite, Reads: true, Complete: true, Path: out.Path, Worktree: "/w"}, 60, Ask},
		{Action{Kind: FSWrite, Reads: true, Complete: true, Path: "/w/prod.env", Worktree: "/w"}, 30, Allow},
		{Action{Kind: FSWrite, Reads: true, Complete: true, Path: "/elsewhere/notes", Worktree: "/w"}, 30, Allow},
		{Action{Kind: FSWrite, Reads: true, Complete: false, Path: out.Path, Worktree: "/w"}, MaxScore, Refused},
	} {
		if d := p.Evaluate(Allow, tc.a); d.Score != tc.score || d.Verdict != tc.want {
			t.Errorf("%+v: %+v, want score %d verdict %d", tc.a, d, tc.score, tc.want)
		}
	}
	// Reads widens only a write: an exec or net action is never scored by the read predicates.
	if d := p.Evaluate(Allow, Action{Kind: Net, Reads: true, Complete: true, Path: out.Path, Worktree: "/w"}); d.Score != 0 || d.Verdict != Allow {
		t.Errorf("a net action with Reads: %+v", d)
	}
	// With no write predicate at all, the read ones still score a reading write.
	r, err := New([]Rule{{ReadMatches, "*.env", 30}, {ReadMatches, "prod*", 30}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := r.Evaluate(Allow, Action{Kind: FSWrite, Reads: true, Complete: true, Path: "/w/prod.env", Worktree: "/w"}); d.Score != 60 || d.Verdict != Ask {
		t.Errorf("read-only gate on a reading write: %+v", d)
	}
	if p.MayAsk(FSRead) || p.MayAsk(FSWrite) || p.MayEscalate(FSRead) || p.MayEscalate(FSWrite) || !p.MayAskReadWrite() || !p.MayEscalateReadWrite() {
		t.Fatalf("read 30 + write 30: read %t/%t write %t/%t read+write %t/%t", p.MayAsk(FSRead), p.MayEscalate(FSRead),
			p.MayAsk(FSWrite), p.MayEscalate(FSWrite), p.MayAskReadWrite(), p.MayEscalateReadWrite())
	}
	// Each kind's own reach is part of the combination's: a write 90 refuses alone and asks with nothing.
	q, err := New([]Rule{{ReadMatches, "*.env", 10}, {WriteOutsideWorktree, "", 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if q.MayAskReadWrite() || !q.MayEscalateReadWrite() {
		t.Fatalf("read 10 + write 90: read+write %t/%t", q.MayAskReadWrite(), q.MayEscalateReadWrite())
	}
	if s, err := New([]Rule{{ExecMatches, "rm", 60}}, 50, 80); err != nil || s.MayAskReadWrite() || s.MayEscalateReadWrite() {
		t.Fatalf("an exec-only gate: %v", err)
	}
}

// TestGateMoveCountsEachRuleOnceAcrossItsEnds: a rename or hard link is one call, one
// line and one verdict, so it is one action over its two ends (Dest): every rule that matches an end it scores counts
// once and the scores sum. The write predicates score both ends; the read ones score the source (Reads) and, under
// RENAME_EXCHANGE, the destination (DestReads). Before, each end was its own action and the stronger kept, so
// renaming /w/prod.env (the read rule's name) to /out/x (the write rule's place) scored 30 and was allowed.
func TestGateMoveCountsEachRuleOnceAcrossItsEnds(t *testing.T) {
	p, err := New([]Rule{{ReadMatches, "*.env", 30}, {WriteOutsideWorktree, "", 30}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	move := func(from, to string, exchange bool) Action {
		return Action{Kind: FSWrite, Reads: true, Complete: true, Path: from, Dest: to, DestReads: exchange, Worktree: "/w"}
	}
	for _, tc := range []struct {
		name  string
		a     Action
		score int
		want  Verdict
	}{
		{"a matching source out of the worktree", move("/w/prod.env", "/out/x", false), 60, Ask},
		{"a matching source within the worktree", move("/w/prod.env", "/w/x", false), 30, Allow},
		{"the write rule matches both ends, counted once", move("/out/a", "/out/b", false), 30, Allow},
		{"a destination that only receives the matching name", move("/w/a", "/out/prod.env", false), 30, Allow},
		{"an exchange reads its destination too", move("/w/a", "/out/prod.env", true), 60, Ask},
		{"the read rule matches both ends of an exchange, counted once", move("/w/a.env", "/w/b.env", true), 30, Allow},
		{"nothing matches", move("/w/a", "/w/b", true), 0, Allow},
	} {
		if d := p.Evaluate(Allow, tc.a); d.Score != tc.score || d.Verdict != tc.want {
			t.Errorf("%s: %+v, want score %d verdict %d", tc.name, d, tc.score, tc.want)
		}
	}
	// The first contributing declaration is named in rule order, whichever end matched it.
	if d := p.Evaluate(Allow, move("/w/prod.env", "/out/x", false)); d.Rule != "gate.rules[0]" {
		t.Errorf("rule: %+v", d)
	}
	// Dest and DestReads widen only a write: a read action is scored on Path alone.
	if d := p.Evaluate(Allow, Action{Kind: FSRead, Complete: true, Path: "/w/a", Dest: "/w/prod.env", DestReads: true, Worktree: "/w"}); d.Score != 0 {
		t.Errorf("a read action with Dest: %+v", d)
	}
	// With no read predicate, a gate of write rules scores the move by its ends.
	q, err := New([]Rule{{WriteOutsideWorktree, "", 60}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := q.Evaluate(Allow, move("/w/a", "/out/b", false)); d.Score != 60 || d.Verdict != Ask {
		t.Errorf("write-only gate on a move out: %+v", d)
	}
	// A read-only gate scores an exchange's destination without Reads on the source.
	r, err := New([]Rule{{ReadMatches, "*.env", 60}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := r.Evaluate(Allow, Action{Kind: FSWrite, Complete: true, Path: "/w/a", Dest: "/w/b.env", DestReads: true, Worktree: "/w"}); d.Score != 60 || d.Verdict != Ask {
		t.Errorf("read-only gate on an exchange's destination: %+v", d)
	}
}

// A move of a directory renames every file beneath it, so an `fs.read matches` pattern holding a separator scores a
// move end it could match a path beneath: `mv secrets public` under "secrets/*" read
// secrets/key as public/key with no race, the move scored 0.
func TestGateReadMatchesScoresAMovedAncestor(t *testing.T) {
	move := func(from, to string, exchange bool) Action {
		return Action{Kind: FSWrite, Reads: true, Complete: true, Path: from, Dest: to, DestReads: exchange, Worktree: "/w"}
	}
	for _, tc := range []struct {
		name    string
		pattern string
		a       Action
		score   int
	}{
		{"a relative pattern's directory", "secrets/*", move("/w/secrets", "/w/public", false), 60},
		{"a relative pattern's grandparent", "a/secrets/*", move("/w/a", "/w/b", false), 60},
		{"a globbed directory component", "s*/key", move("/w/secrets", "/w/public", false), 60},
		{"an absolute pattern's directory", "/home/u/.ssh/*", move("/home/u/.ssh", "/home/u/x", false), 60},
		{"an absolute pattern's ancestor", "/home/u/.ssh/*", move("/home/u", "/home/v", false), 60},
		{"the worktree itself", "secrets/*", move("/w", "/v", false), 60},
		{"an ancestor of the worktree", "secrets/*", move("/", "/v", false), 60},
		{"a class that leaves the separator out", "x/s[^x/]k", move("/w/x", "/w/y", false), 60},
		{"an escaped component", `x/\s*/k`, move("/w/x/sec", "/w/y", false), 60},
		{"an exchange's destination", "secrets/*", move("/w/public", "/w/secrets", true), 60},
		{"the file the pattern names is still scored", "secrets/*", move("/w/secrets/key", "/w/public/key", false), 60},
		{"a sibling directory", "secrets/*", move("/w/public", "/w/other", false), 0},
		{"a directory the pattern's component does not match", "s*/key", move("/w/public", "/w/other", false), 0},
		{"a name-only pattern ignores directories", "*.env", move("/w/conf", "/w/other", false), 0},
		{"the pattern's last component is not a directory of it", "secrets/*", move("/w/secrets/key/deeper", "/w/x", false), 0},
		{"a destination that only receives the name", "secrets/*", move("/w/public", "/w/secrets", false), 0},
		{"a directory outside an absolute pattern's path", "/home/u/.ssh/*", move("/home/v", "/home/x", false), 0},
	} {
		p, err := New([]Rule{{ReadMatches, tc.pattern, 60}}, 50, 80)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d := p.Evaluate(Allow, tc.a); d.Score != tc.score {
			t.Errorf("%s: %+v, want score %d", tc.name, d, tc.score)
		}
	}
	// A read of the directory itself is no move: a read predicate scores a read action by the path it names.
	p, err := New([]Rule{{ReadMatches, "secrets/*", 60}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(Allow, Action{Kind: FSRead, Complete: true, Path: "/w/secrets", Worktree: "/w"}); d.Score != 0 {
		t.Errorf("a read-open of the directory: %+v", d)
	}
	// Nor is a read-write open of it, which has no Dest.
	if d := p.Evaluate(Allow, Action{Kind: FSWrite, Reads: true, Complete: true, Path: "/w/secrets", Worktree: "/w"}); d.Score != 0 {
		t.Errorf("a read-write open named as the directory: %+v", d)
	}
}

// lanHost is a running host with one address on one subnet (thishost.Addrs).
type lanHost struct{}

func (lanHost) Own(a netip.Addr) bool       { return a == netip.MustParseAddr("192.0.2.10") }
func (lanHost) Broadcast(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.255") }

// TestNetToOnThisHostScoresEverySpelling: a rule that names this host is on the destination, not on a spelling of it. A
// server bound to all interfaces answers on every loopback address and on the host's own, so each of them is scored on
// the rule's port, and so is a datagram to a group or a broadcast address, which reaches the same server. A rule on
// another machine, or on a group, names no spelling of this host. Each rule counts once, however many spellings it has.
func TestNetToOnThisHostScoresEverySpelling(t *testing.T) {
	p, err := New([]Rule{{NetTo, "127.0.0.1:5000", 90}, {NetTo, "[::1]:5001", 90}, {NetTo, "localhost:5002", 90},
		{NetTo, "192.0.2.10:5003", 90}, {NetTo, "0.0.0.0:5004", 90}, {NetTo, "203.0.113.7:5005", 90},
		{NetTo, "224.0.0.1:5006", 90}, {NetTo, "127.0.0.9:5007", 30}, {NetTo, "[::1]:5007", 30}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	spellings := []string{"127.0.0.1", "127.0.0.2", "127.255.255.254", "::ffff:127.0.0.1", "::ffff:127.0.0.2", "::1", "::1%1",
		"0.0.0.0", "::", "192.0.2.10", "::ffff:192.0.2.10", "224.0.0.1", "::ffff:224.0.0.1", "ff02::1", "ff02::1%2",
		"255.255.255.255", "192.0.2.255", "localhost", "db.localhost"}
	verdict := func(host string, port uint16, h thishost.Addrs) Verdict {
		return p.Evaluate(Allow, Action{Kind: Net, Complete: true, Host: host, Port: port, ThisHost: h}).Verdict
	}
	for _, port := range []uint16{5000, 5001, 5002, 5003, 5004} {
		for _, host := range spellings {
			if got := verdict(host, port, lanHost{}); got != Refused {
				t.Errorf("%s on port %d = %d, want refused", host, port, got)
			}
		}
		if got := verdict("203.0.113.8", port, lanHost{}); got != Allow {
			t.Errorf("another machine on port %d = %d, want allow", port, got)
		}
	}
	for _, host := range spellings {
		if got := verdict(host, 5005, lanHost{}); got != Allow {
			t.Errorf("%s on a remote rule's port = %d, want allow", host, got)
		}
		if got := verdict(host, 6000, lanHost{}); got != Allow {
			t.Errorf("%s on no rule's port = %d, want allow", host, got)
		}
		want := Allow
		if strings.Contains(host, "224.0.0.1") {
			want = Refused
		}
		if got := verdict(host, 5006, lanHost{}); got != want {
			t.Errorf("%s on a group rule's port = %d, want %d", host, got, want)
		}
	}
	if d := p.Evaluate(Allow, Action{Kind: Net, Complete: true, Host: "127.0.0.1", Port: 5007, ThisHost: lanHost{}}); d.Score != 60 {
		t.Errorf("two rules on this host, score %d, want each counted once", d.Score)
	}

	// With no running host to ask, as `compile --test` has none, an address answers for itself and a host's own does not.
	for host, want := range map[string]Verdict{"127.0.0.2": Refused, "::1": Refused, "224.0.0.1": Refused, "255.255.255.255": Refused,
		"localhost": Refused, "192.0.2.10": Allow, "192.0.2.255": Allow} {
		if got := verdict(host, 5000, nil); got != want {
			t.Errorf("no snapshot: %s = %d, want %d", host, got, want)
		}
	}
	if got := verdict("127.0.0.1", 5003, nil); got != Allow {
		t.Errorf("no snapshot: a rule on a literal only the running host can place = %d", got)
	}
}

// TestNetToIgnoresAnIPv6ScopeID: the supervisor keeps sin6_scope_id as an address zone for the ledger's dst. It names
// a link, not another destination: a rule scores the address however the scope reads, in Host and in every alias, a
// link-local rule included, whose connect normally has to carry one.
func TestNetToIgnoresAnIPv6ScopeID(t *testing.T) {
	p, err := New([]Rule{{NetTo, "[::1]:443", 90}, {NetTo, "[fe80::1]:443", 90}, {NetTo, "[2001:db8::1]:443", 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		a       Action
		refused bool
	}{
		{"no scope", Action{Host: "::1"}, true},
		{"a scope", Action{Host: "::1%1"}, true},
		{"a scope nothing has", Action{Host: "::1%4242"}, true},
		{"link-local with its scope", Action{Host: "fe80::1%2"}, true},
		{"global with a scope", Action{Host: "2001:db8::1%7"}, true},
		{"an alias with a scope", Action{Host: "2001:db8::2", Hosts: []string{"::1%1"}}, true},
		{"another address with a scope", Action{Host: "2001:db8::2%1"}, false},
	} {
		tc.a.Kind, tc.a.Complete, tc.a.Port = Net, true, 443
		if d := p.Evaluate(Allow, tc.a); (d.Verdict == Refused) != tc.refused {
			t.Errorf("%s: decision %+v, want refused %v", tc.name, d, tc.refused)
		}
	}
}

func TestGateClosedPredicatesFactsAndExecutableIdentity(t *testing.T) {
	p, err := New([]Rule{{WriteOutsideWorktree, "", 90}, {ReadMatches, "*.env", 90}, {ExecMatches, "rm -rf", 90}, {NetTo, "[::ffff:127.0.0.1]:443", 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		a       Action
		refused bool
	}{
		{Action{Kind: FSWrite, Complete: true, Path: "/work/sub/file", Worktree: "/work"}, false},
		{Action{Kind: FSWrite, Complete: true, Path: "/work-else/file", Worktree: "/work"}, true},
		{Action{Kind: FSRead, Complete: true, Path: "/work/secret.env", Worktree: "/work"}, true},
		{Action{Kind: Exec, Complete: true, Executable: "/bin/rm", Args: []string{"innocent-argv-zero", "-rf", "/work"}}, true},
		{Action{Kind: Exec, Complete: true, Executable: "/bin/true", Args: []string{"rm", "-rf", "/work"}}, true},
		// ADR 0048 (5): the command reading reads -rfake as -r -f with letters rm does not list (GNU rm refuses the
		// cluster anyway), so the union escalates it; the legacy literal reading alone did not.
		{Action{Kind: Exec, Complete: true, Executable: "/bin/rm", Args: []string{"rm", "-rfake"}}, true},
		{Action{Kind: Exec, Complete: true, Executable: "/bin/rm", Args: []string{"rm", "-r", "fake"}}, false},
		{Action{Kind: Exec, Complete: true, Executable: "/bin/coreutils", Invocation: "/bin/rm", Args: []string{"innocent", "-rf", "/work"}}, true},
		{Action{Kind: Net, Complete: true, Host: "127.0.0.1", Port: 443}, true},
		{Action{Kind: Net, Complete: false, Host: "other", Port: 1}, true},
	} {
		if d := p.Evaluate(Allow, tc.a); (d.Verdict == Refused) != tc.refused {
			t.Fatalf("action%+v decision%+v", tc.a, d)
		}
	}
	glob, err := New([]Rule{{ExecMatches, "rm -rf *", 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if d := glob.Evaluate(Allow, Action{Kind: Exec, Complete: true, Executable: "/bin/rm", Args: []string{"fake", "-rf", "/work/sub"}}); d.Verdict != Refused {
		t.Fatalf("argv slash glob %+v", d)
	}
}

func TestGateImmutableBoundsAndConservativeApprovalKinds(t *testing.T) {
	rules := []Rule{{NetUndeclared, "", 40}, {NetTo, "h.example:443", 40}}
	p, err := New(rules, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Score = 0
	if !p.MayAsk(Net) || p.MayAsk(Exec) || !p.Has(Net) || p.Has(FSRead) {
		t.Fatal("incorrect bounded kind selection")
	}
	if d := p.Evaluate(Allow, Action{Kind: Net, Complete: true, Host: "h.example", Port: 443}); d.Score != 80 || d.Verdict != Ask {
		t.Fatalf("mutated source rules %+v", d)
	}
	for _, r := range []Rule{{99, "", 1}, {NetUndeclared, "", -1}, {NetUndeclared, "", 101}, {ReadMatches, "[", 50}, {ExecMatches, "**", 50}, {NetTo, "tcp://host:443", 50}, {NetTo, "[fe80::1%eth0]:443", 50}} {
		if _, err := New([]Rule{r}, 50, 80); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if _, err := New(make([]Rule, MaxRules+1), 50, 80); err == nil {
		t.Fatal("rule bound")
	}
	if _, err := New(nil, 80, 50); err == nil {
		t.Fatal("threshold order")
	}
	p, err = New([]Rule{{ExecMatches, "*", 50}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []Action{{Kind: Exec, Complete: true, Executable: "/bin/a", Args: []string{"a", strings.Repeat("x", MaxText+1)}}, {Kind: Exec, Complete: true, Executable: "/bin/a", Args: make([]string, MaxArgs+1)}} {
		if d := p.Evaluate(Allow, a); d.Verdict != Refused || d.Rule != "gate.unreadable" {
			t.Fatalf("unbounded argv %+v", d)
		}
	}
}

// TestMayEscalateIsAScoreAtOrAboveAllow is ADR 0041 D1's "MayEscalate(kind)": a kind whose rules can sum to the allow
// threshold or above can raise a verdict, so its actions carry a supervisor decision; one whose rules stay below
// allow, alone or together, never escalates (only an incomplete action refuses it, as gate.unreadable).
// MayEscalateBy narrows the sum to one predicate's rules: a unix destination is matched by `net to undeclared
// host` alone, never by `net to host:port`.
func TestMayEscalateIsAScoreAtOrAboveAllow(t *testing.T) {
	p, err := New([]Rule{
		{ReadMatches, "*.env", 30}, {ReadMatches, "*.pem", 30}, // 60 together
		{WriteOutsideWorktree, "", 49}, // below allow: never escalates
		{ExecMatches, "rm", 95},
		{NetTo, "h.example:443", 90}, {NetUndeclared, "", 20},
	}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind Kind
		want bool
	}{{FSRead, true}, {FSWrite, false}, {Exec, true}, {Net, true}} {
		if got := p.MayEscalate(tc.kind); got != tc.want {
			t.Errorf("MayEscalate(%d) = %t, want %t", tc.kind, got, tc.want)
		}
	}
	if p.MayEscalateBy(NetUndeclared) || !p.MayEscalateBy(NetTo) || !p.MayEscalateBy(ReadMatches) {
		t.Errorf("MayEscalateBy: undeclared %t, to %t, read %t", p.MayEscalateBy(NetUndeclared), p.MayEscalateBy(NetTo), p.MayEscalateBy(ReadMatches))
	}
	var none *Policy
	if none.MayEscalate(FSRead) || none.MayEscalateBy(ReadMatches) {
		t.Error("a nil policy escalates nothing")
	}
}

// An exec pattern's first word is matched against basenames only (R2: the requested pathname's, the resolved
// image's and argv[0]'s), so a first word with a '/' can never match an executable: `exec matches
// "/usr/bin/curl *": 100` was accepted, printed as an active rule, and never fired, and
// "*/curl *" matched only argument text. New refuses such a pattern and names the basename to write; a '/'
// after the first word is argument text and stays.
func TestGateExecPatternFirstWordIsABasename(t *testing.T) {
	for _, pattern := range []string{"/usr/bin/curl *", "/usr/bin/curl", "/bin/rm -rf", "*/curl *", "./tool --x", "bin/rm"} {
		_, err := New([]Rule{{ExecMatches, pattern, 100}}, 50, 80)
		if err == nil || !strings.Contains(err.Error(), "basename") {
			t.Errorf("exec matches %q: err %v, want a refusal naming the basename", pattern, err)
		}
	}
	p, err := New([]Rule{{ExecMatches, "curl http://x/*", 100}, {ExecMatches, "rm -rf /work", 100}}, 50, 80)
	if err != nil {
		t.Fatalf("a '/' after the first word refused: %v", err)
	}
	if d := p.Evaluate(Allow, Action{Kind: Exec, Complete: true, Executable: "/usr/bin/curl", Args: []string{"/usr/bin/curl", "http://x/y"}}); d.Verdict != Refused {
		t.Fatalf("curl http://x/y = %+v, want refused", d)
	}
}

// TestGateReadPatternMatchesSomeCleanPath: a read pattern is matched against a clean path
// (the path itself, or the path from the worktree, which filepath.Rel cleans), and New accepted patterns no clean
// path can match, which never fired: under `fs.read matches "./secrets/*"` a read of secrets/key was allowed, with no
// warning. New accepts a pattern only when filepath.Match's grammar accepts the whole of it (filepath.Match(p, "")
// stops at the first chunk that fails, so "a*[" was accepted) and some clean path matches it, and it refuses a
// pattern holding '/' with a class that could match '/' (a path's '/' is matched by a '/' of the pattern alone). The
// refusal of an unclean spelling names its clean one.
func TestGateReadPatternMatchesSomeCleanPath(t *testing.T) {
	for pattern, fix := range map[string]string{
		"./secrets/*": "secrets/*", "secrets//*": "secrets/*", "secrets/*/": "secrets/*", "secrets/./key": "secrets/key",
		"/home/u//.ssh/*": "/home/u/.ssh/*", "/home/u/./.ssh/*": "/home/u/.ssh/*", "/home/u/.ssh/": "/home/u/.ssh",
		"secrets/": "", "./x": "", "a/../b": "", "a/*/../b": "", "/a/../b": "", "/..": "", "secrets/.": "", ".": "",
		"..": "", `\.`: "", "[.]": "", "[/]": "", "a/[.]/b": "", "a/[/]": "", `a\/b`: "", "x/s[^x]k": "", "x/[/]k": "",
		"x/[!-0]k": "", "x/a*[": "", "a*[": "", `a*\`: "", "x/a*[^": "", "x/[]": "", "a*b[z-": "",
	} {
		_, err := New([]Rule{{ReadMatches, pattern, 90}}, 50, 80)
		if err == nil {
			t.Errorf("fs.read matches %q accepted; no clean path matches it as written", pattern)
			continue
		}
		if fix != "" && !strings.Contains(err.Error(), "write "+strconv.Quote(fix)) {
			t.Errorf("fs.read matches %q: %v, want it to name %q", pattern, err, fix)
		}
	}
	for _, pattern := range []string{"rm *[", "rm -rf *[^", `rm \`} {
		if _, err := New([]Rule{{ExecMatches, pattern, 90}}, 50, 80); err == nil {
			t.Errorf("exec matches %q accepted; its glob is malformed and never matched", pattern)
		}
	}
	for _, tc := range []struct{ pattern, worktree, path string }{
		{"secrets/*", "/w", "/w/secrets/key"},
		{"../secrets/*", "/w/proj", "/w/secrets/key"},
		{"/home/u/.ssh/*", "/w", "/home/u/.ssh/id"},
		{"/", "/w", "/"},
		// The root's one name is empty, which a star matches, as filepath.Match("/*", "/") does (RD5-1).
		{"/*", "/w", "/"},
		{"/*", "/w", "/etc"},
		{"x/s[^x/]k", "/w", "/w/x/sak"},
		{"*[^é/]/*", "/w", "/w/é/k"},
		{"*.env", "/w", "/w/a/b/c.env"},
		{"..*", "/w", "/w/..hidden"},
		{`a\*b`, "/w", "/w/sub/a*b"},
		// A '/' inside a class is no separator: the pattern matches a base name.
		{"[^/]*.env", "/w", "/w/sub/x.env"},
	} {
		p, err := New([]Rule{{ReadMatches, tc.pattern, 90}}, 50, 80)
		if err != nil {
			t.Errorf("fs.read matches %q refused: %v", tc.pattern, err)
			continue
		}
		if d := p.Evaluate(Allow, Action{Kind: FSRead, Complete: true, Path: tc.path, Worktree: tc.worktree}); d.Score != 90 {
			t.Errorf("fs.read matches %q, read of %s from %s: %+v, want score 90", tc.pattern, tc.path, tc.worktree, d)
		}
	}
}

// TestGateReadPatternReachesTheWorktreesAncestors: a relative read pattern
// is matched against the path from the worktree, which starts with at most as many ".." components as the worktree
// has names, so a pattern needing more matches nothing in that worktree. New accepted it, as its worktree is not
// New's to know, and the compile that captures the run's worktree accepted it too, so the rule never fired. CheckWorktree
// refuses it and names the absolute pattern the run's resolution reads (/.. is /) when its leading components are
// literal "..". A glob that matches ".." as well as names reaches no ancestor it must, so it is accepted.
func TestGateReadPatternReachesTheWorktreesAncestors(t *testing.T) {
	for _, tc := range []struct {
		pattern, worktree, want string
	}{
		{"../../../secrets/*", "/home/u", `write "/secrets/*"`},
		{"../../secrets/k", "/w", `write "/secrets/k"`},
		{"../..", "/w", `write "/"`},
		{"../*/../x", "/w", "no path from the worktree"},
		{"../*", "/", `write "/*"`},
	} {
		p, err := New([]Rule{{ReadMatches, tc.pattern, 90}}, 50, 80)
		if err != nil {
			t.Fatalf("fs.read matches %q refused by New: %v", tc.pattern, err)
		}
		if err := p.CheckWorktree(tc.worktree); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("fs.read matches %q in worktree %s: %v, want a refusal holding %q", tc.pattern, tc.worktree, err, tc.want)
		}
	}
	for _, tc := range []struct{ pattern, worktree, path string }{
		{"../../secrets/*", "/home/u", "/secrets/k"},
		{"../..", "/home/u", "/"},
		{"*/x", "/", "/a/x"},
		{"../*/x", "/w", "/a/x"},
		{"*/*/x", "/w", "/a/x"},
		{"secrets/*", "/", "/secrets/k"},
		{"/a/*", "/", "/a/b"},
		{"*.env", "/", "/a/b.env"},
	} {
		p, err := New([]Rule{{ReadMatches, tc.pattern, 90}}, 50, 80)
		if err != nil {
			t.Fatalf("fs.read matches %q refused by New: %v", tc.pattern, err)
		}
		if err := p.CheckWorktree(tc.worktree); err != nil {
			t.Errorf("fs.read matches %q in worktree %s refused: %v", tc.pattern, tc.worktree, err)
		}
		if d := p.Evaluate(Allow, Action{Kind: FSRead, Complete: true, Path: tc.path, Worktree: tc.worktree}); d.Score != 90 {
			t.Errorf("fs.read matches %q, read of %s from %s: %+v, want score 90", tc.pattern, tc.path, tc.worktree, d)
		}
	}
	// A refused pattern names its rule, and a policy with no relative read pattern has nothing to check.
	p, err := New([]Rule{{WriteOutsideWorktree, "", 10}, {ReadMatches, "../../../x", 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckWorktree("/w"); err == nil || !strings.HasPrefix(err.Error(), "gate.rules[1]: ") {
		t.Errorf("refusal %v, want it to name gate.rules[1]", err)
	}
	if err := (*Policy)(nil).CheckWorktree("/w"); err != nil {
		t.Errorf("nil policy: %v", err)
	}
}

// TestGateReadPatternRefusalSaysWhatFilepathMatchDid: the refusal of an escaped '/' said
// it "never matches a path's separator", where filepath.Match reads it as a '/' that does, so the gate before the
// component reading fired on a/x under `fs.read matches "a\/x"`. It is refused because the two readings differ, and the
// refusal says so and names the spelling with a plain '/'. A '/' inside a class of a pattern with no other '/' makes
// no path pattern, so such a pattern is a base name's, which never holds '/'; the refusal says where the '/' goes.
func TestGateReadPatternRefusalSaysWhatFilepathMatchDid(t *testing.T) {
	for _, tc := range []struct{ pattern, path, want string }{
		{`a\/x`, "a/x", `across a separator; write "a/x"`},
		{`?\/?`, "a/x", `across a separator; write "?/?"`},
		{`x/a\/b`, "x/a/b", `across a separator; write "x/a/b"`},
		{`/home/u/.ssh\/*`, "/home/u/.ssh/id", `across a separator; write "/home/u/.ssh/*"`},
		{`a\\\/b`, `a\/b`, `across a separator; write "a\\\\/b"`},
		{"x/[^y]z", "x//z", "can match '/'"},
		{"a[/]b", "a/b", "a base name never holds '/'; a path pattern holds '/' outside a class"},
	} {
		if m, err := filepath.Match(tc.pattern, tc.path); !m || err != nil {
			t.Fatalf("filepath.Match(%q, %q) = %v, %v; the case proves nothing", tc.pattern, tc.path, m, err)
		}
		_, err := New([]Rule{{ReadMatches, tc.pattern, 90}}, 50, 80)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "never matches") {
			t.Errorf("fs.read matches %q: %v, want a refusal saying %q", tc.pattern, err, tc.want)
		}
	}
}

// TestGateMovedDirectoryWithAMultibyteName: a move's end was matched by a second reader
// of filepath.Match's grammar that stepped a rune at a time, where filepath.Match's star skips bytes, so under
// `fs.read matches "*[^é/]/*"` the move of a directory named é scored 0 although the pattern matches é/k beneath it.
// Each end is now matched by filepath.Match itself, one name at a time.
func TestGateMovedDirectoryWithAMultibyteName(t *testing.T) {
	move := func(from, to string) Action {
		return Action{Kind: FSWrite, Reads: true, Complete: true, Path: from, Dest: to, Worktree: "/w"}
	}
	for _, tc := range []struct {
		pattern string
		read    string
		a       Action
	}{
		{"*[^é/]/*", "/w/é/k", move("/w/é", "/w/x")},
		{"work/*[가-�]/key", "/w/work/é/key", move("/w/work/é", "/w/work/x")},
		{"é*/?", "/w/éa/b", move("/w/éa", "/w/x")},
	} {
		p, err := New([]Rule{{ReadMatches, tc.pattern, 60}}, 50, 80)
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		if d := p.Evaluate(Allow, Action{Kind: FSRead, Complete: true, Path: tc.read, Worktree: "/w"}); d.Score != 60 {
			t.Errorf("%q: read of %s %+v, want score 60", tc.pattern, tc.read, d)
		}
		if d := p.Evaluate(Allow, tc.a); d.Score != 60 {
			t.Errorf("%q: move of %s %+v, want score 60", tc.pattern, tc.a.Path, d)
		}
	}
}

// TestGateMoveOfANonDirectoryIsMatchedByItsName: the gate took every move's end to be a
// directory, so under a wildcard directory component (`*/.env`) every move of a regular file at that depth scored the
// rule, an editor's atomic save included. An end known to be no directory (PathNotDir, DestNotDir) has nothing beneath
// it and is matched by its own name; the zero value, unknown, is still read as a directory.
func TestGateMoveOfANonDirectoryIsMatchedByItsName(t *testing.T) {
	type end struct {
		path   string
		notDir bool
	}
	move := func(from, to end, exchange bool) Action {
		return Action{Kind: FSWrite, Reads: true, Complete: true, Path: from.path, PathNotDir: from.notDir, Dest: to.path, DestNotDir: to.notDir, DestReads: exchange, Worktree: "/w"}
	}
	file := func(p string) end { return end{p, true} }
	unknown := func(p string) end { return end{p, false} }
	for _, tc := range []struct {
		name    string
		pattern string
		a       Action
		score   int
	}{
		{"an atomic save", "*/.env", move(file("/w/.out.json.tmp"), file("/w/out.json"), false), 0},
		{"a regular file's move at the wildcard's depth", "*/.env", move(file("/w/notes.txt"), unknown("/w/notes.bak"), false), 0},
		{"an absolute pattern's atomic save", "/home/u/.config/*/token", move(file("/home/u/.config/app.json.tmp"), file("/home/u/.config/app.json"), false), 0},
		{"a regular file named as the pattern's directory", "secrets/*", move(file("/w/secrets"), unknown("/w/public"), false), 0},
		{"an exchange of two regular files", "*/.env", move(file("/w/a"), file("/w/b"), true), 0},
		{"the file the pattern names", "secrets/*", move(file("/w/secrets/key"), unknown("/w/public"), false), 90},
		{"an end of unknown type", "*/.env", move(unknown("/w/notes.txt"), file("/w/notes.bak"), false), 90},
		{"an exchange with a destination of unknown type", "secrets/*", move(file("/w/public"), unknown("/w/secrets"), true), 90},
		{"an exchange's file destination", "secrets/*", move(file("/w/public"), file("/w/secrets"), true), 0},
	} {
		p, err := New([]Rule{{ReadMatches, tc.pattern, 90}}, 50, 80)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d := p.Evaluate(Allow, tc.a); d.Score != tc.score {
			t.Errorf("%s: %+v, want score %d", tc.name, d, tc.score)
		}
	}
	for pattern, want := range map[string]bool{"*/.env": true, "/home/u/*": true, "*.env": false, "[^/]*.env": false} {
		p, err := New([]Rule{{ReadMatches, pattern, 90}, {WriteOutsideWorktree, "", 10}}, 50, 80)
		if err != nil {
			t.Fatal(err)
		}
		if p.ScoresBeneath() != want {
			t.Errorf("%q: ScoresBeneath %v, want %v", pattern, !want, want)
		}
	}
}
