// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// actionsTable is the fixture of the conformance actions' tests (plans/adr0017 C9): a write entry with a deny_read
// nested in it (unenforced at tier 1), a built-in deny_write target beneath the write entry, a watch entry, a unix
// entry, one UDP host entry and an ICMP (port 0) entry, under a contract whose exec: section restricts images.
func actionsTable(exec *agent.ExecSection) *agent.RuleTable {
	return &agent.RuleTable{
		Tier:     backend.TierLandlock,
		Contract: &agent.Contract{Name: "actions", Net: &agent.NetSection{}, Exec: exec},
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/w/out", Raw: "./out/", Resolved: "/w/out", Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: "/w/out/keys", Raw: "./out/keys/", Resolved: "/w/out/keys", Unenforced: true},
			{Kind: agent.FSWatch, Path: "/w/config", Raw: "./config/", Resolved: "/w/config"},
		},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/w/out/.git/config", Resolved: "/w/out/.git/config", BuiltIn: true, Unenforced: true}},
		Net: []agent.NetRule{
			{Raw: "unix:/run/a.sock", Proto: agent.ProtoUnix, UnixPath: "/run/a.sock", Verdict: agent.VerdictAllow},
			{Raw: "udp://127.0.0.1:8125", Proto: agent.ProtoUDP, Port: 8125, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true, Verdict: agent.VerdictAllow},
			{Raw: "10.0.0.1:0", Proto: agent.ProtoInet, Port: 0, IPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Static: true, Verdict: agent.VerdictAllow},
		},
	}
}

type actionCase struct {
	name    string
	a       agent.Action
	tier    backend.Tier
	verdict agent.Verdict
	rule    string
	reason  record.Reason
}

// checkActions asks every case of both the reference model (Evaluate) and the indexed one (Evaluator), which must
// agree with each other and with the case.
func checkActions(t *testing.T, rt *agent.RuleTable, cases []actionCase) {
	t.Helper()
	ev := NewEvaluator(rt)
	for _, c := range cases {
		for _, got := range []agent.EvalResult{Evaluate(rt, c.a, c.tier), ev.Evaluate(c.a, c.tier)} {
			if got.Verdict != c.verdict || got.Rule != c.rule || got.Reason != c.reason {
				t.Errorf("%s at %s: %+v, want %s via %s (%s)", c.name, c.tier, got, c.verdict, c.rule, c.reason)
			}
		}
	}
}

var (
	writeOut = "fs.write[./out/]"
	keys     = "fs.deny_read[./out/keys/]"
	gitCfg   = (agent.FSRule{Kind: agent.FSDenyWrite, Path: "/w/out/.git/config"}).RuleName()
	l1, l2   = backend.TierLandlock, backend.TierCgroup
	l3, obs  = backend.TierBPFLSM, backend.TierObserve
)

// TestEvaluateLink: a hard link is decided on both ends as modifications at themselves, then REFER's no-gain rule,
// as the supervisor's recordLink decides it at tiers 1 and 2 (decideFS on the existing file, decideMoveDest on the
// new name), with a built-in deny_write target at either end refused first (R15c) and, at tier 2, a link out of a
// deny_read the listener enforces by path refused (R15d). An allowed link is named by the source's grant, as the
// run's line is. Tier 3's root model refuses a link out of a nested deny_read on the walk.
func TestEvaluateLink(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{})
	link := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSLink, Path: src, DestPath: dst}
	}
	wo := record.ReasonWriteOutsideContract
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		cases = append(cases,
			actionCase{"link within the write entry", link("/w/out/a", "/w/out/b"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"link of a file outside every entry into it", link("/w/notes", "/w/out/l"), tier, agent.VerdictRefused, agent.UnmatchedRule, wo},
			actionCase{"link out of the write entry", link("/w/out/a", "/w/l"), tier, agent.VerdictRefused, agent.UnmatchedRule, wo},
			actionCase{"link of a watched file", link("/w/config/app.toml", "/w/out/app"), tier, agent.VerdictRefused, "fs.watch[./config/]", wo},
			actionCase{"a second name for the deny_write target", link("/w/out/.git/config", "/w/out/cfg"), tier, agent.VerdictRefused, gitCfg, wo},
			actionCase{"a new name inside the deny_write target", link("/w/out/a", "/w/out/.git/config"), tier, agent.VerdictRefused, gitCfg, wo},
			actionCase{"a link with no destination", link("/w/out/a", ""), tier, agent.VerdictRefused, agent.InvalidActionRule, ""},
		)
	}
	cases = append(cases,
		actionCase{"landlock: out of the nested deny_read, unenforced there", link("/w/out/keys/k", "/w/out/k"), l1, agent.VerdictAllow, writeOut, ""},
		actionCase{"cgroup: out of the nested deny_read the listener enforces", link("/w/out/keys/k", "/w/out/k"), l2, agent.VerdictRefused, keys, wo},
		actionCase{"bpflsm: out of the nested deny_read, refused on the walk", link("/w/out/keys/k", "/w/out/k"), l3, agent.VerdictRefused, keys, wo},
		actionCase{"bpflsm: into the nested deny_read", link("/w/out/a", "/w/out/keys/a"), l3, agent.VerdictRefused, keys, wo},
		actionCase{"observe enforces nothing", link("/w/notes", "/w/l"), obs, agent.VerdictAllow, agent.UnmatchedRule, ""},
	)
	checkActions(t, rt, cases)
}

// TestEvaluateLinkAsLandlockDecidesIt holds tiers 1 and 2 to Landlock's hook_path_link (security/landlock/fs.c,
// current_check_refer_path), which the run inherits for every modification: MAKE_REG on the new name's directory and,
// when the two directories differ, REFER on both directories, never on the file itself, and then no file right at the
// new name's directory that the file did not have where it was (an exec.allow directory's EXECUTE included). A
// file-level write entry grants no directory right (the builder masks it to file rights), so a cross-directory link
// of it is refused with EXDEV, and the run's line must say so (security F1, F3 and F4). A rename into
// an exec.allow directory is refused by the same no-gain rule.
func TestEvaluateLinkAsLandlockDecidesIt(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{Allow: []string{"/w/out/bin/"}})
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: "/w/a.txt", Raw: "./a.txt", Resolved: "/w/a.txt", Access: agent.AccessWriteSet, Regular: true})
	rt.Exec = []agent.ExecRule{{Raw: "./out/bin/", Path: "/w/out/bin", Resolved: "/w/out/bin", IsDir: true, Verdict: agent.VerdictAllow}}
	link := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSLink, Path: src, DestPath: dst}
	}
	rename := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSRename, Path: src, DestPath: dst}
	}
	wo, ro := record.ReasonWriteOutsideContract, record.ReasonRenameOutsideContract
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2} {
		cases = append(cases,
			actionCase{"a file-level write entry linked into a write directory", link("/w/a.txt", "/w/out/a2"), tier, agent.VerdictRefused, agent.UnmatchedRule, wo},
			actionCase{"a file-level write entry linked beside itself", link("/w/a.txt", "/w/b.txt"), tier, agent.VerdictRefused, agent.UnmatchedRule, wo},
			actionCase{"a link into an exec.allow directory gains EXECUTE", link("/w/out/a", "/w/out/bin/a2"), tier, agent.VerdictRefused, writeOut, wo},
			actionCase{"a link out of it loses EXECUTE", link("/w/out/bin/t", "/w/out/t2"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"a link within it", link("/w/out/bin/t", "/w/out/bin/t2"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"a rename into it gains EXECUTE", rename("/w/out/a", "/w/out/bin/a2"), tier, agent.VerdictRefused, writeOut, ro},
			actionCase{"a rename out of it", rename("/w/out/bin/t", "/w/out/t2"), tier, agent.VerdictAllow, writeOut, ""},
		)
	}
	checkActions(t, rt, cases)

	// With images unrestricted every write entry carries EXECUTE (the builder's writeMask), so nothing is gained.
	open := actionsTable(nil)
	open.Exec = rt.Exec
	var unrestricted []actionCase
	for _, tier := range []backend.Tier{l1, l2} {
		unrestricted = append(unrestricted,
			actionCase{"unrestricted images: a link into the exec directory", link("/w/out/a", "/w/out/bin/a2"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"unrestricted images: a rename into it", rename("/w/out/a", "/w/out/bin/a2"), tier, agent.VerdictAllow, writeOut, ""})
	}
	checkActions(t, open, unrestricted)

	// The scan and the supervisor's index answer the no-gain rule alike.
	ix := NewFSIndex(rt)
	for _, c := range [][2]string{{"/w/out/a", "/w/out/bin/a2"}, {"/w/out/bin/t", "/w/out/t2"}, {"/w/a.txt", "/w/out/a2"}, {"/w/out/a", "/w/out/b"}} {
		if got, want := ix.LinkGains(c[0], c[1]), LinkGains(rt, c[0], c[1]); got != want {
			t.Errorf("LinkGains(%q, %q): index %v, scan %v", c[0], c[1], got, want)
		}
		if got, want := ix.RenameGains(c[0], c[1], false), RenameGains(rt, c[0], c[1], false); got != want {
			t.Errorf("RenameGains(%q, %q): index %v, scan %v", c[0], c[1], got, want)
		}
	}
	if !LinkGains(rt, "/w/out/a", "/w/out/bin/a2") || LinkGains(rt, "/w/out/bin/t", "/w/out/t2") {
		t.Error("LinkGains does not see the exec directory's EXECUTE")
	}
}

// TestEvaluateRenameAsLandlockDecidesIt holds a rename to Landlock's hook_path_rename (current_check_refer_path,
// no_more_access), which every enforcing tier keeps: a rename within one directory reparents nothing, so REFER's
// no-gain rule is not asked; across directories the rights at the new name's directory are compared with the moved
// object's own (its parent chain and its own rule), never with a rule on the name it replaces; and only the file
// rights count for an object that is not a directory. An atomic replace of an exec.allow file entry inside a write
// entry (mv out/tool.new out/tool) was recorded refused while the kernel allowed it, and a regular
// file moved where only a directory right is gained was refused where the kernel allows it (F2).
func TestEvaluateRenameAsLandlockDecidesIt(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{Allow: []string{"/w/out/tool", "/w/out/bin/"}})
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: "/w/narrow", Raw: "./narrow/", Resolved: "/w/narrow",
		Access: agent.AccessWriteSet &^ agent.AccessMakeChar})
	rt.Exec = []agent.ExecRule{
		{Raw: "./out/tool", Path: "/w/out/tool", Resolved: "/w/out/tool", Verdict: agent.VerdictAllow},
		{Raw: "./out/bin/", Path: "/w/out/bin", Resolved: "/w/out/bin", IsDir: true, Verdict: agent.VerdictAllow},
	}
	rename := func(src, dst string, dir bool) agent.Action {
		return agent.Action{Kind: agent.ActionFSRename, Path: src, DestPath: dst, Dir: dir}
	}
	ro := record.ReasonRenameOutsideContract
	allow := func(name string, a agent.Action) []actionCase {
		var cs []actionCase
		for _, tier := range []backend.Tier{l1, l2, l3} {
			cs = append(cs, actionCase{name, a, tier, agent.VerdictAllow, writeOut, ""})
		}
		return cs
	}
	var cases []actionCase
	cases = append(cases, allow("an atomic replace of the exec.allow file entry", rename("/w/out/tool.new", "/w/out/tool", false))...)
	cases = append(cases, allow("a move onto it from another directory", rename("/w/out/sub/x", "/w/out/tool", false))...)
	cases = append(cases, allow("the exec.allow file moved to another directory", rename("/w/out/tool", "/w/out/sub/tool", false))...)
	cases = append(cases, allow("a rename inside the exec.allow directory", rename("/w/out/bin/a", "/w/out/bin/b", false))...)
	cases = append(cases, allow("a directory replacing the exec.allow directory", rename("/w/out/newbin", "/w/out/bin", true))...)
	for _, tier := range []backend.Tier{l1, l2, l3} {
		cases = append(cases,
			actionCase{"a directory moved into the exec.allow directory gains EXECUTE", rename("/w/out/d", "/w/out/bin/d", true), tier, agent.VerdictRefused, writeOut, ro},
			actionCase{"a file moved into it gains EXECUTE", rename("/w/out/a", "/w/out/bin/a", false), tier, agent.VerdictRefused, writeOut, ro})
	}
	narrow := "fs.write[./narrow/]"
	for _, tier := range []backend.Tier{l1, l2} {
		cases = append(cases,
			actionCase{"a file gaining a directory right only", rename("/w/narrow/a", "/w/out/a", false), tier, agent.VerdictAllow, narrow, ""},
			actionCase{"a directory gaining it", rename("/w/narrow/d", "/w/out/d", true), tier, agent.VerdictRefused, narrow, ro})
	}
	checkActions(t, rt, cases)

	// The bpflsm column composes the same floor after the plane's own answer.
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	for _, c := range cases {
		if c.tier != l3 {
			continue
		}
		if got := pe.Evaluate(c.a, Env{}); got.Verdict != c.verdict || got.Rule != c.rule || got.Reason != c.reason {
			t.Errorf("plane: %s: %+v, want %s via %s (%s)", c.name, got, c.verdict, c.rule, c.reason)
		}
	}

	// The scan and the supervisor's index answer the no-gain rule alike. RenameGains(a, b) asks of the object at a
	// landing in b's directory, so RENAME_EXCHANGE asks it both ways (the supervisor's decideMoveDest).
	ix := NewFSIndex(rt)
	for _, c := range []struct {
		src, dst string
		dir      bool
		gains    bool
	}{
		{"/w/out/tool.new", "/w/out/tool", false, false},
		{"/w/out/sub/x", "/w/out/tool", false, false},
		{"/w/out/tool", "/w/out/sub/x", false, false}, // exchanging the two: the exec file lands in out/sub
		{"/w/out/a", "/w/out/bin/a", false, true},
		{"/w/out/bin/t", "/w/out/a", false, false}, // exchanging out/bin/t with out/a: t lands in out ...
		{"/w/out/a", "/w/out/bin/t", false, true},  // ... and out/a lands in out/bin, where it gains EXECUTE
		{"/w/out/newbin", "/w/out/bin", true, false},
		{"/w/narrow/a", "/w/out/a", false, false},
		{"/w/narrow/d", "/w/out/d", true, true},
	} {
		got, scan := ix.RenameGains(c.src, c.dst, c.dir), RenameGains(rt, c.src, c.dst, c.dir)
		if got != scan || got != c.gains {
			t.Errorf("RenameGains(%q, %q, dir=%v): index %v, scan %v, want %v", c.src, c.dst, c.dir, got, scan, c.gains)
		}
	}
}

// TestEvaluateAttr: an attribute change is allowed at every tier (no Landlock ABI has a chmod, chown or xattr
// right), named as the supervisor's recordAttr names it: the write entry that covers it, else the nearest entry,
// else unmatched. Where a decision plane decides (the bpflsm column), path_chmod and the attribute hooks refuse it
// at or beneath a deny_write target (enforce-plane R12); at tiers 1 and 2 nothing refuses that one (CAPABILITIES).
func TestEvaluateAttr(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{})
	attr := func(p string) agent.Action { return agent.Action{Kind: agent.ActionFSAttr, Path: p} }
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3, obs} {
		cases = append(cases,
			actionCase{"chmod in the write entry", attr("/w/out/a"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"chmod outside every entry", attr("/etc/hosts"), tier, agent.VerdictAllow, agent.UnmatchedRule, ""},
			actionCase{"chmod of a watched file", attr("/w/config/app.toml"), tier, agent.VerdictAllow, "fs.watch[./config/]", ""},
			actionCase{"chmod under the nested deny_read", attr("/w/out/keys/k"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"no path", attr(""), tier, agent.VerdictRefused, agent.InvalidActionRule, ""},
		)
	}
	cases = append(cases,
		actionCase{"landlock: the deny_write target", attr("/w/out/.git/config"), l1, agent.VerdictAllow, writeOut, ""},
		actionCase{"cgroup's listener: the deny_write target", attr("/w/out/.git/config"), l2, agent.VerdictAllow, writeOut, ""},
		actionCase{"bpflsm: the deny_write target", attr("/w/out/.git/config"), l3, agent.VerdictRefused, gitCfg, record.ReasonWriteOutsideContract},
	)
	checkActions(t, rt, cases)
}

// TestEvaluateSocket is ADR 0018 (1)'s allowlist, answered from RuleTable.NetSocketPolicy, the predicate the filter's
// socket arm and the plane's slot header read: under a net: section AF_UNIX and NETLINK_ROUTE of any type, TCP and UDP
// on AF_INET and AF_INET6, ping sockets only with a port-0 entry; socketpair AF_UNIX only. Without a net: section
// nothing is refused. IPPROTO_MPTCP is refused by every filter (E30). A refusal is rule unmatched, net-not-allowed.
func TestEvaluateSocket(t *testing.T) {
	sock := func(f, ty, p int32, pair bool) agent.Action {
		return agent.Action{Kind: agent.ActionNetSocket, Socket: agent.SocketTriple{Family: f, Type: ty, Protocol: p, Pair: pair}}
	}
	nn := record.ReasonNetNotAllowed
	um := agent.UnmatchedRule
	restricted := actionsTable(&agent.ExecSection{})
	noICMP := actionsTable(&agent.ExecSection{})
	noICMP.Net = noICMP.Net[:2]
	open := actionsTable(&agent.ExecSection{})
	open.Contract.Net = nil
	var r, n, o []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		r = append(r,
			actionCase{"tcp", sock(2, 1, 0, false), tier, agent.VerdictAllow, um, ""},
			actionCase{"tcp6 nonblocking", sock(10, 1|0o4000, 6, false), tier, agent.VerdictAllow, um, ""},
			actionCase{"udp", sock(2, 2, 17, false), tier, agent.VerdictAllow, um, ""},
			actionCase{"sctp", sock(2, 1, 132, false), tier, agent.VerdictRefused, um, nn},
			actionCase{"raw", sock(2, 3, 1, false), tier, agent.VerdictRefused, um, nn},
			actionCase{"ping with an ICMP entry", sock(2, 2, 1, false), tier, agent.VerdictAllow, um, ""},
			actionCase{"packet", sock(17, 3, 0, false), tier, agent.VerdictRefused, um, nn},
			actionCase{"vsock", sock(40, 1, 0, false), tier, agent.VerdictRefused, um, nn},
			actionCase{"unix seqpacket", sock(1, 5, 0, false), tier, agent.VerdictAllow, um, ""},
			actionCase{"netlink route", sock(16, 3, 0, false), tier, agent.VerdictAllow, um, ""},
			actionCase{"netlink generic", sock(16, 3, 16, false), tier, agent.VerdictRefused, um, nn},
			actionCase{"netlink sock_diag", sock(16, 2, 4, false), tier, agent.VerdictRefused, um, nn},
			actionCase{"mptcp", sock(2, 1, 262, false), tier, agent.VerdictRefused, um, nn},
			actionCase{"socketpair unix", sock(1, 1, 0, true), tier, agent.VerdictAllow, um, ""},
			actionCase{"socketpair tipc", sock(30, 5, 0, true), tier, agent.VerdictRefused, um, nn},
			actionCase{"socketpair inet", sock(2, 1, 0, true), tier, agent.VerdictRefused, um, nn},
		)
		n = append(n, actionCase{"ping without an ICMP entry", sock(10, 2, 58, false), tier, agent.VerdictRefused, um, nn})
		o = append(o,
			actionCase{"no net: section, sctp", sock(2, 1, 132, false), tier, agent.VerdictAllow, um, ""},
			actionCase{"no net: section, socketpair tipc", sock(30, 5, 0, true), tier, agent.VerdictAllow, um, ""},
			actionCase{"no net: section, mptcp", sock(2, 1, 262, false), tier, agent.VerdictRefused, um, nn},
		)
	}
	r = append(r,
		actionCase{"observe: sctp", sock(2, 1, 132, false), obs, agent.VerdictAllow, um, ""},
		actionCase{"observe: mptcp, refused by every filter", sock(2, 1, 262, false), obs, agent.VerdictRefused, um, nn},
		actionCase{"a negative family", sock(-1, 1, 0, false), l1, agent.VerdictRefused, agent.InvalidActionRule, ""},
	)
	checkActions(t, restricted, r)
	checkActions(t, noICMP, n)
	checkActions(t, open, o)
}

// TestEvaluateSend: an unconnected datagram send is answered as the connect to its destination over UDP, or to its
// unix socket (supervisor R13b: sendDecisionCtl decides it with the connect's own decision); the resolver
// exception applies to a UDP send to a resolver on port 53 (EvaluateIn, R14).
func TestEvaluateSend(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{})
	send := func(host string, port int) agent.Action {
		return agent.Action{Kind: agent.ActionNetSend, Host: host, Port: port, Proto: agent.ProtoUDP}
	}
	nn := record.ReasonNetNotAllowed
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		cases = append(cases,
			actionCase{"a declared UDP destination", send("127.0.0.1", 8125), tier, agent.VerdictAllow, rt.Net[1].RuleName(), ""},
			actionCase{"an undeclared one", send("127.0.0.1", 8126), tier, agent.VerdictRefused, agent.UnmatchedRule, nn},
			actionCase{"a declared unix socket", agent.Action{Kind: agent.ActionNetSend, Path: "unix:/run/a.sock"}, tier, agent.VerdictAllow, rt.Net[0].RuleName(), ""},
			actionCase{"an undeclared abstract name", agent.Action{Kind: agent.ActionNetSend, Path: "unix:@log"}, tier, agent.VerdictRefused, agent.UnmatchedRule, nn},
			actionCase{"no destination", agent.Action{Kind: agent.ActionNetSend}, tier, agent.VerdictRefused, agent.InvalidActionRule, ""},
		)
		got := EvaluateIn(rt, send("192.0.2.53", 53), tier, Env{Resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}})
		if got.Verdict != agent.VerdictAllow || got.Rule != agent.ResolverRule {
			t.Errorf("%s: a send to the resolver = %+v, want allow via %s", tier, got, agent.ResolverRule)
		}
		if got := NewEvaluator(rt).EvaluateIn(send("192.0.2.53", 53), tier, Env{Resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}}); got.Rule != agent.ResolverRule {
			t.Errorf("%s: the indexed model's send to the resolver = %+v", tier, got)
		}
	}
	checkActions(t, rt, cases)
}

// TestEvaluateExecAnonymous: the exec of an anonymous image (a memfd) is refused, rule exec-anon, reason
// exec-not-allowed, at every enforcing tier when the run restricts images (the supervisor's decideExec at tiers 1 to
// 3, the plane's bprm_check without TEGO_SLOT_EXEC_ANON); allowed, unmatched, under exec.anonymous: true, with no
// exec: section, or with a deny-list exec: section. An observe run allows it and still names exec-anon.
func TestEvaluateExecAnonymous(t *testing.T) {
	anon := agent.Action{Kind: agent.ActionExecAnon}
	en := record.ReasonExecNotAllowed
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		cases = append(cases, actionCase{"restricted images", anon, tier, agent.VerdictRefused, agent.ExecAnonRule, en})
	}
	cases = append(cases, actionCase{"observe", anon, obs, agent.VerdictAllow, agent.ExecAnonRule, ""})
	checkActions(t, actionsTable(&agent.ExecSection{Allow: []string{"sh"}}), cases)

	for name, exec := range map[string]*agent.ExecSection{
		"exec.anonymous: true": {Allow: []string{"sh"}, Anonymous: true},
		"no exec: section":     nil,
		"a deny-list section":  {Deny: []string{"curl"}},
	} {
		var open []actionCase
		for _, tier := range []backend.Tier{l1, l2, l3, obs} {
			open = append(open, actionCase{name, anon, tier, agent.VerdictAllow, agent.UnmatchedRule, ""})
		}
		checkActions(t, actionsTable(exec), open)
	}
	// A table with no contract fails closed, as the Landlock builder and the plane's slot header do.
	bare := actionsTable(nil)
	bare.Contract = nil
	checkActions(t, bare, []actionCase{{"no contract", anon, l1, agent.VerdictRefused, agent.ExecAnonRule, en}})
}

// TestEvaluateEndsAtASymlinkEntrysOwnName: rename(2), linkat(2) without AT_SYMLINK_FOLLOW and unlink(2) act on a
// name itself and never follow it, so an end that is a symlinked fs entry's declared name is the symlink, in its own
// directory, not the entry's target (Landlock's rule for the entry is on the target's inode). The ends were
// canonicalized to the target: an atomic swap of a symlink write entry (mv out/cur.new out/cur, ln -sfn's pattern)
// was refused while the kernel allowed it, a link and a move of that symlink into an exec.allow directory read allow
// while the kernel refused them with EXDEV, and renames onto and of a symlink entry outside every write directory read
// allow while the kernel refused them with EACCES (F1 and F2).
func TestEvaluateEndsAtASymlinkEntrysOwnName(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{Allow: []string{"/w/out/bin/"}})
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: "/w/out/cur", Raw: "./out/cur", Resolved: "/w/out/bin/v1", Access: agent.AccessWriteSet})
	rt.Exec = []agent.ExecRule{{Raw: "./out/bin/", Path: "/w/out/bin", Resolved: "/w/out/bin", IsDir: true, Verdict: agent.VerdictAllow}}
	link := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSLink, Path: src, DestPath: dst}
	}
	rename := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSRename, Path: src, DestPath: dst}
	}
	del := func(p string) agent.Action { return agent.Action{Kind: agent.ActionFSDelete, Path: p} }
	wo, ro, do := record.ReasonWriteOutsideContract, record.ReasonRenameOutsideContract, record.ReasonDeleteOutsideContract
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		cases = append(cases,
			actionCase{"A: the atomic swap of the symlink entry", rename("/w/out/cur.new", "/w/out/cur"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"B: a move onto it from another directory", rename("/w/out/sub/t", "/w/out/cur"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"C: a link of the symlink into the exec directory", link("/w/out/cur", "/w/out/bin/x2"), tier, agent.VerdictRefused, writeOut, wo},
			actionCase{"D: a move of the symlink into the exec directory", rename("/w/out/cur", "/w/out/bin/cur2"), tier, agent.VerdictRefused, writeOut, ro},
			actionCase{"the symlink deleted", del("/w/out/cur"), tier, agent.VerdictAllow, writeOut, ""},
		)
	}
	checkActions(t, rt, cases)
	checkPlane(t, rt, cases)
	ix := NewFSIndex(rt)
	for _, c := range []struct {
		src, dst string
		link     bool
		gains    bool
	}{
		{"/w/out/cur.new", "/w/out/cur", false, false},
		{"/w/out/sub/t", "/w/out/cur", false, false},
		{"/w/out/cur", "/w/out/bin/x2", true, true},
		{"/w/out/cur", "/w/out/bin/cur2", false, true},
	} {
		got, scan := ix.RenameGains(c.src, c.dst, false), RenameGains(rt, c.src, c.dst, false)
		if c.link {
			got, scan = ix.LinkGains(c.src, c.dst), LinkGains(rt, c.src, c.dst)
		}
		if got != scan || got != c.gains {
			t.Errorf("gains(%q, %q, link=%v): index %v, scan %v, want %v", c.src, c.dst, c.link, got, scan, c.gains)
		}
	}

	// A symlink write entry outside every write directory, pointing into one (fs.write [./w/, ./cur], cur -> w/v1):
	// the symlink's directory grants nothing, so Landlock refuses every change of the name (EACCES).
	out := actionsTable(&agent.ExecSection{})
	out.FS = []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/w/w", Raw: "./w/", Resolved: "/w/w", Access: agent.AccessWriteSet},
		{Kind: agent.FSWrite, Path: "/w/cur", Raw: "./cur", Resolved: "/w/w/v1", Access: agent.AccessWriteSet},
	}
	um := agent.UnmatchedRule
	var outside []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		outside = append(outside,
			actionCase{"E: a move onto the symlink entry", rename("/w/w/x", "/w/cur"), tier, agent.VerdictRefused, um, ro},
			actionCase{"F: a move of the symlink entry into the write directory", rename("/w/cur", "/w/w/cur2"), tier, agent.VerdictRefused, um, ro},
			actionCase{"a link of the symlink entry", link("/w/cur", "/w/w/l"), tier, agent.VerdictRefused, um, wo},
			actionCase{"the symlink entry deleted", del("/w/cur"), tier, agent.VerdictRefused, um, do},
		)
	}
	checkActions(t, out, outside)
	checkPlane(t, out, outside)
}

// TestEvaluateTakesAnExecDirectoryLinkAsItLands: an exec.allow directory declared through a symlink (exec.allow
// ./out/bl/, out/bl -> realbin inside out/) holds its grant on the target's inode. rename(2) and linkat(2) follow every
// component of a name but the last, so a move or a link into out/bl lands in realbin and gains EXECUTE (EXDEV):
// compile --test hands such a row over landed, at realbin (supervisor.Land), and the run's walk lands it there too. A
// path at the declared spelling is a landed one as well: the name then holds a real directory, which the agent made
// after removing the link, and no grant, nor does anything beneath it (landedEnd, landlockExecGrant). The decision
// core rewrote that spelling to the target, so the run recorded refused for a move and a link the
// kernel allowed (S4-1 and R4-C1), and beneath it the spelling itself granted EXECUTE. The
// symlink itself is still an end: moving it gains nothing, and a link of an exec file entry's symlink into an exec
// directory gains the EXECUTE the symlink never held.
func TestEvaluateTakesAnExecDirectoryLinkAsItLands(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{Allow: []string{"./out/bl/", "./out/tool"}})
	rt.Exec = []agent.ExecRule{
		{Raw: "./out/bl/", Path: "/w/out/bl", Resolved: "/w/out/realbin", IsDir: true, Verdict: agent.VerdictAllow},
		{Raw: "./out/tool", Path: "/w/out/tool", Resolved: "/usr/bin/true", Verdict: agent.VerdictAllow},
	}
	link := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSLink, Path: src, DestPath: dst}
	}
	rename := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSRename, Path: src, DestPath: dst}
	}
	wo, ro := record.ReasonWriteOutsideContract, record.ReasonRenameOutsideContract
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		cases = append(cases,
			actionCase{"a rename into the exec directory, landed at the target", rename("/w/out/x", "/w/out/realbin/x"), tier, agent.VerdictRefused, writeOut, ro},
			actionCase{"a link into it", link("/w/out/y", "/w/out/realbin/y"), tier, agent.VerdictRefused, writeOut, wo},
			actionCase{"a rename into the directory at the declared name", rename("/w/out/z", "/w/out/bl/z"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"a link into it", link("/w/out/v", "/w/out/bl/v"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"a rename into a directory beneath the declared name", rename("/w/out/s", "/w/out/bl/sub/s"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"the symlink itself moved", rename("/w/out/bl", "/w/out/sub/bl"), tier, agent.VerdictAllow, writeOut, ""},
			actionCase{"a link of the exec file entry's symlink into the exec directory", link("/w/out/tool", "/w/out/realbin/tool2"), tier, agent.VerdictRefused, writeOut, wo},
		)
	}
	checkActions(t, rt, cases)
	checkPlane(t, rt, cases)
	ix := NewFSIndex(rt)
	for _, c := range []struct {
		src, dst string
		link     bool
		gains    bool
	}{
		{"/w/out/x", "/w/out/realbin/x", false, true},
		{"/w/out/y", "/w/out/realbin/y", true, true},
		{"/w/out/z", "/w/out/bl/z", false, false},
		{"/w/out/v", "/w/out/bl/v", true, false},
		{"/w/out/s", "/w/out/bl/sub/s", false, false},
		{"/w/out/u", "/w/out/bl/sub/u", true, false},
		{"/w/out/bl", "/w/out/sub/bl", false, false},
		{"/w/out/tool", "/w/out/realbin/tool2", true, true},
	} {
		got, scan := ix.RenameGains(c.src, c.dst, false), RenameGains(rt, c.src, c.dst, false)
		if c.link {
			got, scan = ix.LinkGains(c.src, c.dst), LinkGains(rt, c.src, c.dst)
		}
		if got != scan || got != c.gains {
			t.Errorf("gains(%q, %q, link=%v): index %v, scan %v, want %v", c.src, c.dst, c.link, got, scan, c.gains)
		}
	}
}

// TestBPFLSMKeepsTheLandlockFloorsDirectoryRights: tier 3 keeps the Landlock ruleset under the plane, which asks a
// rename's and an unlink's directory rights (REMOVE_* and REFER on the source's directory, MAKE_* and REFER on the
// new name's) and grants a file-level write entry none of them. The plane's hooks decide on the object and allowed a
// file-level entry's own rename or unlink, so the bpflsm column read allow while the kernel refused it with EACCES.
// The column and Evaluate at bpflsm now compose the floor's directory checks as they compose
// hook_path_link's for a link.
func TestBPFLSMKeepsTheLandlockFloorsDirectoryRights(t *testing.T) {
	rt := actionsTable(&agent.ExecSection{})
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: "/w/a.txt", Raw: "./a.txt", Resolved: "/w/a.txt", Access: agent.AccessWriteSet, Regular: true})
	rename := func(src, dst string) agent.Action {
		return agent.Action{Kind: agent.ActionFSRename, Path: src, DestPath: dst}
	}
	um := agent.UnmatchedRule
	ro, do := record.ReasonRenameOutsideContract, record.ReasonDeleteOutsideContract
	var cases []actionCase
	for _, tier := range []backend.Tier{l1, l2, l3} {
		cases = append(cases,
			actionCase{"a file-level write entry moved into a write directory", rename("/w/a.txt", "/w/out/a2.txt"), tier, agent.VerdictRefused, um, ro},
			actionCase{"a file moved onto the file-level entry", rename("/w/out/x", "/w/a.txt"), tier, agent.VerdictRefused, um, ro},
			actionCase{"the file-level entry deleted", agent.Action{Kind: agent.ActionFSDelete, Path: "/w/a.txt"}, tier, agent.VerdictRefused, um, do},
			actionCase{"a rename within the write directory", rename("/w/out/x", "/w/out/y"), tier, agent.VerdictAllow, writeOut, ""},
		)
	}
	checkActions(t, rt, cases)
	checkPlane(t, rt, cases)
}

// checkPlane asks the bpflsm column (PlaneEvaluator) every tier-3 case.
func checkPlane(t *testing.T, rt *agent.RuleTable, cases []actionCase) {
	t.Helper()
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	for _, c := range cases {
		if c.tier != l3 {
			continue
		}
		if got := pe.Evaluate(c.a, Env{}); got.Verdict != c.verdict || got.Rule != c.rule || got.Reason != c.reason {
			t.Errorf("plane: %s: %+v, want %s via %s (%s)", c.name, got, c.verdict, c.rule, c.reason)
		}
	}
}
