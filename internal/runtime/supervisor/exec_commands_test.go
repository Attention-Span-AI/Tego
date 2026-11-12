// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"path"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// commandPolicy is a policy whose contract holds the given exec entries ("deny: git push", "allow: git status"),
// compiled into RuleTable.ExecCommands, with exec rules granting /usr/bin/git, /usr/bin/rm and /usr/bin/python3
// for an allow-list section.
func commandPolicy(t testing.TB, entries ...string) *Policy {
	t.Helper()
	sec := &agent.ExecSection{}
	var ps []*execmatch.Pattern
	for _, e := range entries {
		list, body, _ := strings.Cut(e, ": ")
		l := map[string]execmatch.List{"allow": execmatch.ListAllow, "deny": execmatch.ListDeny, "ask": execmatch.ListAsk}[list]
		switch l {
		case execmatch.ListAllow:
			sec.Allow = append(sec.Allow, body)
		case execmatch.ListDeny:
			sec.Deny = append(sec.Deny, body)
		case execmatch.ListAsk:
			sec.Ask = append(sec.Ask, body)
		}
		p, err := execmatch.Parse(body, l, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	pol := contractPolicy(&agent.Contract{Exec: sec}, nil, nil)
	if sec.Allow != nil {
		for _, p := range []string{"/usr/bin/git", "/usr/bin/rm", "/usr/bin/python3"} {
			pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: path.Base(p), Path: p, Basename: path.Base(p), ByName: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
		}
	}
	ec := &agent.ExecCommands{Index: execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})}
	for _, p := range ps {
		ec.Entries = append(ec.Entries, agent.ExecCommandEntry{Pattern: p})
	}
	pol.Rules.ExecCommands = ec
	return pol
}

// execPayloadOf decodes an exec line's payload.
func execPayloadOf(t *testing.T, ev *record.Event) execPayload {
	t.Helper()
	var p execPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestExecCommandDeny: under a deny-list section the supervisor refuses, before the syscall runs, every exec a deny
// entry matches wherever the tool's options put the subcommand (ADR 0048 (3)): EACCES, a refused line naming the
// entry, its list, how it matched, the interpretation, and copied_syscall. Every other exec continues.
func TestExecCommandDeny(t *testing.T) {
	nr := nrFor(t, "execve")
	for _, tc := range []struct {
		path string
		argv []string
		rule string
		via  string
	}{
		{"/usr/bin/git", []string{"git", "-C", ".", "push"}, "exec.deny[git push]", "name"},
		{"/usr/lib/git-core/git-push", []string{"git-push", "origin"}, "exec.deny[git push]", "dashed"},
		{"/usr/bin/rm", []string{"rm", "x", "--rec", "--forc"}, "exec.deny[rm -r]", "name"},
		{"/usr/bin/busybox", []string{"busybox", "rm", "-fr", "x"}, "exec.deny[rm -r]", "multicall"},
	} {
		f := newFake()
		l, sink := newTestLoop(t, f, commandPolicy(t, "deny: git push", "deny: rm -r"))
		execAt(l, f, nr, 42, 0, tc.path, tc.argv...)
		wantExecAnswer(t, f, record.VerdictRefused)
		ev := sink.one(t)
		if ev.Verdict != record.VerdictRefused || ev.Rule != tc.rule || ev.Reason != record.ReasonExecNotAllowed {
			t.Errorf("%v: %s %s %s", tc.argv, ev.Verdict, ev.Rule, ev.Reason)
		}
		p := execPayloadOf(t, ev)
		if p.CommandList != "deny" || p.CommandMatch != "definite" || p.CommandVia != tc.via || p.ArgvFacts != record.ArgvFactsCopied || p.ArgvRead != len(tc.argv) {
			t.Errorf("%v: payload %+v", tc.argv, p.ExecPayload)
		}
	}
	f := newFake()
	l, sink := newTestLoop(t, f, commandPolicy(t, "deny: git push"))
	execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "stash", "push")
	wantExecAnswer(t, f, record.VerdictAllow)
	if p := execPayloadOf(t, sink.one(t)); p.CommandRule != "" {
		t.Errorf("git stash push carries a command rule: %+v", p.ExecPayload)
	}
	if m := l.Metrics(); m.ExecRules == nil {
		t.Error("no exec_rules counters on a run with command rules")
	}
}

// TestExecCommandMulticallLinks: the link count the walk's fstat read reaches the matcher (execmatch.Facts.Links), so a
// symlink named xrm to a file of 116 links (Ubuntu 26.04's uutils ls) is refused under deny: [rm -r] as the rm
// upstream uutils would run, via multicall, while the same name to a file of one link runs as before.
func TestExecCommandMulticallLinks(t *testing.T) {
	nr := nrFor(t, "execve")
	const uu = "/usr/lib/cargo/bin/coreutils/ls"
	for _, tc := range []struct {
		links uint64
		want  record.Verdict
	}{{116, record.VerdictRefused}, {1, record.VerdictAllow}} {
		f := newFake()
		f.images["/w/xrm"] = execImage{id: fakeID(uu), linked: true, nlink: tc.links, link: uu, here: true}
		l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
		execAt(l, f, nr, 42, 0, "/w/xrm", "xrm", "-r", "x")
		wantExecAnswer(t, f, tc.want)
		ev := sink.one(t)
		if ev.Verdict != tc.want {
			t.Errorf("%d links: %s %s, want %s", tc.links, ev.Verdict, ev.Rule, tc.want)
			continue
		}
		if tc.want == record.VerdictRefused {
			if p := execPayloadOf(t, ev); ev.Rule != "exec.deny[rm -r]" || p.CommandVia != "multicall" || p.ArgvRead != 3 {
				t.Errorf("%d links: rule %s, payload %+v", tc.links, ev.Rule, p.ExecPayload)
			}
		}
	}
}

// TestExecCommandMulticallArgv1PastTheFirstStage: a symlink named xbox to a file of 116 links runs the applet argv[1]
// names (upstream uutils), and an argv[0] long enough that the first staged read (32 entries, 8 KiB) holds no argv[1]
// does not settle the decision there: the read goes on and argv[1] is met (found in review on 2026-11-11: 8191 bytes or more of
// argv[0] was allowed unmatched).
func TestExecCommandMulticallArgv1PastTheFirstStage(t *testing.T) {
	nr := nrFor(t, "execve")
	const uu = "/usr/lib/cargo/bin/coreutils/ls"
	for _, a0 := range []string{"xbox", strings.Repeat("A", 8100), strings.Repeat("A", 8191), strings.Repeat("A", 9000)} {
		f := newFake()
		f.images["/w/xbox"] = execImage{id: fakeID(uu), linked: true, nlink: 116, link: uu, here: true}
		l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
		execAt(l, f, nr, 42, 0, "/w/xbox", a0, "rm", "-r", "x")
		wantExecAnswer(t, f, record.VerdictRefused)
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != "exec.deny[rm -r]" {
			t.Errorf("argv[0] of %d bytes: %s %s, want refused exec.deny[rm -r]", len(a0), ev.Verdict, ev.Rule)
		}
	}
}

// TestExecCommandPrefixNotFinalPastTheFirstStage: a first stage (32 elements) that ends where later argv can still
// change the decision is not final, so the supervisor reads the rest and refuses. python's -m cut at element 32 has
// not read its module, under an entry with words and under a bare entry on the module alike; cargo's --config after
// the subcommand can still name an alias (`alias.pub=publish` makes `cargo pub` run publish). Before the fix, each
// first stage settled on none and the exec was continued. (An allow entry's case is
// TestExecCommandAllowEntryPrefixNotFinalPastTheFirstStage.)
func TestExecCommandPrefixNotFinalPastTheFirstStage(t *testing.T) {
	nr := nrFor(t, "execve")
	python := []string{"python3"}
	for range 15 {
		python = append(python, "-W", "ignore")
	}
	python = append(python, "-m", "pip", "install", "x")
	cargo := []string{"cargo", "pub"}
	for range 15 {
		cargo = append(cargo, "--features", "f")
	}
	cargo = append(cargo, "--config", "alias.pub=publish")
	for _, c := range []struct {
		entry, path, rule string
		argv              []string
	}{
		{"deny: pip install", "/usr/bin/python3", "exec.deny[pip install]", python},
		{"deny: pip", "/usr/bin/python3", "exec.deny[pip]", python},
		{"deny: cargo publish", "/usr/bin/cargo", "exec.deny[cargo publish]", cargo},
	} {
		t.Run(c.entry, func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoop(t, f, commandPolicy(t, c.entry))
			execAt(l, f, nr, 42, 0, c.path, c.argv...)
			wantExecAnswer(t, f, record.VerdictRefused)
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != c.rule {
				t.Errorf("%s: %s %s, want refused %s", c.argv[0], ev.Verdict, ev.Rule, c.rule)
			}
		})
	}
}

// TestExecCommandAllowEntryPrefixNotFinalPastTheFirstStage: the same first stages under an exec.allow entry with
// words, whose tool's image the contract grants (an allow entry with words grants its tool and constrains it, ADR
// 0048). The whole vector is unlisted (exec.args), and the first stage, which reads only an admitted invocation, is
// not final: cargo build's later --config can name an alias, python's -m cut at element 32 has not read its module.
// Before the fix the cargo stage was allowed under the entry and the python stage settled on none, and both execs
// were continued.
func TestExecCommandAllowEntryPrefixNotFinalPastTheFirstStage(t *testing.T) {
	nr := nrFor(t, "execve")
	python := []string{"python3"}
	for range 15 {
		python = append(python, "-W", "ignore")
	}
	python = append(python, "-m", "pip", "install", "x")
	cargo := []string{"cargo", "build"}
	for range 15 {
		cargo = append(cargo, "--features", "f")
	}
	cargo = append(cargo, "--config", "alias.build=publish")
	for _, c := range []struct {
		entry, path, rule string
		argv              []string
	}{
		{"allow: pip list", "/usr/bin/python3", "exec.args[pip]", python},
		{"allow: cargo build", "/usr/bin/cargo", "exec.args[cargo]", cargo},
	} {
		t.Run(c.entry, func(t *testing.T) {
			pol := commandPolicy(t, c.entry)
			pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: path.Base(c.path), Path: c.path, Basename: path.Base(c.path), ByName: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
			f := newFake()
			l, sink := newTestLoop(t, f, pol)
			execAt(l, f, nr, 42, 0, c.path, c.argv...)
			wantExecAnswer(t, f, record.VerdictRefused)
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != c.rule {
				t.Errorf("%s: %s %s, want refused %s", c.argv[0], ev.Verdict, ev.Rule, c.rule)
			}
		})
	}
}

// TestExecCommandAllowList: a constrained tool runs only as its allow entries say; an unlisted invocation is refused
// under exec.args[<tool>], and an admitted one names the entry that admitted it.
func TestExecCommandAllowList(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	l, sink := newTestLoop(t, f, commandPolicy(t, "allow: git status", "allow: git log"))
	execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "status", "-s")
	wantExecAnswer(t, f, record.VerdictAllow)
	p := execPayloadOf(t, sink.one(t))
	if p.CommandRule != "git status" || p.CommandList != "allow" {
		t.Errorf("git status: %+v", p.ExecPayload)
	}
	f = newFake()
	l, sink = newTestLoop(t, f, commandPolicy(t, "allow: git status", "allow: git log"))
	execAt(l, f, nr, 42, 0, "/usr/bin/git", "git", "push")
	wantExecAnswer(t, f, record.VerdictRefused)
	ev := sink.one(t)
	if ev.Rule != "exec.args[git]" || execPayloadOf(t, ev).CommandList != "unlisted" {
		t.Errorf("git push under an allow list: %s %+v", ev.Rule, execPayloadOf(t, ev).ExecPayload)
	}
	// No entry matched an unlisted invocation, so the line has no command_match: the record's set is definite or
	// ambiguous, and an unlisted refusal wrote "none".
	if m := execPayloadOf(t, ev).CommandMatch; m != "" {
		t.Errorf("git push under an allow list: command_match %q, want none written", m)
	}
}

// TestExecCommandAsk: exec.ask is reserved; every match is refused, completion_unsupported (ADR 0048 (5)).
func TestExecCommandAsk(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	l, sink := newTestLoop(t, f, commandPolicy(t, "ask: npm install"))
	execAt(l, f, nr, 42, 0, "/usr/bin/npm", "npm", "i", "left-pad")
	wantExecAnswer(t, f, record.VerdictRefused)
	ev := sink.one(t)
	p := execPayloadOf(t, ev)
	if ev.Rule != "exec.ask[npm install]" || !p.CompletionUnsupported || p.CommandList != "ask" {
		t.Errorf("npm i: %s %+v", ev.Rule, p)
	}
}

// TestExecCommandStagedRead: a guarded exec reads as much argv as its decision needs (ADR 0048 (3)). `git add` of
// 10,000 paths under allow: [git add] is decided on its prefix and allowed; a deny entry whose option stands past the
// prefix reads the tail; a decision that depends on argv past the budget is refused args-unreadable.
func TestExecCommandStagedRead(t *testing.T) {
	nr := nrFor(t, "execve")
	many := []string{"git", "add"}
	for i := 0; i < 10000; i++ {
		many = append(many, "f"+strconv.Itoa(i))
	}
	f := newFake()
	pol := commandPolicy(t, "allow: git add")
	pol.Record = agent.RecordOff
	l, _ := newTestLoop(t, f, pol)
	before := f.memReads
	execAt(l, f, nr, 42, 0, "/usr/bin/git", many...)
	wantExecAnswer(t, f, record.VerdictAllow)
	if reads := f.memReads - before; reads > 40 {
		t.Errorf("git add of 10,000 paths decided on its prefix took %d target reads", reads)
	}
	tail := []string{"rm"}
	for i := 0; i < 100; i++ {
		tail = append(tail, "f"+strconv.Itoa(i))
	}
	tail = append(tail, "-r")
	f = newFake()
	l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
	execAt(l, f, nr, 42, 0, "/usr/bin/rm", tail...)
	wantExecAnswer(t, f, record.VerdictRefused)
	if ev := sink.one(t); ev.Rule != "exec.deny[rm -r]" {
		t.Errorf("rm with -r past the prefix: %s", ev.Rule)
	}
	huge := []string{"rm"}
	for i := 0; i < argvEntries+10; i++ {
		huge = append(huge, "f")
	}
	f = newFake()
	l, sink = newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
	execAt(l, f, nr, 42, 0, "/usr/bin/rm", huge...)
	wantExecAnswer(t, f, record.VerdictRefused)
	if ev := sink.one(t); ev.Rule != ruleArgsUnreadable {
		t.Errorf("a verdict past the budget: %s", ev.Rule)
	}
}

// TestExecCommandReadsAVectorOfExactlyTheBound: a vector of exactly argvEntries pointers is within R16's bound, as
// the record's read (pointersLimited) holds it: the staged read reads the NULL after the last pointer and decides the
// exec. It read pointers in batches of ptrBatch, the last batch ending on the bound, and never read that NULL, so `rm`
// with 8192 operands under deny: [rm -r] was refused args-unreadable. One more pointer is past the bound, refused.
func TestExecCommandReadsAVectorOfExactlyTheBound(t *testing.T) {
	nr := nrFor(t, "execve")
	for _, c := range []struct {
		entries int
		verdict record.Verdict
		rule    string
	}{{argvEntries - 1, record.VerdictAllow, ""}, {argvEntries, record.VerdictAllow, ""}, {argvEntries + 1, record.VerdictRefused, ruleArgsUnreadable}} {
		t.Run(strconv.Itoa(c.entries), func(t *testing.T) {
			argv := []string{"rm"}
			for len(argv) < c.entries {
				argv = append(argv, "f")
			}
			f := newFake()
			pol := commandPolicy(t, "deny: rm -r")
			pol.Record = agent.RecordOff
			l, sink := newTestLoop(t, f, pol)
			// execAt lays strings out 64 KiB past the pointer array, which a vector this long overruns: its own layout,
			// the strings 1 MiB away.
			const pathAddr, ptrAddr, strAddr = 0x100000, 0x200000, 0x300000
			f.put(pathAddr, cstr("/usr/bin/rm"))
			ptrs := make([]byte, 8*(len(argv)+1))
			blob := []byte{}
			for i, a := range argv {
				putU64(ptrs[i*8:], strAddr+uint64(len(blob)))
				blob = append(blob, cstr(a)...)
			}
			f.put(strAddr, blob)
			f.put(ptrAddr, ptrs)
			l.handle(notifFor(nr, 42, pathAddr, ptrAddr, 0))
			wantExecAnswer(t, f, c.verdict)
			if c.rule != "" {
				if ev := sink.one(t); ev.Rule != c.rule {
					t.Errorf("%d entries: %s, want %s", c.entries, ev.Rule, c.rule)
				}
			}
		})
	}
}

// TestExecCommandBudgetIsTheWholeVector is ADR 0048 R7's bound as a tail-dependent decision reads it: the vector's
// bytes, each element's NUL counted, up to DefaultMaxArgv, whatever its elements' sizes. One element longer than the
// recorder's per-string bound (argMax) is read whole within the budget (K6's large argv cell), a vector of exactly the
// budget is decided, and one byte more is refused args-unreadable.
func TestExecCommandBudgetIsTheWholeVector(t *testing.T) {
	nr := nrFor(t, "execve")
	long := strings.Repeat("x", 2*argMax)
	for _, tc := range []struct {
		argv []string
		want record.Verdict
		rule string
	}{
		{[]string{"rm", long, "f"}, record.VerdictAllow, ""},
		{[]string{"rm", long, "-r"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{fillTo([]string{"rm", "f"}, DefaultMaxArgv), record.VerdictAllow, ""},
		{fillTo([]string{"rm", "-r"}, DefaultMaxArgv), record.VerdictRefused, "exec.deny[rm -r]"},
		{fillTo([]string{"rm", "f"}, DefaultMaxArgv+1), record.VerdictRefused, ruleArgsUnreadable},
	} {
		f := newFake()
		l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
		execAt(l, f, nr, 42, 0, "/usr/bin/rm", tc.argv...)
		wantExecAnswer(t, f, tc.want)
		if tc.rule == "" {
			continue
		}
		if ev := sink.one(t); ev.Rule != tc.rule {
			t.Errorf("%d elements, %d bytes: rule %q, want %q", len(tc.argv), vectorBytes(tc.argv), ev.Rule, tc.rule)
		}
	}
}

// fillTo appends elements of up to 2*argMax bytes to argv until its bytes, each element's NUL counted, are exactly n.
func fillTo(argv []string, n int) []string {
	for left := n - vectorBytes(argv); left > 0; left = n - vectorBytes(argv) {
		argv = append(argv, strings.Repeat("y", min(left, 2*argMax)-1))
	}
	return argv
}

// vectorBytes is the bytes of argv as the kernel lays it out: each element and its NUL.
func vectorBytes(argv []string) int {
	n := 0
	for _, a := range argv {
		n += len(a) + 1
	}
	return n
}

// TestExecCommandUnguardedReadsArgv0Only: in a run with command rules, an exec no interpretation guards reads its
// names and argv[0] and nothing more, under record: off (supervisor R16 as ADR 0048 (3) amends it).
func TestExecCommandUnguardedReadsArgv0Only(t *testing.T) {
	nr := nrFor(t, "execve")
	reads := func(argv ...string) int {
		f := newFake()
		pol := commandPolicy(t, "deny: git push")
		pol.Record = agent.RecordOff
		l, _ := newTestLoop(t, f, pol)
		before := f.memReads
		execAt(l, f, nr, 42, 0, "/usr/bin/ls", argv...)
		wantExecAnswer(t, f, record.VerdictAllow)
		return f.memReads - before
	}
	long := []string{"ls"}
	for i := 0; i < 40; i++ {
		long = append(long, "x")
	}
	if one, forty := reads("ls"), reads(long...); forty != one {
		t.Errorf("an unguarded exec read %d times with 40 args against %d with one", forty, one)
	}
}

// TestExecCommandUnreadableArgv0IsNotUnguarded: argv[0] can add an interpretation, never remove one (ADR 0048 (2)). A
// hard link of a multicall binary reads its applet from argv[0], so an exec whose argv[0] was not read is refused
// args-unreadable, on an unruled image and on a guarded one that would settle on the empty prefix. An argv[0] longer
// than the recorder's per-string bound is read whole within R7's budget, and matched. A NULL or empty argv has no
// argv[0] to lose, and is allowed.
func TestExecCommandUnreadableArgv0IsNotUnguarded(t *testing.T) {
	nr := nrFor(t, "execve")
	const pathAddr, ptrAddr, strAddr, nowhere = 0x100000, 0x200000, 0x300000, 0xdead0000
	longRm := strings.Repeat("a/", 8500) + "rm"
	ptrArray := func(ptrs ...uint64) []byte {
		b := make([]byte, 8*(len(ptrs)+1))
		for i, p := range ptrs {
			putU64(b[i*8:], p)
		}
		return b
	}
	// allow: ls makes ls Ruled and settled on an empty prefix: its bare entry names no word to wait for.
	lists := []struct {
		name  string
		rules []string
	}{
		{"unruled image", []string{"deny: rm -r"}},
		{"guarded image", []string{"deny: rm -r", "allow: ls"}},
	}
	cases := []struct {
		name    string
		argv    uint64
		mem     map[uint64][]byte
		verdict record.Verdict
		rule    string
	}{
		{name: "pointer array faults", argv: nowhere, verdict: record.VerdictRefused, rule: ruleArgsUnreadable},
		{
			name: "argv[0] faults", argv: ptrAddr, mem: map[uint64][]byte{ptrAddr: ptrArray(nowhere, strAddr)},
			verdict: record.VerdictRefused, rule: ruleArgsUnreadable,
		},
		{
			name: "argv[0] past the budget", argv: ptrAddr,
			mem:     map[uint64][]byte{ptrAddr: ptrArray(strAddr), strAddr: cstr(strings.Repeat("x", DefaultMaxArgv))},
			verdict: record.VerdictRefused, rule: ruleArgsUnreadable,
		},
		{
			name: "17 KiB argv[0] ending in rm", argv: ptrAddr,
			mem:     map[uint64][]byte{ptrAddr: ptrArray(strAddr, strAddr+0x10000), strAddr: cstr(longRm), strAddr + 0x10000: cstr("-rf")},
			verdict: record.VerdictRefused, rule: "exec.deny[rm -r]",
		},
		{name: "NULL argv", argv: 0, verdict: record.VerdictAllow},
		{name: "empty vector", argv: ptrAddr, mem: map[uint64][]byte{ptrAddr: ptrArray()}, verdict: record.VerdictAllow},
	}
	for _, list := range lists {
		for _, tc := range cases {
			t.Run(list.name+"/"+tc.name, func(t *testing.T) {
				f := newFake()
				pol := commandPolicy(t, list.rules...)
				pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: "ls", Path: "/usr/bin/ls", Basename: "ls", ByName: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
				l, sink := newTestLoop(t, f, pol)
				f.put(pathAddr, cstr("/usr/bin/ls"))
				for addr, data := range tc.mem {
					f.put(addr, data)
				}
				l.handle(notifFor(nr, 42, pathAddr, tc.argv, 0))
				wantExecAnswer(t, f, tc.verdict)
				if ev := sink.one(t); ev.Rule != tc.rule && tc.rule != "" {
					t.Errorf("rule %q, want %q", ev.Rule, tc.rule)
				}
			})
		}
	}
}

// TestExecCommandShebang: a script's #! chain is a fact (ADR 0048 (3)): the header is read through the walk's own
// descriptor, the interpreter walked as the task walks it, and a failed walk answers its own errno.
func TestExecCommandShebang(t *testing.T) {
	nr := nrFor(t, "execve")
	f := newFake()
	f.images = map[string]execImage{
		"/opt/x/tool":      {id: fakeID("/opt/x/tool"), linked: true, link: "/opt/x/tool", here: true, head: []byte("#!/usr/bin/python3 -u\nprint(1)\n")},
		"/usr/bin/python3": {id: fakeID("/usr/bin/python3"), linked: true, link: "/usr/bin/python3", here: true, head: []byte("\x7fELF")},
	}
	l, sink := newTestLoop(t, f, commandPolicy(t, "deny: python3"))
	execAt(l, f, nr, 42, 0, "/opt/x/tool", "tool", "go")
	wantExecAnswer(t, f, record.VerdictRefused)
	ev := sink.one(t)
	if ev.Rule != "exec.deny[python3]" || execPayloadOf(t, ev).CommandVia != "shebang" {
		t.Errorf("a python script: %s %+v", ev.Rule, execPayloadOf(t, ev).ExecPayload)
	}
	var headAsked bool
	for _, q := range f.execQueries {
		headAsked = headAsked || q.head
	}
	if !headAsked {
		t.Error("the image's head was not asked for")
	}
	f = newFake()
	f.images = map[string]execImage{"/opt/x/tool": {id: fakeID("/opt/x/tool"), linked: true, link: "/opt/x/tool", here: true, head: []byte("#!/opt/none/python3\n")}}
	f.imageErrs = map[string]error{"/opt/none/python3": unix.ENOENT}
	l, sink = newTestLoop(t, f, commandPolicy(t, "deny: python3"))
	execAt(l, f, nr, 42, 0, "/opt/x/tool", "tool")
	got, _ := f.lastResp()
	if got.Error != -int32(unix.ENOENT) {
		t.Errorf("a missing interpreter: response %+v, want ENOENT", got)
	}
	if ev := sink.one(t); ev.Rule != ruleInterpUnresolved {
		t.Errorf("a missing interpreter: %s", ev.Rule)
	}
}

// TestExecCommandShebangAnyRuledTool: any ruled tool can be a #! interpreter, and the kernel loads it inside the same
// execve, with no notification of its own. So a run with command rules reads every image's header, whether or not a
// rule names an interpreter: under deny: [rm -r] a script `#!/usr/bin/rm -rf` run as `./out/s out/tree` is `rm -rf
// ./out/s out/tree` and refused. An image whose head cannot be read (an execute-only file at tier 1) could be such a
// script and is refused image-unreadable; an empty file reads as no script, as the kernel reads it.
func TestExecCommandShebangAnyRuledTool(t *testing.T) {
	nr := nrFor(t, "execve")
	const script = "/work/out/s"
	for _, c := range []struct {
		name     string
		head     string
		headless bool
		verdict  record.Verdict
		rule     string
	}{
		{"#!/usr/bin/rm -rf", "#!/usr/bin/rm -rf\n", false, record.VerdictRefused, "exec.deny[rm -r]"},
		{"#! /usr/bin/rm -r, spaced", "#! /usr/bin/rm\t-r\n", false, record.VerdictRefused, "exec.deny[rm -r]"},
		{"#!/usr/bin/rm -f", "#!/usr/bin/rm -f\n", false, record.VerdictAllow, ruleUnmatched},
		{"#!/bin/sh", "#!/bin/sh\nrm -rf out/tree\n", false, record.VerdictAllow, ruleUnmatched},
		{"an empty file", "", false, record.VerdictAllow, ruleUnmatched},
		{"execute-only", "", true, record.VerdictRefused, ruleImageUnreadable},
	} {
		f := newFake()
		f.images = map[string]execImage{script: {id: fakeID(script), linked: true, link: script, here: true, head: []byte(c.head)}}
		if c.headless {
			f.headless = map[string]bool{script: true}
		}
		l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
		execAt(l, f, nr, 42, 0, script, "./out/s", "out/tree")
		wantExecAnswer(t, f, c.verdict)
		ev := sink.one(t)
		if ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want %s %s", c.name, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		if c.rule == "exec.deny[rm -r]" {
			if p := execPayloadOf(t, ev); p.CommandVia != "shebang" {
				t.Errorf("%s: command_via %q, want shebang", c.name, p.CommandVia)
			}
		}
	}
	// An interpreter whose own head cannot be read could be a script in turn: the form is unknown.
	f := newFake()
	f.images = map[string]execImage{script: {id: fakeID(script), linked: true, link: script, here: true, head: []byte("#!/opt/x/interp\n")}}
	f.headless = map[string]bool{"/opt/x/interp": true}
	l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
	execAt(l, f, nr, 42, 0, script, "./out/s")
	wantExecAnswer(t, f, record.VerdictRefused)
	if ev := sink.one(t); ev.Rule != ruleImageUnreadable {
		t.Errorf("an unreadable interpreter: %s, want %s", ev.Rule, ruleImageUnreadable)
	}
}

// TestExecCommandShebangEmptyArgument: a #! line's empty argument reaches the decision, as the empty element the kernel
// maps in front of the script: an allow entry that names the script alone holds for the line with no argument and not
// for this one, whose vector it does not name.
func TestExecCommandShebangEmptyArgument(t *testing.T) {
	nr := nrFor(t, "execve")
	const script = "/work/out/s"
	for _, c := range []struct {
		head    string
		verdict record.Verdict
	}{
		{"#!/usr/bin/rm\n", record.VerdictAllow},
		{"#!/usr/bin/rm \x00\n", record.VerdictRefused},
	} {
		f := newFake()
		f.images = map[string]execImage{script: {id: fakeID(script), linked: true, link: script, here: true, head: []byte(c.head)}}
		pol := commandPolicy(t, "allow: rm "+script)
		pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: "s", Path: script, Basename: "s", ByName: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
		l, _ := newTestLoop(t, f, pol)
		execAt(l, f, nr, 42, 0, script, "./out/s")
		wantExecAnswer(t, f, c.verdict)
	}
}

// TestExecCommandKeepsLookupErrno: command rules apply only to an exec whose walk reached an image; a failed lookup
// keeps its own errno (ENOENT for a PATH-search candidate), so execvp keeps searching. The loop answers it under a
// deny-list and an allow list alike, and never continues it (unwalkedExec): never EACCES, never CONTINUE, and no
// command rule names it.
func TestExecCommandKeepsLookupErrno(t *testing.T) {
	nr := nrFor(t, "execve")
	for _, entries := range [][]string{{"deny: git"}, {"allow: git status"}} {
		f := newFake()
		f.imageErrs = map[string]error{"/usr/local/bin/git": unix.ENOENT}
		l, sink := newTestLoop(t, f, commandPolicy(t, entries...))
		execAt(l, f, nr, 42, 0, "/usr/local/bin/git", "git", "push")
		got, _ := f.lastResp()
		if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.ENOENT) {
			t.Errorf("%v: response %+v, want the lookup's ENOENT answered by the loop", entries, got)
		}
		for _, ev := range sink.all() {
			if p := execPayloadOf(t, ev); p.CommandRule != "" {
				t.Errorf("%v: a failed lookup names a command rule: %+v", entries, p.ExecPayload)
			}
		}
	}
}

// TestExecCommandNeverContinuesUnwalked: in a run with command rules no exec is continued unless its walk reached an
// image the rules then decided (ADR 0048 (3)). Continued, the kernel's own lookup could reach a file the walk did
// not: the probe that found it renamed a symlink to git in and out of existence while execing it as `git push` under
// deny: [git push], and a third of the attempts ran git push on lines that said "allow unmatched". Each case below
// was continued before: a deny-list run's failed lookup, an unreadable pathname, a failure that is not the task's
// own lookup's (EMFILE), and an allow list's directory grant matched on the spelling of a walk that failed.
func TestExecCommandNeverContinuesUnwalked(t *testing.T) {
	nr := nrFor(t, "execve")
	for _, c := range []struct {
		name    string
		entries []string
		dir     string // a directory exec entry, for the allow list
		err     error  // the walk's failure; nil for an unreadable pathname
		errno   unix.Errno
		verdict record.Verdict
		rule    string
		path    []byte // an unreadable pathname's mapped bytes, with no NUL; nil for an unmapped page
	}{
		// A walk that found nothing is a miss (R16b (0)): answered with its errno, and no line.
		{"deny-list, the link renamed away", []string{"deny: git push"}, "", unix.ENOENT, unix.ENOENT, "", "", nil},
		{"deny-list, a component that is no directory", []string{"deny: git push"}, "", unix.ENOTDIR, unix.ENOTDIR, "", "", nil},
		{"deny-list, a loop of links", []string{"deny: git push"}, "", unix.ELOOP, unix.ELOOP, record.VerdictObserved, ruleUnmatched, nil},
		{"deny-list, EMFILE", []string{"deny: git push"}, "", unix.EMFILE, refusalErrno, record.VerdictRefused, rulePathUnreliable, nil},
		{"deny-list, an unreadable pathname", []string{"deny: git push"}, "", nil, unix.EFAULT, record.VerdictObserved, ruleArgsUnreadable, nil},
		// The kernel's getname answers ENAMETOOLONG for PATH_MAX bytes with no NUL, and EFAULT only for a pathname
		// whose read faults before its NUL.
		{"deny-list, a pathname past PATH_MAX", []string{"deny: git push"}, "", nil, unix.ENAMETOOLONG, record.VerdictObserved, rulePathTruncated, bytes.Repeat([]byte("a"), 5000)},
		{"deny-list, a pathname faulting at 100 bytes", []string{"deny: git push"}, "", nil, unix.EFAULT, record.VerdictObserved, rulePathTruncated, bytes.Repeat([]byte("a"), 100)},
		{"allow list, a pathname past PATH_MAX", []string{"allow: git status"}, "", nil, unix.ENAMETOOLONG, record.VerdictRefused, rulePathTruncated, bytes.Repeat([]byte("a"), 5000)},
		{"allow list, a directory grant's spelling", []string{"allow: git status"}, "/work/bin/", unix.ENOENT, unix.ENOENT, "", "", nil},
		{"allow list, a directory grant's spelling, a loop of links", []string{"allow: git status"}, "/work/bin/", unix.ELOOP, unix.ELOOP, record.VerdictObserved, "exec[/work/bin/]", nil},
	} {
		f := newFake()
		pol := commandPolicy(t, c.entries...)
		if c.dir != "" {
			pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: c.dir, Path: c.dir, IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow})
		}
		const p = "/work/bin/l"
		if c.err != nil {
			f.imageErrs = map[string]error{p: c.err}
		}
		l, sink := newTestLoop(t, f, pol)
		if c.err != nil {
			execAt(l, f, nr, 42, 0, p, "git", "push")
		} else {
			const argvAddr = 0x210000
			execFixture(f, argvAddr, []string{"git", "push"})
			pathAddr := uint64(0xdead0000) // the pathname's page is not mapped
			if c.path != nil {
				pathAddr = 0x400000
				f.put(pathAddr, c.path)
			}
			l.handle(notifFor(nr, 42, pathAddr, argvAddr, 0))
		}
		got, _ := f.lastResp()
		if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(c.errno) {
			t.Errorf("%s: response %+v, want errno %v answered by the loop, never CONTINUE", c.name, got, c.errno)
		}
		evs := sink.all()
		if c.verdict == "" {
			if len(evs) != 0 {
				t.Errorf("%s: %d lines, want none for a miss", c.name, len(evs))
			}
			continue
		}
		if len(evs) != 1 {
			t.Errorf("%s: %d lines, want one", c.name, len(evs))
			continue
		}
		if ev := evs[0]; ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: line %s %s, want %s %s", c.name, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
	}
}

// TestExecCommandPrefixEndsAtDefaultLevel: the staged read's first stage is 32 elements, and a vector of git, 15 `-c
// a.b=c` pairs and `stash drop` is 33, so the prefix ends at stash. That prefix is not `git stash push` (ADR 0048
// (3)): the decision reads on and refuses the drop under deny: [git stash drop], and refuses it unlisted under
// allow: [git stash push].
func TestExecCommandPrefixEndsAtDefaultLevel(t *testing.T) {
	nr := nrFor(t, "execve")
	argv := []string{"git"}
	for range 15 {
		argv = append(argv, "-c", "a.b=c")
	}
	argv = append(argv, "stash", "drop")
	if len(argv) != cmdPrefixArgs+1 {
		t.Fatalf("the vector has %d elements, want the prefix's %d and one more", len(argv), cmdPrefixArgs)
	}
	for _, c := range []struct{ entry, rule string }{
		{"deny: git stash drop", "exec.deny[git stash drop]"},
		{"allow: git stash push", "exec.args[git]"},
	} {
		f := newFake()
		l, sink := newTestLoop(t, f, commandPolicy(t, c.entry))
		execAt(l, f, nr, 42, 0, "/usr/bin/git", argv...)
		wantExecAnswer(t, f, record.VerdictRefused)
		if ev := sink.one(t); ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want refused %s", c.entry, ev.Verdict, ev.Rule, c.rule)
		}
	}
}

// TestExecCommandShebangKernelParse: the #! line is read exactly as fs/binfmt_script.c reads it. Only spaces and tabs
// are trimmed from its end, so a CRLF line's '\r' is part of the interpreter's name: under deny: [rm -r], a script
// `#!/work/y\r` with /work/y any file and `/work/y\r` a symlink to rm, run as `./s -r tree`, is the kernel's
// `rm -r` and refused. A NUL ends the name and leaves no argument. With no newline in the 256 bytes the name must end
// before the last byte, or the file is no script (ENOEXEC).
func TestExecCommandShebangKernelParse(t *testing.T) {
	nr := nrFor(t, "execve")
	const script = "/work/s"
	trueImg := execImage{id: fakeID("/usr/bin/true"), linked: true, link: "/usr/bin/true", here: true, head: []byte("\x7fELF")}
	rmImg := execImage{id: fakeID("/usr/bin/rm"), linked: true, link: "/usr/bin/rm", here: true, head: []byte("\x7fELF")}
	// A 253-byte interpreter path that is rm: a 255-byte file `#!<it>` with no newline ends the name at the zero
	// padding of byte 255, and a space there ends it too. The kernel runs both.
	long := "/work/" + strings.Repeat("x", 247)
	for _, c := range []struct {
		name    string
		head    string
		argv    []string
		verdict record.Verdict
		rule    string
	}{
		{"a CRLF line names y\\r, which is rm", "#!/work/y\r\n", []string{"./s", "-r", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{"a CRLF line names y\\r, without -r", "#!/work/y\r\n", []string{"./s", "tree"}, record.VerdictAllow, ruleUnmatched},
		{"a NUL ends the name and leaves no argument", "#!/usr/bin/rm\x00-r\n", []string{"./s", "tree"}, record.VerdictAllow, ruleUnmatched},
		{"a NUL inside the argument ends it", "#!/usr/bin/rm -r\x00x\n", []string{"./s", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{"a 255-byte file's name ends at byte 255", "#!" + long, []string{"./s", "-r", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
		{"a space at byte 255 ends the name", "#!" + long + " -f", []string{"./s", "-r", "tree"}, record.VerdictRefused, "exec.deny[rm -r]"},
	} {
		f := newFake()
		f.images = map[string]execImage{
			script:          {id: fakeID(script), linked: true, link: script, here: true, head: []byte(c.head)},
			"/work/y":       trueImg,
			"/work/y\r":     rmImg,
			"/usr/bin/rm":   rmImg,
			"/usr/bin/true": trueImg,
			long:            rmImg,
		}
		l, sink := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
		execAt(l, f, nr, 42, 0, script, c.argv...)
		if ev := sink.one(t); ev.Verdict != c.verdict || ev.Rule != c.rule {
			t.Errorf("%s: %s %s, want %s %s", c.name, ev.Verdict, ev.Rule, c.verdict, c.rule)
		}
		wantExecAnswer(t, f, c.verdict)
	}
}

func TestParseShebangAsKernel(t *testing.T) {
	long := "#!/" + strings.Repeat("a", 300)
	// binfmt_script's next_non_spacetab and next_terminator scan up to and including the buffer's last byte (255):
	// a 255-byte file with no newline ends its name at the zero padding there, and a space or tab at 255 ends it
	// too. The name stops at byte 254 either way, and 256 bytes of name with no terminator are still no script.
	name253 := "/" + strings.Repeat("b", 252)
	for _, c := range []struct {
		in, interp, arg string
		ok              bool
	}{
		{"#!/work/y\r\n", "/work/y\r", "", true},
		{"#!/bin/sh -e\r\n", "/bin/sh", "-e\r", true},
		{"#!/bin/sh \t\n", "/bin/sh", "", true},
		{"#!/bin/sh\x00-e\n", "/bin/sh", "", true},
		{"#!/bin/sh -e\x00x\n", "/bin/sh", "-e", true},
		{"#!./rel arg\n", "./rel", "arg", true},
		{"#!/bin/sh", "/bin/sh", "", true},
		{long, "", "", false},
		{"#!" + name253, name253, "", true},
		{"#!" + name253 + " ", name253, "", true},
		{"#!" + name253 + "\t-rf", name253, "", true},
		{"#! " + name253, "", "", false},
		{"#!" + name253 + "c", "", "", false},
		{"#!/b " + strings.Repeat("a", 300), "/b", strings.Repeat("a", 250), true},
		{"#! \t\n", "", "", false},
		{"#! \x00/x\n", "", "", true}, // an empty name: the kernel's open of it answers ENOENT
		{"#!\n", "", "", false},
		{"\x7fELF", "", "", false},
	} {
		interp, arg, _, ok := parseShebang([]byte(c.in))
		if interp != c.interp || arg != c.arg || ok != c.ok {
			t.Errorf("parseShebang(%q) = %q %q %v, want %q %q %v", c.in, interp, arg, ok, c.interp, c.arg, c.ok)
		}
	}
}

// TestExecCommandUnreadableWritesNoCommandRule: a sentinel refusal (the argv bound) is not a command-rule decision,
// so the exec line and its refused mirror carry no command_rule/command_match/command_via from the prefix the staged
// read matched. Under allow: [git log --oneline] a `git log --oneline` whose argv runs past
// the entry cap is refused args-unreadable; the prefix matched the allow entry, but the verdict is the bound's, and
// the stale allow entry must not appear on the refusal.
func TestExecCommandUnreadableWritesNoCommandRule(t *testing.T) {
	nr := nrFor(t, "execve")
	argv := []string{"git", "log", "--oneline", "-1"}
	for i := 0; i < argvEntries+10; i++ {
		argv = append(argv, "f"+strconv.Itoa(i))
	}
	f := newFake()
	l, sink := newTestLoop(t, f, commandPolicy(t, "allow: git log --oneline"))
	execAt(l, f, nr, 42, 0, "/usr/bin/git", argv...)
	wantExecAnswer(t, f, record.VerdictRefused)
	ev := sink.one(t)
	if ev.Rule != ruleArgsUnreadable {
		t.Fatalf("rule %q, want %s", ev.Rule, ruleArgsUnreadable)
	}
	p := execPayloadOf(t, ev)
	if p.CommandRule != "" || p.CommandList != "" || p.CommandMatch != "" || p.CommandVia != "" {
		t.Errorf("args-unreadable line carries a stale command decision: rule=%q list=%q match=%q via=%q, want all empty",
			p.CommandRule, p.CommandList, p.CommandMatch, p.CommandVia)
	}
}

// TestExecCommandObserveDoesNotCount: an --observe run enforces nothing, so a command rule's would-be refusal runs
// (CONTINUE, the line stamped observed), and run_end's exec_rules counters count only what was actually refused, not
// what ran. The same exec under enforcement is counted.
func TestExecCommandObserveDoesNotCount(t *testing.T) {
	nr := nrFor(t, "execve")
	// Enforcement: the deny counts.
	f := newFake()
	l, _ := newTestLoop(t, f, commandPolicy(t, "deny: rm -r"))
	execAt(l, f, nr, 42, 0, "/usr/bin/rm", "rm", "-r", "x")
	wantExecAnswer(t, f, record.VerdictRefused)
	if m := l.Metrics(); m.ExecRules == nil || m.ExecRules.Refused != 1 {
		t.Fatalf("enforced deny: exec_rules = %+v, want refused 1", m.ExecRules)
	}
	// Observe: the same exec runs, and nothing is counted as refused.
	f = newFake()
	pol := commandPolicy(t, "deny: rm -r")
	pol.Observe = true
	l, sink := newTestLoop(t, f, pol)
	execAt(l, f, nr, 42, 0, "/usr/bin/rm", "rm", "-r", "x")
	wantExecAnswer(t, f, record.VerdictAllow) // observe CONTINUEs
	if ev := sink.one(t); ev.Verdict != record.VerdictObserved {
		t.Errorf("observe line verdict %s, want observed", ev.Verdict)
	}
	if m := l.Metrics(); m.ExecRules != nil && m.ExecRules.Refused != 0 {
		t.Errorf("observe run counted a refusal that ran: exec_rules = %+v, want refused 0", m.ExecRules)
	}
}

// TestExecCommandRulesLeaveTheFloorsDecisionAlone: in a run with command rules, an exec the image floor refuses
// (or, in an observe run, would refuse and runs) is still walked for what it loads, for its dropped flag (supervisor R16b),
// but the command rules never decide it: its line keeps the floor's rule and carries no command
// rule, list, match, route or argv facts, and run_end's exec_rules counts nothing. Under deny: [rm -r] and an
// allow-list that grants only /usr/bin/rm, /opt/bin/rm -r x is the floor's refusal, not the deny entry's, and so is
// an image whose head could not be read, which the command rules alone would refuse image-unreadable.
func TestExecCommandRulesLeaveTheFloorsDecisionAlone(t *testing.T) {
	nr := nrFor(t, "execve")
	for _, observe := range []bool{false, true} {
		for _, headless := range []bool{false, true} {
			f := newFake()
			if headless {
				f.headless = map[string]bool{"/opt/bin/rm": true}
			}
			pol := commandPolicy(t, "allow: git status", "deny: rm -r")
			pol.Observe = observe
			l, sink := newTestLoop(t, f, pol)
			execAt(l, f, nr, 42, 0, "/opt/bin/rm", "rm", "-r", "x")
			want := record.VerdictRefused
			if observe {
				want = record.VerdictObserved
			}
			wantExecAnswer(t, f, want)
			ev := sink.one(t)
			p := execPayloadOf(t, ev)
			if ev.Verdict != want || ev.Rule != ruleUnmatched || p.CommandRule != "" || p.CommandList != "" ||
				p.CommandMatch != "" || p.CommandVia != "" || p.ArgvFacts != "" {
				t.Errorf("observe=%v headless=%v: %s %s command rule=%q list=%q match=%q via=%q argv_facts=%q, want the floor's %s %s and no command decision",
					observe, headless, ev.Verdict, ev.Rule, p.CommandRule, p.CommandList, p.CommandMatch, p.CommandVia, p.ArgvFacts, want, ruleUnmatched)
			}
			if m := l.Metrics(); m.ExecRules != nil && (m.ExecRules.Refused != 0 || m.ExecRules.Ambiguous != 0) {
				t.Errorf("observe=%v headless=%v: exec_rules = %+v, want nothing counted", observe, headless, m.ExecRules)
			}
		}
	}
}
