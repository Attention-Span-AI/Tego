// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEvaluateUnixUnderWrite: a pathname unix socket under a declared fs.write entry is allowed implicitly,
// named by that entry, as the supervisor's decideUnix allows it (SEMANTICS §5, R15); a deny_read nearer than
// the write entry, an abstract name, a relative path or a socket outside every write entry stays refused.
func TestEvaluateUnixUnderWrite(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/work", Raw: "./work", Resolved: "/work", Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: "/work/secret", Raw: "./work/secret", Resolved: "/work/secret"},
			{Kind: agent.FSWrite, Path: "/link", Raw: "./link", Resolved: "/real", Access: agent.AccessWriteSet},
		},
		Net: []agent.NetRule{{Proto: agent.ProtoUnix, UnixPath: "/run/declared.sock", Verdict: agent.VerdictAllow}},
	}
	wantRule := func(p string) string {
		for _, r := range rt.FS {
			if r.Path == p {
				return r.RuleName()
			}
		}
		t.Fatalf("no entry %s", p)
		return ""
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, c := range []struct {
			path  string
			allow bool
			rule  string
		}{
			{"/work/a.sock", true, wantRule("/work")},
			{"unix:/work/sub/../mcp.sock", true, wantRule("/work")},
			{"/real/x.sock", true, wantRule("/link")},
			{"/link/x.sock", true, wantRule("/link")},
			{"/run/declared.sock", true, rt.Net[0].RuleName()},
			{"/work/secret/a.sock", false, ""},
			{"/tmp/a.sock", false, ""},
			{"@abstract", false, ""},
			{"work/a.sock", false, ""},
		} {
			res := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Path: c.path}, tier)
			if (res.Verdict == agent.VerdictAllow) != c.allow || (c.allow && res.Rule != c.rule) {
				t.Errorf("tier %v connect %s = %v %s, want allow=%v %s", tier, c.path, res.Verdict, res.Rule, c.allow, c.rule)
			}
		}
	}
}

// TestEvaluateUnixDecidedWhereTheNameLands: a connect or a datagram to a unix pathname is decided as the supervisor
// decides it (R11, R11a; SEMANTICS §5 as amended 2026-10-16): on the name it passes, then on the socket that name
// reaches (Action.Landed), matched as decideResolved matches it, a unix: entry by its resolved path and the nearest
// filesystem entry by its resolved path alone, and named by the entry that admitted the socket. A name admitted through
// a symlink in a write entry to a socket outside it was answered allow, which the run refuses with rule unmatched. A
// name that was not landed is decided on its spelling alone,
// and an observe column continues everything.
func TestEvaluateUnixDecidedWhereTheNameLands(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/work", Raw: "./work", Resolved: "/work", Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: "/work/secret", Raw: "./work/secret", Resolved: "/work/secret"},
			{Kind: agent.FSWrite, Path: "/link", Raw: "./link", Resolved: "/real", Access: agent.AccessWriteSet},
		},
		Net: []agent.NetRule{
			{Proto: agent.ProtoUnix, Raw: "unix:/run/declared.sock", UnixPath: "/run/declared.sock", UnixResolved: "/run/declared.sock", Verdict: agent.VerdictAllow},
			{Proto: agent.ProtoUnix, Raw: "unix:/link/d.sock", UnixPath: "/link/d.sock", UnixResolved: "/real/d.sock", Verdict: agent.VerdictAllow},
			{Proto: agent.ProtoUnix, Raw: "unix:/hand/built.sock", UnixPath: "/hand/built.sock", Verdict: agent.VerdictAllow},
		},
	}
	for _, kind := range []agent.ActionKind{agent.ActionNetConnect, agent.ActionNetSend} {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			for _, c := range []struct {
				path, landed string
				allow        bool
				rule         string
			}{
				{"unix:/work/lk/s.sock", "/tmp/s.sock", false, agent.UnmatchedRule},
				{"unix:/work/lk/s.sock", "/work/secret/s.sock", false, agent.UnmatchedRule},
				{"unix:/work/lk/../s.sock", "/s.sock", false, agent.UnmatchedRule},
				{"unix:/run/declared.sock", "/tmp/other.sock", false, agent.UnmatchedRule},
				{"unix:/work/to-run/declared.sock", "/run/declared.sock", true, "net[unix:/run/declared.sock]"},
				{"unix:/link/d.sock", "/real/d.sock", true, "net[unix:/link/d.sock]"},
				{"unix:/work/hb.sock", "/hand/built.sock", true, "net[unix:/hand/built.sock]"},
				{"unix:/work/a.sock", "/work/a.sock", true, "fs.write[./work]"},
				{"unix:/link/x.sock", "/real/x.sock", true, "fs.write[./link]"},
				// The landed socket is matched by the entries' resolved paths alone: /link is a spelling, not a place.
				{"unix:/work/x.sock", "/link/x.sock", false, agent.UnmatchedRule},
				// The name decides first: a name nothing admits is refused wherever it lands.
				{"unix:/tmp/x.sock", "/work/x.sock", false, agent.UnmatchedRule},
				// Not landed: the spelling alone.
				{"unix:/work/lk/s.sock", "", true, "fs.write[./work]"},
			} {
				res := Evaluate(rt, agent.Action{Kind: kind, Path: c.path, Landed: c.landed}, tier)
				if (res.Verdict == agent.VerdictAllow) != c.allow || res.Rule != c.rule {
					t.Errorf("%s tier %v %s landed at %q = %v %s, want allow=%v %s", kind, tier, c.path, c.landed, res.Verdict, res.Rule, c.allow, c.rule)
				}
				if !c.allow && res.Reason != record.ReasonNetNotAllowed {
					t.Errorf("%s tier %v %s landed at %q: reason %q, want %q", kind, tier, c.path, c.landed, res.Reason, record.ReasonNetNotAllowed)
				}
			}
		}
		if res := Evaluate(rt, agent.Action{Kind: kind, Path: "unix:/work/lk/s.sock", Landed: "/tmp/s.sock"}, backend.TierObserve); res.Verdict != agent.VerdictAllow {
			t.Errorf("%s observe: %v %s, want allow", kind, res.Verdict, res.Rule)
		}
	}
	// A refused landed socket allocates nothing, however many entries the table holds.
	padded := envPadded(backend.TierCgroup, 5000)
	padded.FS = append(padded.FS, agent.FSRule{Kind: agent.FSWrite, Path: "/sock", Raw: "/sock", Resolved: "/sock", Access: agent.AccessWriteSet})
	if n := testing.AllocsPerRun(10, func() {
		unixLanded(padded, agent.Action{Kind: agent.ActionNetSend, Landed: "/var/run/a.sock"}, "fs.write[/sock]", true)
	}); n != 0 {
		t.Errorf("unixLanded makes %v allocations for a refused socket, want 0", n)
	}
}

// TestEvaluateUnixAbstractExactBytes: an abstract entry matches the name it holds byte for byte, as the
// cgroup key (UnixAbstractKey(UnixPath)) and the supervisor compare it. `unix:@@foo` names the abstract
// name "@foo"; stripping an "@" from the entry as well allowed "foo" and refused "@foo".
func TestEvaluateUnixAbstractExactBytes(t *testing.T) {
	rt := &agent.RuleTable{
		Net: []agent.NetRule{{Proto: agent.ProtoUnix, Abstract: true, UnixPath: "@foo", Verdict: agent.VerdictAllow}},
	}
	for _, c := range []struct {
		path  string
		allow bool
	}{
		{"unix:@@foo", true},
		{"@@foo", true},
		{"unix:@foo", false},
		{"@foo", false},
		{"@foo2", false},
		{"foo", false},
	} {
		res := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Path: c.path}, backend.TierCgroup)
		if (res.Verdict == agent.VerdictAllow) != c.allow {
			t.Errorf("connect %s = %v %s, want allow=%v", c.path, res.Verdict, res.Rule, c.allow)
		}
	}
}

// TestUnixUnderWriteAllocatesNothing: the implicit unix-under-write lookup scans the table rather than
// building the advisory tables for each connect, so a refused unix row costs no allocation however many
// entries the .env scan added (an allowed one allocates only its rule name). It sorted and indexed all of
// them, about 65 ms at 50,000, on every row.
func TestUnixUnderWriteAllocatesNothing(t *testing.T) {
	rt := envPadded(backend.TierCgroup, 5000)
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: "/sock", Raw: "/sock", Resolved: "/sock", Access: agent.AccessWriteSet})
	for _, p := range []string{"/var/run/a.sock", "/home/u/proj/gen/d1/100/.env/x.sock"} {
		if n := testing.AllocsPerRun(10, func() { unixUnderWrite(rt, p) }); n != 0 {
			t.Errorf("unixUnderWrite(%s) makes %v allocations, want 0", p, n)
		}
	}
	if _, ok := unixUnderWrite(rt, "/sock/a.sock"); !ok {
		t.Error("a socket under the fs.write entry /sock was not allowed")
	}
}

// TestUnixUnderWriteMatchesNearestIn: the scan names the entry NearestIn(NewAdvisoryTables(...).Both) names,
// on tables of nested write, implicit, deny_read and watch entries, symlinked and trailing-slashed ones among
// them, several entries on one path included.
func TestUnixUnderWriteMatchesNearestIn(t *testing.T) {
	kinds := []agent.FSKind{agent.FSWrite, agent.FSImplicit, agent.FSDenyRead, agent.FSWatch}
	paths := []string{"/", "/a", "/a/", "/a/b", "/ab", "/a/b/c", "/r", "/r/b"}
	targets := []string{"/a/x.sock", "/a/b/x.sock", "/a/b/c", "/ab/x.sock", "/r/b/x.sock", "/r/x.sock", "/z.sock", "/a/b/c/d/e.sock"}
	for seed := range 400 {
		var rt agent.RuleTable
		for j := range 1 + seed%5 {
			v := seed*7 + j*13
			p := paths[v%len(paths)]
			r := agent.FSRule{Kind: kinds[(v/3)%len(kinds)], Path: p, Raw: p + "#" + strconv.Itoa(j)}
			if (v/5)%3 == 0 {
				r.Resolved = paths[(v/2)%len(paths)]
			}
			rt.FS = append(rt.FS, r)
		}
		tables := NewAdvisoryTables(rt.FS)
		for _, p := range targets {
			want, wantOK := "", false
			if near := NearestIn(tables.Both, p); near != nil && near.Write {
				want, wantOK = near.Name, true
			}
			if got, ok := unixUnderWrite(&rt, p); got != want || ok != wantOK {
				t.Fatalf("table %+v, socket %s: scan %q %v, NearestIn %q %v", rt.FS, p, got, ok, want, wantOK)
			}
			// The landed socket's scan asks the resolved spellings alone, as decideResolved asks fsResolved.
			want, wantOK = "", false
			if near := NearestIn(tables.Resolved, p); near != nil && near.Write {
				want, wantOK = near.Name, true
			}
			if got, ok := nearestUnixWrite(&rt, p, false); got != want || ok != wantOK {
				t.Fatalf("table %+v, landed socket %s: scan %q %v, NearestIn(Resolved) %q %v", rt.FS, p, got, ok, want, wantOK)
			}
		}
	}
}

// TestEvaluateUnixDecidedOnWhatTheWalkMet: a connect or a datagram whose name the contract admits is answered on what
// the run's own unix walk met (Action.Walk), as the supervisor answers it (-3): a name that names nothing, or whose
// lookup fails otherwise as the agent's own, keeps the
// name's verdict for a connect (the relay's unixUnresolved: the agent's connect fails with that errno) and refuses a
// datagram unix-absent or path-unreliable (unixLandedRefusal); a walk through a magic link, a symlink loop or procfs
// is refused path-unreliable; a socket only the component walk reached refuses a connect path-unreliable
// (errWalkedOnly) and decides a datagram on that socket. A name the contract refuses is refused by its name first,
// whatever the walk met. A datagram's absolute name the kernel programs do not admit as spelled (Action.Uncanonical)
// is refused unmatched at tiers cgroup and bpflsm when it would be admitted, and a bind whose
// walk failed is refused path-unreliable, as the run's bindUnix refuses it.
func TestEvaluateUnixDecidedOnWhatTheWalkMet(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/work", Raw: "./work", Resolved: "/work", Access: agent.AccessWriteSet}},
		Net: []agent.NetRule{{Proto: agent.ProtoUnix, Raw: "unix:/run/d.sock", UnixPath: "/run/d.sock", UnixResolved: "/run/d.sock",
			Verdict: agent.VerdictAllow}},
	}
	const named = "fs.write[./work]"
	for _, c := range []struct {
		kind          agent.ActionKind
		walk          agent.UnixWalk
		landed        string
		allow         bool
		rule          string
		path, comment string
	}{
		{agent.ActionNetConnect, agent.UnixWalkAbsent, "", true, named, "", "the agent's connect fails ENOENT, its line the name's"},
		{agent.ActionNetSend, agent.UnixWalkAbsent, "", false, agent.UnixAbsentRule, "", ""},
		{agent.ActionNetConnect, agent.UnixWalkFailed, "", true, named, "", "EACCES: the name's"},
		{agent.ActionNetSend, agent.UnixWalkFailed, "", false, agent.PathUnreliableRule, "", ""},
		{agent.ActionNetConnect, agent.UnixWalkUnreliable, "", false, agent.PathUnreliableRule, "", "a magic link"},
		{agent.ActionNetSend, agent.UnixWalkUnreliable, "", false, agent.PathUnreliableRule, "", ""},
		{agent.ActionNetConnect, agent.UnixWalkStepwise, "/work/s.sock", false, agent.PathUnreliableRule, "", "walked only"},
		{agent.ActionNetSend, agent.UnixWalkStepwise, "/work/s.sock", true, named, "", ""},
		{agent.ActionNetSend, agent.UnixWalkStepwise, "/tmp/s.sock", false, agent.UnmatchedRule, "", ""},
		{agent.ActionNetConnect, agent.UnixWalkUnreliable, "", false, agent.UnmatchedRule, "unix:/tmp/s.sock", "the name first"},
		{agent.ActionNetSend, agent.UnixWalkAbsent, "", false, agent.UnmatchedRule, "unix:/tmp/s.sock", ""},
	} {
		path := c.path
		if path == "" {
			path = "unix:/work/lk/s.sock"
		}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			res := Evaluate(rt, agent.Action{Kind: c.kind, Path: path, Landed: c.landed, Walk: c.walk}, tier)
			if (res.Verdict == agent.VerdictAllow) != c.allow || res.Rule != c.rule {
				t.Errorf("%s %s walk %d tier %v (%s) = %v %s, want allow=%v %s", c.kind, path, c.walk, tier, c.comment, res.Verdict,
					res.Rule, c.allow, c.rule)
			}
			if !c.allow && res.Reason != record.ReasonNetNotAllowed {
				t.Errorf("%s walk %d tier %v: reason %q", c.kind, c.walk, tier, res.Reason)
			}
		}
		if res := Evaluate(rt, agent.Action{Kind: c.kind, Path: path, Walk: c.walk}, backend.TierObserve); res.Verdict != agent.VerdictAllow {
			t.Errorf("%s walk %d observe: %v %s, want allow", c.kind, c.walk, res.Verdict, res.Rule)
		}
	}
	for _, c := range []struct {
		kind  agent.ActionKind
		tier  backend.Tier
		allow bool
		rule  string
	}{
		{agent.ActionNetSend, backend.TierLandlock, true, named},
		{agent.ActionNetSend, backend.TierCgroup, false, agent.UnmatchedRule},
		{agent.ActionNetSend, backend.TierBPFLSM, false, agent.UnmatchedRule},
		{agent.ActionNetSend, backend.TierObserve, true, agent.UnmatchedRule}, // observe names no write entry
		// A connect is relayed, never continued to the kernel's programs.
		{agent.ActionNetConnect, backend.TierCgroup, true, named},
	} {
		a := agent.Action{Kind: c.kind, Path: "unix:/work/./s.sock", Landed: "/work/s.sock", Uncanonical: true}
		res := Evaluate(rt, a, c.tier)
		if (res.Verdict == agent.VerdictAllow) != c.allow || res.Rule != c.rule {
			t.Errorf("uncanonical %s tier %v = %v %s, want allow=%v %s", c.kind, c.tier, res.Verdict, res.Rule, c.allow, c.rule)
		}
	}
	// A refusal stays the supervisor's own, named as it named it.
	a := agent.Action{Kind: agent.ActionNetSend, Path: "unix:/work/./s.sock", Walk: agent.UnixWalkAbsent, Uncanonical: true}
	if res := Evaluate(rt, a, backend.TierCgroup); res.Rule != agent.UnixAbsentRule {
		t.Errorf("an uncanonical datagram the walk refused: %v %s, want %s", res.Verdict, res.Rule, agent.UnixAbsentRule)
	}
	// A bind whose walk failed is refused path-unreliable only where the run's bindUnix decides it, under a listener
	// policy; with none, the run continues every bind with no line and the kernel answers it, so the row is the
	// creation floor on its spelling, as a filesystem row whose walk fails is.
	// Under a listener policy the bpflsm column is the decision plane's, to which the supervisor hands the bind
	// (bindHandoffReady): the plane decides at path_mknod, which a bind whose lookup fails never reaches, so the row is
	// answered on its spelling there, as every row whose walk fails is (-2s4-3: path-unreliable was a line that run
	// never writes).
	listen := &agent.RuleTable{FS: rt.FS, Listen: []agent.ListenRule{{Proto: agent.ProtoUnix, UnixPath: "/work/f/s.sock",
		Raw: "unix:/work/f/s.sock"}}}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		failed := agent.Action{Kind: agent.ActionNetBind, Proto: agent.ProtoUnix, Path: "unix:/work/f/s.sock", Walk: agent.UnixWalkUnreliable}
		res := Evaluate(listen, failed, tier)
		switch {
		case tier == backend.TierBPFLSM:
			if res.Verdict != agent.VerdictAllow || res.Rule != listen.Listen[0].RuleName() {
				t.Errorf("a bind whose walk failed under a listener policy, the plane's column: %v %s, want allow %s (its spelling)",
					res.Verdict, res.Rule, listen.Listen[0].RuleName())
			}
			undeclared := failed
			undeclared.Path = "unix:/work/f/other.sock"
			if res := Evaluate(listen, undeclared, tier); res.Verdict != agent.VerdictRefused || res.Rule != agent.UnmatchedRule {
				t.Errorf("an undeclared bind whose walk failed, the plane's column: %v %s, want refused %s (its spelling)",
					res.Verdict, res.Rule, agent.UnmatchedRule)
			}
		case res.Verdict != agent.VerdictRefused || res.Rule != agent.PathUnreliableRule || res.Reason != record.ReasonNetNotAllowed:
			t.Errorf("a bind whose walk failed under a listener policy, tier %v: %v %s %s, want refused %s", tier, res.Verdict,
				res.Rule, res.Reason, agent.PathUnreliableRule)
		}
		if res := Evaluate(&agent.RuleTable{FS: rt.FS}, failed, tier); res.Verdict != agent.VerdictAllow || res.Rule != agent.UnmatchedRule {
			t.Errorf("a bind whose walk failed with no listener policy, tier %v: %v %s, want allow %s (the floor admits it)",
				tier, res.Verdict, res.Rule, agent.UnmatchedRule)
		}
		if res := Evaluate(&agent.RuleTable{}, failed, tier); res.Verdict != agent.VerdictRefused || res.Rule == agent.PathUnreliableRule {
			t.Errorf("a bind whose walk failed outside the write entry, no listener policy, tier %v: %v %s, want the floor's refusal",
				tier, res.Verdict, res.Rule)
		}
		ok := agent.Action{Kind: agent.ActionNetBind, Proto: agent.ProtoUnix, Path: "unix:/work/f/s.sock"}
		if res := Evaluate(listen, ok, tier); res.Verdict != agent.VerdictAllow {
			t.Errorf("control, a declared bind in the write entry, tier %v: %v %s", tier, res.Verdict, res.Rule)
		}
	}
}

// TestEvaluateUnixLandedOnNoSocket: a connect's or a datagram's name that reaches no socket when the agent calls (a
// directory, already there or one the name has the agent make; a file there that is not a socket: Action.NoSocket) is
// decided there as the supervisor decides any landing (decideResolved): a unix: entry whose resolved path it is admits
// it, the kernel then refusing the connect or the send itself; the nearest write entry's implicit admit holds only for
// a socket a process of the run bound (boundByRun), so it is refused unix-foreign; anything else is unmatched. The
// landing was decided as the socket the agent binds, so a datagram to out/x/y/.., out/d/ or out/d read allow where the
// run refuses it unix-foreign (design).
func TestEvaluateUnixLandedOnNoSocket(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/work", Raw: "./work", Resolved: "/work", Access: agent.AccessWriteSet}},
		Net: []agent.NetRule{{Proto: agent.ProtoUnix, Raw: "unix:/run/d.sock", UnixPath: "/run/d.sock", UnixResolved: "/run/d.sock",
			Verdict: agent.VerdictAllow}},
	}
	const named = "fs.write[./work]"
	for _, c := range []struct {
		kind     agent.ActionKind
		walk     agent.UnixWalk
		landed   string
		noSocket bool
		allow    bool
		rule     string
	}{
		{agent.ActionNetSend, agent.UnixWalkLookup, "/work/d", true, false, agent.UnixForeignRule},
		{agent.ActionNetConnect, agent.UnixWalkLookup, "/work/d", true, false, agent.UnixForeignRule},
		{agent.ActionNetSend, agent.UnixWalkLookup, "/run/d.sock", true, true, "net[unix:/run/d.sock]"},
		{agent.ActionNetConnect, agent.UnixWalkLookup, "/run/d.sock", true, true, "net[unix:/run/d.sock]"},
		{agent.ActionNetSend, agent.UnixWalkLookup, "/tmp/d", true, false, agent.UnmatchedRule},
		{agent.ActionNetSend, agent.UnixWalkStepwise, "/work/d", true, false, agent.UnixForeignRule},
		{agent.ActionNetConnect, agent.UnixWalkStepwise, "/work/d", true, false, agent.PathUnreliableRule},
		// Controls: the socket the name ends on, already there or bound by the agent, is the run's.
		{agent.ActionNetSend, agent.UnixWalkLookup, "/work/d", false, true, named},
		{agent.ActionNetConnect, agent.UnixWalkLookup, "/work/d", false, true, named},
	} {
		a := agent.Action{Kind: c.kind, Path: "unix:/work/lk/x", Landed: c.landed, Walk: c.walk, NoSocket: c.noSocket}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			res := Evaluate(rt, a, tier)
			if (res.Verdict == agent.VerdictAllow) != c.allow || res.Rule != c.rule {
				t.Errorf("%s landed %s (no socket %v, walk %d) tier %v = %v %s, want allow=%v %s", c.kind, c.landed, c.noSocket,
					c.walk, tier, res.Verdict, res.Rule, c.allow, c.rule)
			}
			if !c.allow && res.Reason != record.ReasonNetNotAllowed {
				t.Errorf("%s landed %s tier %v: reason %q", c.kind, c.landed, tier, res.Reason)
			}
		}
		if res := Evaluate(rt, a, backend.TierObserve); res.Verdict != agent.VerdictAllow {
			t.Errorf("%s landed %s observe: %v %s, want allow", c.kind, c.landed, res.Verdict, res.Rule)
		}
	}
	// A refusal of what the name reaches stays the supervisor's own where the kernel's programs would refuse the
	// spelling too.
	a := agent.Action{Kind: agent.ActionNetSend, Path: "unix:/work/./d", Landed: "/work/d", NoSocket: true, Uncanonical: true}
	if res := Evaluate(rt, a, backend.TierCgroup); res.Rule != agent.UnixForeignRule {
		t.Errorf("an uncanonical datagram to a directory: %v %s, want %s", res.Verdict, res.Rule, agent.UnixForeignRule)
	}
}

// TestEvaluateUnixAskScopeUnderWrite: a net.ask unix: scope inside a write entry is refused under the scope's own
// rule, as an ask compiles in P0 (SEMANTICS §3.1, agent-contract R15), not allowed through the write entry around it:
// the run holds that connect for a person (supervisor R11c), so a static evaluation cannot certify it. A socket
// beside the scope stays the write entry's, and a scope outside every write entry stays refused.
func TestEvaluateUnixAskScopeUnderWrite(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/work", Raw: "./work", Resolved: "/work", Access: agent.AccessWriteSet}},
		NetAsk: []agent.NetRule{
			{Proto: agent.ProtoUnix, UnixPath: "/work/app.sock", Verdict: agent.VerdictAsk},
			{Proto: agent.ProtoUnix, UnixPath: "/run/other.sock", Verdict: agent.VerdictAsk},
			{Proto: agent.ProtoUnix, UnixPath: "bus", Abstract: true, Verdict: agent.VerdictAsk},
			// /work/link is a symlink to /work/real: the run matches the scope's socket by the resolved spelling.
			{Proto: agent.ProtoUnix, UnixPath: "/work/link/app.sock", UnixResolved: "/work/real/app.sock", Verdict: agent.VerdictAsk},
		},
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, c := range []struct {
			path  string
			allow bool
			rule  string
		}{
			{"unix:/work/app.sock", false, rt.NetAsk[0].RuleName()},
			{"/work/sub/../app.sock", false, rt.NetAsk[0].RuleName()},
			{"/work/other.sock", true, rt.FS[0].RuleName()},
			{"/run/other.sock", false, ""},
			{"@bus", false, ""},
			{"/work/link/app.sock", false, rt.NetAsk[3].RuleName()},
			{"/work/real/app.sock", false, rt.NetAsk[3].RuleName()},
		} {
			res := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Path: c.path}, tier)
			if (res.Verdict == agent.VerdictAllow) != c.allow || (c.rule != "" && res.Rule != c.rule) {
				t.Errorf("tier %v connect %s = %v %s, want allow=%v %s", tier, c.path, res.Verdict, res.Rule, c.allow, c.rule)
			}
		}
	}
}

// TestEvaluateUnixLandedAtAnAskScope: a unix name whose walk lands at a net.ask unix: scope's place (Action.Landed
// equal to the scope's NetRule.UnixResolved) is answered as the run answers it (supervisor R11c), whatever its spelling
// (compile --test once landed the name and admitted it through the write entry
// around the scope, while the run asked or refused it). A connect no declared entry names is asked at the scope's place
// (unixScopeOf places the name by the walk), so it is refused under the scope's own rule, as an ask compiles in P0; a
// datagram, which nobody is asked about, and a connect a declared entry's spelling admits but whose walk reaches the
// scope's place, are refused unix-ask-scope (decideResolved). A landing beside the scope stays the write entry's.
func TestEvaluateUnixLandedAtAnAskScope(t *testing.T) {
	rt := &agent.RuleTable{
		FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/work", Raw: "./work", Resolved: "/work", Access: agent.AccessWriteSet}},
		Net: []agent.NetRule{{Proto: agent.ProtoUnix, Raw: "unix:/work/dec.sock", UnixPath: "/work/dec.sock", UnixResolved: "/work/dec.sock",
			Verdict: agent.VerdictAllow}},
		NetAsk: []agent.NetRule{{Proto: agent.ProtoUnix, Raw: "unix:/work/app.sock", UnixPath: "/work/app.sock", UnixResolved: "/work/real/app.sock",
			Verdict: agent.VerdictAsk}},
	}
	scope := rt.NetAsk[0].RuleName()
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, c := range []struct {
			kind         agent.ActionKind
			path, landed string
			allow        bool
			rule         string
		}{
			{agent.ActionNetConnect, "unix:/work/lnk.sock", "/work/real/app.sock", false, scope},
			{agent.ActionNetSend, "unix:/work/lnk.sock", "/work/real/app.sock", false, agent.UnixAskScopeRule},
			{agent.ActionNetConnect, "unix:/work/dec.sock", "/work/real/app.sock", false, agent.UnixAskScopeRule},
			{agent.ActionNetSend, "unix:/work/dec.sock", "/work/real/app.sock", false, agent.UnixAskScopeRule},
			{agent.ActionNetConnect, "unix:/work/lnk.sock", "/work/real/other.sock", true, "fs.write[./work]"},
			{agent.ActionNetSend, "unix:/work/lnk.sock", "/work/real/other.sock", true, "fs.write[./work]"},
			{agent.ActionNetConnect, "unix:/work/dec.sock", "/work/dec.sock", true, "net[unix:/work/dec.sock]"},
		} {
			res := Evaluate(rt, agent.Action{Kind: c.kind, Path: c.path, Landed: c.landed}, tier)
			if (res.Verdict == agent.VerdictAllow) != c.allow || res.Rule != c.rule {
				t.Errorf("tier %v %s %s landed %s = %v %s, want allow=%v %s", tier, c.kind, c.path, c.landed, res.Verdict, res.Rule, c.allow, c.rule)
			}
		}
	}
}
