// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// mcContracts are the command rules the differential tests decide under: deny, ask and constrained allow entries, alone
// and together, on rm, git, ls, npm and the uutils names whose applets end with another's (chmod and od, readlink and
// link, md5sum and sum).
var mcContracts = [][]string{
	{"deny: rm -r"},
	{"allow: rm -f", "deny: rm -r"},
	{"allow: rm -i"},
	{"allow: git status", "allow: git log", "deny: git push", "deny: rm -r", "ask: npm install"},
	{"allow: ls -l", "deny: rm -r"},
	{"allow: ls", "allow: cat", "deny: od", "deny: link", "deny: sum"},
	{"ask: rm"},
	{"deny: coreutils"},
	{"deny: cargo publish"},
}

// mcIndex builds an index from entries written "deny: rm -r".
func mcIndex(t testing.TB, entries []string) *execmatch.Index {
	t.Helper()
	var ps []*execmatch.Pattern
	for _, e := range entries {
		list, body, _ := strings.Cut(e, ": ")
		l := map[string]execmatch.List{"allow": execmatch.ListAllow, "deny": execmatch.ListDeny, "ask": execmatch.ListAsk}[list]
		p, err := execmatch.Parse(body, l, rows.Builtin())
		if err != nil {
			t.Fatalf("Parse(%q): %v", body, err)
		}
		ps = append(ps, p)
	}
	return execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})
}

// multicallFacts reports whether any file the facts walk is one the readings gate on (execmatch.IsMulticallImage, held
// to its own table by TestMulticallGate), named by the walk's name, or by the name it was reached by when the walk
// gave none.
func multicallFacts(ix *execmatch.Index, f *execmatch.Facts) bool {
	named := func(image, reached string) string {
		if image != "" {
			return image
		}
		if reached == "" {
			return ""
		}
		return path.Base(reached)
	}
	reached := f.Path
	if reached == "" {
		reached = f.Requested
	}
	if execmatch.IsMulticallImage(ix, f.Links, named(f.Image, reached)) {
		return true
	}
	for _, st := range f.Interp {
		if execmatch.IsMulticallImage(ix, st.Links, named(st.Image, st.Path)) {
			return true
		}
	}
	return f.Loaded != nil && execmatch.IsMulticallImage(ix, f.Loaded.Links, named(f.Loaded.Image, f.Loaded.Path))
}

// prefixHolds is the staged read's property (ADR 0048 (3)) for one exec: a decision made on a prefix of its argv that
// says Final and does not refuse is the decision of the whole argv. A Final none or allow on a prefix ends the
// supervisor's read, so a whole argv that a deny entry meets would run unread.
func prefixHolds(ix *execmatch.Index, f *execmatch.Facts) string {
	whole := ix.Decide(f)
	for k := 0; k < len(f.Argv); k++ {
		p := *f
		p.Argv, p.ArgvComplete = f.Argv[:k], false
		r := ix.Decide(&p)
		if r.Final && r.Outcome != execmatch.OutcomeRefused && (r.Outcome != whole.Outcome || r.Rule() != whole.Rule()) {
			return fmt.Sprintf("prefix of %d: %s %s Final, whole argv: %s %s", k, r.Outcome, r.Rule(), whole.Outcome, whole.Rule())
		}
	}
	return ""
}

// onlyTightens holds one exec's decision with the multicall readings (now) to the one without them (was): on an exec
// that walks no multicall image they are equal in every field; on one that does, they differ only where now is a
// deny or ask refusal through a multicall applet, or a fail-closed overflow, and was did not already refuse under a
// deny or ask entry; or where now reads more argv (Final false) for the same outcome. A constrained tool's unlisted
// invocation stays refused, and names the deny entry first, as ADR 0048 (1)'s precedence orders them. No allow entry
// ever decides differently: now never allows what was did not, never refuses as unlisted what was did not, and never
// names an allow entry was did not.
func onlyTightens(ix *execmatch.Index, f *execmatch.Facts, was, now execmatch.Result) string {
	same := was.Outcome == now.Outcome && was.Rule() == now.Rule() && was.Via == now.Via && was.Match == now.Match && was.K == now.K
	if same && was.Final == now.Final {
		return ""
	}
	if !multicallFacts(ix, f) {
		return "changed on an exec of no multicall image"
	}
	if same {
		if !now.Final {
			return ""
		}
		return "settled where it read more before"
	}
	if was.Outcome == execmatch.OutcomeRefused && !was.Unlisted {
		return "a refusal changed"
	}
	if now.Outcome != execmatch.OutcomeRefused || now.Unlisted || now.List == execmatch.ListAllow {
		return "the allow side changed"
	}
	if !now.Overflow && now.Via != execmatch.ViaMulticall {
		return "a deny or ask refusal not through a multicall applet"
	}
	return ""
}

// TestMulticallOnlyTightens is the differential proof that the multicall readings change no allow decision: every exec
// of a vocabulary of names, link counts and argv, under every contract of mcContracts, decided with and without them
// (onlyTightens). It also counts the decisions that changed, so a vocabulary that reaches none fails.
func TestMulticallOnlyTightens(t *testing.T) {
	requested := []string{"/usr/bin/ls", "/proc/self/fd/3", "/w/xrm", "/w/uu-rm", "/usr/bin/coreutils", "/usr/bin/rm", "/usr/bin/git"}
	images := []string{"ls", "coreutils", "rm", "git", "busybox", "unzip"}
	argv0s := []string{"ls", "rm", "xrm", "rm.x", "farm", "myutils", "xbox", "git", "chmod", "xod"}
	tails := [][]string{nil, {"-r", "x"}, {"-f", "x"}, {"rm", "-r", "x"}, {"push"}, {"status"}, {"-l", "-r"}, {"install", "x"}}
	changed, allowFlips := 0, 0
	for _, entries := range mcContracts {
		now := mcIndex(t, entries)
		was := execmatch.WithoutMulticall(now)
		for _, req := range requested {
			for _, image := range images {
				for _, argv0 := range argv0s {
					for _, tail := range tails {
						for _, links := range []uint64{0, 1, 116} {
							for _, complete := range []bool{true, false} {
								argv := append([]string{argv0}, tail...)
								f := execmatch.Facts{Requested: req[strings.LastIndexByte(req, '/')+1:], Path: req, Image: image, Argv0: argv0,
									Argv: argv, ArgvComplete: complete, Links: links}
								w, n := was.Decide(&f), now.Decide(&f)
								if why := onlyTightens(now, &f, w, n); why != "" {
									t.Fatalf("%v: %s on %+v: was %s %s via %s final %v, now %s %s via %s final %v", entries, why, f,
										w.Outcome, w.Rule(), w.Via, w.Final, n.Outcome, n.Rule(), n.Via, n.Final)
								}
								if w.Outcome != n.Outcome {
									changed++
									if w.Outcome == execmatch.OutcomeAllowed {
										allowFlips++
									}
								}
								if was.Guarded(&f) && !now.Guarded(&f) {
									t.Fatalf("%v: %+v guarded without the readings and not with them", entries, f)
								}
							}
						}
					}
				}
			}
		}
	}
	if changed == 0 {
		t.Fatal("no decision changed: the vocabulary reaches no multicall applet")
	}
	t.Logf("%d decisions changed, all deny or ask refusals of multicall images; %d of them an exec an allow entry admitted, which a deny entry now refuses too", changed, allowFlips)
}

// TestMulticallDenyWinsOverAnAllowedReading: where a multicall exec's names read both as a tool an allow entry admits
// and as an applet a deny entry names, the deny entry refuses it, as deny entries do over every other reading (ADR 0048
// (1)). The allow side's own answer is unchanged: without the deny entry the exec is allowed as before.
func TestMulticallDenyWinsOverAnAllowedReading(t *testing.T) {
	f := execmatch.Facts{Requested: "3", Path: "/proc/self/fd/3", Image: "ls", Argv0: "xrm", Argv: []string{"xrm", "-l", "-r", "x"},
		ArgvComplete: true, Links: 116}
	if r := mcIndex(t, []string{"allow: ls -l", "deny: rm -r"}).Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[rm -r]" || r.Via != execmatch.ViaMulticall {
		t.Errorf("allow ls -l, deny rm -r: %s %s via %s, want refused exec.deny[rm -r] via multicall", r.Outcome, r.Rule(), r.Via)
	}
	if r := mcIndex(t, []string{"allow: ls -l", "allow: rm -f"}).Decide(&f); r.Outcome == execmatch.OutcomeRefused {
		t.Errorf("allow ls -l, allow rm -f: %s %s, want the allow side's answer of before", r.Outcome, r.Rule())
	}
}

// FuzzMulticallOnlyTightens is onlyTightens over any names, link count and argv, seeded with the nine name forms of
// rows/multicall_test.go's nameForms (2026-11-11), the forms the Ubuntu 26.04.1 guest ran (ADR 0048's amendment of
// 2026-11-11, What was measured), and two vectors whose prefixes settled where the whole vector is refused.
func FuzzMulticallOnlyTightens(f *testing.F) {
	for _, s := range []struct {
		req, image, argv string
		links            uint64
	}{
		{"/usr/bin/ls", "ls", "rm -r x", 116},
		{"/usr/bin/coreutils", "coreutils", "coreutils rm -r x", 116},
		{"/proc/self/fd/3", "ls", "xrm -r x", 116},
		{"/proc/self/fd/3", "ls", "rm.x -r x", 116},
		{"/proc/self/fd/3", "ls", "farm -r x", 116},
		{"/w/xrm", "ls", "xrm -r x", 116},
		{"/proc/self/fd/3", "ls", "myutils rm -r x", 116},
		{"/proc/self/fd/3", "ls", "xbox rm -r x", 116},
		{"/w/uu-rm", "ls", "uu-rm -r x", 116},
		{"/dev/fd/3", "ls", "xrm -r out/victim", 116},
		{"/home/tego/out/links/xrm", "ls", "xrm -r out/victim", 116},
		{"/usr/lib/cargo/bin/coreutils/ls", "ls", "rm/. -r x", 2},
		{"/usr/bin/ls", "ls", "ls -l", 1},
		{"/usr/bin/chmod", "chmod", "chmod +x f", 116},
		// The sh row settled a prefix of this on none while the whole vector is refused command-unresolved.
		{"sh", "0", " +c0 +0 +0 +0 +0 +0 ", 0},
		// denySettled settled a prefix of this on none: cargo, reached only through the argv[1] dispatch, located at build
		// and pending, while the whole vector is refused under deny: cargo publish (TestMulticallPrefixPendingReading).
		{"/proc/self/fd/3", "ls", "myutils ./cargo build" + strings.Repeat(" --features f", 15) + " --config alias.build=publish", 116},
	} {
		f.Add(s.req, s.image, s.argv, s.links, true)
	}
	ixs := make([]*execmatch.Index, len(mcContracts))
	for i, entries := range mcContracts {
		ixs[i] = mcIndex(f, entries)
	}
	f.Fuzz(func(t *testing.T, req, image, line string, links uint64, complete bool) {
		if len(line) > 512 || len(req) > 512 || len(image) > 255 {
			return
		}
		argv := strings.Split(line, " ")
		fx := execmatch.Facts{Requested: req[strings.LastIndexByte(req, '/')+1:], Path: req, Image: image, Argv0: argv[0], Argv: argv,
			ArgvComplete: complete, Links: links}
		for i, now := range ixs {
			w, n := execmatch.WithoutMulticall(now).Decide(&fx), now.Decide(&fx)
			if why := onlyTightens(now, &fx, w, n); why != "" {
				t.Fatalf("%v: %s on %+v: was %s %s via %s, now %s %s via %s", mcContracts[i], why, fx, w.Outcome, w.Rule(), w.Via, n.Outcome, n.Rule(), n.Via)
			}
			// The staged-read property, with and without the readings (rows' FuzzPrefixFinalHolds holds it for every row).
			if complete {
				if why := prefixHolds(now, &fx); why != "" {
					t.Fatalf("%v: %+v: %s", mcContracts[i], fx, why)
				}
			}
		}
	})
}

// TestMulticallPrefixFinalHolds is prefixHolds over a vocabulary of multicall execs (116 links) under every contract of
// mcContracts, every argv[0] read whole as the supervisor reads it before its staged read, at every prefix length.
func TestMulticallPrefixFinalHolds(t *testing.T) {
	requested := []string{"/usr/bin/ls", "/proc/self/fd/3", "/w/xrm", "/w/xbox", "/w/myutils", "/usr/bin/coreutils"}
	argv0s := []string{"ls", "xrm", "myutils", "xbox", strings.Repeat("A", 8191), strings.Repeat("A", 8187) + "xbox", "coreutils"}
	tails := [][]string{{"rm", "-r", "x"}, {"-r", "x"}, {"git", "push"}, {"npm", "install", "x"}, {"-f", "rm", "-r"}}
	for _, entries := range mcContracts {
		ix := mcIndex(t, entries)
		for _, req := range requested {
			for _, image := range []string{"ls", "coreutils"} {
				for _, argv0 := range argv0s {
					for _, tail := range tails {
						argv := append([]string{argv0}, tail...)
						f := execmatch.Facts{Requested: req[strings.LastIndexByte(req, '/')+1:], Path: req, Image: image, Argv0: argv0,
							Argv: argv, ArgvComplete: true, Links: 116}
						if why := prefixHolds(ix, &f); why != "" {
							t.Errorf("%v: %s, image %s, argv %.40q: %s", entries, req, image, argv, why)
						}
					}
				}
			}
		}
	}
}

// TestMulticallPrefixPendingReading: an invocation reached only through a multicall image's readings is not settled
// while one of its readings is pending (Reading.Pending), as the matcher's own readings are not (settled). Under the
// argv[1] dispatch of a uutils image (stem myutils or xbox), `./cargo build`, fifteen `--features f` pairs, then
// `--config alias.build=publish` is refused under deny: cargo publish and ask: cargo publish, and no prefix of it is a
// final none (review of 2026-11-11: the 32-element prefix was).
func TestMulticallPrefixPendingReading(t *testing.T) {
	tail := []string{"./cargo", "build"}
	for range 15 {
		tail = append(tail, "--features", "f")
	}
	tail = append(tail, "--config", "alias.build=publish")
	for _, fx := range []execmatch.Facts{
		{Requested: "3", Path: "/proc/self/fd/3", Image: "ls", Argv0: "myutils", Links: 116},
		{Requested: "myutils", Path: "/w/myutils", Image: "ls", Argv0: "myutils", Links: 116},
		{Requested: "3", Path: "/proc/self/fd/3", Image: "ls", Argv0: "xbox", Links: 116},
	} {
		fx.Argv, fx.ArgvComplete = append([]string{fx.Argv0}, tail...), true
		for _, entry := range []string{"deny: cargo publish", "ask: cargo publish"} {
			ix := mcIndex(t, []string{entry})
			if r := ix.Decide(&fx); r.Outcome != execmatch.OutcomeRefused || r.Via != execmatch.ViaMulticall {
				t.Errorf("%s, %s argv0 %s: whole vector %s %s via %s, want refused via multicall", entry, fx.Path, fx.Argv0,
					r.Outcome, r.Rule(), r.Via)
			}
			if why := prefixHolds(ix, &fx); why != "" {
				t.Errorf("%s, %s argv0 %s: %s", entry, fx.Path, fx.Argv0, why)
			}
		}
	}
}

// TestMulticallGate: the files the readings gate on. More than one link and a walked name a uutils build links its file
// under: a name ending with a listed utility, one ending in utils or box, or one of the row's other link names; or a
// file named coreutils, whatever its count. A hard-linked program of another name is not one (unzip, perl).
func TestMulticallGate(t *testing.T) {
	ix := mcIndex(t, []string{"deny: rm -r"})
	for _, c := range []struct {
		links uint64
		image string
		want  bool
	}{
		{116, "ls", true}, {2, "xrm", true}, {2, "uu-rm", true}, {2, "[", true}, {2, "relpath", true}, {2, "hashsum", true},
		{2, "b3sum", true}, {2, "myutils", true}, {2, "busybox", true}, {2, "coreutils", true}, {0, "coreutils", true},
		{1, "coreutils", true}, {1, "ls", false}, {0, "ls", false}, {1, "busybox", false},
		{2, "unzip", false}, {2, "zipinfo", false}, {2, "perl", false}, {2, "perl5.40.1", false}, {2, "perlthanks", false},
		{2, "", false},
	} {
		if got := execmatch.IsMulticallImage(ix, c.links, c.image); got != c.want {
			t.Errorf("%q of %d links: %v, want %v", c.image, c.links, got, c.want)
		}
	}
}
