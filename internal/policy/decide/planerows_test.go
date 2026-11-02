// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// genDenyWrite is the deny_write targets a generated table may carry: compile keeps one only beneath a write entry
// and never at a write entry's own path (compile_denywrite.go), so each is tried against every table. A target
// spelled "declared=resolved" is declared through a symlink (a .git/hooks linked elsewhere): its Path and Resolved
// differ, and compile keeps it by the resolved path.
var genDenyWrite = [][]string{{"/w/a/b"}, {"/w/a/b/c"}, {"/w/a"}, {"/x/t"}, {"/w/a/b/c/t"}, {"/w/a/b/c/t", "/w/a/b"},
	{"/w/a/l=/w/a/b"}, {"/w/l/t=/w/a/b/c/t"}, {"/w/a/l=/w/a/b", "/w/a/b/c"}}

// renameDests are the destinations every probe is renamed to: one beneath each kind of place a table makes.
var renameDests = []string{"/w/f", "/w/a", "/w/a/b/f", "/w/a/b/c/t", "/x/f", "/y/f"}

// planeProbes is genPaths with the paths the deny_write pool adds.
var planeProbes = append(append([]string{}, genPaths...), "/x", "/x/t", "/x/t/f", "/w/a/b/c/t", "/w/a/b/c/t/f",
	"/w/a/l", "/w/a/l/f", "/w/l", "/w/l/t", "/w/l/t/f")

// genPlaneTables calls fn with every generated table at bpflsm and, for each, every variant carrying a set of
// deny_write targets compile would keep.
func genPlaneTables(fn func(desc string, rt *agent.RuleTable)) int {
	n := 0
	genTables(backend.TierBPFLSM, func(desc string, rt *agent.RuleTable) {
		n++
		fn(desc, rt)
	nextSet:
		for _, set := range genDenyWrite {
			var dw []agent.FSRule
			for _, spec := range set {
				decl, t, linked := strings.Cut(spec, "=")
				if !linked {
					t = decl
				}
				// A declared spelling above every write entry is refused by both, naming different rules (as
				// checkPlaneRename says); the pool keeps each spelling beneath one.
				under, declUnder := false, false
				for _, r := range rt.FS {
					if r.Kind != agent.FSWrite {
						continue
					}
					if r.Governed() == t || r.Governed() == decl {
						continue nextSet
					}
					under = under || agent.Covers(r.Governed(), t)
					declUnder = declUnder || agent.Covers(r.Governed(), decl)
				}
				if !under || !declUnder {
					continue nextSet
				}
				dw = append(dw, agent.FSRule{Kind: agent.FSDenyWrite, Path: decl, Resolved: t, BuiltIn: true, Unenforced: true})
			}
			v := *rt
			v.DenyWrite = dw
			n++
			fn(desc+"deny_write:"+strings.Join(set, ","), &v)
		}
	})
	return n
}

// TestPlaneRowsMatchEvaluate is TIER3-PLAN T5's parity property (enforce-plane R25): for every generated table (with and without
// deny_write targets), the compiled rows, walked as the kernel walks them (first row met decides), answer every fs
// action on every probe path as Evaluate's bpflsm column does: the verdict, and for a refusal the rule and reason
// the ledger line carries. Where the rows have a RootRow form, RootIndex.Walk over them answers as the rows' walk.
// With ADR 0043's name dimensions (genNameTables, the build's switch on), the rows' walk and then the kernel's name
// check over the name rows (PlaneRows.DecideObject, ScopeMoveRefused) answer as Evaluate does, the object a file or
// a directory.
func TestPlaneRowsMatchEvaluate(t *testing.T) {
	bad := 0
	fail := func(format string, args ...any) {
		bad++
		if bad < 20 {
			t.Errorf(format, args...)
		}
	}
	tables := genPlaneTables(sampled(func(desc string, rt *agent.RuleTable) {
		checkPlaneRows(t, desc, rt, planeProbes, renameDests, false, fail)
	}))
	if tables < 1000 {
		t.Fatalf("only %d tables generated", tables)
	}
	named := genNameTables(sampledNames(func(desc string, rt, _ *agent.RuleTable) {
		checkPlaneRows(t, desc, rt, nameProbes, nameRenameDests, true, fail)
	}))
	if named < 1000 {
		t.Fatalf("only %d tables with name entries", named)
	}
}

// checkPlaneRows is TestPlaneRowsMatchEvaluate's question of one table, over probes renamed to dests; dirs asks each
// probe as a directory too.
func checkPlaneRows(t *testing.T, desc string, rt *agent.RuleTable, probes, dests []string, dirs bool, fail func(string, ...any)) {
	t.Helper()
	kinds := []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir}
	s, err := CompilePlane(rt)
	if err != nil {
		fail("%s: %v", desc, err)
		return
	}
	rows, projectable := s.RootRows()
	x := NewRootIndex(rows)
	objects := []bool{false}
	if dirs {
		objects = append(objects, true)
	}
	for _, p := range probes {
		cp := Canonical(rt, cleanPath(p)) // the spelling the kernel's dentry walk meets
		for _, k := range kinds {
			q := PlaneModify
			if k == agent.ActionFSRead {
				q = PlaneRead
			}
			if projectable {
				if w, v := x.Walk(cp, q == PlaneRead), s.Decide(cp, q); w.Allow != v.Allow {
					fail("%s %s %s: RootIndex.Walk over the rows %+v, plane %+v", desc, k, p, w, v)
				}
			}
			for _, dir := range objects {
				a := agent.Action{Kind: k, Path: p, Dir: dir}
				v := s.DecideObject(cp, q, objectOf(a) == objDir)
				ev := Evaluate(rt, a, backend.TierBPFLSM)
				if v.Allow && k == agent.ActionFSDelete {
					// The run keeps the Landlock ruleset under the plane, which asks an unlink's REMOVE_* of the
					// directory the hooks do not ask: what the rows allow, the floor may refuse.
					if l, refused := (&Evaluator{rt: rt}).landlockDelete(canonicalEnd(rt, cleanPath(p))); refused {
						if ev.Verdict != l.Verdict || ev.Rule != l.Rule || ev.Reason != l.Reason {
							fail("%s %s %s dir=%v: plane allows, the Landlock floor refuses %+v, Evaluate %+v", desc, k, p, dir, l, ev)
						}
						continue
					}
				}
				if v.Allow != (ev.Verdict == agent.VerdictAllow) {
					fail("%s %s %s dir=%v: plane %+v, Evaluate %+v", desc, k, p, dir, v, ev)
					continue
				}
				if v.Allow {
					continue
				}
				if name, reason := PlaneRefusal(rt, v, k); name != ev.Rule || reason != ev.Reason {
					fail("%s %s %s dir=%v: plane names %s/%s, Evaluate %+v", desc, k, p, dir, name, reason, ev)
				}
			}
		}
	}
	for _, src := range probes {
		for _, dst := range dests {
			for _, dir := range objects {
				checkPlaneRename(t, s, rt, desc, src, dst, dir, fail)
			}
		}
	}
}

// checkPlaneRename holds a rename to Evaluate's: each end refused as a rename of itself (a deny_write target or a
// directory above one refuses at depth 0, enforce-plane R11) or as a modification, then REFER. The one difference
// is the rule named for an end that lies above every write entry and above a deny_write target: Evaluate names the
// target, the plane (which keys no row there) names the nearest entry. Both refuse, for the same reason: no write
// entry covers that end, so the modification is refused before the target is asked.
func checkPlaneRename(t *testing.T, s *PlaneRows, rt *agent.RuleTable, desc, src, dst string, dir bool, fail func(string, ...any)) {
	t.Helper()
	ev := Evaluate(rt, agent.Action{Kind: agent.ActionFSRename, Path: src, DestPath: dst, Dir: dir}, backend.TierBPFLSM)
	src, dst = Canonical(rt, cleanPath(src)), Canonical(rt, cleanPath(dst))
	v, end := s.DecideObject(src, PlaneRename, dir), src
	if v.Allow {
		v, end = s.DecideObject(dst, PlaneRename, dir), dst
	}
	name, reason := "", record.Reason("")
	if !v.Allow {
		name, reason = PlaneRefusal(rt, v, agent.ActionFSRename)
	} else {
		sv := s.Decide(src, PlaneRead)
		name = agent.UnmatchedRule
		if sv.Named >= 0 {
			name = rt.FS[sv.Named].RuleName()
		}
		if PlaneReferRefused(s.KindAt(src), s.KindAt(dst)) {
			v.Allow, reason = false, record.ReasonRenameOutsideContract
		} else if rule, unresolved, refused := s.ScopeMoveRefused(src, dst); refused && dir {
			v.Allow, reason, name = false, record.ReasonRenameOutsideContract, rule.Name(rt)
			if unresolved {
				reason, name = record.ReasonPathUnresolved, agent.UnmatchedRule
			}
		} else if rule, refused := (&Evaluator{rt: rt}).landlockRename(src, dst, dir, true); refused {
			// The Landlock floor under the plane: REFER on both directories, then its no-gain rule.
			v.Allow, reason, name = false, record.ReasonRenameOutsideContract, rule
		}
	}
	if v.Allow != (ev.Verdict == agent.VerdictAllow) || reason != ev.Reason {
		fail("%s rename %s -> %s dir=%v: plane %+v (%s/%s), Evaluate %+v", desc, src, dst, dir, v, name, reason, ev)
		return
	}
	if name == ev.Rule {
		return
	}
	if _, ok := denyWriteIdx(rt, end, true); ok && !v.Allow && !underWrite(rt, end) {
		return // the stated difference above
	}
	fail("%s rename %s -> %s: plane names %s, Evaluate %+v", desc, src, dst, name, ev)
}

func underWrite(rt *agent.RuleTable, p string) bool {
	for _, r := range rt.FS {
		if r.Kind == agent.FSWrite && agent.Covers(r.Canonical(), p) {
			return true
		}
	}
	return false
}

// TestPlaneRowsDenyWriteAncestors: a deny_write target is a row refusing every modification beneath it, and each
// directory from it up to the outermost write entry refuses a rename of itself while still allowing what the write
// entry allows beneath it (enforce-plane R11: `mv .git .git.old` is refused, `touch .git/x` is not).
func TestPlaneRowsDenyWriteAncestors(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/h", Raw: "/h", Resolved: "/h", Access: agent.AccessWriteSet},
			{Kind: agent.FSWrite, Path: "/h/p", Raw: "/h/p", Resolved: "/h/p", Access: agent.AccessWriteSet},
		},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/h/p/.git/hooks", Resolved: "/h/p/.git/hooks", BuiltIn: true, Unenforced: true}},
	}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range s.FS {
		got = append(got, r.Path)
	}
	if strings.Join(got, " ") != "/h /h/p /h/p/.git /h/p/.git/hooks" {
		t.Fatalf("rows at %v, want the target and every directory up to the outermost write entry /h", got)
	}
	for _, tc := range []struct {
		path  string
		q     PlaneQuestion
		allow bool
	}{
		{"/h/p/.git", PlaneRename, false},
		{"/h/p", PlaneRename, false},
		{"/h", PlaneRename, false},
		{"/h/p/.git/x", PlaneModify, true},
		{"/h/p/.git/x", PlaneRename, true},
		{"/h/p/.git/hooks", PlaneModify, false},
		{"/h/p/.git/hooks/pre-commit", PlaneModify, false},
		{"/h/p/.git/hooks/pre-commit", PlaneRead, true},
		{"/h/q", PlaneRename, true},
	} {
		if v := s.Decide(tc.path, tc.q); v.Allow != tc.allow {
			t.Errorf("%s q=%d: %+v, want allow=%v", tc.path, tc.q, v, tc.allow)
		}
	}
	if v := s.Decide("/h/p/.git", PlaneRename); v.Rule != (PlaneRule{Section: PlaneDenyWriteRule, Index: 0}) {
		t.Errorf("a rename of /h/p/.git names %+v, want the deny_write target", v.Rule)
	}
	if k := s.FS[2].Kind; k != PlaneModifyAllow|PlaneRenameRefused {
		t.Errorf("/h/p/.git kind %04b, want modify-allow and rename-refused", k)
	}
	if _, ok := s.RootRows(); ok {
		t.Error("a row decided by a deny_write target has no RootRow form")
	}
}

// TestPlaneRowsKeyALinkedTargetAtItsOwnInode: a deny_write target declared through a symlink (.git/hooks ->
// real-hooks) keys the link itself and its directories up to the write entry, unfollowed (PlaneRows.NoFollow), so
// unlinking or renaming the link is refused in the kernel as the model refuses it (enforce-plane R11).
func TestPlaneRowsKeyALinkedTargetAtItsOwnInode(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS:        []agent.FSRule{{Kind: agent.FSWrite, Path: "/h", Raw: "/h", Resolved: "/h", Access: agent.AccessWriteSet}},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/h/.git/hooks", Resolved: "/h/real-hooks", BuiltIn: true, Unenforced: true}},
	}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.NoFollow, " "); got != "/h/.git /h/.git/hooks" {
		t.Errorf("NoFollow = %q, want the link and its directory below the write entry", got)
	}
	if got := strings.Join(s.Keyed, " "); got != "/h /h/real-hooks" {
		t.Errorf("Keyed = %q, want the resolved chain alone (a link row is not opened following)", got)
	}
	for _, q := range []PlaneQuestion{PlaneModify, PlaneRename} {
		if v := s.Decide("/h/.git/hooks", q); v.Allow || v.Rule != (PlaneRule{Section: PlaneDenyWriteRule, Index: 0}) {
			t.Errorf("q=%d on the link: %+v, want refused by the deny_write target", q, v)
		}
		if _, ok := rt.DenyWriteTarget("/h/.git/hooks", q == PlaneRename); !ok {
			t.Errorf("q=%d: the model does not protect the link; the test's premise is gone", q)
		}
	}
	if v := s.Decide("/h/.git", PlaneRename); v.Allow {
		t.Errorf("a rename of /h/.git, above the link: %+v, want refused", v)
	}
	if v := s.Decide("/h/.git/x", PlaneModify); !v.Allow {
		t.Errorf("a write beside the link: %+v, want allowed", v)
	}
}

// TestPlaneKindStrictness: REFER's order (enforce-plane R10), and that a move to a stricter row passes where one to a looser row does
// not (enforce-plane R10).
func TestPlaneKindStrictness(t *testing.T) {
	write, read, deny := PlaneModifyAllow, PlaneKind(0), PlaneReadDeny
	for _, tc := range []struct {
		src, dst PlaneKind
		refused  bool
	}{
		{write, write, false}, {write, read, false}, {write, deny, false},
		{read, write, true}, {read, read, false}, {read, deny, false},
		{deny, write, true}, {deny, read, true}, {deny, deny, false},
		{deny | PlaneRenameRefused | PlaneExecDir, deny, false},
	} {
		if got := PlaneReferRefused(tc.src, tc.dst); got != tc.refused {
			t.Errorf("%04b -> %04b: refused=%v, want %v", tc.src, tc.dst, got, tc.refused)
		}
	}
}

// genExecPool is the exec entries a generated exec table draws from.
var genExecPool = []agent.ExecRule{
	{Path: "/usr/bin/a", Resolved: "/usr/bin/a", Raw: "/usr/bin/a", Basename: "a", Verdict: agent.VerdictAllow},
	{Path: "/usr/bin", Resolved: "/usr/bin", Raw: "/usr/bin", IsDir: true, Verdict: agent.VerdictAllow},
	{Path: "/opt", Resolved: "/opt", Raw: "/opt", IsDir: true, Verdict: agent.VerdictAllow},
	{Path: "/usr/bin/a", Resolved: "/usr/bin/a", Raw: "a", Basename: "a", ByName: true, Verdict: agent.VerdictAllow},
	{Path: "/bin/sh", Resolved: "/usr/bin/dash", Raw: "/bin/sh", Basename: "sh", Verdict: agent.VerdictAllow},
	{Path: "/opt/x/b", Resolved: "/opt/x/b", Raw: "/opt/x/b", Basename: "b", Verdict: agent.VerdictAllow},
	{Path: "/l/tools", Resolved: "/srv/tools", Raw: "/l/tools", IsDir: true, Verdict: agent.VerdictAllow},
}

// execProbes are canonical files: none passes through a declared spelling that is a link.
var execProbes = []string{"/usr/bin/a", "/usr/bin/b", "/usr/bin/dash", "/usr/bin", "/opt/x/b", "/opt/b", "/tmp/a",
	"/tmp/b", "/tmp/sh", "/srv/tools/rg", "/srv/tools/sub/fd", "/srv/toolsx/rg", "/home/u/.venv/bin/a"}

// TestPlaneExecMatchesMatchExec: the exec rows, the directory bit on the fs rows and the name rows answer every
// canonical file as matchExec does at tier 3, for every table of one to three entries of genExecPool beside one fs
// table, with the lowest entry winning (SEMANTICS §4).
func TestPlaneExecMatchesMatchExec(t *testing.T) {
	fs := []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/opt/x", Raw: "/opt/x", Resolved: "/opt/x", Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: "/usr/bin/secret", Raw: "/usr/bin/secret", Resolved: "/usr/bin/secret"},
	}
	n, count := len(genExecPool), 0
	check := func(idx ...int) {
		var ex []agent.ExecRule
		for _, i := range idx {
			ex = append(ex, genExecPool[i])
		}
		rt := &agent.RuleTable{FS: fs, Exec: ex, Tier: backend.TierBPFLSM}
		s, err := CompilePlane(rt)
		if err != nil {
			t.Fatalf("%v: %v", idx, err)
		}
		count++
		for _, p := range execProbes {
			want, wantOK := matchExec(rt, p, backend.TierBPFLSM)
			got, ok := s.ExecMatch(p)
			if ok != wantOK || got != want {
				t.Errorf("%v %s: plane entry %d (%v), matchExec %d (%v)", idx, p, got, ok, want, wantOK)
			}
		}
		for _, e := range s.Exec {
			if !keyed(s, e.Path) || !keyed(s, e.Parent) {
				t.Errorf("%v: exec row %+v: executable and directory must both be keyed", idx, e)
			}
		}
	}
	for a := 0; a < n; a++ {
		check(a)
		for b := a + 1; b < n; b++ {
			check(a, b)
			for c := b + 1; c < n; c++ {
				check(a, b, c)
			}
		}
	}
	if count < 60 {
		t.Fatalf("only %d exec tables", count)
	}
}

func keyed(s *PlaneRows, p string) bool {
	for _, k := range s.Keyed {
		if k == p {
			return true
		}
	}
	return false
}

// llRule is one rule of the Landlock plan as the builder adds it: an inode (a path here) and its rights.
type llRule struct {
	path   string
	access agent.AccessSet
}

// landlockPlanModel is the tier-1/2 Landlock plan written out as rules, independently of the core's grant model
// (enforce-landlock R3, R5): write entries with the read set and their rights, exec entries with READ_FILE and
// EXECUTE (and READ_DIR on a directory), and either the read set on "/" or the enumeration of the enforced deny_read
// targets: READ_DIR on each ancestor level and the read set on each sibling of names, which stands for a directory
// listing.
func landlockPlanModel(rt *agent.RuleTable, names []string) []llRule {
	const read = agent.AccessReadFile | agent.AccessReadDir
	var out []llRule
	for _, r := range rt.FS {
		if r.Kind == agent.FSWrite {
			out = append(out, llRule{r.Governed(), r.Access | read})
		}
	}
	for i := range rt.Exec {
		r := &rt.Exec[i]
		p := r.Resolved
		if p == "" {
			p = r.Path
		}
		a := agent.AccessReadFile | agent.AccessExecute
		if r.IsDir {
			a |= agent.AccessReadDir
		}
		out = append(out, llRule{p, a})
	}
	var targets []string
	for _, r := range rt.FS {
		if r.Kind == agent.FSDenyRead && !r.Unenforced && r.Governed() != "/" {
			targets = append(targets, r.Governed())
		}
	}
	if len(targets) == 0 {
		return append(out, llRule{"/", read})
	}
	onPath := func(p string) bool { // p is a target or lies on the way to one
		for _, t := range targets {
			if agent.Covers(p, t) {
				return true
			}
		}
		return false
	}
	levels := map[string]bool{}
	for _, t := range targets {
		for cur := filepath.Dir(t); ; cur = filepath.Dir(cur) {
			inside := false
			for _, o := range targets {
				inside = inside || (o != t && agent.Covers(o, cur))
			}
			if !inside {
				levels[cur] = true
			}
			if cur == "/" {
				break
			}
		}
	}
	for l := range levels {
		out = append(out, llRule{l, agent.AccessReadDir})
		for _, n := range names {
			if c := filepath.Join(l, n); !onPath(c) && !insideAny(targets, c) {
				out = append(out, llRule{c, read})
			}
		}
	}
	return out
}

// enumeratedLevel reports whether p is a directory strictly above an enforced deny_read target and at or inside
// none.
func enumeratedLevel(rt *agent.RuleTable, p string) bool {
	above := false
	for _, r := range rt.FS {
		if r.Kind != agent.FSDenyRead || r.Unenforced {
			continue
		}
		if agent.Covers(r.Governed(), p) {
			return false
		}
		above = above || agent.Covers(p, r.Governed())
	}
	return above
}

func insideAny(targets []string, p string) bool {
	for _, t := range targets {
		if agent.Covers(t, p) {
			return true
		}
	}
	return false
}

func llGrant(rules []llRule, p string) agent.AccessSet {
	var a agent.AccessSet
	for _, r := range rules {
		if agent.Covers(r.path, p) {
			a |= r.access
		}
	}
	return a
}

// TestNeutralRulesKeepTheUnion is ADR 0025 (3)'s property (enforce-plane R17): for every generated table, with and
// without exec entries, adding the compiled neutral rules to the Landlock plan changes no grant at any probe path,
// keyed path or path beneath one, so no Landlock verdict changes. Each neutral rule carries read rights only and is
// non-empty; a keyed path without one is where the domain grants no read right. The plan model is first held to the
// core's landlock tier model (Evaluate at landlock) on reads and writes, so the property is checked against it.
func TestNeutralRulesKeepTheUnion(t *testing.T) {
	const readRights = agent.AccessReadFile | agent.AccessReadDir
	execSets := [][]agent.ExecRule{nil, {genExecPool[0], genExecPool[1]}, {genExecPool[2], genExecPool[5]}, {genExecPool[6], genExecPool[4]}}
	bad, tables := 0, 0
	fail := func(format string, args ...any) {
		bad++
		if bad < 20 {
			t.Errorf(format, args...)
		}
	}
	genTables(backend.TierLandlock, func(desc string, base *agent.RuleTable) {
		for _, r := range base.FS {
			if r.Kind == agent.FSDenyRead && r.Governed() == "/" {
				return // E5: compile refuses it and the builder fails closed, so there is no plan to pin
			}
		}
		for _, ex := range execSets {
			rt := *base
			rt.Exec = ex
			tables++
			s, err := CompilePlane(&rt)
			if err != nil {
				fail("%s: %v", desc, err)
				return
			}
			universe := append([]string{}, planeProbes...)
			for _, k := range s.Keyed {
				universe = append(universe, k, filepath.Join(k, "f"))
			}
			names := map[string]bool{}
			for _, p := range universe {
				for c := range strings.SplitSeq(strings.Trim(p, "/"), "/") {
					if c != "" {
						names[c] = true
					}
				}
			}
			var nameList []string
			for n := range names {
				nameList = append(nameList, n)
			}
			plan := landlockPlanModel(&rt, nameList)
			if ex == nil {
				for _, p := range genPaths {
					for _, k := range []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite} {
						need := fsAccess(k)
						if k == agent.ActionFSRead && enumeratedLevel(&rt, p) {
							need = agent.AccessReadDir // a directory on the way to a target is listed, not read
						}
						got := llGrant(plan, p)&need == need
						if ev := Evaluate(&rt, agent.Action{Kind: k, Path: p}, backend.TierLandlock); got != (ev.Verdict == agent.VerdictAllow) {
							fail("%s %s %s: plan model allow=%v, Evaluate(landlock) %+v", desc, k, p, got, ev)
						}
					}
				}
			}
			withNeutral := append([]llRule{}, plan...)
			pinned := map[string]bool{}
			for _, n := range s.Neutral {
				if n.Access == 0 || n.Access&^readRights != 0 {
					fail("%s: neutral rule %+v must carry read rights only, and some", desc, n)
				}
				pinned[n.Path] = true
				withNeutral = append(withNeutral, llRule{n.Path, n.Access})
			}
			for _, p := range universe {
				if a, b := llGrant(plan, p), llGrant(withNeutral, p); a != b {
					fail("%s exec=%d %s: the neutral rules change the grant from %v to %v", desc, len(ex), p, a, b)
				}
			}
			for _, k := range s.Keyed {
				if !pinned[k] && llGrant(plan, k)&readRights != 0 {
					fail("%s: keyed %s has a read grant %v but no neutral rule", desc, k, llGrant(plan, k))
				}
			}
		}
	})
	if tables < 1000 {
		t.Fatalf("only %d tables", tables)
	}
}

// TestPlaneCap (enforce-plane E13): a table over either map's capacity is ErrPlaneCap, never a truncated row set; at the capacity it
// compiles. A non-allow exec entry is ErrPlaneExecVerdict. The fs rows are exec.allow directories here, which key
// rows as fs entries do, so the table at the cap compiles in a fraction of a second.
func TestPlaneCap(t *testing.T) {
	table := func(dirs, files int) *agent.RuleTable {
		rt := &agent.RuleTable{Tier: backend.TierBPFLSM}
		for i := range dirs {
			p := "/d/" + strconv.Itoa(i)
			rt.Exec = append(rt.Exec, agent.ExecRule{Path: p, Resolved: p, IsDir: true, Verdict: agent.VerdictAllow})
		}
		for i := range files {
			p := "/b/t" + strconv.Itoa(i)
			rt.Exec = append(rt.Exec, agent.ExecRule{Path: p, Resolved: p, Verdict: agent.VerdictAllow})
		}
		return rt
	}
	// No contract decides exec (as Prepare does); the slot header says so, and 1024 executables fill the exec map.
	s, err := CompilePlane(table(PlaneRowsMax, PlaneExecRowsMax))
	if err != nil || len(s.FS) != PlaneRowsMax || len(s.Exec) != PlaneExecRowsMax || s.ExecMapEntries() != PlaneExecRowsMax {
		t.Fatalf("at the caps: %v", err)
	}
	if len(s.Keyed) != PlaneRowsMax+PlaneExecRowsMax+1 {
		t.Errorf("%d keyed inodes, want every row, every executable and their one directory", len(s.Keyed))
	}
	var capErr *ErrPlaneCap
	if _, err := CompilePlane(table(PlaneRowsMax+1, 0)); !errors.As(err, &capErr) || capErr.FSRows != PlaneRowsMax+1 {
		t.Fatalf("over the fs cap: %v", err)
	}
	// 1025 executables are 1025 entries in a map of 1024: the fill would fail map-full at Prepare.
	if _, err := CompilePlane(table(0, PlaneExecRowsMax+1)); !errors.As(err, &capErr) || capErr.ExecRows != PlaneExecRowsMax+1 {
		t.Fatalf("1025 executables: %v, want ErrPlaneCap with 1025 exec rows", err)
	}
	// Without an exec: section no name row is written: 1024 executables fit.
	noExec := table(0, PlaneExecRowsMax)
	noExec.Contract = &agent.Contract{}
	if s, err := CompilePlane(noExec); err != nil || s.ExecMapEntries() != PlaneExecRowsMax {
		t.Fatalf("1024 executables without an exec: section: %v", err)
	}
	// Each bare-name entry is a row of its own in the same map.
	named := func(n int) *agent.RuleTable {
		rt := table(0, PlaneExecRowsMax-2)
		for i := range n {
			rt.Exec[i].ByName, rt.Exec[i].Basename = true, "t"+strconv.Itoa(i)
		}
		return rt
	}
	if _, err := CompilePlane(named(2)); err != nil {
		t.Fatalf("1022 executables and two bare names: %v", err)
	}
	over := named(2)
	over.Exec = append(over.Exec, agent.ExecRule{Path: "/b/extra", Resolved: "/b/extra", Verdict: agent.VerdictAllow})
	if _, err := CompilePlane(over); !errors.As(err, &capErr) || capErr.ExecRows != PlaneExecRowsMax+1 {
		t.Fatalf("1023 executables and two bare names: %v, want ErrPlaneCap", err)
	}
	rt := table(0, 1)
	rt.Exec[0].Verdict = agent.VerdictAsk
	var verdictErr *ErrPlaneExecVerdict
	if _, err := CompilePlane(rt); !errors.As(err, &verdictErr) {
		t.Fatalf("an ask exec entry: %v", err)
	}
}

// TestPlaneDiagnostic (enforce-plane E13, §2.4 condition 7): compile reports a table over the cap as an error when
// bpflsm is the only tier it can run at (pinned), a warning naming bpflsm and saying an auto run gets tier cgroup when
// an auto run may land there (compiled to bpflsm or not), and nothing when bpflsm is out of reach or the table fits.
func TestPlaneDiagnostic(t *testing.T) {
	over := &agent.RuleTable{Contract: &agent.Contract{}} // no net: section, so no net policy row counts
	for i := range PlaneRowsMax + 1 {
		p := "/d/" + strconv.Itoa(i)
		over.Exec = append(over.Exec, agent.ExecRule{Path: p, Resolved: p, IsDir: true, Verdict: agent.VerdictAllow})
	}
	auto := []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
	for _, tc := range []struct {
		tier     backend.Tier
		reach    []backend.Tier
		severity string
	}{
		{backend.TierBPFLSM, []backend.Tier{backend.TierBPFLSM}, agent.SeverityError},
		{backend.TierBPFLSM, nil, agent.SeverityError},
		{backend.TierBPFLSM, auto, agent.SeverityWarning},
		{backend.TierCgroup, auto, agent.SeverityWarning},
		{backend.TierCgroup, []backend.Tier{backend.TierLandlock, backend.TierCgroup}, ""},
	} {
		over.Tier, over.Reach = tc.tier, tc.reach
		d, ok := PlaneDiagnostic(over, "agent.yaml", -1)
		if ok != (tc.severity != "") || d.Severity != tc.severity {
			t.Errorf("tier %s reach %v: %+v (%v), want severity %q", tc.tier, tc.reach, d, ok, tc.severity)
			continue
		}
		if ok && (d.Tier != backend.TierBPFLSM || d.Code != agent.CodeUnenforced ||
			!strings.Contains(d.Message, strconv.Itoa(PlaneRowsMax+1)+" inodes") || !strings.Contains(d.Message, "at most 4096")) {
			t.Errorf("diagnostic %+v must name bpflsm, the keyed count and the cap", d)
		}
		if ok && tc.severity == agent.SeverityWarning && !strings.Contains(d.Message, "an auto run is given tier cgroup") {
			t.Errorf("warning %+v does not say where an auto run goes", d)
		}
	}
	fits := &agent.RuleTable{Tier: backend.TierBPFLSM, Reach: []backend.Tier{backend.TierBPFLSM}}
	if d, ok := PlaneDiagnostic(fits, "agent.yaml", -1); ok {
		t.Errorf("a table that fits: %+v", d)
	}
}

// TestPlaneDiagnosticCountsTheDescriptorCap (enforce-plane §2.4 condition 7): rows inside the maps' caps whose keyed
// paths pass the launcher's descriptor budget are reported, naming the count and that cap, never left to EMFILE at
// Prepare; at the budget they fit, and an unknown budget (negative) refuses nothing.
func TestPlaneDiagnosticCountsTheDescriptorCap(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Reach: []backend.Tier{backend.TierBPFLSM}, Contract: &agent.Contract{}}
	for i := range 100 {
		p := "/p/" + strconv.Itoa(i)
		rt.FS = append(rt.FS, agent.FSRule{Path: p, Resolved: p, Kind: agent.FSDenyRead})
	}
	rows, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	held := rows.Held()
	if held < 100 {
		t.Fatalf("100 deny_read targets hold %d descriptors", held)
	}
	for _, tc := range []struct {
		cap  int
		want bool
	}{{held - 1, true}, {held, false}, {held + 1, false}, {-1, false}} {
		err := rows.FitFDs(tc.cap)
		var capErr *ErrPlaneCap
		if (err != nil) != tc.want || (tc.want && (!errors.As(err, &capErr) || capErr.FDCap != tc.cap || capErr.Held != held)) {
			t.Errorf("cap %d over %d held: %v", tc.cap, held, err)
		}
		d, ok := PlaneDiagnostic(rt, "agent.yaml", tc.cap)
		if ok != tc.want {
			t.Errorf("cap %d: diagnostic %+v (%v)", tc.cap, d, ok)
			continue
		}
		if ok && (d.Severity != agent.SeverityError ||
			!strings.Contains(d.Message, fmt.Sprintf("keys %d paths", held)) ||
			!strings.Contains(d.Message, fmt.Sprintf("descriptor cap is %d", tc.cap))) {
			t.Errorf("cap %d: diagnostic %+v must name the count and the cap", tc.cap, d)
		}
	}
}

// TestPlaneQueriesAllocateNothing: the plane's query paths (the reference of the kernel's walk and the ledger's
// rule lookup) allocate nothing per question, like the core's other query paths (ADR 0028 S1).
func TestPlaneQueriesAllocateNothing(t *testing.T) {
	s := benchPlane(t)
	fn := func() {
		for _, p := range []string{benchRead, benchDenied, benchNested, benchOutside} {
			s.Decide(p, PlaneRead)
			s.Decide(p, PlaneModify)
			s.Decide(p, PlaneRename)
			s.KindAt(p)
			s.ExecMatch(p)
			s.RuleAt(0, PlaneRead, 0)
		}
	}
	if n := testing.AllocsPerRun(100, fn); n != 0 {
		t.Errorf("the plane's queries make %v allocations, want 0", n)
	}
}

func benchPlane(tb testing.TB) *PlaneRows {
	rt := realisticTable(backend.TierBPFLSM)
	rt.DenyWrite = []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/home/u/proj/.git/hooks", Resolved: "/home/u/proj/.git/hooks", BuiltIn: true, Unenforced: true}}
	rt.Exec = []agent.ExecRule{
		{Path: "/usr/bin/git", Resolved: "/usr/bin/git", Basename: "git", Raw: "git", ByName: true, Verdict: agent.VerdictAllow},
		{Path: "/home/u/proj/node_modules/.bin", Resolved: "/home/u/proj/node_modules/.bin", IsDir: true, Verdict: agent.VerdictAllow},
	}
	s, err := CompilePlane(rt)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func BenchmarkPlaneDecide(b *testing.B) {
	s := benchPlane(b)
	b.ReportAllocs()
	for b.Loop() {
		s.Decide(benchRead, PlaneRead)
		s.Decide(benchDenied, PlaneRead)
	}
}

func BenchmarkPlaneExecMatch(b *testing.B) {
	s := benchPlane(b)
	b.ReportAllocs()
	for b.Loop() {
		s.ExecMatch("/usr/bin/git")
		s.ExecMatch("/usr/bin/curl")
	}
}

func BenchmarkCompilePlane(b *testing.B) {
	rt := realisticTable(backend.TierBPFLSM)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := CompilePlane(rt); err != nil {
			b.Fatal(err)
		}
	}
}

// TestPlaneRuleIndexNames is TIER3-PLAN T9's resolution of the kernel's rule_idx into the rule a ledger line names:
// an fs row by the hook's question (RowName), a REFER refusal by the row's nearest entry (NamedAt), an exec
// entry's own position, and an exec.allow directory's fs row, which bprm_check records with PlaneRuleFSRow set
// (enforce-plane §2.7's condition 2), by that row's exec.allow entry.
func TestPlaneRuleIndexNames(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/h", Raw: "/h", Resolved: "/h", Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: "/h/s", Raw: "/h/s", Resolved: "/h/s"},
		},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/h/.git/hooks", Resolved: "/h/.git/hooks", BuiltIn: true}},
		Exec: []agent.ExecRule{
			{Path: "/b/t", Resolved: "/b/t", Raw: "/b/t", Basename: "t", Verdict: agent.VerdictAllow},
			{Path: "/d", Resolved: "/d", Raw: "/d", IsDir: true, Verdict: agent.VerdictAllow},
		},
	}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	row := func(p string) int {
		t.Helper()
		for i, r := range s.FS {
			if r.Path == p {
				return i
			}
		}
		t.Fatalf("no row at %s: %+v", p, s.FS)
		return -1
	}
	for _, tc := range []struct {
		desc string
		got  string
		want string
	}{
		{"a read under deny_read", s.RowName(rt, row("/h/s"), PlaneRead, 1), "fs.deny_read[/h/s]"},
		{"a modification under the write entry", s.RowName(rt, row("/h"), PlaneModify, 1), "fs.write[/h]"},
		{"a rename of a deny_write ancestor", s.RowName(rt, row("/h/.git"), PlaneRename, 0), rt.DenyWrite[0].RuleName()},
		{"REFER out of deny_read", s.NamedAt(rt, row("/h/s")), "fs.deny_read[/h/s]"},
		{"no row", s.RowName(rt, -1, PlaneModify, 0), agent.UnmatchedRule},
		{"a row past the table", s.RowName(rt, len(s.FS), PlaneRead, 0), agent.UnmatchedRule},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %q, want %q", tc.desc, tc.got, tc.want)
		}
	}
	for _, tc := range []struct {
		desc string
		idx  uint32
		want int
	}{
		{"an exec entry's own position", 0, 0},
		{"an exec.allow directory's fs row (bit 16)", PlaneRuleFSRow | uint32(row("/d")), 1},
		{"bit 16 on a row no exec.allow directory covers", PlaneRuleFSRow | uint32(row("/h")), -1},
		{"bit 16 past the rows", PlaneRuleFSRow | uint32(len(s.FS)), -1},
		{"an entry past the table", uint32(len(rt.Exec)), -1},
		{"none", 0xffff, -1},
	} {
		if got := s.ExecRuleAt(rt, tc.idx); got != tc.want {
			t.Errorf("%s: ExecRuleAt(%#x) = %d, want %d", tc.desc, tc.idx, got, tc.want)
		}
	}
}

// denyWriteIdx is the scan planeIndex.denyWriteIdx answers as: RuleTable.DenyWriteTarget as a position, the
// first target at or above p, or, with ancestors (a rename, which carries a directory's subtree), beneath it.
// It lives here, as the tests' reference, so production keeps one copy of the rule.
func denyWriteIdx(rt *agent.RuleTable, p string, ancestors bool) (int, bool) {
	for j := range rt.DenyWrite {
		r := &rt.DenyWrite[j]
		for _, t := range [2]string{r.Path, r.Resolved} {
			if t != "" && (agent.Covers(t, p) || (ancestors && agent.Covers(p, t))) {
				return j, true
			}
		}
	}
	return -1, false
}
