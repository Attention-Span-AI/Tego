// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// withCompactAt sets PlaneCompactAt for one test.
func withCompactAt(tb testing.TB, n int) {
	tb.Helper()
	was := PlaneCompactAt
	PlaneCompactAt = n
	tb.Cleanup(func() { PlaneCompactAt = was })
}

// envFile is a built-in .env entry at p with the facts compile records for a regular ext4 file of one link in a
// case-exact directory: the row D6 may drop.
func envFile(p string) agent.FSRule {
	return agent.FSRule{Kind: agent.FSDenyRead, Path: p, Resolved: p, BuiltIn: true, Unenforced: true, Regular: true, Nlink: 1,
		Filesystem: "ext4", DirCaseExact: true}
}

// envTable is a project /w, writable, with the built-in pair scoped to /w and n .env files /w/s<i>/.env.
func envTable(n int) *agent.RuleTable {
	fs := []agent.FSRule{{Kind: agent.FSWrite, Path: "/w", Raw: "/w", Resolved: "/w", Access: agent.AccessWriteSet}}
	for i := range n {
		fs = append(fs, envFile("/w/s"+strconv.Itoa(i)+"/.env"))
	}
	return &agent.RuleTable{FS: fs, Tier: backend.TierBPFLSM, Record: agent.RecordFull, NameDeny: builtInPair("/w")}
}

// TestPlaneNameRows is ADR 0043 D3, D4 and D9's row layout: the built-in pair is six rows (the exact and the prefix
// row, an exception row per example name), each scope a bit on a row at its directory (a scope-only row the walk
// passes where no entry keys it), D3's exemption an exempt arm at depth 1 on its name's exact row, one lead and one
// prefix length; and a table without name entries, none of it.
func TestPlaneNameRows(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	bare := *rt
	bare.NameDeny, bare.NameExempt = nil, nil
	s, err := CompilePlane(&bare)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.NameRows) != 0 || len(s.Scopes) != 0 || slices.ContainsFunc(s.FS, func(r PlaneRow) bool { return r.Path == "/p/cfg" }) {
		t.Fatalf("name rows %d, scopes %v for a table without name entries", len(s.NameRows), s.Scopes)
	}
	s, err = CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.Scopes, " ") != "/p /p/app /p/cfg" {
		t.Errorf("scopes %v, want the built-in's, the exemption's parent and the declared glob's base", s.Scopes)
	}
	var names []string
	for _, r := range s.NameRows {
		form := r.Name
		if r.Prefix {
			form += "*"
		}
		names = append(names, form)
		if k, _ := agent.NameKey(r.Name, r.Prefix); k != r.Key {
			t.Errorf("row %s keyed %#x, want %#x", form, r.Key, k)
		}
	}
	if got := strings.Join(names, " "); got != ".env .env.* .env.dist .env.example .env.sample .env.template .env.test token.json" {
		t.Errorf("name rows %s", got)
	}
	cfg := s.FS[s.fsByPath["/p/cfg"]]
	if cfg.Kind != PlaneScopeOnly || cfg.Scopes != 1<<2 {
		t.Errorf("/p/cfg row %+v, want a scope-only row with bit 2", cfg)
	}
	if p := s.FS[s.fsByPath["/p"]]; p.Kind&PlaneScopeOnly != 0 || p.Scopes != 1 || p.Kind&PlaneModifyAllow == 0 {
		t.Errorf("/p row %+v, want the write entry's row with bit 0", p)
	}
	for _, r := range s.NameRows {
		if r.Name == ".env.test" && (len(r.Arms) != 1 || !r.Arms[0].Exempt || r.Arms[0].Depth != 1 || r.Arms[0].Rule != PlaneNameAll || r.Arms[0].Scopes != 1<<1) {
			t.Errorf("exemption row %+v", r)
		}
		if r.Name == ".env.example" && (len(r.Arms) != 1 || !r.Arms[0].Exempt || r.Arms[0].Rule != 2 || r.Arms[0].RawFrom != 5) {
			t.Errorf("exception row %+v, want the prefix entry's (2) cancelled from byte 5", r)
		}
	}
	if strings.Join(s.Leads, " ") != ".env token.js" || len(s.PrefixLens) != 1 || s.PrefixLens[0] != 5 {
		t.Errorf("leads %v, prefix lengths %v", s.Leads, s.PrefixLens)
	}
	if v := s.Decide("/p/cfg/x", PlaneModify); v.Row != s.fsByPath["/p"] {
		t.Errorf("the walk stopped at %d, want the write entry's row: a scope-only row is passed", v.Row)
	}
}

// TestPlaneNameCaps: a hand-built table whose name entries pass a cap is ErrPlaneNameCap, never a truncated set.
func TestPlaneNameCaps(t *testing.T) {
	rt := envTable(0)
	for i := range 9 {
		rt.NameDeny = append(rt.NameDeny, agent.NameDenyRule{Literal: "f" + strconv.Itoa(i) + ".json", Raw: "x",
			Scopes: []agent.NameScope{{Canonical: "/d" + strconv.Itoa(i)}}})
	}
	var capErr *ErrPlaneNameCap
	if _, err := CompilePlane(rt); !errors.As(err, &capErr) || !strings.Contains(err.Error(), "scope directories") {
		t.Errorf("ten scopes: %v", err)
	}
}

// TestPlaneNameClimbBoundMatchesEvaluate: the plane's climb bound is the root model's (ADR 0043 D4): a covered file
// 62 to 64 levels below its scope is decided, 65 and 66 refused path-unresolved, with a write entry near enough that
// the walk itself stays within its bound.
func TestPlaneNameClimbBoundMatchesEvaluate(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	near := "/p/" + strings.Repeat("d/", 59) + "d"
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: near, Resolved: near, Raw: "near", Access: agent.AccessWriteSet})
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	for depth := 62; depth <= 66; depth++ {
		p := "/p/" + strings.Repeat("d/", depth-1) + ".env.local"
		for _, k := range []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite} {
			a := agent.Action{Kind: k, Path: p}
			got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM)
			if got != want {
				t.Errorf("%d levels %s: plane %+v, Evaluate %+v", depth, k, got, want)
			}
			if unresolved := want.Reason == record.ReasonPathUnresolved; unresolved != (depth > agent.MaxWalk) {
				t.Errorf("%d levels %s: %+v", depth, k, want)
			}
		}
	}
}

// compactProbes are the paths compaction neutrality is asked of on envTable variants: the files, their names
// created later, siblings, directories and places outside the scope.
func compactProbes(n int) []string {
	out := []string{"/w", "/w/x/.env", "/w/new/.env.local", "/w/a.txt", "/r/.env", "/w/locked/.env", "/w/link/.env", "/tmp/.env"}
	for i := range n {
		d := "/w/s" + strconv.Itoa(i)
		out = append(out, d, d+"/.env", d+"/.env.local", d+"/.env.example", d+"/b.txt")
	}
	return out
}

// aliasVariants are envTable(12) with one row each D6 condition keeps: two links, a declared symlink, a casefold
// directory, a filesystem with other spellings, a file mount point, a watch entry at the same path, a read-only parent,
// a deny_read directory above.
func aliasVariants() map[string]*agent.RuleTable {
	out := map[string]*agent.RuleTable{}
	mk := func(name string, edit func(rt *agent.RuleTable)) {
		rt := envTable(12)
		rt.FS = slices.Clone(rt.FS)
		edit(rt)
		out[name] = rt
	}
	mk("plain", func(*agent.RuleTable) {})
	mk("nlink2", func(rt *agent.RuleTable) { rt.FS[2].Nlink = 2 })
	mk("symlink", func(rt *agent.RuleTable) { rt.FS[3].Path = "/w/link/.env" })
	mk("casefold", func(rt *agent.RuleTable) { rt.FS[4].DirCaseExact = false })
	mk("vfat", func(rt *agent.RuleTable) { rt.FS[5].Filesystem = "vfat" })
	mk("filemount", func(rt *agent.RuleTable) { rt.FS[6].FileMountPoint = true })
	mk("watch", func(rt *agent.RuleTable) {
		rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWatch, Path: "/w/s7/.env", Raw: "s7/.env", Resolved: "/w/s7/.env"})
	})
	mk("readonly", func(rt *agent.RuleTable) {
		rt.NameDeny = builtInPair("/w", "/r")
		rt.FS = append(rt.FS, envFile("/r/.env"))
	})
	mk("denyread", func(rt *agent.RuleTable) {
		rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSDenyRead, Path: "/w/locked", Raw: "locked", Resolved: "/w/locked", Unenforced: true},
			envFile("/w/locked/.env"))
	})
	mk("bind", func(rt *agent.RuleTable) {
		rt.NameDeny[0].BindExposed = true
		rt.NameDeny[1].BindExposed = true
	})
	return out
}

// TestPlaneCompactionIsVerdictNeutral is ADR 0043 D6's property: the plane's rows with every qualifying per-file row
// dropped answer every probe, as a file and as a directory, read, write, delete, mkdir and rename (into the scope and
// out of it), exactly as the rows without compaction do and as the root model does, names and reasons included
// (TestPlaneCompactionIsNameNeutral is the same property named for D8).
func TestPlaneCompactionIsVerdictNeutral(t *testing.T) {
	checkCompactionNeutral(t)
}

// TestPlaneCompactionIsNameNeutral: a refusal of a compacted file is named by its own entry, as its row named it
// (ADR 0043 D8), never by the name entry's label.
func TestPlaneCompactionIsNameNeutral(t *testing.T) {
	withCompactAt(t, 0)
	rt := envTable(3)
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	if pe.rows.Compacted != 3 {
		t.Fatalf("%d rows compacted, want 3", pe.rows.Compacted)
	}
	for _, k := range []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete} {
		got := pe.Evaluate(agent.Action{Kind: k, Path: "/w/s1/.env"}, Env{})
		if got.Verdict != agent.VerdictRefused || got.Rule != "fs.deny_read[/w/s1/.env]" {
			t.Errorf("%s of a compacted .env: %+v, want its own entry", k, got)
		}
	}
	checkCompactionNeutral(t)
}

func checkCompactionNeutral(t *testing.T) {
	t.Helper()
	kinds := []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir}
	for name, rt := range aliasVariants() {
		withCompactAt(t, 1<<30)
		full, err := CompilePlane(rt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		withCompactAt(t, 0)
		pe := NewPlaneEvaluator(rt)
		if pe.Err() != nil {
			t.Fatalf("%s: %v", name, pe.Err())
		}
		compact := pe.rows
		if name == "plain" && compact.Compacted != 12 {
			t.Errorf("plain: %d rows compacted, want all 12", compact.Compacted)
		}
		for _, p := range compactProbes(12) {
			for _, dir := range []bool{false, true} {
				for _, k := range kinds {
					q := PlaneModify
					if k == agent.ActionFSRead {
						q = PlaneRead
					}
					a := agent.Action{Kind: k, Path: p, Dir: dir}
					d := objectOf(a) == objDir
					fv, cv := full.DecideObject(p, q, d), compact.DecideObject(p, q, d)
					fn, fr := PlaneRefusal(rt, fv, k)
					cn, cr := PlaneRefusal(rt, cv, k)
					if fv.Allow != cv.Allow || (!fv.Allow && (fn != cn || fr != cr)) {
						t.Errorf("%s %s %s dir=%v: uncompacted %+v (%s), compacted %+v (%s)", name, k, p, dir, fv, fn, cv, cn)
					}
					if got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM); got != want {
						t.Errorf("%s %s %s dir=%v: compacted plane %+v, Evaluate %+v", name, k, p, dir, got, want)
					}
				}
				for _, dst := range []string{"/w/y", "/tmp/y", "/w/node_modules/y"} {
					a := agent.Action{Kind: agent.ActionFSRename, Path: p, DestPath: dst, Dir: dir}
					if got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM); got.Verdict != want.Verdict || got.Reason != want.Reason {
						t.Errorf("%s rename %s -> %s dir=%v: compacted plane %+v, Evaluate %+v", name, p, dst, dir, got, want)
					}
				}
			}
		}
	}
}

// TestPlaneCompactionKeepsAliases is D6's (b) to (g): each row a condition rules out stays, so the inode-following
// row still catches what the name alone would not (a second link, another spelling, a bind, a mount over the file),
// and so does each row whose walk the name check would not reach (a read-only parent, a deny_read above).
func TestPlaneCompactionKeepsAliases(t *testing.T) {
	withCompactAt(t, 0)
	keep := map[string]string{"nlink2": "/w/s1/.env", "symlink": "/w/s2/.env", "casefold": "/w/s3/.env", "vfat": "/w/s4/.env",
		"filemount": "/w/s5/.env", "watch": "/w/s7/.env", "readonly": "/r/.env", "denyread": "/w/locked/.env"}
	for name, rt := range aliasVariants() {
		s, err := CompilePlane(rt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p, ok := keep[name]; ok {
			if _, kept := s.fsByPath[p]; !kept {
				t.Errorf("%s: the row at %s was dropped", name, p)
			}
			// Every other file of the twelve is dropped; the readonly and denyread variants add the kept file.
			want := 11
			if name == "readonly" || name == "denyread" {
				want = 12
			}
			if s.Compacted != want {
				t.Errorf("%s: %d compacted, want %d", name, s.Compacted, want)
			}
		}
		if name == "bind" && s.Compacted != 0 {
			t.Errorf("bind: %d rows compacted under a bind-exposed scope", s.Compacted)
		}
	}
}

// TestPlaneCompactionDropsOnlyAsNeeded: compaction stops once the keyed paths are PlaneCompactAt, dropping in reverse
// path order, and does nothing at or below it; the rows that stay keep following their inodes.
func TestPlaneCompactionDropsOnlyAsNeeded(t *testing.T) {
	rt := envTable(10)
	withCompactAt(t, 1<<30)
	full, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	keyed := len(full.Keyed) + len(full.NoFollow)
	withCompactAt(t, keyed)
	if s, _ := CompilePlane(rt); s.Compacted != 0 {
		t.Errorf("at the threshold: %d compacted", s.Compacted)
	}
	withCompactAt(t, keyed-3)
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	var dropped []string
	for p := range s.compacted {
		dropped = append(dropped, p)
	}
	slices.Sort(dropped)
	if strings.Join(dropped, " ") != "/w/s7/.env /w/s8/.env /w/s9/.env" || len(s.Keyed)+len(s.NoFollow) != keyed-3 {
		t.Errorf("dropped %v, keyed %d", dropped, len(s.Keyed)+len(s.NoFollow))
	}
}

// TestPlaneCompactionIsDeterministic and TestRecorderCompilesTheSameRows: the rows, compacted or not, are a pure
// function of the table (ADR 0043 F8): the recorder compiles its own copy of the run's table (internal/runtime/observe
// planeRows) and must meet the row positions Prepare filled, whatever the map order of either compile.
func TestPlaneCompactionIsDeterministic(t *testing.T) {
	withCompactAt(t, 5)
	rt := aliasVariants()["watch"]
	first, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := CompilePlane(rt)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("a second compile differs: %v", err)
		}
	}
}

func TestRecorderCompilesTheSameRows(t *testing.T) {
	for _, at := range []int{agent.NameCompactAt, 3} {
		withCompactAt(t, at)
		for name, rt := range aliasVariants() {
			prepare, err := CompilePlane(rt)
			if err != nil {
				t.Fatal(err)
			}
			copied := *rt
			copied.FS, copied.NameDeny, copied.NameExempt = slices.Clone(rt.FS), slices.Clone(rt.NameDeny), slices.Clone(rt.NameExempt)
			recorder, err := CompilePlane(&copied)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(prepare.FS, recorder.FS) || !reflect.DeepEqual(prepare.NameRows, recorder.NameRows) ||
				!reflect.DeepEqual(prepare.Keyed, recorder.Keyed) || prepare.Compacted != recorder.Compacted {
				t.Errorf("%s at %d: the recorder's rows differ from Prepare's", name, at)
			}
			for i := range prepare.FS {
				if a, b := prepare.RowName(rt, i, PlaneRead, 1), recorder.RowName(&copied, i, PlaneRead, 1); a != b {
					t.Errorf("%s: row %d names %s and %s", name, i, a, b)
				}
			}
		}
	}
}

// TestPlaneNameRuleTagDisjoint is D8's rule_idx space: a name decision's tag lies above every fs row's position, is
// never 0xffff (none), stays within 16 bits (PlaneRuleFSRow and the listener's bit lie above), and decodes back.
func TestPlaneNameRuleTagDisjoint(t *testing.T) {
	for e := range 64 {
		for bit := range 8 {
			tag := PlaneNameTag(e, bit)
			if int(tag) < PlaneRowsMax || tag == 0xffff || uint32(tag)&PlaneRuleFSRow != 0 {
				t.Fatalf("tag %#x of entry %d scope %d", tag, e, bit)
			}
			if ge, gb, ok := PlaneNameUntag(tag); !ok || ge != e || gb != bit {
				t.Fatalf("untag %#x: %d %d %v", tag, ge, gb, ok)
			}
		}
	}
	for _, idx := range []uint16{0, PlaneRowsMax - 1, 0xffff} {
		if _, _, ok := PlaneNameUntag(idx); ok {
			t.Errorf("%#x reads as a name tag", idx)
		}
	}
}

// TestCompactedTableFits is the 4,500-.env worktree (ADR 0043 D6, Users-see 8): without name entries its rows pass
// the plane's cap, compacted they fit, and every file is still refused, named by its own entry.
func TestCompactedTableFits(t *testing.T) {
	rt := envTable(4500)
	bare := *rt
	bare.NameDeny = nil
	var capErr *ErrPlaneCap
	if _, err := CompilePlane(&bare); !errors.As(err, &capErr) {
		t.Fatalf("4,500 rows without name entries: %v, want ErrPlaneCap", err)
	}
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	if held := pe.rows.Held(); held > PlaneCompactAt || pe.rows.Compacted == 0 {
		t.Errorf("%d keyed paths after compacting %d", held, pe.rows.Compacted)
	}
	for i := 0; i < 4500; i += 7 {
		p := "/w/s" + strconv.Itoa(i) + "/.env"
		if got := pe.Evaluate(agent.Action{Kind: agent.ActionFSRead, Path: p}, Env{}); got.Verdict != agent.VerdictRefused || got.Rule != "fs.deny_read["+p+"]" {
			t.Fatalf("%s: %+v", p, got)
		}
	}
}

// TestPlaneNameQueriesAllocateNothing: the plane's name check and D5's climb allocate nothing per question.
func TestPlaneNameQueriesAllocateNothing(t *testing.T) {
	withCompactAt(t, 0)
	rt := nameTable(backend.TierBPFLSM)
	rt.FS = append(rt.FS, envFile("/p/s/.env"))
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	fn := func() {
		for _, p := range []string{"/p/later/.env.local", "/p/app/.env.test", "/p/src/main.go", "/p/s/.env", "/p/cfg/x/token.json", "/p/a/.env.EXAMPLE"} {
			s.DecideObject(p, PlaneRead, false)
			s.DecideObject(p, PlaneModify, false)
			s.DecideObject(p, PlaneRename, false)
		}
		s.ScopeMoveRefused("/p/sub", "/tmp/sub")
	}
	if n := testing.AllocsPerRun(100, fn); n != 0 {
		t.Errorf("%v allocations", n)
	}
}

func BenchmarkPlaneDecideName(b *testing.B) {
	s, err := CompilePlane(nameTable(backend.TierBPFLSM))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		s.DecideObject("/p/later/deep/.env.local", PlaneRead, false)
		s.DecideObject("/p/src/pkg/main.go", PlaneRead, false)
	}
}

// BenchmarkCompilePlaneCompaction is the 4,500-.env table compiled with compaction, against BenchmarkCompilePlaneScale
// (ADR 0043 C4: at most 1.5 times its cap table).
func BenchmarkCompilePlaneCompaction(b *testing.B) {
	rt := envTable(4500)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := CompilePlane(rt); err != nil {
			b.Fatal(err)
		}
	}
}

// TestPlaneRowNameNamesATaggedRule is ADR 0043 D8 in the recorder's naming of a plane decision: a kernel rule_idx
// carrying TEGO_PLANE_RULE_NAME (a name check's refusal, a covered source's REFER refusal, D5's) is named by the name
// entry's own rule at the scope its bit is, whatever the question and depth, by RowName and NamedAt alike; a tag
// naming no entry or no scope of these rows, and an index without the tag past the rows, stay unmatched; an untagged
// row is named as before.
func TestPlaneRowNameNamesATaggedRule(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	bit := func(scope string) int { return slices.Index(s.Scopes, scope) }
	cases := []struct {
		entry int
		scope string
		want  string
	}{
		{0, "/p/cfg", rt.NameDeny[0].RuleName(0)},
		{1, "/p", rt.NameDeny[1].RuleName(0)},
		{2, "/p", rt.NameDeny[2].RuleName(0)},
	}
	for _, c := range cases {
		if bit(c.scope) < 0 {
			t.Fatalf("no scope bit for %s in %v", c.scope, s.Scopes)
		}
		tag := int(PlaneNameTag(c.entry, bit(c.scope)))
		for _, q := range []PlaneQuestion{PlaneRead, PlaneModify, PlaneRename} {
			if got := s.RowName(rt, tag, q, 0); got != c.want {
				t.Errorf("RowName(entry %d, scope %s, question %v) = %q, want %q", c.entry, c.scope, q, got, c.want)
			}
		}
		if got := s.NamedAt(rt, tag); got != c.want {
			t.Errorf("NamedAt(entry %d, scope %s) = %q, want %q", c.entry, c.scope, got, c.want)
		}
	}
	for _, bad := range []int{int(PlaneNameTag(len(rt.NameDeny), 0)), int(PlaneNameTag(0, len(s.Scopes))), 0xffff, len(s.FS)} {
		if got := s.RowName(rt, bad, PlaneRead, 1); got != agent.UnmatchedRule {
			t.Errorf("RowName(%#x) = %q, want unmatched", bad, got)
		}
		if got := s.NamedAt(rt, bad); got != agent.UnmatchedRule {
			t.Errorf("NamedAt(%#x) = %q, want unmatched", bad, got)
		}
	}
	if got := s.RowName(rt, s.fsByPath["/p/.env"], PlaneRead, 0); got != "fs.deny_read[/p/.env]" {
		t.Errorf("the expansion's own row is named %q", got)
	}
}
