// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// scaleTable is a random table of about fs fs entries and exec exec entries over a random directory tree: every fs
// kind, symlinked entries (a declared path whose resolution lies elsewhere in the tree), Unenforced stamped at
// random, deny_write targets beneath write entries and elsewhere, exec files, directories and bare names. Nothing
// here is what compile would refuse or accept; the row compiler is a function of the table, and the indexed one
// must answer every table as the oracle does.
func scaleTable(rng *rand.Rand, fs, exec, dw int) *agent.RuleTable {
	dirs := []string{"/"}
	for i := range 8 {
		dirs = append(dirs, "/r"+strconv.Itoa(i))
	}
	depth := map[string]int{"/": 0}
	for _, d := range dirs[1:] {
		depth[d] = 1
	}
	for len(dirs) < 4*fs+16 {
		parent := dirs[rng.IntN(len(dirs))]
		if depth[parent] >= 10 && rng.IntN(20) != 0 {
			continue
		}
		c := parent + "/c" + strconv.Itoa(rng.IntN(6))
		if parent == "/" {
			c = "/c" + strconv.Itoa(rng.IntN(6))
		}
		if _, seen := depth[c]; seen {
			// grow a new name instead of repeating one
			c += "x" + strconv.Itoa(len(dirs))
		}
		depth[c] = depth[parent] + 1
		dirs = append(dirs, c)
	}
	// Few distinct hot paths make entries collide on one path, as a table's do.
	pick := func() string {
		if rng.IntN(4) == 0 {
			return dirs[rng.IntN(min(len(dirs), 40))]
		}
		return dirs[rng.IntN(len(dirs))]
	}
	kinds := []agent.FSKind{agent.FSWrite, agent.FSWrite, agent.FSDenyRead, agent.FSDenyRead, agent.FSWatch, agent.FSImplicit, agent.FSAsk}
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Record: agent.RecordFull}
	for i := range fs {
		k := kinds[rng.IntN(len(kinds))]
		p := pick()
		r := agent.FSRule{Kind: k, Path: p, Raw: p}
		switch rng.IntN(10) {
		case 0: // a link declared elsewhere, resolving into the tree
			r.Path = "/l" + strconv.Itoa(i)
			if rng.IntN(2) == 0 {
				r.Path = pick() + "/l" + strconv.Itoa(i)
			}
			r.Raw, r.Resolved = r.Path, p
		case 1:
			r.Resolved = p // resolved spelled out, equal
		case 2:
			if rng.IntN(4) == 0 {
				r.Path += "/" // unclean declared spelling
			}
		case 3:
			if len(rt.FS) == 0 {
				break
			}
			// a link beneath another entry resolving to one of that entry's ancestors, or to the entry itself
			base := rt.FS[rng.IntN(len(rt.FS))].Canonical()
			r.Path = base + "/l" + strconv.Itoa(i)
			for r.Resolved = base; rng.IntN(3) != 0; {
				up, ok := parent(r.Resolved)
				if !ok {
					break
				}
				r.Resolved = up
			}
			r.Raw = r.Path
		case 4:
			if rng.IntN(4) == 0 {
				r.Path, r.Resolved = "", p // an entry known only by its resolution
			}
		}
		switch k {
		case agent.FSWrite:
			r.Access = agent.AccessWriteSet
			if rng.IntN(5) == 0 {
				r.Access = agent.AccessWriteFile | agent.AccessReadFile
			}
		case agent.FSDenyRead:
			r.Unenforced = rng.IntN(3) == 0
		case agent.FSAsk:
			r.Access = agent.AccessWriteFile
		}
		rt.FS = append(rt.FS, r)
	}
	var writes []string
	for _, r := range rt.FS {
		if r.Kind == agent.FSWrite {
			writes = append(writes, r.Canonical())
		}
	}
	for i := range dw {
		t := pick() + "/dw" + strconv.Itoa(i)
		if len(writes) > 0 && rng.IntN(4) != 0 {
			t = writes[rng.IntN(len(writes))] + "/t" + strconv.Itoa(rng.IntN(3)) + "/h" + strconv.Itoa(i)
		}
		r := agent.FSRule{Kind: agent.FSDenyWrite, Path: t, Resolved: t, BuiltIn: true, Unenforced: true}
		if rng.IntN(8) == 0 {
			r.Path = "/dl" + strconv.Itoa(i) // a declared spelling through a link
		}
		if rng.IntN(10) == 0 {
			r.Resolved += "/" // an unclean spelling
		}
		rt.DenyWrite = append(rt.DenyWrite, r)
	}
	for i := range exec {
		p := pick() + "/b" + strconv.Itoa(i)
		r := agent.ExecRule{Path: p, Verdict: agent.VerdictAllow, Basename: "b" + strconv.Itoa(i)}
		switch rng.IntN(6) {
		case 0:
			r.IsDir = true
			r.Path = pick()
		case 1:
			r.Resolved = pick() + "/real" + strconv.Itoa(i)
		case 2:
			r.Resolved = p
		case 3:
			r.ByName = true
			r.Basename = "cmd" + strconv.Itoa(rng.IntN(20))
		}
		rt.Exec = append(rt.Exec, r)
	}
	if rng.IntN(200) == 0 && len(rt.Exec) > 0 {
		rt.Exec[rng.IntN(len(rt.Exec))].Verdict = agent.VerdictAsk
	}
	return rt
}

// capTable is a scale table as large as the plane holds: fs rows and exec rows just under the caps.
func capTable(seed uint64) *agent.RuleTable {
	rng := rand.New(rand.NewPCG(seed, 7))
	fs := 3000
	for {
		rt := scaleTable(rng, fs, PlaneExecRowsMax-40, 40)
		for i := range rt.Exec {
			rt.Exec[i].Verdict = agent.VerdictAllow
		}
		n, err := oracleCompilePlaneRowCount(rt)
		if err == nil && n > PlaneRowsMax-200 {
			return rt
		}
		if err != nil {
			n = PlaneRowsMax + 200
		}
		fs = fs * (PlaneRowsMax - 100) / n // aim for the middle of the window
	}
}

// oracleCompilePlaneRowCount is the number of fs rows rt keys, as CompilePlane counts them before its cap check,
// without compiling a row.
func oracleCompilePlaneRowCount(rt *agent.RuleTable) (int, error) {
	paths := map[string]bool{}
	for i := range rt.FS {
		if rt.FS[i].Path != "" {
			paths[rt.FS[i].Canonical()] = true
		}
	}
	for j := range rt.DenyWrite {
		t := denyWritePath(rt.DenyWrite[j])
		top, ok := oracleOutermostWrite(rt, t)
		for cur := t; ok; cur = filepath.Dir(cur) {
			paths[cur] = true
			if cur == top || cur == "/" {
				break
			}
		}
	}
	for i := range rt.Exec {
		if r := &rt.Exec[i]; r.IsDir && execPath(r) != "" {
			paths[execPath(r)] = true
		}
	}
	if len(paths) > PlaneRowsMax {
		return 0, &ErrPlaneCap{FSRows: len(paths)}
	}
	return len(paths), nil
}

var scaleSizes = []struct {
	name string
	rt   func() *agent.RuleTable
}{
	{"100", func() *agent.RuleTable { return scaleTable(rand.New(rand.NewPCG(1, 2)), 100, 25, 4) }},
	{"1000", func() *agent.RuleTable { return scaleTable(rand.New(rand.NewPCG(3, 4)), 1000, 250, 10) }},
	{"cap", func() *agent.RuleTable { return capTable(5) }},
}

func BenchmarkCompilePlaneScale(b *testing.B) {
	for _, sz := range scaleSizes {
		rt := sz.rt()
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := CompilePlane(rt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRootRowsScale(b *testing.B) {
	for _, sz := range scaleSizes {
		rt := sz.rt()
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				RootRows(rt)
			}
		})
	}
}

func BenchmarkOracleCompilePlaneScale(b *testing.B) {
	for _, sz := range scaleSizes {
		rt := sz.rt()
		b.Run(sz.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := oracleCompilePlane(rt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// oracleEdges is tables the random ones reach too rarely: a deny_read declared through a link at a row another entry
// keys, which a write entry nested in its target reopens from above the row (the row takes no read answer of its
// own), and a deny_write target spelled unclean.
var oracleEdges = []func() *agent.RuleTable{
	func() *agent.RuleTable {
		return &agent.RuleTable{Tier: backend.TierBPFLSM, FS: []agent.FSRule{
			{Kind: agent.FSWatch, Path: "/l"},
			{Kind: agent.FSDenyRead, Path: "/l", Resolved: "/w/a"},
			{Kind: agent.FSWrite, Path: "/", Resolved: "/w/a/b", Access: agent.AccessWriteSet},
		}}
	},
	func() *agent.RuleTable {
		return &agent.RuleTable{Tier: backend.TierBPFLSM,
			FS:        []agent.FSRule{{Kind: agent.FSWrite, Path: "/w", Access: agent.AccessWriteSet}},
			DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/w/a/", Resolved: "/w/a//b"}},
		}
	},
}

// TestCompilePlaneMatchesOracle is the indexed row compiler held to the quadratic one it replaced
// (oracle_rows_test.go): on 5000 random tables, from a handful of entries to the plane's caps, CompilePlane and
// RootRows return exactly what the oracle returns, rows, exec rows, keyed inodes, neutral rules and errors alike.
func TestCompilePlaneMatchesOracle(t *testing.T) {
	// 500 tables in the ordinary run (the old oracle takes 5-11 s on a cap-size table); the full 5000 and two at the caps,
	// about 45 s, under TEGO_STRESS=1, which the stress pass runs.
	tables, caps := 500, 0
	if os.Getenv("TEGO_STRESS") != "" {
		tables, caps = 5000, 2
	}
	rng := rand.New(rand.NewPCG(11, 13))
	bad := 0
	for n := range tables + len(oracleEdges) {
		var rt *agent.RuleTable
		switch {
		case n >= tables:
			rt = oracleEdges[n-tables]()
		case n < caps:
			rt = capTable(uint64(100 + n))
		case n%500 == 0:
			rt = scaleTable(rng, 500+rng.IntN(1000), rng.IntN(300), rng.IntN(30))
		default:
			rt = scaleTable(rng, 1+rng.IntN(60), rng.IntN(15), rng.IntN(5))
		}
		if rt.Tier = backend.TierBPFLSM; n%3 == 0 {
			rt.Tier = backend.TierLandlock
		}
		if got, want := RootRows(rt), oracleRootRows(rt); !reflect.DeepEqual(got, want) {
			bad++
			t.Errorf("table %d: RootRows differs from the oracle", n)
		}
		got, gerr := CompilePlane(rt)
		want, werr := oracleCompilePlane(rt)
		switch {
		case (gerr == nil) != (werr == nil) || (gerr != nil && gerr.Error() != werr.Error()):
			bad++
			t.Errorf("table %d: error %v, oracle %v", n, gerr, werr)
		case gerr == nil && !reflect.DeepEqual(got, want):
			bad++
			t.Errorf("table %d: rows differ from the oracle", n)
			diffPlane(t, got, want)
		case gerr != nil:
			var capErr *ErrPlaneCap
			var verdictErr *ErrPlaneExecVerdict
			if !errors.As(gerr, &capErr) && !errors.As(gerr, &verdictErr) {
				t.Errorf("table %d: unexpected error %v", n, gerr)
			}
		}
		if bad > 10 {
			t.FailNow()
		}
	}
}

func diffPlane(t *testing.T, got, want *PlaneRows) {
	t.Helper()
	if len(got.FS) != len(want.FS) {
		t.Errorf("%d fs rows, oracle %d", len(got.FS), len(want.FS))
		return
	}
	for i := range got.FS {
		if got.FS[i] != want.FS[i] {
			t.Errorf("row %d: %+v, oracle %+v", i, got.FS[i], want.FS[i])
			return
		}
	}
	if !reflect.DeepEqual(got.Neutral, want.Neutral) {
		t.Errorf("neutral rules differ")
	}
	if !reflect.DeepEqual(got.Keyed, want.Keyed) {
		t.Errorf("keyed inodes differ")
	}
}
