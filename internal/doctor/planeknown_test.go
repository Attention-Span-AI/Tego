// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"golang.org/x/sys/unix"
)

// passingKnown is every known-answer cell answered as the plane must answer it.
func passingKnown() []PlaneKnownAnswer {
	var out []PlaneKnownAnswer
	for _, c := range planeKnownCells() {
		out = append(out, PlaneKnownAnswer{Cell: c.Cell, Want: c.Want, Got: c.Want, WantCounts: c.WantCounts,
			GotCounts: c.WantCounts})
	}
	return out
}

// TestPlaneKnownCells holds the known answers to the principal's list (enforce-plane R21): a deny_read row two levels
// up across a tmpfs mount, a stale row, a corrupted identity, the walk's bound either side of 64 levels, an exec by a
// directory row, by a file row and by a hard link of it under another name, and an rmdir, each with the verdict and
// the fail-closed counters it must leave; and ADR 0043 C9's name cells: a .env and a .ENV made after the fill
// refused, .env.example, a .env outside the scope and one beneath node_modules allowed, a directory renamed within
// its scope allowed and one moved out refused. Every cell has a child action.
func TestPlaneKnownCells(t *testing.T) {
	type answer struct {
		verdict string
		counts  PlaneCountDelta
	}
	want := map[string]answer{
		"deny-read-across-mount": {planeRefused, PlaneCountDelta{}},
		"stale-row":              {planePassed, PlaneCountDelta{}},
		"identity-mismatch":      {planeRefused, PlaneCountDelta{Mismatch: 1}},
		"depth-64":               {planeRefused, PlaneCountDelta{}},
		"depth-65":               {planeRefused, PlaneCountDelta{Bound: 1}},
		"exec-dir-row":           {planePassed, PlaneCountDelta{}},
		"exec-file-row":          {planePassed, PlaneCountDelta{}},
		"exec-hard-link":         {planeRefused, PlaneCountDelta{}},
		"rmdir":                  {planeRefused, PlaneCountDelta{}},
	}
	for cell, verdict := range map[string]string{"name-created-later": planeRefused, "name-folded": planeRefused,
		"name-exception": planePassed, "name-outside-scope": planePassed, "name-dependency-dir": planePassed,
		"name-dir-renamed-within": planePassed, "name-dir-moved-out": planeRefused} {
		want[cell] = answer{verdict: verdict}
	}
	cells := planeKnownCells()
	if len(cells) != len(want) {
		t.Fatalf("%d cells, want %d", len(cells), len(want))
	}
	for _, c := range cells {
		w, ok := want[c.Cell]
		if !ok {
			t.Errorf("unexpected cell %s", c.Cell)
			continue
		}
		if c.Want != w.verdict || c.WantCounts != w.counts {
			t.Errorf("%s: want %s %v, the table says %s %v", c.Cell, w.verdict, w.counts, c.Want, c.WantCounts)
		}
		if planeKnownActions[c.Cell] == nil {
			t.Errorf("%s: no child action", c.Cell)
		}
	}
}

// TestPlaneKnownFlipRejectsTheMode is the test-only switch: flipping one cell's expected verdict makes a probe that
// answered correctly fail the mode, and the detail doctor prints names the cell, both verdicts and the counters.
func TestPlaneKnownFlipRejectsTheMode(t *testing.T) {
	planeKnownFlip = "stale-row"
	defer func() { planeKnownFlip = "" }()
	var got []PlaneKnownAnswer
	for _, c := range planeKnownCells() {
		if c.Cell == "stale-row" && c.Want != planeRefused {
			t.Fatalf("the flip left stale-row's verdict %s", c.Want)
		}
		got = append(got, PlaneKnownAnswer{Cell: c.Cell, Want: c.Want, Got: c.Want, WantCounts: c.WantCounts,
			GotCounts: c.WantCounts})
	}
	// The kernel answered stale-row as it must (passed); the flipped table wants refused.
	for i := range got {
		if got[i].Cell == "stale-row" {
			got[i].Got = planePassed
		}
	}
	rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
	v := planeModeVerdict(bpfobj.PlaneLSM, rows, planeScope{Inside: 1}, got)
	if v.OK || !strings.Contains(v.Detail, "known answer stale-row: passed, want refused") || v.Fix == "" {
		t.Errorf("a flipped cell: %+v", v)
	}
	st := &PlaneState{Build: bpfobj.ObjectPlaneRdonly, Modes: []PlaneModeResult{v}, Pin: "auto", Source: planeSourceProbed}
	selectPlane(st)
	if s := planeSummary(st, true); !strings.Contains(s, "known answer stale-row") || st.Selected != PlaneFanotify {
		t.Errorf("doctor's line does not say why the mode was rejected: %s (selected %s)", s, st.Selected)
	}
}

// TestPlaneModeVerdictNeedsEveryKnownAnswer: a mode is selected only on an exact verdict and counter match of every
// known-answer cell; a missing cell, a wrong verdict and a counter off by one each fail it, and the detail says which.
func TestPlaneModeVerdictNeedsEveryKnownAnswer(t *testing.T) {
	rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
	sc := planeScope{Inside: 1}
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, passingKnown()); !v.OK ||
		!strings.Contains(v.Detail, "16 known answers matched") || len(v.Known) != 16 {
		t.Errorf("every cell matched: %+v", v)
	}
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, nil); v.OK || !strings.Contains(v.Detail, "known answers: 0 of 16") {
		t.Errorf("no cell answered: %+v", v)
	}
	missing := passingKnown()[1:]
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, missing); v.OK || !strings.Contains(v.Detail, "known answers: 15 of 16") {
		t.Errorf("a cell missing: %+v", v)
	}
	wrong := passingKnown()
	wrong[4].Got = planePassed // depth-65 allowed: the BOUND branch hard-wired away
	wrong[4].GotCounts = PlaneCountDelta{}
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, wrong); v.OK ||
		!strings.Contains(v.Detail, "known answer depth-65: passed, want refused (counters none, want bound=1)") {
		t.Errorf("a wrong verdict: %+v", v)
	}
	count := passingKnown()
	count[4].GotCounts = PlaneCountDelta{} // refused, but met the row 65 levels up instead of the bound
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, count); v.OK ||
		!strings.Contains(v.Detail, "known answer depth-65: refused (counters none, want bound=1)") {
		t.Errorf("a counter off: %+v", v)
	}
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, wrong); v.Faulted {
		t.Errorf("a wrong verdict is the mode's answer, not a fault: %+v", v)
	}
}

// TestPlaneModeVerdictFaultsATransientKnownAnswer: a cell whose action failed with an errno that may pass on its
// own (fork's ENOMEM, EMFILE) or a cell with no answer could not run, so the mode is Faulted and not cached; ENOSYS
// and EOPNOTSUPP are the kernel's same answer every time, a failed mode.
func TestPlaneModeVerdictFaultsATransientKnownAnswer(t *testing.T) {
	rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
	sc := planeScope{Inside: 1}
	for _, got := range []string{"failed: fork/exec x: " + unix.ENOMEM.Error(), "failed: open f: " + unix.EMFILE.Error(),
		"failed: the exec'd noop ended: signal: killed"} {
		k := passingKnown()
		i := slices.IndexFunc(k, func(a PlaneKnownAnswer) bool { return a.Cell == "exec-dir-row" })
		k[i].Got = got
		if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, k); v.OK || !v.Faulted ||
			!strings.Contains(v.Fix, "nothing is cached") || !strings.Contains(v.Detail, "known answer exec-dir-row") {
			t.Errorf("%s: %+v", got, v)
		}
	}
	k := passingKnown()
	k[0].Got = "failed: " + unix.EOPNOTSUPP.Error()
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, k); v.OK || v.Faulted {
		t.Errorf("EOPNOTSUPP is a failed mode: %+v", v)
	}
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, passingKnown()[1:]); v.OK || !v.Faulted {
		t.Errorf("a cell with no answer is a fault: %+v", v)
	}
}

// TestPlaneKnownFixtures lays the known answers' fixtures out as the child and the rows expect: the deep chain puts
// one file bpf.PlaneWalkMax levels below the deny_read row and one a level further, the mountpoints are empty
// directories, and the rows are the table the fill writes.
func TestPlaneKnownFixtures(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "k")
	if err := makePlaneKnownFixtures(dir); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"st/f", "bad/f", "dr/m", "x", "rmd", planeKnownDeep(bpfobj.PlaneWalkMax),
		planeKnownDeep(bpfobj.PlaneWalkMax + 1)} {
		if _, err := os.Lstat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
	for _, levels := range []int{bpfobj.PlaneWalkMax, bpfobj.PlaneWalkMax + 1} {
		rel, err := filepath.Rel("deep", planeKnownDeep(levels))
		if err != nil {
			t.Fatal(err)
		}
		if n := len(strings.Split(rel, "/")); n != levels {
			t.Errorf("the file %d levels below the row is %d components down", levels, n)
		}
	}
	root := "/proc/42/root"
	stale, named, bad, err := planeKnownTables(dir, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale.FS) != 1 || stale.FS[0].Path != filepath.Join(dir, "st") || stale.FS[0].Kind != decide.PlaneReadDeny ||
		stale.ExecPolicy {
		t.Errorf("stale table: %+v", stale)
	}
	// The scope row of nm/p with its bit first, where the compiler put it, then the hand rows (bad is the row the probe
	// corrupts) and the write row on nm; the built-in pair's name rows and leads, and the config row's entry masks
	// read from the scope row (each entry covers scope bit 0); the name cells' directories exist, their files not
	// until makePlaneKnownNameFiles.
	var fs []string
	for _, r := range named.FS {
		fs = append(fs, r.Path+" "+strings.TrimSpace(kindName(r.Kind)))
	}
	wantFS := []string{filepath.Join(dir, "bad") + " read-deny", filepath.Join(dir, "deep") + " read-deny",
		filepath.Join(dir, "dr") + " read-deny", root + filepath.Join(dir, "x/xd") + " exec-dir"}
	if len(fs) != len(wantFS)+2 || !slices.Equal(fs[1:len(wantFS)+1], wantFS) {
		t.Errorf("fs rows %v, want %v between the scope row and the write row", fs, wantFS)
	}
	if bad != 1 || named.FS[bad].Path != filepath.Join(dir, "bad") {
		t.Errorf("rule %d is %s, not the row the probe corrupts", bad, named.FS[bad].Path)
	}
	if !named.ExecPolicy || len(named.Exec) != 1 || named.Exec[0].Path != root+filepath.Join(dir, "x/xf/run") ||
		named.Exec[0].Parent != root+filepath.Join(dir, "x/xf") || named.Exec[0].Name != "run" {
		t.Errorf("exec rows: %+v policy %v", named.Exec, named.ExecPolicy)
	}
	if named.FS[0].Path != filepath.Join(dir, "nm/p") || named.FS[0].Scopes != 1 ||
		named.FS[len(wantFS)+1].Path != filepath.Join(dir, "nm") || named.FS[len(wantFS)+1].Kind != decide.PlaneModifyAllow {
		t.Errorf("fs rows with names: %+v", named.FS)
	}
	if masks := named.NameEntryMasks(); !slices.Equal(masks, []uint8{1, 1}) {
		t.Errorf("the config row's entry masks are %v, want each entry on scope bit 0", masks)
	}
	if len(named.NameRows) == 0 || len(named.Leads) == 0 || !named.ExecPolicy || named.NetPolicy || len(named.Exec) != 1 {
		t.Errorf("name rows %d, leads %v, exec %v (%d rows), net %v", len(named.NameRows), named.Leads, named.ExecPolicy,
			len(named.Exec), named.NetPolicy)
	}
	for _, d := range []string{"nm/p/d", "nm/p/e", "nm/p/node_modules/q", "nm/out"} {
		if fi, err := os.Stat(filepath.Join(dir, d)); err != nil || !fi.IsDir() {
			t.Errorf("%s: not a directory (%v)", d, err)
		}
	}
	if err := makePlaneKnownNameFiles(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range planeKnownNameFiles {
		if _, err := os.Lstat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// kindName names the kind bits the known answers use.
func kindName(k decide.PlaneKind) string {
	if n, ok := map[decide.PlaneKind]string{decide.PlaneReadDeny: "read-deny", decide.PlaneExecDir: "exec-dir"}[k]; ok {
		return n
	}
	return "other"
}
