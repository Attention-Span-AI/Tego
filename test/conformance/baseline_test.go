// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// The baseline's own tests (ADR 0017, amended 2026-10-05): the machine predicate of an entry, the canonical form
// of the file, the `-conformance.update=<space>` flag and the refusals that keep a fail-open out of the file.
// None needs privilege or a kernel feature: they run on synthetic baselines and synthetic runs. The two runners
// (TestConformanceCompile, TestConformanceKernel) end in settleBaseline, which is where the flag takes effect.

// updateFlag names the flag that rewrites testdata/baseline.json from a run: `go test ./test/conformance
// -run TestConformanceCompile -conformance.update=<space>`, and the same with -tags integration as root for the
// kernel runner (test/conformance/README.md).
const updateFlag = "conformance.update"

var updateSpace = flag.String(updateFlag, "", "rewrite testdata/baseline.json from this run: drop the entries that now pass and add the "+
	"run's new disagreements, with the reason TODO, as the named space's (see test/conformance/README.md)")

// requestedSpace is the space -conformance.update names, "" when the flag is not given; a name that is no space is
// a failure, so a typo never reads as "no update".
func requestedSpace(t testing.TB) string {
	t.Helper()
	if *updateSpace == "" {
		return ""
	}
	for _, sp := range Spaces() {
		if sp.Name == *updateSpace {
			return sp.Name
		}
	}
	t.Fatalf("-%s=%s: no such space (spaces: %s)", updateFlag, *updateSpace, spaceNames())
	return ""
}

func spaceNames() string {
	var names []string
	for _, sp := range Spaces() {
		names = append(names, sp.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// runRefusals lists why a test run cannot write a baseline, whatever disagreements it found. One: the runner test
// already failed. Everything a baseline cannot excuse (a fail-open, a finding that changed, a fixture that did not
// run) is reported with t.Errorf as it is found and a disagreement a baseline can excuse is held back until the
// end, so a runner that has failed by then is one whose result is not sound. Two: -run or -skip narrowed the run
// below a whole runner, so the cells it did not run would read as entries that now pass and be dropped.
func runRefusals(failed bool, run, skip string) []string {
	var out []string
	if failed {
		out = append(out, "the run already reported errors a baseline cannot excuse (a fail-open, an effect violation, a finding that changed, a fixture that did not run); fix them first, they are in the output above")
	}
	if strings.Contains(run, "/") || skip != "" {
		out = append(out, fmt.Sprintf("the run was narrowed (-run %q, -skip %q): the cells it did not run would read as entries that now pass; run each runner whole", run, skip))
	}
	return out
}

func testFlag(name string) string {
	if f := flag.Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

// settleBaseline ends a runner: it holds the run's disagreements against testdata/baseline.json (the ratchet: a
// new failure and a stale entry both fail), or, with -conformance.update=<space>, writes the baseline from the run
// (Update refuses what a baseline must never hold). ran and failures are keyed as Ratchet reads them; what names
// the two sides that disagreed, for the message.
func settleBaseline(t *testing.T, what string, ran map[string]bool, failures map[string]string) {
	t.Helper()
	settleBaselineAt(t, baselinePath, testFlag("test.run"), testFlag("test.skip"), what, ran, failures)
}

// settleBaselineAt is settleBaseline for the baseline at path and a run started with -run and -skip as given, so
// that a test can drive it.
func settleBaselineAt(t testing.TB, path, run, skip, what string, ran map[string]bool, failures map[string]string) {
	t.Helper()
	m, err := CurrentMachine()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("baseline machine: %s", m)
	space := requestedSpace(t)
	selected, every, err := SelectedSpaces()
	if err != nil {
		t.Fatal(err)
	}
	if space == "" {
		base, err := LoadBaseline(path)
		if err != nil {
			t.Fatal(err)
		}
		if !every {
			// The spaces SpacesEnv left out did not run: their entries are neither excused nor stale here.
			base = entriesOf(t, base, selected)
		}
		newFailures, stale := Ratchet(base, ran, failures, m)
		for _, f := range newFailures {
			t.Errorf("new disagreement between %s: %s", what, f)
		}
		for _, s := range stale {
			t.Errorf("baseline: %s", s)
		}
		return
	}
	cells, err := AllCells()
	if err != nil {
		t.Fatal(err)
	}
	res, err := UpdateBaselineFile(path, UpdateRequest{
		Space: space, Spaces: cellSpaces(cells), Machine: m, Ran: ran, Failures: failures,
		Unsound: append(runRefusals(t.Failed(), run, skip), narrowedSpaces(every)...),
	})
	if err != nil {
		t.Fatalf("-%s=%s refused; %s is unchanged:\n%v", updateFlag, space, path, err)
	}
	for _, k := range res.Dropped {
		t.Logf("baseline: dropped %s (it passes)", k)
	}
	for _, k := range res.Added {
		t.Logf("baseline: added %s with the reason %s: write why before committing", k, todoReason)
	}
	if !res.Written {
		t.Logf("%s needs no change", path)
	}
}

// narrowedSpaces refuses an update from a run SpacesEnv narrowed: the entries of the spaces it left out would read
// as entries that now pass.
func narrowedSpaces(every bool) []string {
	if every {
		return nil
	}
	return []string{fmt.Sprintf("%s narrowed the run to some spaces: the entries of the others would read as entries that now pass; run every space (%s=all)",
		SpacesEnv, SpacesEnv)}
}

// entriesOf is the baseline's entries whose cell belongs to one of the spaces, and the entries that name no cell
// (Ratchet reports those).
func entriesOf(t testing.TB, base []BaselineEntry, spaces []Space) []BaselineEntry {
	t.Helper()
	cells, err := AllCells()
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]bool{}
	for _, sp := range spaces {
		in[sp.Name] = true
	}
	var out []BaselineEntry
	for _, b := range base {
		if ref, ok := cells[b.Cell]; !ok || in[ref.Space] {
			out = append(out, b)
		}
	}
	return out
}

func cellSpaces(cells map[string]CellRef) map[string]string {
	out := make(map[string]string, len(cells))
	for id, c := range cells {
		out[id] = c.Space
	}
	return out
}

// mach builds a Machine from a uname -r string.
func mach(release string, abi int, arch string, bpf bool, row string) Machine {
	major, minor, err := parseKernel(release)
	if err != nil {
		panic(err)
	}
	return Machine{Kernel: [2]int{major, minor}, ABI: abi, Arch: arch, BPFLSM: bpf, Row: row}
}

func ptr[T any](v T) *T { return &v }

func TestParseKernel(t *testing.T) {
	for _, c := range []struct {
		in           string
		major, minor int
		ok           bool
	}{
		{"6.17.0-41-generic", 6, 17, true},
		{"5.14.0-503.el9.x86_64", 5, 14, true},
		{"6.1.115-126.197.amzn2023.x86_64", 6, 1, true},
		{"6.8.0-rc1+", 6, 8, true},
		{"7.0.0", 7, 0, true},
		{"6.17", 6, 17, true},
		{"", 0, 0, false},
		{"generic", 0, 0, false},
		{"6", 0, 0, false},
		{"6.x", 0, 0, false},
		{".17", 0, 0, false},
		{"v6.17", 0, 0, false},
		{"99999999999999999999.1", 0, 0, false},
	} {
		major, minor, err := parseKernel(c.in)
		if (err == nil) != c.ok || (c.ok && (major != c.major || minor != c.minor)) {
			t.Errorf("parseKernel(%q) = %d.%d, %v; want %d.%d, ok=%v", c.in, major, minor, err, c.major, c.minor, c.ok)
		}
	}
}

// TestCurrentMachine: the machine the run is on describes itself, and a Where pinned to it matches it.
func TestCurrentMachine(t *testing.T) {
	m, err := CurrentMachine()
	if err != nil {
		t.Fatal(err)
	}
	if m.Arch != runtime.GOARCH {
		t.Errorf("arch %q, want %q", m.Arch, runtime.GOARCH)
	}
	if m.Kernel[0] < 3 {
		t.Errorf("kernel %v: not a Linux release this suite can run on", m.Kernel)
	}
	if m.Row != os.Getenv(RowEnv) {
		t.Errorf("row %q, want $%s = %q", m.Row, RowEnv, os.Getenv(RowEnv))
	}
	if err := m.Where().Validate(); err != nil {
		t.Errorf("the machine's own Where is invalid: %v", err)
	}
	if !m.Where().Matches(m) {
		t.Errorf("Where %v does not match the machine %v it was made from", m.Where(), m)
	}
}

func TestWhereMatches(t *testing.T) {
	m61 := mach("6.1.115-126.197.amzn2023.x86_64", 2, "amd64", false, "al2023")
	m69 := mach("6.9.0", 4, "arm64", false, "")
	m617 := mach("6.17.0-41-generic", 7, "amd64", true, "ubuntu-25.10")
	noABI := mach("6.17.0", 0, "amd64", true, "")
	for _, c := range []struct {
		name  string
		where Where
		m     Machine
		want  bool
	}{
		{"no predicate holds everywhere", Where{}, m617, true},
		{"no predicate holds on an unknown ABI", Where{}, noABI, true},

		// Kernels compare as numbers: as strings "6.17" < "6.9" and "6.10" < "6.9".
		{"kernel_max 6.1 on 6.1", Where{KernelMax: "6.1"}, m61, true},
		{"kernel_max 6.1 on 6.17", Where{KernelMax: "6.1"}, m617, false},
		{"kernel_max 6.9 on 6.17", Where{KernelMax: "6.9"}, m617, false},
		{"kernel_min 6.10 on 6.9", Where{KernelMin: "6.10"}, m69, false},
		{"kernel_min 6.9 on 6.17", Where{KernelMin: "6.9"}, m617, true},
		{"kernel_min and max are inclusive (low)", Where{KernelMin: "6.9", KernelMax: "6.12"}, m69, true},
		{"kernel_min and max are inclusive (high)", Where{KernelMin: "6.1", KernelMax: "6.17"}, m617, true},
		{"between", Where{KernelMin: "6.2", KernelMax: "6.16"}, m69, true},
		{"below the range", Where{KernelMin: "6.2", KernelMax: "6.16"}, m61, false},
		{"above the range", Where{KernelMin: "6.2", KernelMax: "6.16"}, m617, false},
		{"6.1 only is every 6.1.x", Where{KernelMin: "6.1", KernelMax: "6.1"}, m61, true},

		{"abi_max 3 on ABI 2", Where{ABIMax: 3}, m61, true},
		{"abi_max 3 on ABI 4", Where{ABIMax: 3}, m69, false},
		{"abi_min 4 on ABI 2", Where{ABIMin: 4}, m61, false},
		{"abi_min 4 on ABI 7", Where{ABIMin: 4}, m617, true},
		{"abi range", Where{ABIMin: 4, ABIMax: 6}, m69, true},
		// An unknown ABI (no Landlock) satisfies no abi predicate, so an abi_max entry cannot apply to it.
		{"abi_max on an unknown ABI", Where{ABIMax: 3}, noABI, false},
		{"abi_min on an unknown ABI", Where{ABIMin: 1}, noABI, false},

		{"arch amd64 on amd64", Where{Arch: "amd64"}, m617, true},
		{"arch amd64 on arm64", Where{Arch: "amd64"}, m69, false},

		{"bpf_lsm true on a bpf boot", Where{BPFLSM: ptr(true)}, m617, true},
		{"bpf_lsm true on a boot without", Where{BPFLSM: ptr(true)}, m61, false},
		{"bpf_lsm false on a boot without", Where{BPFLSM: ptr(false)}, m61, true},
		{"bpf_lsm false on a bpf boot", Where{BPFLSM: ptr(false)}, m617, false},

		{"row on its row", Where{Row: "al2023"}, m61, true},
		{"row on another row", Where{Row: "al2023"}, m617, false},
		{"row where the machine has none", Where{Row: "al2023"}, m69, false},

		{"every field", Where{KernelMin: "6.17", KernelMax: "6.17", ABIMin: 7, ABIMax: 7, Arch: "amd64", BPFLSM: ptr(true), Row: "ubuntu-25.10"}, m617, true},
		{"every field but one", Where{KernelMin: "6.17", KernelMax: "6.17", ABIMin: 7, ABIMax: 7, Arch: "arm64", BPFLSM: ptr(true), Row: "ubuntu-25.10"}, m617, false},
	} {
		if got := c.where.Matches(c.m); got != c.want {
			t.Errorf("%s: Matches = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMachineWhere(t *testing.T) {
	got := mach("6.17.0-41-generic", 7, "amd64", true, "").Where()
	want := Where{KernelMin: "6.17", KernelMax: "6.17", ABIMin: 7, ABIMax: 7, Arch: "amd64", BPFLSM: ptr(true)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Where() = %+v, want %+v", got, want)
	}
	got = mach("6.1.115", 0, "arm64", false, "al2023").Where()
	want = Where{KernelMin: "6.1", KernelMax: "6.1", Arch: "arm64", BPFLSM: ptr(false), Row: "al2023"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Where() with no ABI = %+v, want %+v", got, want)
	}
}

// TestRatchetHonoursWhere: an entry binds only the machines its Where matches. On any other machine it is
// neither applied (the failure it excuses elsewhere is a new failure here) nor stale (its cell passing here says
// nothing about the machine it was written for).
func TestRatchetHonoursWhere(t *testing.T) {
	const cell, runner, tier = "fs/truncate-in-write-entry", RunnerKernel, "cgroup"
	key := FailureKey(runner, cell, Tier(tier))
	ran := map[string]bool{runner + "|" + tier: true}
	failing := map[string]string{key: "the kernel allowed it"}
	passing := map[string]string{}
	entry := func(w Where) []BaselineEntry {
		return []BaselineEntry{{Cell: cell, Runner: runner, Tier: tier, Reason: "why", Where: w}}
	}
	m61 := mach("6.1.115-126.197.amzn2023.x86_64", 2, "amd64", false, "al2023")
	m617 := mach("6.17.0-41-generic", 7, "amd64", true, "")
	only61 := Where{KernelMin: "6.1", KernelMax: "6.1"}

	for _, c := range []struct {
		name      string
		base      []BaselineEntry
		m         Machine
		failures  map[string]string
		ran       map[string]bool
		wantNew   int
		wantStale int
	}{
		// The case that motivates the predicate: an entry written for 6.1 alone (the truncate floor below ABI 3, say).
		{"a 6.1-only entry on 6.1, still failing: excused", entry(only61), m61, failing, ran, 0, 0},
		{"a 6.1-only entry on 6.1, now passing: stale", entry(only61), m61, passing, ran, 0, 1},
		{"a 6.1-only entry on 6.17, failing: not applied, so a new failure", entry(only61), m617, failing, ran, 1, 0},
		{"a 6.1-only entry on 6.17, passing: neither applied nor stale", entry(only61), m617, passing, ran, 0, 0},

		// An entry with no Where is a v1 entry: it binds every machine.
		{"no where, failing", entry(Where{}), m617, failing, ran, 0, 0},
		{"no where, passing", entry(Where{}), m617, passing, ran, 0, 1},
		{"no where, failing, no baseline", nil, m617, failing, ran, 1, 0},

		// Kernels compare as numbers.
		{"kernel_max 6.9 does not apply on 6.17", entry(Where{KernelMax: "6.9"}), m617, failing, ran, 1, 0},
		{"kernel_min 6.10 does not apply on 6.1", entry(Where{KernelMin: "6.10"}), m61, failing, ran, 1, 0},

		{"abi_max 2 on ABI 2: excused", entry(Where{ABIMax: 2}), m61, failing, ran, 0, 0},
		{"abi_max 2 on ABI 7: not applied", entry(Where{ABIMax: 2}), m617, failing, ran, 1, 0},
		{"arch arm64 on amd64: not applied", entry(Where{Arch: "arm64"}), m617, failing, ran, 1, 0},
		{"bpf_lsm true on a bpf boot: excused", entry(Where{BPFLSM: ptr(true)}), m617, failing, ran, 0, 0},
		{"bpf_lsm true on the other boot: not applied", entry(Where{BPFLSM: ptr(true)}), m61, failing, ran, 1, 0},
		{"row al2023 on its row: excused", entry(Where{Row: "al2023"}), m61, failing, ran, 0, 0},
		{"row al2023 on a dev box with no row: not applied", entry(Where{Row: "al2023"}), m617, failing, ran, 1, 0},

		// The pair a baseline entry names must have run, as before.
		{"a pair that did not run is neither applied nor stale", entry(Where{}), m617, passing, map[string]bool{}, 0, 0},

		// Two machines' entries for one key side by side: each machine reads its own.
		{"two entries for one key, the machine's is stale",
			append(entry(only61), entry(Where{KernelMin: "6.17", KernelMax: "6.17"})...), m617, passing, ran, 0, 1},
		{"two entries for one key, the machine's excuses",
			append(entry(only61), entry(Where{KernelMin: "6.17", KernelMax: "6.17"})...), m617, failing, ran, 0, 0},
	} {
		newFailures, stale := Ratchet(c.base, c.ran, c.failures, c.m)
		if len(newFailures) != c.wantNew || len(stale) != c.wantStale {
			t.Errorf("%s: %d new %v, %d stale %v; want %d new, %d stale", c.name, len(newFailures), newFailures, len(stale), stale, c.wantNew, c.wantStale)
		}
	}
}

// TestRatchetSkipsCellsNotRun: a cell a run skipped on an axis (its fixture needs root, or a filesystem the kernel
// lacks) is not judged there: its entry is neither stale in Ratchet nor dropped by Update, though the axis ran.
func TestRatchetSkipsCellsNotRun(t *testing.T) {
	m := Machine{Kernel: [2]int{6, 17}, ABI: 7, Arch: "amd64"}
	base := []BaselineEntry{{Cell: "mounts/x", Runner: RunnerLedger, Tier: "landlock", Reason: "EY-1"}}
	ran := map[string]bool{RunnerLedger + "|landlock": true, NotRunKey("mounts/x", "landlock"): true}
	if newFailures, stale := Ratchet(base, ran, nil, m); len(newFailures)+len(stale) != 0 {
		t.Errorf("a cell not run: new %v, stale %v", newFailures, stale)
	}
	res, err := Update(base, UpdateRequest{Space: SpaceHandwritten, Spaces: map[string]string{"mounts/x": SpaceHandwritten}, Ran: ran, Machine: m})
	if err != nil || len(res.Entries) != 1 {
		t.Errorf("Update of a cell not run: %v, %v", res.Entries, err)
	}
	delete(ran, NotRunKey("mounts/x", "landlock"))
	if _, stale := Ratchet(base, ran, nil, m); len(stale) != 1 {
		t.Errorf("a cell that ran and passed: stale %v, want its entry", stale)
	}
}

// TestRatchetNeverExcusesAFailOpen: whatever the file holds, an entry under a runner that is not Baselinable
// excuses nothing, so a fail-open recorded as a failure stays a new failure and the entry is not read as stale.
func TestRatchetNeverExcusesAFailOpen(t *testing.T) {
	const cell, tier = "fs/a", "landlock"
	key := FailureKey(RunnerInvariant, cell, tier)
	base := []BaselineEntry{{Cell: cell, Runner: RunnerInvariant, Tier: tier, Reason: "a hand edit that should not hold"}}
	ran := map[string]bool{RunnerInvariant + "|" + tier: true}
	m := mach("6.17.0", 7, "amd64", false, "")
	newFailures, stale := Ratchet(base, ran, map[string]string{key: "a write succeeded outside every write entry"}, m)
	if len(newFailures) != 1 || len(stale) != 0 {
		t.Errorf("a fail-open: %d new %q, %d stale %q; want it new and the entry ignored", len(newFailures), newFailures, len(stale), stale)
	}
	if newFailures, stale = Ratchet(base, ran, nil, m); len(newFailures) != 0 || len(stale) != 0 {
		t.Errorf("an entry that excuses nothing was read as stale: %q %q", newFailures, stale)
	}
}

func TestParseBaselineIsStrict(t *testing.T) {
	entry := func(extra string) string {
		return `[{"cell":"fs/a","runner":"kernel","tier":"landlock","reason":"why"` + extra + `}]`
	}
	for _, c := range []struct {
		name, in, want string // want: a substring of the error; "" means accepted
	}{
		{"a v1 entry", entry(""), ""},
		{"every where field", entry(`,"where":{"kernel_min":"6.1","kernel_max":"6.12","abi_min":2,"abi_max":4,"arch":"amd64","bpf_lsm":false,"row":"al2023"}`), ""},
		{"an empty list", `[]`, ""},
		// A typo must not widen an entry: the field dropped would leave a predicate that matches more machines.
		{"an unknown entry field", entry(`,"wher":{"arch":"arm64"}`), "unknown field"},
		{"an unknown where field", entry(`,"where":{"kernal_min":"6.1"}`), "unknown field"},
		{"a kernel with a patch level", entry(`,"where":{"kernel_min":"6.1.5"}`), "kernel_min"},
		{"a kernel that is no number", entry(`,"where":{"kernel_max":"six"}`), "kernel_max"},
		{"a reversed kernel range", entry(`,"where":{"kernel_min":"6.12","kernel_max":"6.1"}`), "above"},
		{"a reversed abi range", entry(`,"where":{"abi_min":4,"abi_max":2}`), "abi_min"},
		{"a negative abi", entry(`,"where":{"abi_min":-1}`), "abi_min"},
		{"an arch spelled as uname -m does", entry(`,"where":{"arch":"x86_64"}`), "arch"},
		{"a row with a space", entry(`,"where":{"row":"al 2023"}`), "row"},
		{"data after the list", entry("") + "\n[]", "trailing"},
		{"not a list", `{"cell":"x"}`, "cannot unmarshal"},
		{"not json", `[{`, "EOF"},
	} {
		_, err := ParseBaseline([]byte(c.in))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: error %v, want one naming %q", c.name, err, c.want)
		}
	}
}

func TestCanonicalEncoding(t *testing.T) {
	// An empty baseline is the empty list, whether it is nil or not.
	for _, in := range [][]BaselineEntry{nil, {}} {
		got, err := CanonicalBaseline(in)
		if err != nil || string(got) != "[]\n" {
			t.Errorf("CanonicalBaseline(empty) = %q, %v; want %q", got, err, "[]\n")
		}
	}
	in := []BaselineEntry{
		{Cell: "fs/b", Runner: RunnerKernel, Tier: "cgroup", Reason: "ABI < 3 & more"},
		{Cell: "fs/a", Runner: RunnerLedger, Tier: "landlock", Reason: "r2", Where: Where{KernelMin: "6.12"}},
		{Cell: "fs/a", Runner: RunnerLedger, Tier: "landlock", Reason: "r1", Where: Where{KernelMax: "6.1"}},
	}
	// Sorted by key, entries of one key by their where; two-space JSON; <, > and & as written; a final newline.
	want := `[
  {
    "cell": "fs/b",
    "runner": "kernel",
    "tier": "cgroup",
    "reason": "ABI < 3 & more"
  },
  {
    "cell": "fs/a",
    "runner": "ledger",
    "tier": "landlock",
    "reason": "r1",
    "where": {
      "kernel_max": "6.1"
    }
  },
  {
    "cell": "fs/a",
    "runner": "ledger",
    "tier": "landlock",
    "reason": "r2",
    "where": {
      "kernel_min": "6.12"
    }
  }
]
`
	got, err := CanonicalBaseline(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("CanonicalBaseline:\n%s\nwant:\n%s", got, want)
	}
	// The input is not reordered in place, and the canonical form is a fixed point.
	if in[0].Cell != "fs/b" || in[1].Reason != "r2" {
		t.Error("CanonicalBaseline sorted its argument in place")
	}
	back, err := ParseBaseline(got)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalBaseline(back)
	if err != nil || !bytes.Equal(again, got) {
		t.Errorf("the canonical form is not a fixed point: %v\n%s", err, again)
	}
	// Every field of a where survives the round trip, bpf_lsm false included.
	full := []BaselineEntry{{Cell: "c", Runner: RunnerKernel, Tier: "landlock", Reason: "r",
		Where: Where{KernelMin: "6.1", KernelMax: "6.12", ABIMin: 2, ABIMax: 4, Arch: "arm64", BPFLSM: ptr(false), Row: "al2023"}}}
	enc, err := CanonicalBaseline(full)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ParseBaseline(enc)
	if err != nil || !reflect.DeepEqual(dec, full) {
		t.Errorf("round trip: %v\n%+v\nwant %+v", err, dec, full)
	}
}

// TestBaselineCanonical: the committed file is its own canonical re-encoding, so a hand edit that reorders or
// reindents it is a diff the reviewer sees. With -conformance.update=<space> it rewrites the file instead, the
// quick way to canonicalise after a hand edit.
func TestBaselineCanonical(t *testing.T) {
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := CanonicalBaseline(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(canon, data) {
		return
	}
	if requestedSpace(t) != "" {
		if err := writeFileLike(baselinePath, canon); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s rewritten in canonical form", baselinePath)
		return
	}
	t.Errorf("%s is not in canonical form (sorted by key, then by where; two-space JSON; one final newline): %s\n"+
		"rewrite it with `go test ./test/conformance -run TestBaselineCanonical -%s=<space>`", baselinePath, firstDifference(data, canon), updateFlag)
}

// firstDifference names the first line at which two files differ.
func firstDifference(have, want []byte) string {
	h, w := strings.Split(string(have), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(h) || i < len(w); i++ {
		var a, b string
		if i < len(h) {
			a = h[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			return fmt.Sprintf("line %d is %q, the canonical form has %q", i+1, a, b)
		}
	}
	return "the files are equal"
}

// isTODO says a reason is the placeholder Update writes (or a note to self in the same spirit).
func isTODO(reason string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(reason)), todoReason)
}

// baselineProblems lists what a reviewer would object to in a baseline file's bytes: it does not parse (an unknown
// field included), an entry names no cell of any space, has no reason or the placeholder one, is under a runner no
// baseline can hold, excuses a finding (a fail-open), repeats another entry, or the file is not in canonical form.
func baselineProblems(data []byte, cells map[string]CellRef) []string {
	base, err := ParseBaseline(data)
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	seen := map[string]bool{}
	for _, b := range base {
		name := b.describe()
		c, known := cells[b.Cell]
		if !known {
			out = append(out, fmt.Sprintf("baseline names %s, which is no cell of any space (the spaces are %s)", b.Cell, spaceNames()))
		}
		if !Baselinable(b.Runner) {
			out = append(out, fmt.Sprintf("baseline entry %s: runner %q is never baselined (a fail-open, runner %q, is fixed, not baselined)",
				name, b.Runner, RunnerInvariant))
		}
		switch {
		case strings.TrimSpace(b.Reason) == "":
			out = append(out, fmt.Sprintf("baseline entry %s has no reason", name))
		case isTODO(b.Reason):
			out = append(out, fmt.Sprintf("baseline entry %s has the placeholder reason %q: say why the build disagrees with the cell", name, b.Reason))
		}
		if known && c.Cell != nil && c.Cell.Finding != "" && b.Runner == RunnerKernel && string(c.Cell.FindingAt) == b.Tier {
			out = append(out, fmt.Sprintf("baseline entry %s: %s is a finding (a fail-open), which never enters the baseline", b.Key(), b.Cell))
		}
		id := b.Key() + "@" + b.Where.canonical()
		if seen[id] {
			out = append(out, fmt.Sprintf("baseline names %s twice", name))
		}
		seen[id] = true
	}
	canon, err := CanonicalBaseline(base)
	if err != nil {
		return append(out, err.Error())
	}
	if !bytes.Equal(canon, data) {
		out = append(out, "the baseline is not in canonical form: "+firstDifference(data, canon))
	}
	return out
}

// cells for the well-formedness cases.
func testCells() map[string]CellRef {
	return map[string]CellRef{
		"fs/a": {Space: SpaceHandwritten, Cell: &Cell{Name: "a"}},
		"fs/b": {Space: SpaceHandwritten, Cell: &Cell{Name: "b"}},
		"fs/f": {Space: SpaceHandwritten, Cell: &Cell{Name: "f", Finding: "allowed", FindingAt: TierLandlock}},
	}
}

func canonical(t *testing.T, base []BaselineEntry) []byte {
	t.Helper()
	b, err := CanonicalBaseline(base)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBaselineProblems: what a reviewer objects to in a baseline file, each caught.
func TestBaselineProblems(t *testing.T) {
	ok := BaselineEntry{Cell: "fs/a", Runner: RunnerKernel, Tier: "landlock", Reason: "the filter refuses truncate below ABI 3"}
	with := func(f func(*BaselineEntry)) []BaselineEntry {
		b := ok
		f(&b)
		return []BaselineEntry{b}
	}
	for _, c := range []struct {
		name string
		data []byte
		want string // a substring of a problem; "" means none
	}{
		{"an empty baseline", []byte("[]\n"), ""},
		{"a good entry", canonical(t, []BaselineEntry{ok}), ""},
		{"the same key on two machines", canonical(t, []BaselineEntry{ok, func() BaselineEntry { b := ok; b.Where = Where{KernelMax: "6.1"}; return b }()}), ""},
		{"a TODO reason", canonical(t, with(func(b *BaselineEntry) { b.Reason = "TODO" })), "TODO"},
		{"a TODO reason with text", canonical(t, with(func(b *BaselineEntry) { b.Reason = "todo: find out" })), "TODO"},
		{"no reason", canonical(t, with(func(b *BaselineEntry) { b.Reason = " " })), "no reason"},
		{"a cell of no space", canonical(t, with(func(b *BaselineEntry) { b.Cell = "gen/x" })), "no cell of any space"},
		{"the invariant runner", canonical(t, with(func(b *BaselineEntry) { b.Runner = RunnerInvariant })), "never baselined"},
		{"an unknown runner", canonical(t, with(func(b *BaselineEntry) { b.Runner = "kernal" })), "never baselined"},
		{"a finding", canonical(t, with(func(b *BaselineEntry) { b.Cell = "fs/f" })), "finding"},
		{"a duplicate", canonical(t, []BaselineEntry{ok, ok}), "twice"},
		{"four-space indent", []byte(strings.ReplaceAll(string(canonical(t, []BaselineEntry{ok})), "  ", "    ")), "canonical"},
		{"entries out of order", []byte(`[
  {
    "cell": "fs/b",
    "runner": "kernel",
    "tier": "landlock",
    "reason": "r"
  },
  {
    "cell": "fs/a",
    "runner": "kernel",
    "tier": "landlock",
    "reason": "r"
  }
]
`), "canonical"},
		{"no final newline", bytes.TrimSuffix(canonical(t, []BaselineEntry{ok}), []byte("\n")), "canonical"},
		{"an unknown field", []byte(`[{"cell":"fs/a","runner":"kernel","tier":"landlock","reason":"r","space":"fsgrid"}]`), "unknown field"},
	} {
		problems := baselineProblems(c.data, testCells())
		switch {
		case c.want == "" && len(problems) != 0:
			t.Errorf("%s: %q", c.name, problems)
		case c.want != "" && !strings.Contains(strings.ToLower(strings.Join(problems, "\n")), strings.ToLower(c.want)):
			t.Errorf("%s: problems %q, want one naming %q", c.name, problems, c.want)
		}
	}
}

func TestSpacesPartitionTheCells(t *testing.T) {
	cells, err := AllCells()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, sp := range []Space{{Name: SpaceHandwritten, Fixtures: Fixtures}, {Name: SpaceFSGrid, Fixtures: GenFSGrid}} {
		for _, fx := range sp.Fixtures() {
			for i := range fx.Cells {
				total++
				id := fx.ID(&fx.Cells[i])
				if c, ok := cells[id]; !ok || c.Space != sp.Name || c.Cell == nil {
					t.Errorf("cell %s is not in the %s space: %+v", id, sp.Name, c)
				}
			}
		}
	}
	if len(cells) != total {
		t.Errorf("%d cells in the spaces, %d in Fixtures() and GenFSGrid()", len(cells), total)
	}
	seen := map[string]bool{}
	for _, sp := range Spaces() {
		if sp.Name == "" || sp.Fixtures == nil || seen[sp.Name] {
			t.Errorf("space %+v is unnamed, has no fixtures or repeats a name", sp.Name)
		}
		seen[sp.Name] = true
	}
	if !seen[SpaceHandwritten] {
		t.Errorf("no %s space", SpaceHandwritten)
	}
}

func TestFailureKeyRoundTrip(t *testing.T) {
	for _, c := range []struct{ runner, cell, tier string }{
		{RunnerKernel, "fs/read-unmatched", "cgroup@lsm"},
		{RunnerCompile, "fsplan/regranted-read", "bpflsm"},
		{RunnerLedger, "a|b/c", "landlock"}, // a cell that holds the separator: the tier is what follows the last one
	} {
		runner, cell, tier, ok := ParseFailureKey(FailureKey(c.runner, c.cell, Tier(c.tier)))
		if !ok || runner != c.runner || cell != c.cell || string(tier) != c.tier {
			t.Errorf("ParseFailureKey(FailureKey(%v)) = %q %q %q %v", c, runner, cell, tier, ok)
		}
	}
	for _, bad := range []string{"", "kernel", "kernel|cell", "|cell|tier", "kernel||tier", "kernel|cell|"} {
		if _, _, _, ok := ParseFailureKey(bad); ok {
			t.Errorf("ParseFailureKey(%q) accepted", bad)
		}
	}
}

func TestBaselinable(t *testing.T) {
	for r, want := range map[string]bool{RunnerCompile: true, RunnerKernel: true, RunnerLedger: true, RunnerParity: true,
		RunnerInvariant: false, "effect": false, "finding": false, "": false, "kernal": false} {
		if got := Baselinable(r); got != want {
			t.Errorf("Baselinable(%q) = %v, want %v", r, got, want)
		}
	}
}

// updSpaces are the cells of the synthetic spaces the update tests run over.
var updSpaces = map[string]string{
	"fs/a": SpaceHandwritten, "fs/b": SpaceHandwritten,
	"gen/x": "fsgrid", "gen/y": "fsgrid",
}

func updRequest(failures map[string]string) UpdateRequest {
	return UpdateRequest{
		Space: "fsgrid", Spaces: updSpaces, Machine: mach("6.17.0-41-generic", 7, "amd64", true, ""),
		Ran:      map[string]bool{"kernel|landlock": true, "ledger|landlock": true},
		Failures: failures,
	}
}

// TestUpdateRefusesFailOpen: a fail-open never enters the baseline (ADR 0017): -update refuses it, and a refusal
// is all or nothing, so the legitimate disagreements of the same run are not written either.
func TestUpdateRefusesFailOpen(t *testing.T) {
	legit := FailureKey(RunnerKernel, "gen/x", "landlock") // a disagreement the named space may baseline
	base := []BaselineEntry{{Cell: "fs/a", Runner: RunnerLedger, Tier: "landlock", Reason: "kept"}}
	for _, c := range []struct {
		name     string
		failures map[string]string
		unsound  []string
		want     string
	}{
		{"the runner saw a fail-open", map[string]string{legit: "x"}, []string{"FAIL-OPEN gen/y at landlock: a mutation succeeded outside every write entry"}, "FAIL-OPEN gen/y"},
		{"the run already failed", map[string]string{legit: "x"}, []string{runRefusals(true, "", "")[0]}, "already reported errors"},
		{"an invariant failure of the named space", map[string]string{legit: "x", FailureKey(RunnerInvariant, "gen/y", "landlock"): "a write succeeded"}, nil, "fail-open"},
		{"an invariant failure of another space", map[string]string{legit: "x", FailureKey(RunnerInvariant, "fs/a", "landlock"): "a write succeeded"}, nil, "fail-open"},
		{"an effect failure", map[string]string{legit: "x", FailureKey("effect", "gen/y", "cgroup@lsm"): "a refused create left a file"}, nil, "fail-open"},
		{"a runner no baseline can hold", map[string]string{legit: "x", FailureKey("kernal", "gen/y", "landlock"): "x"}, nil, "never baselined"},
	} {
		req := updRequest(c.failures)
		req.Unsound = c.unsound
		res, err := Update(base, req)
		if err == nil {
			t.Errorf("%s: Update succeeded: %+v", c.name, res)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q, want one naming %q", c.name, err, c.want)
		}
		if res.Entries != nil || res.Added != nil || res.Dropped != nil {
			t.Errorf("%s: a refusal returned a result: %+v", c.name, res)
		}

		// The file stays byte for byte what it was, and no temporary file is left beside it.
		dir := t.TempDir()
		path := filepath.Join(dir, "baseline.json")
		orig := canonical(t, base)
		if err := os.WriteFile(path, orig, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := UpdateBaselineFile(path, req); err == nil {
			t.Errorf("%s: UpdateBaselineFile succeeded", c.name)
		}
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, orig) {
			t.Errorf("%s: a refused update changed the file: %v\n%s", c.name, err, after)
		}
		if names := dirNames(t, dir); !reflect.DeepEqual(names, []string{"baseline.json"}) {
			t.Errorf("%s: the directory holds %v", c.name, names)
		}
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestUpdateAddsOnlyItsSpace: -conformance.update=<space> adds the run's new disagreements for that space's cells,
// as TODO entries pinned to this machine, and refuses a new disagreement of any other space or of no space.
func TestUpdateAddsOnlyItsSpace(t *testing.T) {
	fsgrid := FailureKey(RunnerKernel, "gen/x", "landlock")
	fsgrid2 := FailureKey(RunnerLedger, "gen/y", "landlock")
	handwritten := FailureKey(RunnerKernel, "fs/b", "landlock")
	stray := FailureKey(RunnerKernel, "gen/nowhere", "landlock")
	m := mach("6.17.0-41-generic", 7, "amd64", true, "")

	// compile --test makes no kernel call (ADR 0019): its disagreement is the decision core's and holds on every
	// machine, so its entry has no where. The runners that perform real calls saw theirs on this machine only.
	compiled := FailureKey(RunnerCompile, "gen/x", "cgroup")

	res, err := Update(nil, updRequest(map[string]string{fsgrid: "the kernel allowed it", fsgrid2: "the ledger holds no line", compiled: "compile says allow"}))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{compiled, fsgrid, fsgrid2}; !reflect.DeepEqual(res.Added, want) || res.Dropped != nil {
		t.Errorf("added %v, dropped %v; want %v added, none dropped", res.Added, res.Dropped, want)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("entries %+v", res.Entries)
	}
	for i, e := range res.Entries {
		want := m.Where()
		if e.Runner == RunnerCompile {
			want = Where{}
		}
		if e.Reason != todoReason || !reflect.DeepEqual(e.Where, want) {
			t.Errorf("new entry %+v: want the reason %q and the where %+v", e, todoReason, want)
		}
		if e.Key() != res.Added[i] {
			t.Errorf("entries not in key order: %+v", res.Entries)
		}
	}

	for _, c := range []struct {
		name     string
		space    string
		failures map[string]string
		want     string
	}{
		{"a disagreement of another space", "fsgrid", map[string]string{fsgrid: "x", handwritten: "x"}, "belongs to the space handwritten"},
		{"a disagreement of no space", "fsgrid", map[string]string{fsgrid: "x", stray: "x"}, "no cell of any space"},
		{"a space that does not exist", "nope", map[string]string{fsgrid: "x"}, "no such space"},
		{"the other space, for the other failure", SpaceHandwritten, map[string]string{fsgrid: "x"}, "belongs to the space fsgrid"},
	} {
		req := updRequest(c.failures)
		req.Space = c.space
		if res, err := Update(nil, req); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (%+v), want a refusal naming %q", c.name, err, res, c.want)
		}
	}

	// A refusal names every offender, not only the first.
	req := updRequest(map[string]string{handwritten: "x", stray: "x"})
	_, err = Update(nil, req)
	if err == nil || !strings.Contains(err.Error(), "fs/b") || !strings.Contains(err.Error(), "gen/nowhere") {
		t.Errorf("a refusal should name every offender: %v", err)
	}
}

// TestUpdateKeepsWhatItCannotJudge: an update drops the entries that now pass, and only those the run could judge:
// the pair ran and the entry's where matches this machine. Entries of other machines and of pairs that did not
// run are kept as they are, and an entry that still fails keeps its reason.
func TestUpdateKeepsWhatItCannotJudge(t *testing.T) {
	still := BaselineEntry{Cell: "fs/b", Runner: RunnerKernel, Tier: "landlock", Reason: "the filter refuses truncate below ABI 3"}
	base := []BaselineEntry{
		{Cell: "fs/a", Runner: RunnerKernel, Tier: "landlock", Reason: "fixed since"}, // ran, passes: dropped
		still, // ran, fails: kept
		{Cell: "fs/a", Runner: RunnerLedger, Tier: "cgroup", Reason: "a pair that did not run"},                                      // kept
		{Cell: "fs/a", Runner: RunnerKernel, Tier: "landlock", Reason: "6.1 only", Where: Where{KernelMin: "6.1", KernelMax: "6.1"}}, // another machine: kept
		{Cell: "fs/a", Runner: RunnerKernel, Tier: "landlock", Reason: "ABI 7 only", Where: Where{ABIMin: 7, ABIMax: 7}},             // this machine, passes: dropped
	}
	req := updRequest(map[string]string{FailureKey(RunnerKernel, "fs/b", "landlock"): "x"})
	res, err := Update(base, req)
	if err != nil {
		t.Fatal(err)
	}
	// What is dropped is named by its key, and by its where when it has one.
	if want := []string{"kernel|fs/a|landlock", "kernel|fs/a|landlock [abi_min=7 abi_max=7]"}; !reflect.DeepEqual(res.Dropped, want) || res.Added != nil {
		t.Errorf("dropped %q added %q; want %q dropped, none added", res.Dropped, res.Added, want)
	}
	var reasons []string
	for _, e := range res.Entries {
		reasons = append(reasons, e.Reason)
	}
	sort.Strings(reasons)
	if want := []string{"6.1 only", "a pair that did not run", "the filter refuses truncate below ABI 3"}; !reflect.DeepEqual(reasons, want) {
		t.Errorf("kept %q, want %q", reasons, want)
	}
	// A disagreement the baseline already excuses on this machine is not new, so another space's cell may stay in it.
	again := updRequest(map[string]string{FailureKey(RunnerKernel, "fs/b", "landlock"): "x"})
	if _, err := Update([]BaselineEntry{still}, again); err != nil {
		t.Errorf("an excused disagreement of another space refused the update: %v", err)
	}
	// An entry whose where is another machine's does not excuse it here.
	other := still
	other.Where = Where{KernelMin: "6.1", KernelMax: "6.1"}
	if _, err := Update([]BaselineEntry{other}, again); err == nil || !strings.Contains(err.Error(), "belongs to the space handwritten") {
		t.Errorf("a disagreement excused only on 6.1 was taken as excused on 6.17: %v", err)
	}
}

// TestUpdateBaselineFile: the file is rewritten canonical with the file's mode, atomically, and an update that
// changes nothing leaves the file alone.
func TestUpdateBaselineFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	req := updRequest(map[string]string{FailureKey(RunnerKernel, "gen/x", "landlock"): "x"})
	res, err := UpdateBaselineFile(path, req)
	if err != nil || !res.Written || len(res.Added) != 1 {
		t.Fatalf("%+v, %v", res, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseBaseline(data)
	if err != nil || len(base) != 1 || base[0].Reason != todoReason {
		t.Fatalf("%v: %s", err, data)
	}
	if !bytes.Equal(data, canonical(t, base)) {
		t.Errorf("the written file is not canonical:\n%s", data)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("mode %v (%v), want 0640 kept", info.Mode().Perm(), err)
	}
	if names := dirNames(t, dir); !reflect.DeepEqual(names, []string{"baseline.json"}) {
		t.Errorf("the directory holds %v", names)
	}

	// The same run again changes nothing: the entry now excuses the disagreement.
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	res, err = UpdateBaselineFile(path, req)
	if err != nil || res.Written || len(res.Added) != 0 {
		t.Errorf("a second update: %+v, %v", res, err)
	}
	if info, err := os.Stat(path); err != nil || !info.ModTime().Equal(old) {
		t.Errorf("an update that changed nothing rewrote the file (mtime %v, %v)", info.ModTime(), err)
	}

	// A hand-edited file that is not canonical is rewritten even when no entry changes.
	messy := strings.ReplaceAll(string(data), "  ", "    ")
	if err := os.WriteFile(path, []byte(messy), 0o640); err != nil {
		t.Fatal(err)
	}
	res, err = UpdateBaselineFile(path, req)
	if err != nil || !res.Written || len(res.Added) != 0 {
		t.Errorf("canonicalising update: %+v, %v", res, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, data) {
		t.Errorf("not canonicalised: %v\n%s", err, after)
	}

	// A file that does not parse is an error, not an empty baseline.
	if err := os.WriteFile(path, []byte(`[{"cell":"fs/a","wher":{}}]`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateBaselineFile(path, req); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("a baseline with an unknown field was updated: %v", err)
	}
	if _, err := UpdateBaselineFile(filepath.Join(dir, "missing.json"), req); err == nil {
		t.Error("a missing baseline was updated")
	}
}

// fakeT stands in for *testing.T so that settleBaselineAt can be run to its end and judged. Fatalf records and
// ends the call as t.Fatalf ends a test, with a panic its caller recovers.
type fakeT struct {
	testing.TB
	failed bool
	errs   []string
	logs   []string
}

type fataled struct{}

func (f *fakeT) Helper()                      {}
func (f *fakeT) Failed() bool                 { return f.failed }
func (f *fakeT) Logf(format string, a ...any) { f.logs = append(f.logs, fmt.Sprintf(format, a...)) }
func (f *fakeT) Errorf(format string, a ...any) {
	f.failed = true
	f.errs = append(f.errs, fmt.Sprintf(format, a...))
}
func (f *fakeT) Fatalf(format string, a ...any) { f.Errorf(format, a...); panic(fataled{}) }
func (f *fakeT) Fatal(a ...any)                 { f.Fatalf("%s", fmt.Sprint(a...)) }

// settleWith runs settleBaselineAt with -conformance.update set to space ("" is not given) on a fake test that has
// already failed or not, and says whether the call ended in a Fatal.
func settleWith(space, path, run, skip string, alreadyFailed bool, ran map[string]bool, failures map[string]string) (f *fakeT, ended bool) {
	old := *updateSpace
	*updateSpace = space
	defer func() { *updateSpace = old }()
	f = &fakeT{failed: alreadyFailed}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(fataled); !ok {
				panic(r)
			}
			ended = true
		}
	}()
	settleBaselineAt(f, path, run, skip, "the kernel and a cell", ran, failures)
	return f, false
}

// TestSettleBaseline: how a runner ends. Without the flag it holds the run against the baseline; with it, it writes
// the baseline, and a run that already failed, a narrowed run, a fail-open and a space that does not exist each end
// the call without writing a byte.
func TestSettleBaseline(t *testing.T) {
	m, err := CurrentMachine()
	if err != nil {
		t.Fatal(err)
	}
	const cell, tier = "fs/read-unmatched", "landlock" // a cell of the handwritten space
	key := FailureKey(RunnerKernel, cell, tier)
	disagree := map[string]string{key: "the kernel allowed it"}
	ran := map[string]bool{RunnerKernel + "|" + tier: true}
	entry := BaselineEntry{Cell: cell, Runner: RunnerKernel, Tier: tier, Reason: "a known disagreement", Where: m.Where()}

	path := filepath.Join(t.TempDir(), "baseline.json")
	put := func(entries ...BaselineEntry) []byte {
		t.Helper()
		data := canonical(t, entries)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return data
	}
	unchanged := func(name string, want []byte) {
		t.Helper()
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: the baseline changed: %v\n%s", name, err, got)
		}
	}
	has := func(lines []string, want string) bool {
		for _, l := range lines {
			if strings.Contains(l, want) {
				return true
			}
		}
		return false
	}

	// Without the flag: the ratchet, and no write.
	orig := put()
	f, ended := settleWith("", path, "", "", false, ran, disagree)
	if ended || len(f.errs) != 1 || !has(f.errs, "new disagreement between the kernel and a cell: "+key) {
		t.Errorf("a new disagreement: ended %v, errors %q", ended, f.errs)
	}
	unchanged("ratchet", orig)
	orig = put(entry)
	if f, ended = settleWith("", path, "", "", false, ran, disagree); ended || len(f.errs) != 0 {
		t.Errorf("an excused disagreement: ended %v, errors %q", ended, f.errs)
	}
	if f, ended = settleWith("", path, "", "", false, ran, nil); ended || !has(f.errs, "now passes") {
		t.Errorf("an entry that now passes: ended %v, errors %q", ended, f.errs)
	}
	unchanged("ratchet with an entry", orig)

	// With the flag, a sound whole run: the disagreement is written as a TODO entry for this machine.
	put()
	f, ended = settleWith(SpaceHandwritten, path, "TestConformanceKernel", "", false, ran, disagree)
	if ended || len(f.errs) != 0 || !has(f.logs, "added "+key) {
		t.Fatalf("an update: ended %v, errors %q, logs %q", ended, f.errs, f.logs)
	}
	base, err := LoadBaseline(path)
	if err != nil || len(base) != 1 || base[0].Reason != todoReason || !reflect.DeepEqual(base[0].Where, m.Where()) {
		t.Fatalf("the written baseline: %v %+v", err, base)
	}
	written, _ := os.ReadFile(path)
	if f, ended = settleWith(SpaceHandwritten, path, "", "", false, ran, disagree); ended || !has(f.logs, "needs no change") {
		t.Errorf("a second update: ended %v, logs %q", ended, f.logs)
	}
	unchanged("a second update", written)
	// The fix lands: the entry is dropped and the file is the empty list again.
	if f, ended = settleWith(SpaceHandwritten, path, "", "", false, ran, nil); ended || !has(f.logs, "dropped "+key) {
		t.Errorf("an update after the fix: ended %v, logs %q", ended, f.logs)
	}
	unchanged("an update after the fix", []byte("[]\n"))

	// The refusals: each ends the call and leaves the file as it was.
	for _, c := range []struct {
		name          string
		space         string
		run, skip     string
		alreadyFailed bool
		failures      map[string]string
		want          string
	}{
		{"a run that already failed (a fail-open reported as it was found)", SpaceHandwritten, "", "", true, disagree, "already reported errors"},
		{"a run narrowed with -run", SpaceHandwritten, "TestConformanceKernel/cgroup", "", false, disagree, "narrowed"},
		{"a run narrowed with -skip", SpaceHandwritten, "", "TestConformanceKernel/cgroup", false, disagree, "narrowed"},
		{"a fail-open recorded as a failure", SpaceHandwritten, "", "", false, map[string]string{FailureKey(RunnerInvariant, cell, tier): "x"}, "fail-open"},
		{"a space that does not exist", "nope", "", "", false, disagree, "no such space"},
	} {
		orig = put(entry)
		f, ended = settleWith(c.space, path, c.run, c.skip, c.alreadyFailed, ran, c.failures)
		if !ended || !has(f.errs, c.want) {
			t.Errorf("%s: ended %v, errors %q; want a refusal naming %q", c.name, ended, f.errs, c.want)
		}
		unchanged(c.name, orig)
	}
}

func TestRunRefusals(t *testing.T) {
	for _, c := range []struct {
		name      string
		failed    bool
		run, skip string
		want      int
	}{
		{"a clean whole run", false, "TestConformanceKernel", "", 0},
		{"no filter", false, "", "", 0},
		{"both runners", false, "TestConformance", "", 0},
		{"an anchored runner", false, "^TestConformanceKernel$", "", 0},
		{"a failed run", true, "TestConformanceKernel", "", 1},
		{"a subtest filter", false, "TestConformanceKernel/cgroup@lsm", "", 1},
		{"a skip", false, "TestConformanceKernel", "TestConformanceKernel/landlock", 1},
		{"failed and narrowed", true, "TestConformanceKernel/fs", "", 2},
	} {
		if got := runRefusals(c.failed, c.run, c.skip); len(got) != c.want {
			t.Errorf("%s: %q, want %d reasons", c.name, got, c.want)
		}
	}
}

func TestUpdateFlagIsRegistered(t *testing.T) {
	f := flag.Lookup(updateFlag)
	if f == nil {
		t.Fatalf("no -%s flag", updateFlag)
	}
	if f.DefValue != "" {
		t.Errorf("-%s defaults to %q: an update must be asked for", updateFlag, f.DefValue)
	}
}
