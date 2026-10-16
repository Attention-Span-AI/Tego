// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The model behind TestPlaneSeqcountStress (plane_seqcount_stress_integration_test.go, enforce-plane §2.15), and
// its tests, which need no root: the chain of directories the cell's renamer flips, the states its cycle visits,
// what a walk that read the chain's levels at different times could name, how a ledger line is read, and the
// agent the run is given. The cell is only as good as its oracle, so the oracle's own cases are pinned here, where
// every CI run sees them.

// stressPositions is how many positions of the chain the renamer flips.
const stressPositions = 4

// stressCycle is the order the renamer flips the positions in: bottom up, which is the order a walk reads them in,
// and twice, so that the chain ends in the state it began in. Four binary positions can be spelled sixteen ways;
// the cycle's eight states are the ones the directory really has, and a path spelled any other way, one of the other
// eight or a pair split between its two spellings (P0 with m1), was never one.
var stressCycle = []int{0, 1, 2, 3, 0, 1, 2, 3}

// stressSamples is how many offending lines a tally keeps to quote.
const stressSamples = 8

// stressChain is the chain of directories below a root, and the state it is in:
//
//	root/u{3}/t{2}/P{1}/m{1}/G{0}/c{0}/leaf
//
// where {p} is bit p of bits. Position 3 is u and position 2 is t, each renamed where it is. Position 1 is the pair
// (P, m): flipping it renames the directory m and moves it between the two directories P0 and P1 in one rename, so
// m's name and its parent change together. Position 0 is the pair (G, c) in the same way, c between G0 and G1, both
// of them in m. A walk reads a dentry's sequence, then its parent, then its name, so a pair is the one place a
// single flip can tear what one dentry's reads say: the old parent with the new name. The agent mutates leaf,
// through a descriptor it holds, so the chain can move under it without its calls failing.
type stressChain struct {
	root string
	bits uint8
}

// stressSpell is a path of the chain spelled component by component: the G and P a parent pointer led to, the c and
// m names, and t and u. A whole state spells G and c from one bit, and P and m from one.
type stressSpell struct{ g, c, p, m, t, u uint8 }

// stressSpelled is the leaf's path as spelled by s below root.
func stressSpelled(root string, s stressSpell) string {
	n := func(prefix string, v uint8) string { return prefix + strconv.Itoa(int(v&1)) }
	return filepath.Join(root, n("u", s.u), n("t", s.t), n("P", s.p), n("m", s.m), n("G", s.g), n("c", s.c), "leaf")
}

// leaf is the leaf directory's path at the chain's present state.
func (c stressChain) leaf() string {
	bit := func(i int) uint8 { return c.bits >> i & 1 }
	return stressSpelled(c.root, stressSpell{g: bit(0), c: bit(0), p: bit(1), m: bit(1), t: bit(2), u: bit(3)})
}

// stressPath is the leaf's path in state bits.
func stressPath(root string, bits uint8) string { return stressChain{root: root, bits: bits}.leaf() }

// flip is the rename that flips position pos from the present state: the directory, and the path it is renamed to.
func (c stressChain) flip(pos int) (from, to string) {
	b := func(i int) string { return strconv.Itoa(int(c.bits >> i & 1)) }
	o := func(i int) string { return strconv.Itoa(1 - int(c.bits>>i&1)) } // the other spelling of position i
	u := filepath.Join(c.root, "u"+b(3))
	t := filepath.Join(u, "t"+b(2))
	m := filepath.Join(t, "P"+b(1), "m"+b(1))
	switch pos {
	case 0:
		return filepath.Join(m, "G"+b(0), "c"+b(0)), filepath.Join(m, "G"+o(0), "c"+o(0))
	case 1:
		return m, filepath.Join(t, "P"+o(1), "m"+o(1))
	case 2:
		return t, filepath.Join(u, "t"+o(2))
	default:
		return u, filepath.Join(c.root, "u"+o(3))
	}
}

// layout is the directories a project needs for the chain at state 0: the leaf, which makes the rest, and the
// second parents m and c move to.
func (c stressChain) layout() []string {
	return []string{c.leaf(), filepath.Join(c.root, "u0", "t0", "P1"), filepath.Join(c.root, "u0", "t0", "P0", "m0", "G1")}
}

// states is the set of leaf paths the cycle visits from the chain's present state: every path the leaf had.
func (c stressChain) states() map[string]struct{} {
	out := map[string]struct{}{c.leaf(): {}}
	for _, pos := range stressCycle {
		c.bits ^= 1 << pos
		out[c.leaf()] = struct{}{}
	}
	return out
}

// stressLine is the part of a ledger line the cell reads.
type stressLine struct {
	Kind          string `json:"kind"`
	Op            string `json:"op"`
	Path          string `json:"path"`
	Verdict       string `json:"verdict"`
	DecisionPlane string `json:"decision_plane"`
}

// stressCounts is what a run's ledger came to, as numbers.
type stressCounts struct {
	named          int // under the chain, named by a path the chain had
	marked         int // a walk that could not prove its path: the line says dev:ino/name, which fails closed
	wrong          int // under the chain, named by a spelling the chain never had
	refusedInChain int // an action under the chain the plane refused, which also fails closed
	deniedRefused  int // an action the contract denies, refused
	wrongAllow     int // an action the contract denies, not refused
}

// stressTally is stressCounts and the first lines that made the two failing counts.
type stressTally struct {
	stressCounts
	wrongPath      []string
	wrongAllowLine []string
}

// stressMarked is the form of a path the recorder gives a side its walk could not prove (observe's
// ruleIndex.matchDir): the device, the inode of the directory and the name, with no rule.
var stressMarked = regexp.MustCompile(`^[0-9]+:[0-9]+/`)

// add reads one ledger line of a run whose chain is rooted at root, in the project at project, and whose valid set
// is the leaf paths the chain had. Only fs actions are read. A line under the chain is named by the leaf's path or
// by a name in the leaf, and either must be a path the chain had: anything else is a wrong path, the thing the walk's
// sequence checks exist to prevent (enforce-plane §2.15). A line whose walk could not prove its path is marked, which
// is the walk failing closed and no fault. A line about what the contract denies (the denied tree, a name made for
// a refused move or link, a write outside every entry) must be a refusal; any other verdict is a wrong allow.
func (t *stressTally) add(root, project string, valid map[string]struct{}, l stressLine) {
	if l.Kind != "fs" {
		return
	}
	keep := func(list *[]string) {
		if len(*list) < stressSamples {
			*list = append(*list, l.Path)
		}
	}
	if !strings.HasPrefix(l.Path, "/") {
		if stressMarked.MatchString(l.Path) {
			t.marked++
		} else {
			t.wrong++
			keep(&t.wrongPath)
		}
		return
	}
	secret := project + "/out/secret"
	switch {
	case l.Path == root || strings.HasPrefix(l.Path, root+"/"):
		_, own := valid[l.Path]
		_, inLeaf := valid[filepath.Dir(l.Path)]
		if !own && !inLeaf {
			t.wrong++
			keep(&t.wrongPath)
			return
		}
		t.named++
		if l.Verdict == "refused" {
			t.refusedInChain++
		}
	case l.Path == secret || strings.HasPrefix(l.Path, secret+"/") || l.Path == project+"/forbidden.txt" ||
		strings.HasPrefix(filepath.Base(l.Path), "dn-"):
		if l.Verdict == "refused" {
			t.deniedRefused++
			return
		}
		t.wrongAllow++
		keep(&t.wrongAllowLine)
	}
}

// stressAgentSource is the agent: python3, because a run's agent is a command and every machine the plane runs on
// has it, and threads, because a thread's syscall holds no lock the others wait for. It opens the leaf once, which
// the plane decides, says ready, and waits for the test to start the renamer and say go. Then every thread does,
// through that descriptor, what the walk records, a create and remove of a directory, of a file and of a symlink,
// and an open and read of a file that is decided on the chain too; and every few turns it tries what the
// contract denies. It stops at the later of SECONDS and MIN_OPS completed calls, and at MAX_SECONDS whatever
// happened, and prints what it did as RESULT lines the test reads.
const stressAgentSource = `import os, threading, time

LEAF = "@LEAF@"
SECONDS = @SECONDS@
THREADS = @THREADS@
MIN_OPS = @MINOPS@
MAX_SECONDS = 60

# What the contract denies: every attempt must be refused, and none may ever succeed.
DENIED = (
    lambda: os.close(os.open("out/secret/key", os.O_RDONLY)),
    lambda: os.mkdir("out/secret/dn-sub"),
    lambda: os.unlink("out/secret/key2"),
    lambda: os.rename("out/secret/key3", "out/dn-moved"),
    lambda: os.link("out/secret/key4", "out/dn-hard"),
    lambda: os.close(os.open("forbidden.txt", os.O_WRONLY | os.O_CREAT, 0o644)),
)

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

leaf = os.open(LEAF, os.O_RDONLY | os.O_DIRECTORY)
with open("out/ready", "w") as f:
    f.write("x")
while not os.path.exists("out/go"):
    time.sleep(0.01)

stop = threading.Event()

class Tally:
    ops = refused = errors = denied = denied_refused = denied_allowed = denied_other = 0

def churn(i, tally):
    d, f, l = "sq-d%d" % i, "sq-f%d" % i, "sq-l%d" % i

    def mkdir():
        os.mkdir(d, dir_fd=leaf)
        os.rmdir(d, dir_fd=leaf)

    def create():
        h = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=leaf)
        os.close(h)
        os.unlink(f, dir_fd=leaf)

    def symlink():
        os.symlink("data", l, dir_fd=leaf)
        os.unlink(l, dir_fd=leaf)

    def read():
        h = os.open("data", os.O_RDONLY, dir_fd=leaf)
        os.read(h, 1)
        os.close(h)

    turn = 0
    while not stop.is_set():
        for call in (mkdir, create, symlink, read):
            try:
                call()
                tally.ops += 1
            except PermissionError:
                tally.refused += 1
            except OSError:
                tally.errors += 1
        turn += 1
        if turn % 8 == 0:
            attempt = DENIED[(turn // 8 + i) % len(DENIED)]
            tally.denied += 1
            try:
                attempt()
                tally.denied_allowed += 1
            except PermissionError:
                tally.denied_refused += 1
            except OSError:
                tally.denied_other += 1

tallies = [Tally() for _ in range(THREADS)]
threads = [threading.Thread(target=churn, args=(i, tallies[i])) for i in range(THREADS)]
start = time.monotonic()
for t in threads:
    t.start()
while True:
    time.sleep(0.05)
    elapsed = time.monotonic() - start
    if elapsed >= MAX_SECONDS or (elapsed >= SECONDS and sum(t.ops for t in tallies) >= MIN_OPS):
        break
stop.set()
for t in threads:
    t.join()
total = lambda name: sum(getattr(t, name) for t in tallies)
result("stress", "seconds=%.2f threads=%d ops=%d refused=%d errors=%d" %
       (time.monotonic() - start, THREADS, total("ops"), total("refused"), total("errors")))
result("denied", "attempts=%d refused=%d allowed=%d other=%d" %
       (total("denied"), total("denied_refused"), total("denied_allowed"), total("denied_other")))
`

// stressAgent is stressAgentSource for a chain rooted at c.root (a path relative to the project), run for seconds
// and at least minOps calls, by threads threads.
func stressAgent(c stressChain, seconds, threads, minOps int) string {
	return strings.NewReplacer("@LEAF@", c.leaf(), "@SECONDS@", strconv.Itoa(seconds),
		"@THREADS@", strconv.Itoa(threads), "@MINOPS@", strconv.Itoa(minOps)).Replace(stressAgentSource)
}

// stressFields reads the key=value words of one of the agent's RESULT lines.
func stressFields(line string) map[string]float64 {
	out := map[string]float64{}
	for _, w := range strings.Fields(line) {
		if k, v, ok := strings.Cut(w, "="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				out[k] = f
			}
		}
	}
	return out
}

// walkedSet is the set of leaf paths the cycle visits, for the oracle's cases.
func walkedSet(root string) map[string]struct{} {
	return stressChain{root: root}.states()
}

// TestStressChainCyclesThroughEightStates: two passes over the four positions, bottom up, visit eight distinct
// states and end where they began, and each flip changes exactly one position. Of the sixteen spellings four
// binary positions can have, the other eight are spellings no state ever had, which a torn read can name.
func TestStressChainCyclesThroughEightStates(t *testing.T) {
	root := "/p/out/sq"
	c := stressChain{root: root}
	seen := map[uint8]bool{c.bits: true}
	prev := c.bits
	for i, pos := range stressCycle {
		from, to := c.flip(pos)
		if from == to {
			t.Fatalf("flip %d (position %d) renames %s onto itself", i, pos, from)
		}
		c.bits ^= 1 << pos
		if d := c.bits ^ prev; d != 1<<pos {
			t.Fatalf("flip %d changed bits %04b -> %04b, want only position %d to change", i, prev, c.bits, pos)
		}
		prev = c.bits
		if i < len(stressCycle)-1 && seen[c.bits] {
			t.Fatalf("flip %d revisits state %04b before the cycle ends", i, c.bits)
		}
		seen[c.bits] = true
	}
	if c.bits != 0 {
		t.Fatalf("the cycle ends at state %04b, want 0", c.bits)
	}
	if got := len(seen); got != 8 {
		t.Fatalf("the cycle visits %d states, want 8", got)
	}
	if got := len(walkedSet(root)); got != 8 {
		t.Fatalf("states() holds %d leaf paths, want 8", got)
	}
}

// TestStressChainRenamesMatchTheModel runs the model's flips against a real tree (no root: a temporary directory),
// two full cycles, and requires the leaf to be at exactly the path the model names after each one, and at no other
// spelling the sixteen states give. A model that named a path the renames do not make would call every correct
// walk wrong.
func TestStressChainRenamesMatchTheModel(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sq")
	c := stressChain{root: root}
	for _, d := range c.layout() {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(c.leaf(), "data"), []byte("d"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := range 2 * len(stressCycle) {
		pos := stressCycle[i%len(stressCycle)]
		from, to := c.flip(pos)
		if err := os.Rename(from, to); err != nil {
			t.Fatalf("flip %d (position %d): %v", i, pos, err)
		}
		c.bits ^= 1 << pos
		for bits := range uint8(1 << stressPositions) {
			_, err := os.Stat(filepath.Join(stressPath(root, bits), "data"))
			if want := bits == c.bits; (err == nil) != want {
				t.Fatalf("after flip %d (state %04b): the leaf's data at state %04b's path: %v, want present=%v",
					i, c.bits, bits, err, want)
			}
		}
	}
}

// TestStressChainATornReadNamesNoState is why the chain is the one it is. A walk reads each dentry's parent and then
// its name, the levels from the leaf up, and the renamer flips the positions in that same order. A read that sees
// no flip at all, or every component after the same flip, names a state the chain had. A pair flips in one rename,
// so a walk whose read of m's parent came before the flip and whose read of its name came after names (P0, m1), which
// the directory never was; and a read that straddles two flips of different positions, taking a low level from before
// them and a higher one from after, names a spelling no state had. Those are the paths a walk with no sequence
// check, or one whose sequence reads are not ordered, would put in the ledger.
func TestStressChainATornReadNamesNoState(t *testing.T) {
	root := "/p/out/sq"
	valid := walkedSet(root)
	// after[j] is the state once j flips of the cycle have been made, from state 0.
	after := make([]uint8, len(stressCycle)+1)
	for j, pos := range stressCycle {
		after[j+1] = after[j] ^ 1<<pos
	}
	// reads says after how many flips of the cycle each component was read, in the order a walk reads them: the
	// parent pointer (g, p) and the name of c and of m, then t and u.
	type reads struct{ g, c, p, m, t, u int }
	spelling := func(r reads) string {
		bit := func(j, pos int) uint8 { return after[j] >> pos & 1 }
		return stressSpelled(root, stressSpell{g: bit(r.g, 0), c: bit(r.c, 0), p: bit(r.p, 1), m: bit(r.m, 1), t: bit(r.t, 2), u: bit(r.u, 3)})
	}
	torn, whole := 0, 0
	for start := 0; start+3 <= len(stressCycle); start++ {
		for a := range 3 {
			for b := a; b < 3; b++ {
				for c := b; c < 3; c++ {
					for d := c; d < 3; d++ {
						for e := d; e < 3; e++ {
							// Six reads in order, within three flips of one another, from the start-th flip on.
							r := reads{start, start + a, start + b, start + c, start + d, start + e}
							if _, ok := valid[spelling(r)]; ok {
								whole++
							} else {
								torn++
							}
						}
					}
				}
			}
		}
	}
	if torn == 0 {
		t.Fatal("no read that straddles flips names a spelling outside the cycle: the cell could not tell a torn read from a whole one")
	}
	// A read that sees one flip everywhere is whole by construction.
	for j := range after {
		r := reads{j, j, j, j, j, j}
		if _, ok := valid[spelling(r)]; !ok {
			t.Fatalf("a read after flip %d everywhere names %s, which is no state of the cycle", j, spelling(r))
		}
	}
	// One flip of a pair tears one dentry's reads: its parent from before the rename and its name from after it.
	pairs := 0
	for j, pos := range stressCycle {
		var r reads
		switch pos {
		case 0:
			r = reads{j, j + 1, j + 1, j + 1, j + 1, j + 1}
		case 1:
			r = reads{j, j, j, j + 1, j + 1, j + 1}
		default:
			continue
		}
		if _, ok := valid[spelling(r)]; ok {
			t.Fatalf("flip %d (position %d): the parent read before and the name after names %s, a state of the cycle", j, pos, spelling(r))
		}
		pairs++
	}
	if pairs != 4 {
		t.Fatalf("%d pair flips in the cycle, want 4", pairs)
	}
	t.Logf("%d straddling reads name no state of the cycle, %d name one by chance", torn, whole)
}

// TestStressTallyReadsLedgerLines is the oracle's own table: what the cell calls named, marked, wrong, and a wrong
// allow, for a line of each shape the run can write.
func TestStressTallyReadsLedgerLines(t *testing.T) {
	root := "/p/out/sq"
	project := "/p"
	state1 := stressPath(root, 1)
	torn := stressSpelled(root, stressSpell{g: 1, c: 1, p: 0, m: 1})
	cases := []struct {
		name      string
		line      stressLine
		want      stressCounts
		wantPath  []string
		wantAllow []string
	}{
		{"a mkdir named by a path the cycle visits",
			stressLine{Kind: "fs", Op: "mkdir", Path: state1 + "/sq-d1", Verdict: "allow"}, stressCounts{named: 1}, nil, nil},
		{"the leaf's own open, its path a state's",
			stressLine{Kind: "fs", Op: "open", Path: state1, Verdict: "allow"}, stressCounts{named: 1}, nil, nil},
		{"a mkdir named by a spelling no state had",
			stressLine{Kind: "fs", Op: "mkdir", Path: torn + "/sq-d1", Verdict: "allow"},
			stressCounts{wrong: 1}, []string{torn + "/sq-d1"}, nil},
		{"a path that is neither absolute nor a marked side is wrong, not marked",
			stressLine{Kind: "fs", Op: "mkdir", Path: "sq-d1", Verdict: "allow"}, stressCounts{wrong: 1}, []string{"sq-d1"}, nil},
		{"a walk that could not prove its path is marked, which fails closed",
			stressLine{Kind: "fs", Op: "unlink", Path: "26:17/sq-f1", Verdict: "allow"}, stressCounts{marked: 1}, nil, nil},
		{"an action refused under the chain is counted, not wrong",
			stressLine{Kind: "fs", Op: "mkdir", Path: state1 + "/sq-d1", Verdict: "refused"},
			stressCounts{named: 1, refusedInChain: 1}, nil, nil},
		{"a probe of the denied tree that was refused",
			stressLine{Kind: "fs", Op: "open", Path: project + "/out/secret/key", Verdict: "refused"},
			stressCounts{deniedRefused: 1}, nil, nil},
		{"a probe of the denied tree that was allowed is a wrong allow",
			stressLine{Kind: "fs", Op: "open", Path: project + "/out/secret/key", Verdict: "allow"},
			stressCounts{wrongAllow: 1}, nil, []string{project + "/out/secret/key"}},
		{"a write outside every entry that was allowed is a wrong allow",
			stressLine{Kind: "fs", Op: "open", Path: project + "/forbidden.txt", Verdict: "allow"},
			stressCounts{wrongAllow: 1}, nil, []string{project + "/forbidden.txt"}},
		{"a link made for a refused move, allowed, is a wrong allow",
			stressLine{Kind: "fs", Op: "link", Path: project + "/out/dn-hard", Verdict: "allow"},
			stressCounts{wrongAllow: 1}, nil, []string{project + "/out/dn-hard"}},
		{"a line that is not an fs action is not read",
			stressLine{Kind: "net", Path: state1 + "/x", Verdict: "allow"}, stressCounts{}, nil, nil},
		{"an fs line elsewhere in the project is not read",
			stressLine{Kind: "fs", Op: "open", Path: project + "/out/ok.txt", Verdict: "allow"}, stressCounts{}, nil, nil},
		{"the secret tree's name as a prefix of another name is another name",
			stressLine{Kind: "fs", Op: "open", Path: project + "/out/secret2/key", Verdict: "allow"}, stressCounts{}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got stressTally
			got.add(root, project, walkedSet(root), tc.line)
			if got.stressCounts != tc.want {
				t.Fatalf("counts %+v, want %+v", got.stressCounts, tc.want)
			}
			if !slices.Equal(got.wrongPath, tc.wantPath) || !slices.Equal(got.wrongAllowLine, tc.wantAllow) {
				t.Fatalf("samples %v / %v, want %v / %v", got.wrongPath, got.wrongAllowLine, tc.wantPath, tc.wantAllow)
			}
		})
	}
}

// TestStressTallyKeepsFewSamples: a flood of wrong lines is counted whole and quoted in part, so a failing cell's
// message stays readable.
func TestStressTallyKeepsFewSamples(t *testing.T) {
	root := "/p/out/sq"
	valid := walkedSet(root)
	var tl stressTally
	for range 100 {
		tl.add(root, "/p", valid, stressLine{Kind: "fs", Op: "mkdir", Path: stressSpelled(root, stressSpell{g: 1, m: 1}) + "/sq-d", Verdict: "allow"})
	}
	if tl.wrong != 100 || len(tl.wrongPath) != stressSamples {
		t.Fatalf("%d wrong, %d quoted; want 100 and %d", tl.wrong, len(tl.wrongPath), stressSamples)
	}
}

// TestStressAgentIsValidPython compiles the agent the cell hands the run, where python3 is installed: a syntax
// slip in it would otherwise show only in the privileged suites, as a run that ends before it says ready.
func TestStressAgentIsValidPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 is not installed: %v", err)
	}
	script := stressAgent(stressChain{root: "out/sq"}, 6, 3, 20000)
	if strings.Contains(script, "@") {
		t.Fatalf("a placeholder is left in the agent:\n%s", script)
	}
	cmd := exec.Command(python, "-c", "import sys; compile(sys.stdin.read(), 'agent.py', 'exec')")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the stress agent does not compile: %v\n%s", err, out)
	}
}

// TestStressAgentRunsItsCalls runs the agent against a real tree with no run around it, which is no root and no plane,
// so nothing is enforced: its descriptor calls all succeed, none is refused or errs, its attempts at what the contract
// denies succeed too (the tree is a temporary one), and it prints the two RESULT lines the cell reads, in the form
// stressFields reads them. That is the agent's own mechanics (the ready and go files, the descriptor calls, the
// counting and the stop) checked where every CI run sees them, so the privileged suites test the plane and not it.
func TestStressAgentRunsItsCalls(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 is not installed: %v", err)
	}
	project := t.TempDir()
	rel := stressChain{root: filepath.Join("out", "sq")}
	for _, d := range rel.layout() {
		if err := os.MkdirAll(filepath.Join(project, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(project, "out", "secret"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		filepath.Join(rel.leaf(), "data"): "data\n", "out/secret/key": "k\n", "out/secret/key2": "k2\n",
		"out/secret/key3": "k3\n", "out/secret/key4": "k4\n",
		"agent.py": stressAgent(rel, 1, 2, 400),
	} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	cmd := exec.Command(python, "agent.py")
	cmd.Dir = project
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(project, "out", "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("the agent never said ready:\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(project, "out", "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the agent failed: %v\n%s", err, out.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the agent did not stop:\n%s", out.String())
	}
	results := map[string]string{}
	for _, l := range strings.Split(out.String(), "\n") {
		if f := strings.SplitN(l, " ", 3); len(f) == 3 && f[0] == "RESULT" {
			results[f[1]] = f[2]
		}
	}
	churn, denied := stressFields(results["stress"]), stressFields(results["denied"])
	if churn["ops"] < 400 || churn["threads"] != 2 || churn["refused"] != 0 || churn["errors"] != 0 {
		t.Errorf("churn %v from %q, want at least 400 calls on 2 threads, none refused and none an error", churn, results["stress"])
	}
	if denied["attempts"] == 0 || denied["refused"] != 0 || denied["allowed"]+denied["other"] != denied["attempts"] {
		t.Errorf("denied %v from %q, want attempts, none refused, each allowed or an error (nothing enforces here)",
			denied, results["denied"])
	}
	if denied["allowed"] == 0 {
		t.Errorf("no attempt at what the contract denies went through with nothing to refuse it: %q", results["denied"])
	}
}
