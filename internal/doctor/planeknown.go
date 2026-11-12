// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The plane probe's known answers (docs/p0/enforce-plane.md R21, §2.5). The probe row alone exercises one answer
// per hook, the fail-closed NOROWS refusal; a verifier before 6.8 verifies a bpf_loop callback once, from its first
// call's state, and has twice hard-wired a walk branch away (the BOUND check, the unix name check) while every hook
// still refused NOROWS. So once the probe row has passed, each mode fills a scratch slot of the probe's own row
// maps through the real fill (enforce/cgroup ProbeRows: a run's plan, pass and check) from O_PATH descriptors of
// doctor's own fixtures, arms a second scratch cgroup as a run of that slot, and has a child there make one action
// per known-answer cell. A mode is selected only when every cell's verdict and the slot's fail-closed counters
// across it are exactly what the plane must answer.
//
// The fixtures are a directory tree doctor makes, with two tmpfs mounts the child makes in a mount namespace of its
// own (so no mount is ever seen outside it, and none outlives it): dr/m, beneath a deny_read row on dr, and x, an
// exec-capable filesystem for the exec cells (the fixture base is often a noexec /run). doctor opens the paths
// under the child's mounts through /proc/<child>/root, which resolves in the child's namespace.

// Known-answer slots and gens: the probe row keeps slot 0 (planeProbeIdx); each mode fills its own slot of the
// row maps both modes' programs share, so no mode reads another's rows.
const (
	planeKnownStaleGen = 1
	planeKnownGen      = 2
)

// planeKnownSlot is mode m's known-answer slot.
func planeKnownSlot(m bpfobj.PlaneMode) uint32 {
	if m == bpfobj.PlaneLSM {
		return 1
	}
	return 2
}

// PlaneCountDelta is what a known-answer cell added to its slot's fail-closed counters (bpf.PlaneCounts).
type PlaneCountDelta struct {
	Mismatch   uint64 `json:"mismatch,omitempty"`
	Unresolved uint64 `json:"unresolved,omitempty"`
	Bound      uint64 `json:"bound,omitempty"`
	NoRows     uint64 `json:"norows,omitempty"`
}

// String names the counters that moved, "none" when none did.
func (d PlaneCountDelta) String() string {
	var parts []string
	for _, c := range []struct {
		name string
		n    uint64
	}{{"mismatch", d.Mismatch}, {"unresolved", d.Unresolved}, {"bound", d.Bound}, {"norows", d.NoRows}} {
		if c.n != 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", c.name, c.n))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

// countDelta is after less before, field by field.
func countDelta(before, after bpfobj.PlaneCounts) PlaneCountDelta {
	return PlaneCountDelta{Mismatch: after.Mismatch - before.Mismatch, Unresolved: after.Unresolved - before.Unresolved,
		Bound: after.Bound - before.Bound, NoRows: after.NoRows - before.NoRows}
}

// PlaneKnownAnswer is one known-answer cell: the verdict and counters the plane must give, and what it gave.
type PlaneKnownAnswer struct {
	Cell       string          `json:"cell"`
	Want       string          `json:"want"`
	Got        string          `json:"got"`
	WantCounts PlaneCountDelta `json:"want_counts"`
	GotCounts  PlaneCountDelta `json:"got_counts"`
}

// OK is an exact match of verdict and counters.
func (a PlaneKnownAnswer) OK() bool { return a.Got == a.Want && a.GotCounts == a.WantCounts }

// fault says how a cell differs from its answer.
func (a PlaneKnownAnswer) fault() string {
	s := "known answer " + a.Cell + ": " + a.Got
	if a.Got != a.Want {
		s += ", want " + a.Want
	}
	if a.GotCounts != a.WantCounts {
		s += fmt.Sprintf(" (counters %s, want %s)", a.GotCounts, a.WantCounts)
	}
	return s
}

// planeKnownFlip is a test-only switch: the cell it names has its expected verdict flipped, so a kernel that
// answers correctly fails the mode (TestIntegrationPlaneProbeRejectsAFlippedKnownAnswer). Nothing else sets it.
var planeKnownFlip string

// planeKnownCells is the known-answer table, each cell with no answer yet: the verdict the plane must give its
// action and what the action must add to the slot's counters.
func planeKnownCells() []PlaneKnownAnswer {
	cells := []PlaneKnownAnswer{
		// A read two levels below a deny_read row, across the tmpfs mounted at dr/m: the walk crosses the mount at
		// its root without counting a level, and meets the row.
		{Cell: "deny-read-across-mount", Want: planeRefused},
		// A read below a row of the slot's previous gen: absent to the walk, which ends at the root (a read allowed).
		{Cell: "stale-row", Want: planePassed},
		// A read below a current row whose key inode no longer carries its identity: refused and counted.
		{Cell: "identity-mismatch", Want: planeRefused, WantCounts: PlaneCountDelta{Mismatch: 1}},
		// A read bpf.PlaneWalkMax levels below a deny_read row, which the walk still meets.
		{Cell: "depth-64", Want: planeRefused},
		// A read a level further: the walk ends BOUND before the row, refused and counted. A walk whose bound was
		// hard-wired away meets the row instead and counts nothing.
		{Cell: "depth-65", Want: planeRefused, WantCounts: PlaneCountDelta{Bound: 1}},
		// An exec in an exec.allow directory row, of a hard link that no file row names.
		{Cell: "exec-dir-row", Want: planePassed},
		// An exec of the file an exec row names, under its name.
		{Cell: "exec-file-row", Want: planePassed},
		// An exec of the same inode under another name in the same directory: no arm matches.
		{Cell: "exec-hard-link", Want: planeRefused},
		// An rmdir where no row allows a modification.
		{Cell: "rmdir", Want: planeRefused},
	}
	cells = append(cells, planeKnownNameCells...)
	for i := range cells {
		if cells[i].Cell == planeKnownFlip {
			if cells[i].Want == planePassed {
				cells[i].Want = planeRefused
			} else {
				cells[i].Want = planePassed
			}
		}
	}
	return cells
}

// planeKnownNameCells are ADR 0043 C9's cells, since a mode's name check decides every run that has name entries:
// the built-in .env pair over the scope nm/p, beneath a
// write row on nm/, with every file made after the fill, as a file the agent's tools make later. None counts.
var planeKnownNameCells = []PlaneKnownAnswer{
	// A .env no row keys, made after the fill: the name check refuses it by its name.
	{Cell: "name-created-later", Want: planeRefused},
	// .ENV: the compare folds ASCII case (D2).
	{Cell: "name-folded", Want: planeRefused},
	// .env.example: the built-in prefix entry's exception.
	{Cell: "name-exception", Want: planePassed},
	// A .env outside every scope (nm/out).
	{Cell: "name-outside-scope", Want: planePassed},
	// A .env beneath node_modules: the climb stops at a dependency directory's name (D4).
	{Cell: "name-dependency-dir", Want: planePassed},
	// A directory renamed within its scope stays covered (D5), and the write row allows the move.
	{Cell: "name-dir-renamed-within", Want: planePassed},
	// A directory moved out of its scope: what an entry covers beneath it would leave coverage (D5).
	{Cell: "name-dir-moved-out", Want: planeRefused},
}

// planeKnownDeep is the deep chain's file levels directories below the deny_read row at deep/.
func planeKnownDeep(levels int) string {
	return filepath.Join("deep", strings.Repeat("c/", levels-1)+"f")
}

// planeKnownActions are the child's actions, each on the known-answer directory dir.
var planeKnownActions = map[string]func(dir string) error{
	"deny-read-across-mount": func(dir string) error { return planeKnownOpen(filepath.Join(dir, "dr/m/f")) },
	"stale-row":              func(dir string) error { return planeKnownOpen(filepath.Join(dir, "st/f")) },
	"identity-mismatch":      func(dir string) error { return planeKnownOpen(filepath.Join(dir, "bad/f")) },
	"depth-64": func(dir string) error {
		return planeKnownOpen(filepath.Join(dir, planeKnownDeep(bpfobj.PlaneWalkMax)))
	},
	"depth-65": func(dir string) error {
		return planeKnownOpen(filepath.Join(dir, planeKnownDeep(bpfobj.PlaneWalkMax+1)))
	},
	"exec-dir-row":       func(dir string) error { return planeKnownExec(filepath.Join(dir, "x/xd/img")) },
	"exec-file-row":      func(dir string) error { return planeKnownExec(filepath.Join(dir, "x/xf/run")) },
	"exec-hard-link":     func(dir string) error { return planeKnownExec(filepath.Join(dir, "x/xf/alias")) },
	"rmdir":              func(dir string) error { return unix.Rmdir(filepath.Join(dir, "rmd")) },
	"name-created-later": func(dir string) error { return planeKnownOpen(filepath.Join(dir, "nm/p/.env")) },
	"name-folded":        func(dir string) error { return planeKnownOpen(filepath.Join(dir, "nm/p/.ENV")) },
	"name-exception":     func(dir string) error { return planeKnownOpen(filepath.Join(dir, "nm/p/.env.example")) },
	"name-outside-scope": func(dir string) error { return planeKnownOpen(filepath.Join(dir, "nm/out/.env")) },
	"name-dependency-dir": func(dir string) error {
		return planeKnownOpen(filepath.Join(dir, "nm/p/node_modules/q/.env"))
	},
	"name-dir-renamed-within": func(dir string) error {
		return unix.Rename(filepath.Join(dir, "nm/p/e"), filepath.Join(dir, "nm/p/e2"))
	},
	"name-dir-moved-out": func(dir string) error {
		return unix.Rename(filepath.Join(dir, "nm/p/d"), filepath.Join(dir, "nm/out/d"))
	},
}

// planeKnownNameFiles are the name cells' files, which doctor makes after the fill.
var planeKnownNameFiles = []string{"nm/p/.env", "nm/p/.ENV", "nm/p/.env.example", "nm/out/.env", "nm/p/node_modules/q/.env"}

// planeKnownOpen opens a file for reading, raw, and closes it.
func planeKnownOpen(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

// planeKnownExec runs this binary's noop from path, as the probe row's bprm_check syscall does.
func planeKnownExec(path string) error {
	cmd := proc.Command(path, PlaneProbeCommand, "noop")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr, os.Stderr
	if _, err := proc.Start(cmd); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("the exec'd noop ended: %w", err)
	}
	return nil
}

// makePlaneKnownFixtures makes doctor's half of the known answers' tree at dir: the deny_read directory dr/ with
// the empty mountpoint dr/m, st/f and bad/f below the stale and corrupted rows, the deep chain, the directory rmdir
// removes, the empty mountpoint x, and the name cells' directories under nm/ (their files come after the fill).
func makePlaneKnownFixtures(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	for _, d := range []string{"dr/m", "st", "bad", "rmd", "x", filepath.Dir(planeKnownDeep(bpfobj.PlaneWalkMax + 1)),
		"nm/p/d", "nm/p/e", "nm/p/node_modules/q", "nm/out"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}
	for _, f := range []string{"st/f", "bad/f", planeKnownDeep(bpfobj.PlaneWalkMax), planeKnownDeep(bpfobj.PlaneWalkMax + 1)} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// planeKnownTables are the two fills' tables: the stale one, st/'s deny_read row filled at planeKnownStaleGen, and
// the current one at planeKnownGen: deny_read rows on bad/ (bad is its rule_idx, the row the probe corrupts), deep/
// and dr/, an exec.allow directory row on x/xd, an exec row on x/xf/run, and exec decided (the slot header's flag);
// and the built-in .env pair over nm/p, compiled by the plane's row compiler
// as a run's are (its scope row, name rows, leads and the header's flag), and a write row on nm. root prefixes the
// paths under the child's mounts (/proc/<child>/root).
func planeKnownTables(dir, root string) (stale, current *decide.PlaneRows, bad uint16, err error) {
	stale = &decide.PlaneRows{FS: []decide.PlaneRow{{Path: filepath.Join(dir, "st"), Kind: decide.PlaneReadDeny}}}
	x := root + filepath.Join(dir, "x")
	fs := []decide.PlaneRow{
		{Path: filepath.Join(dir, "bad"), Kind: decide.PlaneReadDeny},
		{Path: filepath.Join(dir, "deep"), Kind: decide.PlaneReadDeny},
		{Path: filepath.Join(dir, "dr"), Kind: decide.PlaneReadDeny},
		{Path: filepath.Join(x, "xd"), Kind: decide.PlaneExecDir},
	}
	scope := filepath.Join(dir, "nm/p")
	rt := &agent.RuleTable{Contract: &agent.Contract{},
		NameDeny: agent.BuiltInEnvEntries([]agent.NameScope{{Canonical: scope, Spelling: scope}})}
	if current, err = decide.CompilePlane(rt); err != nil {
		return nil, nil, 0, fmt.Errorf("compile the name cells' table: %w", err)
	}
	if len(current.NameRows) == 0 {
		return nil, nil, 0, errors.New("the name cells' table compiled no name rows")
	}
	fs = append(fs, decide.PlaneRow{Path: filepath.Join(dir, "nm"), Kind: decide.PlaneModifyAllow})
	// The compiled rows keep their positions, which the config row's entry masks are read from
	// (decide.PlaneRows.NameEntryMasks); the hand rows follow them.
	bad = uint16(len(current.FS))
	current.FS = append(current.FS, fs...)
	current.Exec = []decide.PlaneExecRow{{Path: filepath.Join(x, "xf/run"), Parent: filepath.Join(x, "xf"), Name: "run"}}
	current.ExecPolicy, current.NetPolicy = true, false
	return stale, current, bad, nil
}

// makePlaneKnownNameFiles makes the name cells' files, after the fill.
func makePlaneKnownNameFiles(dir string) error {
	for _, f := range planeKnownNameFiles {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// planeKnownSetup is the child's half of the fixtures, made before it says ready: a mount namespace of its own,
// private from the root down so nothing it mounts propagates out, a tmpfs at dr/m with the file f, and a tmpfs at x
// holding this binary as xf/run with two hard links, xf/alias and xd/img. The calling goroutine must be locked to
// its thread: the namespace is the thread's.
func planeKnownSetup(dir string) error {
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("a mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make the namespace's mounts private: %w", err)
	}
	for _, mp := range []string{"dr/m", "x"} {
		if err := unix.Mount("tego-plane-known", filepath.Join(dir, mp), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV,
			"mode=0700"); err != nil {
			return fmt.Errorf("a tmpfs at %s: %w", mp, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "dr/m/f"), nil, 0o600); err != nil {
		return err
	}
	for _, d := range []string{"x/xf", "x/xd"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	run := filepath.Join(dir, "x/xf/run")
	dst, err := os.OpenFile(run, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	for _, l := range []string{"x/xf/alias", "x/xd/img"} {
		if err := os.Link(run, filepath.Join(dir, l)); err != nil {
			return err
		}
	}
	return nil
}

// planeKnownRole is argv[2] of the known-answer child.
const planeKnownRole = "known"

// planeKnownMain is the known-answer child, `tego __doctor-plane-probe known <dir>`: it makes its half of the
// fixtures, says ready, then for each cell name read makes the cell's action and prints "<cell>\t<outcome>", until
// its input ends. It runs on one thread, the one its mount namespace is on, which must be the thread-group leader
// (init keeps it there, onLeader): doctor reaches the namespace's files through /proc/<pid>/root, the leader's view.
func planeKnownMain(dir string) int {
	runtime.LockOSThread() // never unlocked: the thread's namespace is not the process's
	if tid, pid := unix.Gettid(), unix.Getpid(); tid != pid {
		fmt.Fprintf(os.Stderr, "known answers: the child runs on thread %d, not its thread-group leader %d, so doctor "+
			"would not see its mount namespace through /proc/%d/root\n", tid, pid, pid)
		return 1
	}
	if err := planeKnownSetup(dir); err != nil {
		fmt.Fprintln(os.Stderr, "known answers:", err)
		return 1
	}
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		return 1
	}
	in := bufio.NewReader(os.Stdin)
	for {
		line, err := in.ReadString('\n')
		if errors.Is(err, io.EOF) && line == "" {
			return 0
		}
		if err != nil {
			return 1
		}
		cell := strings.TrimSuffix(line, "\n")
		act, ok := planeKnownActions[cell]
		out := "failed: no action"
		if ok {
			out = planeOutcome(act(dir))
		}
		if _, err := os.Stdout.WriteString(cell + "\t" + out + "\n"); err != nil {
			return 1
		}
	}
}

// ask has the known-answer child make one cell's action and reads its outcome.
func (c *planeChild) ask(cell string) (string, error) {
	if _, err := io.WriteString(c.stdin, cell+"\n"); err != nil {
		return "", fmt.Errorf("the known-answer child: %w", err)
	}
	line, err := c.readLine()
	if err != nil {
		return "", fmt.Errorf("the known-answer child did not answer %s: %w", cell, err)
	}
	name, res, _ := strings.Cut(line, "\t")
	if name != cell {
		return "", fmt.Errorf("the known-answer child answered %q for %s", line, cell)
	}
	return res, nil
}

// slotCounts reads a slot's fail-closed counters.
func (r *planeRig) slotCounts(slot uint32) (bpfobj.PlaneCounts, error) {
	var c bpfobj.PlaneCounts
	if r.counters == nil {
		return c, errors.New("the rig has no counters map")
	}
	return c, r.counters.Lookup(slot, &c)
}

// planeKnownHeld holds O_PATH descriptors of the known-answer rows' paths, the fill's input.
type planeKnownHeld map[string]int

// open holds each fs and exec row's path of the tables.
func (h planeKnownHeld) open(tables ...*decide.PlaneRows) error {
	for _, t := range tables {
		var paths []string
		for _, r := range t.FS {
			paths = append(paths, r.Path)
		}
		for _, r := range t.Exec {
			paths = append(paths, r.Path)
		}
		for _, p := range paths {
			if _, ok := h[p]; ok {
				continue
			}
			fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("hold %s: %w", p, err)
			}
			h[p] = fd
		}
	}
	return nil
}

// held is the fill's lookup.
func (h planeKnownHeld) held(path string) (int, bool) {
	fd, ok := h[path]
	return fd, ok
}

// close releases every descriptor.
func (h planeKnownHeld) close() {
	for _, fd := range h {
		_ = unix.Close(fd)
	}
}

// corruptRow flips the identity of the current row of slot whose rule_idx is rule, so that its key inode no longer
// carries it: the one known answer the fill cannot make, since it reads a row's identity from the inode it keys.
// The inner map is the probe's own and unpinned; the key it reads back to rewrite the row is never printed.
func corruptRow(rows *ebpf.Map, slot uint32, rule uint16, gen uint32) error {
	var inner *ebpf.Map
	if err := rows.Lookup(slot, &inner); err != nil {
		return fmt.Errorf("open slot %d's rows: %w", slot, err)
	}
	defer func() { _ = inner.Close() }()
	return corruptSlotRow(inner, slot, rule, gen)
}

// corruptSlotRow is corruptRow on the slot's own fs row map inner.
func corruptSlotRow(inner *ebpf.Map, slot uint32, rule uint16, gen uint32) error {
	var key uint64
	var row bpfobj.PlaneRow
	it := inner.Iterate()
	for it.Next(&key, &row) {
		if row.Gen != gen || row.RuleIdx != rule {
			continue
		}
		row.Generation = ^row.Generation
		if err := inner.Update(key, &row, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("corrupt rule %d's row: %w", rule, err)
		}
		return nil
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("read slot %d's rows: %w", slot, err)
	}
	return fmt.Errorf("slot %d has no row of rule %d at gen %d", slot, rule, gen)
}

// planeKnownTiming is what a mode's known answers took, in all and by phase.
type planeKnownTiming struct {
	Total  time.Duration
	Phases []string
}

// exercisePlaneKnown runs mode m's known answers on an attached rig whose row maps are known's: the fixtures, the
// child in a scratch cgroup of its own, the two fills and the corrupted row, then each cell with the slot armed.
// An error is a stage that could not run to its end.
func exercisePlaneKnown(rig *planeRig, known *planeKnownRows, uid int) (out []PlaneKnownAnswer, tm planeKnownTiming, err error) {
	start := time.Now()
	last := start
	mark := func(phase string) {
		now := time.Now()
		tm.Phases = append(tm.Phases, fmt.Sprintf("%s %v", phase, now.Sub(last).Round(100*time.Microsecond)))
		last = now
	}
	defer func() { tm.Total = time.Since(start) }()
	if err := known.wait(); err != nil {
		return nil, tm, fmt.Errorf("known answers: %w", err)
	}
	pr := known.rows
	mark(fmt.Sprintf("wait for the fill build (loaded in %v)", pr.Load.Round(100*time.Microsecond)))
	base, err := makeFixtureDir(planeScratchPrefix)
	if err != nil {
		return nil, tm, fmt.Errorf("known answers: fixtures: %w", err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	dir := filepath.Join(base, "k")
	if err := makePlaneKnownFixtures(dir); err != nil {
		return nil, tm, fmt.Errorf("known answers: fixtures: %w", err)
	}
	cg, err := newPlaneCgroup(uid)
	if err != nil {
		return nil, tm, fmt.Errorf("known answers: scratch cgroup: %w", err)
	}
	defer cg.remove()
	child, err := startPlaneChildAs(cg, planeKnownRole, dir, -1)
	if err != nil {
		return nil, tm, fmt.Errorf("known answers: %w", err)
	}
	defer child.stop()
	mark("fixtures and child")

	stale, current, bad, err := planeKnownTables(dir, filepath.Join("/proc", strconv.Itoa(child.cmd.Process.Pid), "root"))
	if err != nil {
		return nil, tm, fmt.Errorf("known answers: %w", err)
	}
	held := planeKnownHeld{}
	defer held.close()
	if err := held.open(stale, current); err != nil {
		return nil, tm, fmt.Errorf("known answers: %w", err)
	}
	mark("hold")
	slot := planeKnownSlot(rig.mode)
	for _, f := range []struct {
		gen   uint32
		table *decide.PlaneRows
	}{{planeKnownStaleGen, stale}, {planeKnownGen, current}} {
		if err := pr.Fill(slot, f.gen, f.table, held.held); err != nil {
			return nil, tm, fmt.Errorf("known answers: fill slot %d at gen %d: %w", slot, f.gen, err)
		}
		mark(fmt.Sprintf("fill gen %d (%s)", f.gen, pr.LastFill))
	}
	corrupt := func() error { return corruptRow(pr.Rows, slot, bad, planeKnownGen) }
	if inner := pr.SlotRows(slot); inner != nil {
		// The slot's own map, which the fill's ProbeRows made and kept: no look-up through the outer (40 ms on 6.1).
		corrupt = func() error { return corruptSlotRow(inner, slot, bad, planeKnownGen) }
	}
	if err := corrupt(); err != nil {
		return nil, tm, fmt.Errorf("known answers: %w", err)
	}
	if err := makePlaneKnownNameFiles(dir); err != nil {
		return nil, tm, fmt.Errorf("known answers: the name cells' files: %w", err)
	}
	mark("corrupt")
	if err := rig.counters.Put(slot, bpfobj.PlaneCounts{}); err != nil {
		return nil, tm, fmt.Errorf("known answers: zero slot %d's counters: %w", slot, err)
	}
	key := cg.id
	if err := rig.runSet.Put(key, bpfobj.Run{RunIdx: slot, Tier: 3, Plane: bpfobj.RunPlaneOf(rig.mode), Gen: planeKnownGen}); err != nil {
		return nil, tm, fmt.Errorf("known answers: arm slot %d: %w", slot, err)
	}
	mark("arm")
	defer func() {
		if derr := rig.runSet.Delete(key); derr != nil && err == nil {
			err = fmt.Errorf("known answers: disarm slot %d: %w", slot, derr)
		}
	}()
	for _, c := range planeKnownCells() {
		before, err := rig.slotCounts(slot)
		if err != nil {
			return out, tm, fmt.Errorf("known answers: read slot %d's counters: %w", slot, err)
		}
		if c.Got, err = child.ask(c.Cell); err != nil {
			return out, tm, err
		}
		after, err := rig.slotCounts(slot)
		if err != nil {
			return out, tm, fmt.Errorf("known answers: read slot %d's counters: %w", slot, err)
		}
		c.GotCounts = countDelta(before, after)
		out = append(out, c)
		mark(c.Cell)
	}
	return out, tm, child.wait()
}
