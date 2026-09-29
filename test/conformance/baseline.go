// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
)

// Runners name what a baseline entry excuses. "compile" is compile --test against the cell; "kernel" is the
// action's own result against the cell; "ledger" is the ledger line against the cell. "invariant" is never
// baselined: a cell where the kernel allowed what an invariant refuses is a fail-open (ADR 0017). "parity" is the
// kernel's result against compile --test's own answer for the tier (enforce-plane I9), checked at tier bpflsm.
const (
	RunnerCompile = "compile"
	RunnerKernel  = "kernel"
	RunnerLedger  = "ledger"
	RunnerParity  = "parity"
	// RunnerInvariant is the name a fail-open carries in a failure key. Baselinable refuses it.
	RunnerInvariant = "invariant"
)

// Baselinable reports whether a runner's disagreements may be excused by a baseline entry. Only the four runners
// that compare the build with a cell can be. A failure under any other name (a fail-open's "invariant", the effect
// judge's, a typo) is a fail-open or a malformed key, and is fixed: ADR 0017, "-update refuses to add it".
func Baselinable(runner string) bool {
	switch runner {
	case RunnerCompile, RunnerKernel, RunnerLedger, RunnerParity:
		return true
	}
	return false
}

// machineBound says a runner's disagreements can follow from the machine it ran on. compile --test makes no
// kernel call (ADR 0019): its disagreements are the decision core's and hold wherever the suite runs, so an
// entry Update adds for it has no Where. The runners that perform real calls (kernel, ledger, parity) saw theirs on
// this machine, and their entries are pinned to it until a reviewer widens them.
func machineBound(runner string) bool { return runner != RunnerCompile }

// todoReason is the reason Update gives the entries it adds. TestBaselineIsWellFormed refuses it, so a baseline
// that a tool wrote cannot be committed before a person has said why each cell disagrees.
const todoReason = "TODO"

// BaselineEntry is one known-failing (cell, runner, tier), with why, on the machines its Where names.
type BaselineEntry struct {
	Cell   string `json:"cell"`
	Runner string `json:"runner"`
	// Tier is what the failure is reported under: a tier, or an axis such as cgroup@lsm.
	Tier   string `json:"tier"`
	Reason string `json:"reason"`
	// Where narrows the entry to the machines it holds on. Absent, it holds on all of them.
	Where Where `json:"where,omitzero"`
}

// Key is the entry's identity, the same string a runner reports a failure under. Entries of one Key are told
// apart by their Where: the same cell can disagree on several machines.
func (b BaselineEntry) Key() string { return FailureKey(b.Runner, b.Cell, Tier(b.Tier)) }

// describe names an entry in a message: its key, and the machines it is for when it is for some only.
func (b BaselineEntry) describe() string {
	if b.Where == (Where{}) {
		return b.Key()
	}
	return b.Key() + " [" + b.Where.String() + "]"
}

// FailureKey names one failing check.
func FailureKey(runner, cell string, t Tier) string { return runner + "|" + cell + "|" + string(t) }

// ParseFailureKey undoes FailureKey: the runner is what precedes the first separator and the tier what follows
// the last, so a cell may hold the separator itself. ok is false for a key of any other shape.
func ParseFailureKey(key string) (runner, cell string, tier Tier, ok bool) {
	runner, rest, found := strings.Cut(key, "|")
	if !found {
		return "", "", "", false
	}
	i := strings.LastIndex(rest, "|")
	if i < 0 {
		return "", "", "", false
	}
	cell, tier = rest[:i], Tier(rest[i+1:])
	if runner == "" || cell == "" || tier == "" {
		return "", "", "", false
	}
	return runner, cell, tier, true
}

// LoadBaseline reads test/conformance/testdata/baseline.json.
func LoadBaseline(path string) ([]BaselineEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out, err := ParseBaseline(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// ParseBaseline decodes a baseline file strictly: a field it does not know is an error, since a misspelt "where"
// field dropped silently would leave an entry that holds on more machines than its author meant; so is anything
// after the list, and a Where that cannot be read (Where.Validate).
func ParseBaseline(data []byte) ([]BaselineEntry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var out []BaselineEntry
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the list of entries")
	}
	for i := range out {
		if err := out[i].Where.Validate(); err != nil {
			return nil, fmt.Errorf("entry %d (%s): where: %w", i+1, out[i].Key(), err)
		}
	}
	return out, nil
}

// sortEntries returns the entries in the order of the canonical file: by key, and the entries of one key by
// their Where. It does not reorder its argument.
func sortEntries(entries []BaselineEntry) []BaselineEntry {
	out := slices.Clone(entries)
	if out == nil {
		out = []BaselineEntry{}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ki, kj := out[i].Key(), out[j].Key(); ki != kj {
			return ki < kj
		}
		return out[i].Where.canonical() < out[j].Where.canonical()
	})
	return out
}

// CanonicalBaseline is the one encoding of a baseline that the checked-in file may have: the entries sorted by
// key and then by Where, two-space JSON, <, > and & as written (a reason says "ABI < 3"), one final newline. An
// empty baseline is "[]". A hand edit that reorders or reindents the file is then a diff of its own, and an
// update rewrites only what it changes.
func CanonicalBaseline(entries []BaselineEntry) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sortEntries(entries)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NotRunKey marks, in a run's ran map, a cell the run skipped on an axis (its fixture needs root, or a filesystem the
// kernel lacks) although the axis ran: its entries are neither excused, stale nor dropped there (judged).
func NotRunKey(cell, tier string) string { return "notrun|" + cell + "|" + tier }

// judged says whether a run with this ran map could judge the entry: its (runner, tier) pair ran, and its cell did.
func judged(ran map[string]bool, b BaselineEntry) bool {
	return ran[b.Runner+"|"+b.Tier] && !ran[NotRunKey(b.Cell, b.Tier)]
}

// Ratchet compares the failures a run found with the baseline entries of the (runner, tier) pairs it ran (ran
// is keyed "runner|tier") that hold on the machine it ran on (an entry's Where): a failure the baseline lacks,
// and a baseline entry that now passes, are both problems (the baseline only shrinks unless the PR adds the
// cells' space). An entry written for another machine is neither applied nor stale here, and nothing that is not
// Baselinable excuses a failure, whatever the file holds.
func Ratchet(base []BaselineEntry, ran map[string]bool, failures map[string]string, m Machine) (newFailures, stale []string) {
	inBase := map[string]bool{}
	for _, b := range base {
		if !Baselinable(b.Runner) || !judged(ran, b) || !b.Where.Matches(m) {
			continue
		}
		inBase[b.Key()] = true
		if _, failed := failures[b.Key()]; !failed {
			stale = append(stale, b.describe()+" now passes: drop it from baseline.json ("+b.Reason+")")
		}
	}
	for k, why := range failures {
		if !inBase[k] {
			newFailures = append(newFailures, k+": "+why)
		}
	}
	sort.Strings(newFailures)
	sort.Strings(stale)
	return newFailures, stale
}

// SpaceHandwritten names the cells written by hand: the tables in spec/policy/conformance (fixtures.go).
const SpaceHandwritten = "handwritten"

// Space is a named set of cells that enter the baseline together (ADR 0017: new cells enter the baseline only in
// the PR that adds their space). -conformance.update=<space> may add the disagreements of its cells and of no
// other space's.
type Space struct {
	Name string
	// PerPR is a generated space the per-PR runs include by default (SelectedSpaces); the others run nightly.
	PerPR bool
	// Fixtures returns the space's fixtures, built afresh on each call.
	Fixtures func() []Fixture
}

// Spaces lists every space, the handwritten one first, then the generated ones (gen.go) in the order ADR 0017
// numbers them.
func Spaces() []Space {
	return []Space{
		{Name: SpaceHandwritten, Fixtures: Fixtures},
		{Name: SpaceFSGrid, PerPR: true, Fixtures: GenFSGrid},
	}
}

// CellRef is a cell and the space it belongs to.
type CellRef struct {
	Space string
	Cell  *Cell
}

// AllCells maps every cell ID of every space to its cell. A cell in two places is an error: the baseline names
// cells by ID, so an ID must say one cell and one space.
func AllCells() (map[string]CellRef, error) {
	out := map[string]CellRef{}
	for _, sp := range Spaces() {
		for _, fx := range sp.Fixtures() {
			for i := range fx.Cells {
				id := fx.ID(&fx.Cells[i])
				if prev, dup := out[id]; dup {
					if prev.Space == sp.Name {
						return nil, fmt.Errorf("cell %s is defined twice in the space %s", id, sp.Name)
					}
					return nil, fmt.Errorf("cell %s is in the space %s and in the space %s", id, prev.Space, sp.Name)
				}
				out[id] = CellRef{Space: sp.Name, Cell: &fx.Cells[i]}
			}
		}
	}
	return out, nil
}

// UpdateRequest is a run, and the space its new disagreements may be written for.
type UpdateRequest struct {
	// Space is the space -conformance.update names: the one whose new disagreements may enter the baseline.
	Space string
	// Spaces maps every cell ID of every space to the space's name.
	Spaces map[string]string
	// Machine is where the run happened. It decides which entries the run can judge, and its Where is the one the
	// entries added get.
	Machine Machine
	// Ran and Failures are the run, keyed as Ratchet reads them.
	Ran      map[string]bool
	Failures map[string]string
	// Unsound lists what makes the run unfit to write a baseline whatever it found: a fail-open, an effect
	// violation or a finding that changed (none of which a baseline holds), or a run narrowed below a whole runner
	// (the cells it did not run would read as entries that now pass). Any entry refuses the update.
	Unsound []string
}

// UpdateResult is the baseline an update produced.
type UpdateResult struct {
	// Entries is the next baseline, in canonical order.
	Entries []BaselineEntry
	// Added are the keys of the entries added, each with the reason TODO.
	Added []string
	// Dropped names the entries that now pass, by key and by Where.
	Dropped []string
	// Written says UpdateBaselineFile rewrote the file.
	Written bool
}

// UpdateRefused is an update that did not happen, with each reason on its own line.
type UpdateRefused struct{ Reasons []string }

func (e *UpdateRefused) Error() string {
	const show = 20
	lines := e.Reasons
	if len(lines) > show {
		lines = append(slices.Clone(lines[:show]), fmt.Sprintf("... and %d more", len(e.Reasons)-show))
	}
	return strings.Join(lines, "\n")
}

// Update computes the baseline a run leaves behind (-conformance.update=<space>, ADR 0017: "-update refuses to
// add a fail-open", "new cells enter the baseline only in the PR that adds their space"):
//
//   - an entry the run could judge (its pair ran, its Where matches the machine) and that no longer fails is
//     dropped; every other entry is kept as it is, so a run on one machine leaves the other machines' entries alone;
//   - a failure that no kept entry excuses becomes a new entry with the reason TODO, when its cell belongs to
//     req.Space; its Where is the machine's, save for compile --test's disagreements, which hold on every machine;
//   - anything else refuses the whole update, naming every offender, and nothing is returned: an unsound run
//     (req.Unsound), a failure under a runner that is not Baselinable (a fail-open), a failure of a cell of another
//     space or of no space, a space that does not exist.
func Update(base []BaselineEntry, req UpdateRequest) (UpdateResult, error) {
	var why []string
	if !slices.Contains(slices.Collect(maps.Values(req.Spaces)), req.Space) {
		spaces := slices.Compact(slices.Sorted(maps.Values(req.Spaces)))
		why = append(why, fmt.Sprintf("%q is no such space (the spaces are %s)", req.Space, strings.Join(spaces, ", ")))
	}
	why = append(why, req.Unsound...)

	covered := map[string]bool{}
	var next []BaselineEntry
	var dropped []string
	for _, b := range base {
		if !Baselinable(b.Runner) || !judged(req.Ran, b) || !b.Where.Matches(req.Machine) {
			next = append(next, b) // this run cannot judge it
			continue
		}
		if _, failed := req.Failures[b.Key()]; failed {
			covered[b.Key()] = true
			next = append(next, b)
			continue
		}
		dropped = append(dropped, b.describe())
	}
	sort.Strings(dropped)

	var added []string
	for _, k := range slices.Sorted(maps.Keys(req.Failures)) {
		runner, cell, tier, ok := ParseFailureKey(k)
		if !ok {
			why = append(why, fmt.Sprintf("%s: not a failure key (runner|cell|tier)", k))
			continue
		}
		if !Baselinable(runner) {
			why = append(why, fmt.Sprintf("%s: runner %q is never baselined: a failure under it is a fail-open or a malformed key, "+
				"which is fixed, not excused (ADR 0017): %s", k, runner, req.Failures[k]))
			continue
		}
		if covered[k] {
			continue
		}
		space, known := req.Spaces[cell]
		switch {
		case !known:
			why = append(why, fmt.Sprintf("%s: %s is no cell of any space", k, cell))
		case space != req.Space:
			why = append(why, fmt.Sprintf("%s: %s belongs to the space %s, not %s: a disagreement there is fixed, or baselined by "+
				"hand in the PR that owns it, not by this update", k, cell, space, req.Space))
		default:
			e := BaselineEntry{Cell: cell, Runner: runner, Tier: string(tier), Reason: todoReason}
			if machineBound(runner) {
				e.Where = req.Machine.Where()
			}
			next = append(next, e)
			added = append(added, k)
		}
	}
	if len(why) > 0 {
		return UpdateResult{}, &UpdateRefused{Reasons: why}
	}
	return UpdateResult{Entries: sortEntries(next), Added: added, Dropped: dropped}, nil
}

// UpdateBaselineFile applies Update to the baseline file at path, read afresh, and writes the result in canonical
// form. The file is left alone when the canonical bytes are the ones it holds, and untouched when Update refuses.
func UpdateBaselineFile(path string, req UpdateRequest) (UpdateResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return UpdateResult{}, err
	}
	base, err := ParseBaseline(data)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("%s: %w", path, err)
	}
	res, err := Update(base, req)
	if err != nil {
		return UpdateResult{}, err
	}
	next, err := CanonicalBaseline(res.Entries)
	if err != nil {
		return UpdateResult{}, err
	}
	if bytes.Equal(next, data) {
		return res, nil
	}
	if err := writeFileLike(path, next); err != nil {
		return UpdateResult{}, err
	}
	res.Written = true
	return res, nil
}

// writeFileLike replaces path with data atomically (a temporary file beside it, renamed over it), keeping the
// file's mode and, when this process is root, its owner: `sudo go test` must not leave the checkout's file root's.
func writeFileLike(path string, data []byte) error {
	mode := os.FileMode(0o644)
	uid, gid := -1, -1
	switch info, err := os.Stat(path); {
	case err == nil:
		mode = info.Mode().Perm()
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if uid >= 0 && os.Geteuid() == 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			return fail(err)
		}
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// RequireEnv names the axes of TestConformanceKernel the environment says must run, as a comma-separated list
// of "cgroup", the plane modes ("fmod_ret", "lsm"), "bpflsm" and "landlock" (with which a tier landlock that
// tego doctor refuses fails the test instead of skipping it). root-suites.sh sets it per boot through
// test/vm/conformance-require.sh, so an axis that cannot run there fails the test instead of leaving its column
// of the kernel conformance unchecked behind a green parent test (ADR 0017).
const RequireEnv = "TEGO_CONFORMANCE_REQUIRE"

// AxisRequired reports whether the list (the value of RequireEnv) names the axis.
func AxisRequired(list, axis string) bool {
	for _, f := range strings.Split(list, ",") {
		if strings.TrimSpace(f) == axis {
			return true
		}
	}
	return false
}
