// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
)

// The capability cross-check (ADR 0017 (c): the deny_read and deny_write invariants bind "where the capability line
// reports" the entry enforced). The invariants read the oracle's own enforcement predicates (denyReadEnforced,
// denyWriteEnforced), written from the contract; the product states the same facts in compile --json's per-entry
// markers and in each run's run_start line. The two must agree. Where the oracle says unenforced and the product says
// enforced, the product claims a capability its tier does not have ("capability over-claim"), and no invariant would
// catch the gap; where the oracle says enforced and the product says unenforced, the oracle is stricter than the
// product documents ("oracle stricter than product"), and one of the two is fixed. Either fails the runner, and
// neither is baselined.

// Problem prefixes, the first words of every cross-check problem.
const (
	OverClaim = "capability over-claim"
	Stricter  = "oracle stricter than product"
	Unmodeled = "model and product disagree on the entries"
)

// compileJSONTable is the part of `tego compile --json`'s table (internal/cli TableFS) the cross-check reads.
type compileJSONTable struct {
	FS []struct {
		Path                string `json:"path"`
		Kind                string `json:"kind"`
		Raw                 string `json:"raw"`
		BuiltIn             bool   `json:"builtin"`
		BuiltinRule         string `json:"rule"`
		Unenforced          bool   `json:"unenforced"`
		KernelPlaneRequired bool   `json:"kernel_plane_required"`
		BestEffort          bool   `json:"best_effort"`
	} `json:"fs"`
	// Reads is compile's fs.reads (internal/cli TableReads): landlock is held or direct, "" in a table without it.
	Reads struct {
		Landlock string `json:"landlock"`
	} `json:"reads"`
}

// CompileCapabilityCrossCheck holds the model's predicates to compile --json's table for the contract. compile
// marks a deny_read `unenforced` where tier landlock cannot hold it (the root tiers always do), and each deny_write
// target `best_effort` (fs.assurance's default: the supervisor below a plane) or `kernel_plane_required`
// (fs.assurance: kernel: no run below a plane), never neither, since only a plane enforces one. rel maps a table
// path, which is absolute, to the model's spelling (relative to the project, through any symlink); "" for a path
// outside the project. It returns the problems, sorted.
func CompileCapabilityCrossCheck(m Model, table []byte, rel func(abs string) string) ([]string, error) {
	var tbl compileJSONTable
	if err := json.Unmarshal(table, &tbl); err != nil {
		return nil, fmt.Errorf("compile --json: %w", err)
	}
	var out []string
	declared := map[string]bool{}
	var denyWrite []string
	for _, e := range tbl.FS {
		p := rel(e.Path)
		switch e.Kind {
		case "deny_read":
			if e.BuiltIn || p == "" {
				continue // the built-in list (home directory secrets, .env files) is no entry of the model's
			}
			declared[p] = true
			if !slices.ContainsFunc(m.DenyRead, func(d string) bool { return filepath.Clean(d) == p }) {
				out = append(out, fmt.Sprintf("%s: compile's table has deny_read %s, which the model does not declare", Unmodeled, p))
				continue
			}
			// compile's unenforced marker is the Landlock ruleset's fact (ADR 0069 keeps it): held reads are a layer above it,
			// which reads.landlock says.
			switch oracle := denyReadRulesetEnforced(m, TierLandlock, p); {
			case oracle && e.Unenforced:
				out = append(out, fmt.Sprintf("%s: the oracle's ruleset enforces deny_read %s at tier landlock, compile marks it unenforced", Stricter, p))
			case !oracle && !e.Unenforced:
				out = append(out, fmt.Sprintf("%s: compile marks deny_read %s enforced by the ruleset at tier landlock, the oracle does not (a write entry covers it)", OverClaim, p))
			}
		case "deny_write":
			// The model covers the fixture's filesystem entries. C40's
			// immutable host surfaces are tested by the builtin integration
			// matrix, independently of these contract-entry capabilities.
			if e.BuiltinRule != "" {
				continue
			}
			if p == "" {
				out = append(out, fmt.Sprintf("%s: compile's deny_write target %s lies outside the project", Unmodeled, e.Path))
				continue
			}
			denyWrite = append(denyWrite, p)
			switch {
			case !e.BestEffort && !e.KernelPlaneRequired:
				out = append(out, fmt.Sprintf("%s: compile marks deny_write %s neither best effort nor kernel plane required: enforced where no plane decides, "+
					"which the oracle says only a plane does", OverClaim, p))
			case e.KernelPlaneRequired != m.FSAssuranceKernel:
				out = append(out, fmt.Sprintf("%s: deny_write %s: compile's kernel_plane_required is %t, the model's fs.assurance: kernel is %t",
					Unmodeled, p, e.KernelPlaneRequired, m.FSAssuranceKernel))
			}
		}
	}
	for _, d := range m.DenyRead {
		if !declared[filepath.Clean(d)] {
			out = append(out, fmt.Sprintf("%s: the model's deny_read %s is not in compile's table", Unmodeled, d))
		}
	}
	// Held reads at tier landlock (ADR 0069): where the oracle has a declared deny_read only held reads refuse, compile
	// must hold the run's reads; under fs.reads: direct it must not. A held table with no declared nested entry is
	// compile's own (a built-in entry or a scanned .env nested in a write entry), which the model does not declare.
	switch got := tbl.Reads.Landlock; {
	case got == "":
	case m.Reads == ReadsDirect && got != "direct":
		out = append(out, fmt.Sprintf("%s: compile holds the reads at tier landlock (%s) under fs.reads: direct", Unmodeled, got))
	case m.heldReadsNeeded() && got != "held":
		out = append(out, fmt.Sprintf("%s: the oracle refuses the reads of a deny_read inside a write entry at tier landlock, compile's reads there are %s", Stricter, got))
	}
	model := cleanSorted(m.DenyWrite)
	if got := cleanSorted(denyWrite); !slices.Equal(got, model) {
		out = append(out, fmt.Sprintf("%s: compile's deny_write set is %v, the model's %v", Unmodeled, got, model))
	}
	sort.Strings(out)
	return out, nil
}

func cleanSorted(ps []string) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, filepath.Clean(p))
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// bestEffortDenyWrite is the run_start best_effort id of a deny_write set no plane decides (agent.BestEffortDenyWrite;
// ADR 0041 D7), written here rather than imported: the oracle reads the record's spelling, not the product's code.
const bestEffortDenyWrite = "deny_write/default"

// protectedWriteTargets is the capability line's key for the built-in deny_write set refused race-free
// (backend.CapProtectedWriteTargets), in the record's spelling.
const protectedWriteTargets = "fs.protected_write_targets"

// gateFSOpenCompletion is the capability line's key for the gate's open completion (backend.CapGateFSOpenCompletion),
// in the record's spelling.
const gateFSOpenCompletion = "gate.fs_open_completion"

// createdLater is the capability line's key for name entries (backend.CapReadDenyCreatedLater, ADR 0043 D7), in the
// record's spelling.
const createdLater = "fs.deny_read.created_later"

// heldOpenCells are the run_start best_effort ids of the gate's open cells (agent.BestEffortGateFSReadOpen and
// BestEffortGateFSWriteOpen), which a run whose open deputy completes its opens no longer lists (ADR 0041 Stage B).
var heldOpenCells = []string{"gate.fs.read/open", "gate.fs.write/open"}

// RunCapabilityCrossCheck holds the model's predicates for the tier inv, whose invariants an axis answers, to that
// axis' own run: the run_start line's capabilities (fs.deny_read: every deny_read the run holds is enforced) and
// best_effort (deny_write/default: the deny_write set is refused best effort, so not enforced), and its
// decision_plane, which must be the plane the axis pinned (plane: "" for tier landlock, "fanotify" for the
// listener, the mode for a plane axis), or the axis ran under another name than it reports. It returns the problems.
func RunCapabilityCrossCheck(m Model, inv Tier, plane string, start map[string]any) []string {
	if start == nil {
		return []string{"the run's ledger has no run_start line to read its capabilities from"}
	}
	var out []string
	if got, _ := start["decision_plane"].(string); got != plane {
		out = append(out, fmt.Sprintf("the run's decision_plane is %q, the axis pins %q", got, plane))
	}
	caps, _ := start["capabilities"].(map[string]any)
	product, said := caps["fs.deny_read"].(bool)
	oracle := true
	for _, e := range m.DenyRead {
		oracle = oracle && denyReadEnforced(m, inv, e)
	}
	switch {
	case !said:
		out = append(out, "the run's capability line does not say fs.deny_read")
	case product && !oracle:
		out = append(out, fmt.Sprintf("%s: the run reports fs.deny_read, the oracle says a deny_read is unenforced at %s", OverClaim, inv))
	case !product && oracle:
		out = append(out, fmt.Sprintf("%s: the oracle enforces every deny_read at %s, the run reports fs.deny_read false", Stricter, inv))
	}
	// fs.protected_write_targets (ADR 0041 D7) is the built-in deny_write set decided race-free: exactly where a plane
	// mode decides the run (its own decision_plane, which the first check holds to the axis), whatever the model
	// declares, so the row never says otherwise than best_effort does.
	runPlane, _ := start["decision_plane"].(string)
	want := runPlane == "lsm" || runPlane == "fmod_ret"
	switch protected, said := caps[protectedWriteTargets].(bool); {
	case !said:
		out = append(out, "the run's capability line does not say "+protectedWriteTargets)
	case protected && !want:
		out = append(out, fmt.Sprintf("%s: the run reports %s with decision_plane %q, which decides no target race-free", OverClaim, protectedWriteTargets, runPlane))
	case !protected && want:
		out = append(out, fmt.Sprintf("%s: the plane %q decides the targets by inode, the run reports %s false", Stricter, runPlane, protectedWriteTargets))
	}
	// fs.deny_read.created_later (ADR 0043 D7) is never true where neither a plane mode decides the run nor the run
	// holds its reads (ADR 0069 D4, run_start.fs_reads): tier landlock has the expansion only, and the fanotify
	// fallback refuses a creation best effort. Where a plane decides, a model that declares its name entries (every
	// one the contract has, the built-in pair included) holds the row true: a cap or a collision that left one out, or
	// an approval path over a name scope, is no part of such a fixture. A model that declares none says nothing of
	// the plane's row.
	reads, _ := start["fs_reads"].(map[string]any)
	held := reads["reads"] == "held"
	switch later, said := caps[createdLater].(bool); {
	case !said:
		out = append(out, "the run's capability line does not say "+createdLater)
	case later && !want && !held:
		out = append(out, fmt.Sprintf("%s: the run reports %s with decision_plane %q and reads not held, which decides no name entry race-free", OverClaim, createdLater, runPlane))
	case !later && want && len(m.Names) > 0:
		out = append(out, fmt.Sprintf("%s: the plane %q decides the model's name entries, the run reports %s false", Stricter, runPlane, createdLater))
	}
	var bestEffort bool
	list, _ := start["best_effort"].([]any)
	bestEffort = slices.Contains(list, any(bestEffortDenyWrite))
	// gate.fs_open_completion (ADR 0041 D7, Stage B) is the held completion's row: true exactly where the model holds the
	// run's opens (completion: held), false elsewhere, so the row never says otherwise than best_effort does.
	switch held, said := caps[gateFSOpenCompletion].(bool); {
	case !said:
		out = append(out, "the run's capability line does not say "+gateFSOpenCompletion)
	case held && !m.HeldOpens:
		out = append(out, fmt.Sprintf("%s: the run reports %s, the model holds none of its opens", OverClaim, gateFSOpenCompletion))
	case !held && m.HeldOpens:
		out = append(out, fmt.Sprintf("the run reports %s false under completion: held: the open deputy did not start", gateFSOpenCompletion))
	}
	if m.HeldOpens {
		for _, cell := range heldOpenCells {
			if slices.Contains(list, any(cell)) {
				out = append(out, fmt.Sprintf("the run lists %s best effort under completion: held: the open deputy did not start", cell))
			}
		}
	}
	// Each kind of target has its own cell: the built-in set's deny_write/default, the contract's own entries'
	// fs.deny_write (ADR 0071).
	enforced := denyWriteEnforced(m, inv)
	builtIn := slices.ContainsFunc(m.DenyWrite, func(d string) bool {
		return !slices.ContainsFunc(m.DenyWriteDeclared, func(e string) bool { return filepath.Clean(e) == filepath.Clean(d) })
	})
	for _, k := range []struct {
		id         string
		has, lists bool
	}{{bestEffortDenyWrite, builtIn, bestEffort}, {bestEffortUserDenyWrite, len(m.DenyWriteDeclared) > 0, slices.Contains(list, any(bestEffortUserDenyWrite))}} {
		switch {
		case !k.has && k.lists:
			out = append(out, fmt.Sprintf("%s: the run lists %s best effort, the model declares no such deny_write target", Unmodeled, k.id))
		case !k.has:
		case enforced && k.lists:
			out = append(out, fmt.Sprintf("%s: the oracle enforces deny_write at %s, the run lists %s best effort", Stricter, inv, k.id))
		case !enforced && !k.lists:
			out = append(out, fmt.Sprintf("%s: the run does not list %s best effort, the oracle says nothing at %s enforces it", OverClaim, k.id, inv))
		}
	}
	return out
}

// bestEffortUserDenyWrite is the run_start best_effort id of a contract's own fs.deny_write entries no plane decides
// (agent.BestEffortUserDenyWrite, ADR 0071), in the record's spelling.
const bestEffortUserDenyWrite = "fs.deny_write"
