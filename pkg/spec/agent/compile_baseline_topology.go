// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// BaselineCoverage describes one entry at one actual tier and decision mechanism.
// Refuse-launch rows are retained for diagnostics, never treated as weaker coverage.
type BaselineCoverage struct {
	Tier                           backend.Tier
	Plane                          string
	Held                           string
	ImageMode                      string
	Operations, Conditions, Limits []string
}

// BaselinePlacementDiagnostic retains an unsupported entry's full sources,
// owner context and modeled coverage even when compilation returns no table.
type BaselinePlacementDiagnostic struct {
	Entry *BaselineRule
	Owner config.BaselineOwner
}

type baselinePin struct {
	path  string
	key   fileKey
	links uint64
}
type baselineTopologyFacts struct {
	aliases, detached []string
	linked            []baselinePin
	caseExact         bool
	problem           string
	enclosingWrite    bool
}

// machineLayerPaths includes the owner's next user layer even when another user's
// Machine was loaded for adoption. Protecting it does not import its contents.
func (k *compiler) machineLayerPaths() []string {
	paths := slices.Clone(k.m.Layers)
	for _, source := range k.m.LayerSources() {
		// A layer's File is its shown name; a name that is not a path ($TEGO_CONFIG) has no place to protect that
		// Machine.Layers does not list already.
		if filepath.IsAbs(source.File) && source.State != config.LayerUnselected && !slices.Contains(paths, source.File) {
			paths = append(paths, source.File)
		}
	}
	if filepath.IsAbs(k.o.home) && k.o.home != k.m.Home {
		owner := strings.TrimSuffix(k.o.home, "/") + "/.tego/config.yaml"
		if !slices.Contains(paths, owner) {
			paths = append(paths, owner)
		}
		if k.rt.Baseline != nil {
			k.rt.Baseline.ProtectedOwnerLayer = owner
		}
	}
	return paths
}

func (k *compiler) baselineTopology() {
	bt := k.rt.Baseline
	if bt == nil || len(bt.Entries) == 0 {
		return
	}
	bt.identities = map[string]fileKey{}
	bt.denyWrites = map[string]bool{}
	var mt *MountTable
	var mountErr error
	for i := range bt.Entries {
		e := &bt.Entries[i]
		if !bt.Applied {
			e.Coverage = []BaselineCoverage{{Tier: backend.TierObserve, Held: "not-applied"}}
			continue
		}
		if e.Key == config.BaselineDenyRead || e.Key == config.BaselineDenyWrite {
			if mt == nil && mountErr == nil {
				if bt.MountInfo == "" {
					mountErr = errors.New("mount inventory is disabled")
				} else {
					mt, _, mountErr = ReadMountSnapshot(bt.MountInfo)
				}
			}
			e.topology = inspectBaselineTopology(e, mt, mountErr)
			if e.State != config.LayerAbsent {
				for _, p := range []string{e.Expanded, e.Target} {
					bt.identities[p] = fileKey{e.Device, e.Inode}
					if walked, ok := WalkedPath(p); ok {
						bt.identities[walked] = fileKey{e.Device, e.Inode}
					}
				}
			} else {
				bt.identities[e.Ancestor] = fileKey{e.Device, e.Inode}
			}
			for _, pin := range e.topology.linked {
				bt.identities[pin.path] = pin.key
			}
			for _, g := range k.rt.FS {
				if g.Kind == FSWrite {
					_, enclosing := baselineGrantRelation(e, g.Canonical())
					e.topology.enclosingWrite = e.topology.enclosingWrite || enclosing
				}
			}
			if e.topology.problem != "" {
				d := k.ds.errorf(baselineEntryPos(e), CodeBaselinePlacement, "baseline.%s %q from %v (owner uid %d): %s", e.Key, e.Value, e.Sources, bt.Owner.UID, e.topology.problem).
					fix("use an absolute existing target with a complete supported inventory, or remove this baseline entry")
				d.BaselinePlacement = &BaselinePlacementDiagnostic{Entry: e, Owner: bt.Owner}
			}
			if e.Key == config.BaselineDenyRead {
				for _, pin := range e.topology.linked {
					k.pinBaselineRead(e, pin)
				}
			}
			k.keepBaselineLinkedWrites(e)
			if e.Key == config.BaselineDenyWrite && e.State != config.LayerAbsent {
				k.keepBaselineDenyWrite(e)
				bt.denyWrites[e.Target] = true
			}
		}
	}
	if bt.Applied {
		for _, cell := range []struct {
			tier  backend.Tier
			plane string
		}{{backend.TierLandlock, ""}, {backend.TierCgroup, "lsm"}, {backend.TierCgroup, "fmod_ret"}, {backend.TierCgroup, "fanotify"}, {backend.TierBPFLSM, "lsm"}} {
			rows, _ := k.rt.BaselineCoverageAt(cell.tier, cell.plane, false)
			for i, row := range rows {
				bt.Entries[i].Coverage = append(bt.Entries[i].Coverage, row)
			}
		}
	}
	// Compilation may leave several modeled mechanisms reachable. Reject only
	// when none can hold the complete baseline; selection and preparation still
	// recheck the actual mechanism, including a root tier's fallback.
	supported := !bt.Applied
	if bt.Applied {
		for _, row := range bt.Entries[0].Coverage {
			if slices.Contains(k.rt.Reach, row.Tier) || (len(k.rt.Reach) == 0 && row.Tier == k.rt.Tier) {
				if k.rt.BaselineAt(row.Tier, row.Plane) == nil {
					supported = true
					break
				}
			}
		}
	}
	if !supported {
		for i := range bt.Entries {
			e := &bt.Entries[i]
			for _, row := range e.Coverage {
				if row.Held == "refuse-launch" && e.topology.problem == "" {
					d := k.ds.errorf(baselineEntryPos(e), CodeBaselinePlacement, "baseline.%s %q from %v (owner uid %d): no reachable tier/plane can hold the configured baseline; %s/%s: %s", e.Key, e.Value, e.Sources, bt.Owner.UID, row.Tier, row.Plane, strings.Join(row.Conditions, "; ")).fix("use a supported decision plane/layout, or remove this baseline entry")
					d.BaselinePlacement = &BaselinePlacementDiagnostic{Entry: e, Owner: bt.Owner}
					break
				}
			}
		}
	}
}

func baselineEntryPos(e *BaselineRule) Pos {
	if len(e.Sources) == 0 {
		return Pos{}
	}
	s := e.Sources[0]
	return Pos{File: s.File, Line: s.Line, Col: 1}
}

func inspectBaselineTopology(e *BaselineRule, mt *MountTable, mountErr error) baselineTopologyFacts {
	f := baselineTopologyFacts{caseExact: true}
	if mountErr != nil {
		f.problem = "mount inventory cannot establish baseline coverage: " + mountErr.Error()
		return f
	}
	p := e.Target
	if e.State == config.LayerAbsent {
		p = filepath.Join(e.Ancestor, e.Missing)
	}
	if mt == nil {
		f.problem = "mount inventory is unavailable"
		return f
	}
	var ok bool
	f.aliases, ok = mt.TreeAliases(p)
	if !ok {
		f.problem = "mount inventory holds no mount for " + p
		return f
	}
	f.detached, ok = mt.DetachedParts(p)
	if !ok {
		f.problem = "mount inventory cannot place detached parts of " + p
		return f
	}
	inventory := p
	if e.State == config.LayerAbsent {
		inventory = e.Ancestor
	}
	fi, err := os.Stat(inventory)
	if err != nil {
		f.problem = "target inventory: " + err.Error()
		return f
	}
	if !fi.IsDir() && !fi.Mode().IsRegular() {
		f.problem = "target is neither a regular file nor a directory"
		return f
	}
	if e.State == config.LayerAbsent {
		return f
	}
	if !fi.IsDir() {
		f.caseExact = baselineCaseExact(mt, filepath.Dir(p))
		if nlinkOf(fi) > 1 {
			key, known := fileKeyOf(fi)
			if !known {
				f.problem = "file identity unavailable"
			} else {
				f.linked = []baselinePin{{p, key, nlinkOf(fi)}}
			}
		}
		return f
	}
	// Every linked descendant must be found, including outside all write grants:
	// a later fallback cannot inherit a plane's inode coverage.
	search := &baselineReadInventory{left: maxDenyWriteLinkEntries, end: time.Now().Add(maxDenyWriteLinkTime), mt: mt, exact: true, files: map[fileKey]*baselineLinkedCount{}}
	search.walk(p, 0)
	f.caseExact, f.problem = search.exact, search.problem
	for _, key := range search.order {
		v := search.files[key]
		if v.met < v.pin.links {
			f.linked = append(f.linked, v.pin)
		}
	}
	return f
}

func baselineCaseExact(mt *MountTable, p string) bool {
	m, _, ok := mt.t.lookup(p)
	if !ok {
		return false
	}
	switch m.fstype {
	case "ext4", "f2fs", "tmpfs", "overlay":
		// An unreadable folder answers not exact, as before dirCaseExact returned its error.
		exact, _ := dirCaseExact(p)
		return exact
	case "xfs", "btrfs", "ext2", "ext3", "nfs", "nfs4", "ceph", "afs", "squashfs", "erofs", "ramfs":
		return true
	default:
		return false
	}
}

type baselineLinkedCount struct {
	pin baselinePin
	met uint64
}
type baselineReadInventory struct {
	left    int
	end     time.Time
	mt      *MountTable
	exact   bool
	files   map[fileKey]*baselineLinkedCount
	order   []fileKey
	problem string
}

func (s *baselineReadInventory) walk(p string, depth int) {
	if s.problem != "" {
		return
	}
	if depth > maxDenyWriteLinkDepth || s.left <= 0 || time.Now().After(s.end) {
		s.problem = "baseline link inventory exhausted its entry, depth or time bound"
		return
	}
	s.exact = s.exact && baselineCaseExact(s.mt, p)
	es, more, err := listDir(p, min(s.left, maxDirEntries))
	s.left -= len(es)
	if err != nil || more {
		s.problem = "baseline link inventory could not list the whole directory " + p
		return
	}
	for _, entry := range es {
		if time.Now().After(s.end) {
			s.problem = "baseline link inventory exhausted its time bound"
			return
		}
		child := filepath.Join(p, entry.Name())
		fi, err := entry.Info()
		if err != nil {
			s.problem = "baseline link inventory cannot stat " + child
			return
		}
		if fi.IsDir() {
			s.walk(child, depth+1)
		} else if fi.Mode().IsRegular() && nlinkOf(fi) > 1 {
			key, ok := fileKeyOf(fi)
			if !ok {
				s.problem = "baseline link inventory has no identity for " + child
				return
			}
			if v := s.files[key]; v != nil {
				v.met++
			} else {
				s.files[key] = &baselineLinkedCount{baselinePin{child, key, nlinkOf(fi)}, 1}
				s.order = append(s.order, key)
			}
		}
		if s.problem != "" {
			return
		}
	}
}

func (k *compiler) keepBaselineLinkedWrites(e *BaselineRule) {
	// Metadata hooks need every external hard link even when the default write
	// refusal makes the baseline target redundant for write opens.
	if e.Key == config.BaselineDenyWrite {
		for _, pin := range e.topology.linked {
			if !slices.Contains(k.rt.DenyWriteLinked, pin.path) {
				k.rt.DenyWriteLinked = append(k.rt.DenyWriteLinked, pin.path)
			}
		}
	}
}

func (k *compiler) keepBaselineDenyWrite(e *BaselineRule) {
	for _, r := range k.rt.DenyWrite {
		if r.Raw == e.Expanded || r.Canonical() == e.Target {
			return
		}
	}
	k.rt.DenyWrite = append(k.rt.DenyWrite, FSRule{Path: e.Expanded, Resolved: e.Target, Raw: e.Expanded, Pos: baselineEntryPos(e), Kind: FSDenyWrite, Unenforced: e.topology.enclosingWrite})
}

func (k *compiler) pinBaselineRead(e *BaselineRule, pin baselinePin) {
	for _, r := range k.rt.FS {
		fi, err := os.Stat(r.Canonical())
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		key, ok := fileKeyOf(fi)
		if ok && key == pin.key {
			if r.Kind == FSWrite || r.Kind == FSAsk {
				k.baselineConflict(e, "fs.write", "a granted file is an existing hard link of a baseline read-denied descendant")
				return
			}
			if r.Kind == FSDenyRead {
				return
			}
		}
	}
	k.rt.FS = append(k.rt.FS, FSRule{Path: pin.path, Resolved: pin.path, Kind: FSDenyRead, Raw: e.Expanded, Pos: baselineEntryPos(e), Regular: true, Nlink: pin.links})
}

func (rt *RuleTable) baselineCell(e *BaselineRule, tier backend.Tier, plane string) (BaselineCoverage, string) {
	c := BaselineCoverage{Tier: tier, Plane: plane, Held: "kernel"}
	why := ""
	if rt.baselineReplayFacts != nil && (e.Key == config.BaselineDenyRead || e.Key == config.BaselineDenyWrite) {
		for _, path := range baselineRelationPaths(e.Key, rt.FS, rt.FSAsk, rt.Exec) {
			if _, ok := rt.baselineReplayFacts.relations[baselineRelationKey{e.Key, e.Value, path}]; !ok {
				why = "recorded path relation is unavailable for " + path
				c.Held = "refuse-launch"
				c.Conditions = []string{why}
				return c, why
			}
		}
	}
	holds := rt.HoldsFSNotifications()
	if rt.baselineReplayFacts != nil {
		holds = rt.baselineReplayFacts.HoldsNotifications
	}
	pathDependent := tier == backend.TierLandlock || plane == "fanotify" || plane == "" || holds
	switch e.Key {
	case config.BaselineDenyExec:
		c.Held = "best-effort"
		c.ImageMode = "restricted"
		if source := rt.DecisionContract(); source != nil && source.ExecUnrestricted() {
			c.ImageMode = "unrestricted"
		}
		c.Operations = []string{"matched argv, image name and identity"}
		c.Limits = []string{"copied argv and name matching is best effort", "renamed copies, memfd/deleted images and interpreted code are outside this refusal with unrestricted images"}
		if !pathDependent {
			c.Conditions = []string{"exec image pins are conditional on the actual doctor's exec-pin capability; no pin claim is made here"}
		}
	case config.BaselineDenyEnv:
		c.Held = "conditional"
		c.Operations = []string{"final exec environment delivery"}
		c.Conditions = []string{"denied names absent from final ChildSpec.Env"}
		c.Limits = []string{"child-created or reconstructed values are outside this rule"}
	case config.BaselineDenyRead, config.BaselineDenyWrite:
		f := e.topology
		why = f.problem
		writeAuthority, enclosingWrite := false, f.enclosingWrite
		for _, g := range slices.Concat(rt.FS, rt.FSAsk) {
			if g.Kind == FSWrite || g.Kind == FSAsk {
				writeAuthority = true
				_, encloses := rt.baselineCoverageRelation(e, g.Canonical())
				enclosingWrite = enclosingWrite || encloses
			}
		}
		needsAliasProof := e.Key == config.BaselineDenyRead || writeAuthority
		if pathDependent && needsAliasProof && len(f.aliases) > 0 {
			why = "known bind alias " + f.aliases[0] + " is not held by this path-dependent mechanism"
		}
		if pathDependent && needsAliasProof && !f.caseExact {
			why = "case aliases cannot be ruled out for this path-dependent mechanism"
		}
		if pathDependent && needsAliasProof && len(f.linked) > 0 && (e.Key != config.BaselineDenyRead || !rt.baselineReadLinksCovered(f.linked)) {
			why = "existing hard links outside the denied scope require inode-pinned decision rows"
		}
		if len(f.detached) > 0 && (e.Key == config.BaselineDenyRead || writeAuthority || !pathDependent) {
			why = "detached bind subtree " + f.detached[0] + " bypasses the denied ancestor's decision row"
		}
		if e.Key == config.BaselineDenyRead {
			c.Operations = []string{"read opens"}
			if pathDependent {
				for _, grant := range rt.Exec {
					for _, p := range []string{grant.Path, grant.Resolved, grant.Interp} {
						if p == "" {
							continue
						}
						inside, enclosing := rt.baselineCoverageRelation(e, p)
						if inside || enclosing && grant.IsDir {
							why = "exec grant or generated loader/interpreter " + strconv.Quote(p) + " carries read access across this refusal"
						}
					}
				}
			}
			if plane == "fanotify" {
				c.Held = "conditional"
				c.Conditions = []string{"checked exact paths and unchanged mount topology"}
				c.Limits = []string{"moved and future-name mutation checks remain best effort"}
			}
			for _, r := range rt.FS {
				if r.Kind == FSDenyRead && r.Unenforced && (r.Raw == e.Expanded || r.Canonical() == e.Target) && pathDependent {
					if !rt.ReadsHeldAt(tier) {
						why = "read-denied target under a write grant needs held reads"
					} else {
						c.Held = "conditional"
						c.Conditions = []string{"held reads with launch-pinned targets and observed installations"}
						c.Limits = []string{"future files moved, exchanged or linked out before pinning and transient mount changes can escape (A11)"}
					}
				}
			}
			if enclosingWrite && pathDependent && !rt.ReadsHeldAt(tier) {
				why = "read-denied target under a current write grant needs held reads"
			}
		} else {
			c.Operations = []string{"write opens", "delete", "rename"}
			if !pathDependent {
				c.Operations = append(c.Operations, "supported metadata hooks, including chmod")
			} else {
				c.Limits = []string{"chmod, chown, xattrs and timestamps are outside this kernel claim"}
			}
			if enclosingWrite && pathDependent {
				why = "a write grant enclosing this baseline refusal requires a decision plane"
			}
		}
		if e.State == config.LayerAbsent {
			c.Held = "conditional"
			c.Conditions = []string{"absent system target; nearest existing ancestor/name remains outside every read-bearing/write grant"}
			if e.Key == config.BaselineDenyWrite {
				c.Operations = []string{"write opens", "delete", "rename"}
				c.Limits = []string{"no present inode or metadata row exists; chmod, chown, xattrs and timestamps are outside this claim", "the target must remain absent until preparation; later external target or hard-link creation has no compiled inode coverage"}
			}
			for _, r := range rt.FS {
				if r.Kind == FSWrite && isAncestorOrSelf(r.Canonical(), filepath.Join(e.Ancestor, e.Missing)) {
					why = "absent target lies below a write grant"
				}
			}
			if e.Key == config.BaselineDenyRead {
				for _, r := range rt.Exec {
					if r.IsDir && isAncestorOrSelf(execRulePath(r), filepath.Join(e.Ancestor, e.Missing)) {
						why = "absent target lies below an exec read-bearing grant"
					}
				}
			}
		}
	}
	if why != "" {
		c.Held = "refuse-launch"
		c.Conditions = append(c.Conditions, why)
	}
	return c, why
}

func (rt *RuleTable) baselineReadLinksCovered(pins []baselinePin) bool {
	if rt.baselineReplayFacts != nil {
		for _, e := range rt.baselineReplayFacts.Entries {
			if len(e.Linked) != len(pins) {
				continue
			}
			same := true
			for i, p := range pins {
				q := e.Linked[i]
				same = same && p.path == q.Path && p.key == (fileKey{q.Device, q.Inode}) && p.links == q.Links
			}
			if same {
				return e.LinksCovered
			}
		}
		return false
	}

	for _, pin := range pins {
		names := map[string]bool{}
		for _, r := range rt.FS {
			if r.Kind != FSDenyRead || r.AskRead || r.Unenforced {
				continue
			}
			p := r.Canonical()
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				if key, ok := fileKeyOf(fi); ok && key == pin.key {
					names[p] = true
				}
			}
		}
		if uint64(len(names)) < pin.links {
			return false
		}
	}
	return true
}

// CheckBaselineIdentity binds the opened preparation descriptor to the target
// compiled from the immutable snapshot. Ordinary enumerated paths cost one lookup.
func (rt *RuleTable) CheckBaselineIdentity(path string, dev, ino uint64) error {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied {
		return nil
	}
	if want, ok := rt.Baseline.identities[path]; ok && want != (fileKey{dev, ino}) {
		return fmt.Errorf("baseline target %q changed identity before its preparation descriptor was pinned", path)
	}
	return nil
}

// HasBaselineDenyWriteAt keeps a baseline's protected metadata row even outside
// write grants, where an ordinary contract deny_write row would be redundant.
func (rt *RuleTable) HasBaselineDenyWriteAt(path string) bool {
	return rt != nil && rt.Baseline != nil && rt.Baseline.Applied && rt.Baseline.denyWrites[path]
}

// HasBaselineIdentity reports a target that preparation must pin even beneath
// a write grant. The matching descriptor is checked by CheckBaselineIdentity.
func (rt *RuleTable) HasBaselineIdentity(path string) bool {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied {
		return false
	}
	_, ok := rt.Baseline.identities[path]
	return ok
}

// BaselineFile is a baseline target or linked descendant that a file-only
// adoption must find in the actual decision plane's keyed rows before moving.
type BaselineFile struct {
	Path          string
	Device, Inode uint64
}

// BaselineFiles returns a detached, deterministic list of the required pins.
func (rt *RuleTable) BaselineFiles() []BaselineFile {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied {
		return nil
	}
	var out []BaselineFile
	seen := map[string]bool{}
	for i := range rt.Baseline.Entries {
		e := &rt.Baseline.Entries[i]
		if (e.Key != config.BaselineDenyRead && e.Key != config.BaselineDenyWrite) || e.State == config.LayerAbsent {
			continue
		}
		pins := append([]baselinePin{{path: e.Target, key: fileKey{e.Device, e.Inode}}}, e.topology.linked...)
		for _, pin := range pins {
			if !seen[pin.path] {
				out = append(out, BaselineFile{pin.path, pin.key.dev, pin.key.ino})
				seen[pin.path] = true
			}
		}
	}
	return out
}

// BaselineAt refuses a tier/plane that cannot hold every applicable entry. Empty
// and record-only snapshots retain their existing selection behavior.
func (rt *RuleTable) BaselineAt(tier backend.Tier, plane string) error {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied {
		return nil
	}
	if tier == backend.TierObserve {
		return errors.New("baseline cannot be applied by a record-only mechanism")
	}
	if tier != backend.TierLandlock && tier != backend.TierCgroup && tier != backend.TierBPFLSM {
		return fmt.Errorf("baseline: unknown tier %q", tier)
	}
	if tier == backend.TierBPFLSM && plane != "lsm" {
		return fmt.Errorf("baseline: tier bpflsm requires its lsm decision plane")
	}
	if tier == backend.TierCgroup && plane != "lsm" && plane != "fmod_ret" && plane != "fanotify" {
		return fmt.Errorf("baseline: unknown cgroup mechanism %q", plane)
	}
	for i := range rt.Baseline.Entries {
		e := &rt.Baseline.Entries[i]
		if _, why := rt.baselineCell(e, tier, plane); why != "" {
			return fmt.Errorf("baseline.%s %q from %v (owner uid %d, tier %s, plane %s): %s; use a supported layout/mechanism, or remove this baseline entry", e.Key, e.Value, e.Sources, rt.Baseline.Owner.UID, tier, plane, why)
		}
	}
	return nil
}

// BaselineCoverageAt recomputes the actual mechanism's rows for the record seam.
// execPinned must be the prepared handle's ExecPinClaim, never a tier guess.
func (rt *RuleTable) BaselineCoverageAt(tier backend.Tier, plane string, execPinned bool) ([]BaselineCoverage, error) {
	if rt == nil || rt.Baseline == nil {
		return nil, nil
	}
	rows := make([]BaselineCoverage, 0, len(rt.Baseline.Entries))
	for i := range rt.Baseline.Entries {
		e := &rt.Baseline.Entries[i]
		if !rt.Baseline.Applied {
			rows = append(rows, BaselineCoverage{Tier: tier, Plane: plane, Held: "not-applied"})
			continue
		}
		row, _ := rt.baselineCell(e, tier, plane)
		if e.Key == config.BaselineDenyExec && execPinned && tier != backend.TierLandlock && (plane == "lsm" || plane == "fmod_ret") {
			row.Held = "conditional"
			row.Conditions = []string{"the prepared decision plane's exec-pin capability passed; kernel holds execs to the decided facts"}
			row.Limits = append([]string{"facts are held only for execs covered by the prepared pins"}, row.Limits[1:]...)
		}
		rows = append(rows, row)
	}
	return rows, rt.BaselineAt(tier, plane)
}

// RecheckBaseline verifies the compile-time targets and inventory immediately
// before preparation. It never silently recompiles a changed machine snapshot.
func (rt *RuleTable) RecheckBaseline() error {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied {
		return nil
	}
	if err := rt.ValidateBaselineFS(); err != nil {
		return err
	}
	if err := rt.ValidateBaselineSockets(); err != nil {
		return err
	}
	var mt *MountTable
	var mountErr error
	for i := range rt.Baseline.Entries {
		e := &rt.Baseline.Entries[i]
		if e.Key != config.BaselineDenyRead && e.Key != config.BaselineDenyWrite {
			continue
		}
		p := e.Target
		if e.State == config.LayerAbsent {
			p = e.Ancestor
			if _, err := os.Stat(e.Expanded); !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("baseline.%s %q: absent target changed before preparation", e.Key, e.Value)
			}
			// The target may remain absent while a link redirects its spelling.
			// Partial parent creation is safe only when the final placed name
			// still agrees with the compiled ancestor/name guard.
			walk := walkTarget(e.Expanded)
			if !walk.placed || walk.place != filepath.Join(e.Ancestor, e.Missing) {
				return fmt.Errorf("baseline.%s %q: absent target walk changed before preparation", e.Key, e.Value)
			}
		}
		fi, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("baseline.%s %q: recheck target: %w", e.Key, e.Value, err)
		}
		key, ok := fileKeyOf(fi)
		if !ok || key != (fileKey{e.Device, e.Inode}) {
			return fmt.Errorf("baseline.%s %q: target identity changed before preparation", e.Key, e.Value)
		}
		resolved, err := filepath.EvalSymlinks(e.Expanded)
		if e.State != config.LayerAbsent && (err != nil || resolved != e.Target) {
			return fmt.Errorf("baseline.%s %q: target walk changed before preparation", e.Key, e.Value)
		}
		if mt == nil && mountErr == nil {
			mt, _, mountErr = ReadMountSnapshot(rt.Baseline.MountInfo)
		}
		fresh := inspectBaselineTopology(e, mt, mountErr)
		if fresh.problem != "" || fresh.caseExact != e.topology.caseExact || !slices.Equal(fresh.aliases, e.topology.aliases) || !slices.Equal(fresh.detached, e.topology.detached) || !slices.Equal(fresh.linked, e.topology.linked) {
			return fmt.Errorf("baseline.%s %q: topology or link inventory changed before preparation: %s", e.Key, e.Value, fresh.problem)
		}
	}
	return nil
}

func baselineGrantRelation(e *BaselineRule, p string) (inside, enclosing bool) {
	target := e.Target
	if target == "" {
		target = filepath.Join(e.Ancestor, e.Missing)
	}
	for _, name := range slices.Concat([]string{target, e.Expanded}, e.topology.aliases, e.topology.detached) {
		inside = inside || isAncestorOrSelf(name, p)
		enclosing = enclosing || isAncestorOrSelf(p, name)
	}
	if e.Target != "" {
		inside = inside || ancestorIdentity(p, e.Device, e.Inode)
	}
	for _, pin := range e.topology.linked {
		inside = inside || ancestorIdentity(p, pin.key.dev, pin.key.ino)
	}
	if fi, err := os.Stat(p); err == nil {
		if key, ok := fileKeyOf(fi); ok {
			enclosing = enclosing || ancestorIdentity(target, key.dev, key.ino)
		}
	}
	return inside, enclosing
}

// ValidateBaselineFS checks the final compiled table, including runtime grants.
// A producer cannot reopen the baseline after ordinary contract compilation.
func (rt *RuleTable) ValidateBaselineFS() error {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied {
		return nil
	}
	for i := range rt.Baseline.Entries {
		e := &rt.Baseline.Entries[i]
		if e.Key != config.BaselineDenyRead && e.Key != config.BaselineDenyWrite {
			continue
		}
		for _, g := range slices.Concat(rt.FS, rt.FSAsk) {
			if detail := rt.baselineFSGrantConflict(e, g); detail != "" {
				return fmt.Errorf("baseline-conflict: %s from %s conflicts with baseline.%s %q from %v (owner uid %d, identity %d:%d, tier %s): %s; remove the grant or baseline entry", g.RuleName(), g.Pos.File, e.Key, e.Value, e.Sources, rt.Baseline.Owner.UID, e.Device, e.Inode, rt.Tier, detail)
			}
		}
	}
	return nil
}

func (b *fsBuilder) absentBaseline(e *BaselineRule, writes []writePath) {
	if e.Key != config.BaselineDenyRead {
		return
	}
	res := filepath.Join(e.Ancestor, e.Missing)
	at, ok := absentAt(res)
	if !ok {
		b.k.ds.errorf(baselineEntryPos(e), CodeBaselinePlacement, "baseline.%s %q: absent target cannot be placed", e.Key, e.Value)
		return
	}
	if b.grants(writes).FirstCover(at) >= 0 || b.grants(writes).FirstCover(res) >= 0 {
		b.k.baselineConflict(e, "fs.write", "missing system baseline target lies under a write grant")
		return
	}
	b.k.rt.AbsentDenyRead = append(b.k.rt.AbsentDenyRead, AbsentRow{Path: e.Expanded, Resolved: res, At: at})
}

// Retain the existing linked-write inventory diagnostics for contract-only rules,
// while baseline rows may never turn a cut search into permission to launch.
func (k *compiler) baselineDenyWriteRow(r *FSRule) bool {
	if k.rt.Baseline == nil || !k.rt.Baseline.Applied {
		return false
	}
	for i := range k.rt.Baseline.Entries {
		e := &k.rt.Baseline.Entries[i]
		if e.Key == config.BaselineDenyWrite && (r.Raw == e.Expanded || r.Canonical() == e.Target) {
			return true
		}
	}
	return false
}

func baselineIndex(key string, i int) string { return key + "." + strconv.Itoa(i) }
