// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// RuleUnmatched is the value of an action event's rule field when no declared entry covers it
// (spec/record/v1/README.md: "the declared entry or unmatched"). Every other value this package
// stamps comes from agent.FSRule/NetRule/ExecRule.RuleName, the one spelling of the field, so a
// tier-2 event names the same entry the contract declared and `tego drift` can match the two.
const RuleUnmatched = agent.UnmatchedRule

// dirKey builds a dirIndex key. struct tego_ev_fsop carries the parent directory's whole inode number
// and its device (bpf/include/events.h), so the key is the full pair on both sides; the device is in
// stat(2)'s encoding, which is what the recorder's decoder converts the kernel's s_dev to.
func dirKey(dev, ino uint64) devIno { return devIno{Dev: dev, Ino: ino} }

// devIno is a (device, inode) pair. It keys dirIndex only — a userspace, record-only map, never a
// kernel BPF_MAP_TYPE_INODE_STORAGE, which stays tier-3-only (ADR 0010, §5 R9/I9). A declared path whose
// stat device is not its super block's (btrfs, an overlayfs of one filesystem) is left out of the index
// rather than keyed by a pair the kernel's records never carry (newRuleIndexAt), and a miss degrades
// attribution instead of changing a decision.
type devIno struct {
	Dev uint64
	Ino uint64
}

// fsEntry is one compiled fs rule under one of its spellings, with the name an event carries. A rule whose
// declared path runs through a symlink is two entries: the path the author wrote and the canonical path it
// resolves to (agent.FSRule.Resolved), because bpf_d_path reports the canonical one and a program may still
// spell the other. Both carry the rule's one name.
type fsEntry struct {
	rule agent.FSRule
	name string // fs.write[./out]
	path string // the spelling this entry matches: rule.Path, or rule.Resolved where that differs
	at   int    // the rule's position in the RuleTable's FS
}

// ruleIndex answers "which declared entry does this action belong to, and what verdict does that
// entry imply" for the recorder. It captures rule identities at construction and applies prepared mount metadata
// before Start drains events. The single drain goroutine then reads it without mutation or a lock.
//
// It is the recorder's *stamping* index, not an enforcement decision: the kernel already decided
// (docs/p0/enforce-cgroup-observe.md §5 R3, R9). Exec is answered by decide.Evaluate, the one
// implementation `compile --test` uses too. Net keeps the kernel's exact-before-LPM precedence, which
// Evaluate's first-match does not have, with the port and address rules the enforcing sides use. fs keeps
// the nearest-entry walk that names an event plus the (dev, ino) index R9 needs, which no other component
// has; the entry that decides an fs verdict comes from decide.FSDecider, the root model's own chooser.
type ruleIndex struct {
	rt *agent.RuleTable // the compiled table itself, which answers exec (matchExec)
	fs []fsEntry        // longest resolved path first, so the first match is the nearest entry
	// fx is rt's fs entries indexed (decide.FSIndex): matchFS and the entries deciding each sample are asked of
	// it, since a scan per sample over a table the .env scan filled cost the drain goroutine milliseconds.
	fx *decide.FSIndex
	// ofRule is each rt.FS position's first entry in fs, -1 for a rule with no declared path.
	ofRule []int
	net    []agent.NetRule
	dirs   map[devIno]int // (dev, ino) of each declared fs path -> index into fs
	// unindexed are the declared paths left out of dirs because stat does not name them by their super
	// block's device (applyMounts); the recorder reports them as the run's gap.
	unindexed []string
	mounts    map[devIno]uint64
	// marked is the devices the fanotify listener marks for the unenforced deny_read entries (markedDevicesFrom);
	// nil when there are none to compare with.
	marked map[uint64]struct{}
	// held is the inodes the exec entries named when the index was built, before the agent ran, with the rights the
	// Landlock builder's grants give them (decide.HoldExecGrants): a rename's or a link's chain refusal is explained by
	// where those inodes are now, as the supervisor's line is.
	held decide.HeldExecGrants
}

func newRuleIndexFrom(rt *agent.RuleTable, rows []mountRow) *ruleIndex {
	ri := &ruleIndex{dirs: map[devIno]int{}, mounts: map[devIno]uint64{}}
	if rt == nil {
		return ri
	}
	// Each rule under its declared and its canonical spelling. bpf_d_path reports the canonical path, so
	// under a project reached through a symlink (the cwd a shell reports, a symlinked $HOME) matching the
	// declared spelling alone missed every open: a read the kernel refused under a deny_read entry was
	// recorded allow, and a write Landlock allowed in a write entry observed (§2.4).
	ri.fs = make([]fsEntry, 0, len(rt.FS))
	for i, r := range rt.FS {
		if r.Path == "" {
			continue
		}
		for _, p := range r.Spellings() {
			ri.fs = append(ri.fs, fsEntry{rule: r, name: r.RuleName(), path: p, at: i})
		}
	}
	// Nearest-wins means the longest declared path that is an ancestor of the action's path.
	sort.SliceStable(ri.fs, func(i, j int) bool { return len(ri.fs[i].path) > len(ri.fs[j].path) })
	ri.ofRule = make([]int, len(rt.FS))
	for i := range ri.ofRule {
		ri.ofRule[i] = -1
	}
	for i := range ri.fs {
		if at := ri.fs[i].at; ri.ofRule[at] < 0 {
			ri.ofRule[at] = i
		}
	}
	ri.fx = decide.NewFSIndex(rt)
	for i, e := range ri.fs {
		// The directory index is keyed once per rule, under its canonical spelling, so the path matchDir
		// rebuilds is spelled as bpf_d_path spells an open's.
		if e.path != e.rule.Canonical() {
			continue
		}
		di, mnt, ok := statEntry(e.path)
		if !ok {
			continue
		}
		// A record carries the parent's super block s_dev, and the key is stat's st_dev: where stat reports
		// another device, btrfs's subvolume device and an overlayfs layer's, the two never meet, and every
		// unlink, rename and mkdir under the entry missed while §2.4 said it resolved (R9). ADR
		// 0025 rejects keying btrfs by (super block, inode) instead, since its subvolumes repeat inode numbers
		// under one super block and a key could name a nearer entry than the true one, so no key is guessed:
		// the entry is left out, and the run records that its operations there resolve through nothing.

		key := dirKey(di.Dev, di.Ino)
		if _, taken := ri.dirs[key]; !taken { // nearest entry wins here too: the list is already sorted
			ri.mounts[key] = mnt
			ri.dirs[key] = i
		}
	}
	ri.held = decide.HoldExecGrants(rt, func(p string) (decide.FileKey, error) {
		var st unix.Stat_t
		err := unix.Stat(p, &st)
		return decide.FileKey{Dev: uint64(st.Dev), Ino: st.Ino}, err
	})
	ri.rt = rt
	ri.net = rt.Net
	ri.applyMounts(rows)
	return ri
}

// execGrants is the exec grants by the inodes held (decide.HeldExecGrants.Grants), each end and its directories
// lstat'ed in this process's view, the one every path the index names is spelled in.
func (ri *ruleIndex) execGrants() decide.ExecGrants {
	return ri.held.Grants(ri.rt, func(p string) (decide.FileKey, error) {
		var st unix.Stat_t
		err := unix.Lstat(p, &st)
		return decide.FileKey{Dev: uint64(st.Dev), Ino: st.Ino}, err
	})
}

// execUngranted reports whether rule, the exec entry Evaluate matched an exec of path by, is an entry with a path whose
// EXECUTE the Landlock ruleset no longer gives at path: the grant is on the inode the builder held, a directory
// entry's and a file entry's alike. After `mv out/bin out/old; mkdir out/bin` inside a write entry the fresh out/bin
// holds none, and after `mv out/tool.new out/tool` neither does the new out/tool, so the kernel refuses the exec's
// open (EACCES) and no rule grants it, as the supervisor's line says (dirHeld
// for a directory, execIDs for a file). An end the grants cannot stat, or a table with nothing held, keeps the
// declared names' answer. The inodes are lstat'ed when the sample is processed, not when the syscall ran: a tree
// changed back before then (the old inode moved back under the name) leaves the line at the declared names' answer,
// observed by another mechanism (enforce-cgroup-observe R9).
func (ri *ruleIndex) execUngranted(rule, path string) bool {
	if ri == nil || ri.rt == nil || ri.rt.Tier == backend.TierObserve {
		return false
	}
	named := false
	for i := range ri.rt.Exec {
		if e := &ri.rt.Exec[i]; e.Path != "" && e.RuleName() == rule {
			named = true
			break
		}
	}
	if !named {
		return false
	}
	grants := ri.execGrants()
	return grants != nil && grants(path)&agent.AccessExecute == 0
}

// statEntry opens a declared path O_PATH|O_CLOEXEC and fstats it, and gives the id of the mount the path is on,
// 0 when statx does not report one. O_PATH resolves the name without opening the file for I/O, which is what lets
// a deny_read entry be indexed at all; the fd is closed immediately because the run's inode identity is pinned by
// the launcher's own held fds (docs/ARCHITECTURE.md §10), not here.
func statEntry(path string) (devIno, uint64, bool) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return devIno{}, 0, false
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return devIno{}, 0, false
	}
	var mnt uint64
	var stx unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx) == nil && stx.Mask&unix.STATX_MNT_ID != 0 {
		mnt = stx.Mnt_id
	}
	return devIno{Dev: uint64(st.Dev), Ino: st.Ino}, mnt, true
}

func mountDevsFrom(rows []mountRow) map[uint64]uint64 {
	out := map[uint64]uint64{}
	for _, m := range rows {
		out[m.id] = m.dev
	}
	return out
}

// mountRow is one line of a mountinfo table: the mount's id, its super block's device in stat(2)'s encoding,
// and its mount point with mountinfo's octal escapes undone.
type mountRow struct {
	id    uint64
	dev   uint64
	point string
}

// readRecorderMounts is the acquisition boundary for recorders without prepared facts.
var readRecorderMounts = agent.ReadMountSnapshot

// readMounts is the bounded strict reader for recorders without prepared facts.
func readMounts(path string) []mountRow {
	mt, _, _ := readRecorderMounts(path)
	return rowsFrom(mt)
}

func markedDevicesFrom(rt *agent.RuleTable, rows []mountRow) map[uint64]struct{} {
	if rt.Tier != backend.TierCgroup {
		return nil // only tier 2 leaves such an entry to a listener that marks mounts
	}
	var roots []string
	for _, r := range rt.FS {
		if r.Kind == agent.FSDenyRead && r.Unenforced && r.Path != "" {
			roots = append(roots, r.Canonical())
		}
	}
	// The listener marks each name entry's scope the same way (ADR 0043 D7).
	for _, e := range rt.NameDeny {
		for _, s := range e.Scopes {
			roots = append(roots, s.Canonical)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	if len(rows) == 0 {
		return nil
	}
	out := map[uint64]struct{}{}
	for _, root := range roots {
		// The mount the entry is on: the one statx names, else the nearest mount point above it.
		own := -1
		if _, mnt, ok := statEntry(root); ok && mnt != 0 {
			for i, m := range rows {
				if m.id == mnt {
					own = i
				}
			}
		}
		if own < 0 {
			for i, m := range rows {
				if agent.Covers(m.point, root) && (own < 0 || len(m.point) >= len(rows[own].point)) {
					own = i
				}
			}
		}
		if own >= 0 {
			out[rows[own].dev] = struct{}{}
		}
		for _, m := range rows {
			if m.point != root && agent.Covers(root, m.point) {
				out[m.dev] = struct{}{}
			}
		}
	}
	return out
}

// unmarkedRead reports whether an open on device dev is on no mount the fanotify listener marked for an
// unenforced deny_read entry, so that nothing refused it: a mount the host made beneath the entry after
// Prepare (an automount) carries a device the listener never marked. A device of 0, or no set to compare with,
// is not known to be unmarked.
func (ri *ruleIndex) unmarkedRead(dev uint64) bool {
	if ri == nil || ri.marked == nil || dev == 0 {
		return false
	}
	_, ok := ri.marked[dev]
	return !ok
}

// fsMatch is what the index knows about one filesystem action: the decision core's FSMatch, which says which
// entry names the action and which decide it.
type fsMatch = decide.FSMatch

// newFSMatch is the match of path whose nearest entry is e, with the entries that decide it (decide.FSIndex.NewFSMatch).
func (ri *ruleIndex) newFSMatch(path string, e *fsEntry) fsMatch {
	return ri.fx.NewFSMatch(path, e.name, &e.rule)
}

// listenerOpenRefused reports whether tier 2's fanotify listener refuses an open of path by its own rule
// (decide.ListenerOpenRefused) or by a name entry (decide.ListenerOpenName, ADR 0043 D7), asked of the index: the
// recorder asks it for every open it drains.
func (ri *ruleIndex) listenerOpenRefused(path string) bool {
	if ri == nil {
		return false
	}
	if _, ok := ri.fx.ListenerOpenRefused(path); ok {
		return true
	}
	_, _, named := ri.fx.ListenerOpenName(path)
	return named
}

// denyReadAt is the deny_read entry at the canonical path, asked of the index (decide.FSIndex.DenyReadAt).
func (ri *ruleIndex) denyReadAt(path string) (agent.FSRule, bool) {
	if ri == nil {
		return agent.FSRule{}, false
	}
	return ri.fx.DenyReadAt(path)
}

// grantName is the entry whose grant an allowed modification of path is named by (decide.GrantName), asked of
// the index.
func (ri *ruleIndex) grantName(op, path string) (string, bool) {
	if ri == nil {
		return "", false
	}
	return ri.fx.GrantName(op, path)
}

// matchFS finds the nearest declared entry covering path: the entry itself, or the longest declared
// ancestor directory. Matching is on whole path components, so /work-secret is never covered by a
// rule on /work.
func (ri *ruleIndex) matchFS(path string) fsMatch {
	if path == "" || ri == nil {
		return fsMatch{Rule: RuleUnmatched}
	}
	if i, ok := ri.fx.Nearest(path); ok && ri.ofRule[i] >= 0 {
		return ri.newFSMatch(path, &ri.fs[ri.ofRule[i]])
	}
	return fsMatch{Rule: RuleUnmatched}
}

// matchDir resolves an fs sample that carries no path string — the unlink/rename/mkdir hooks, which
// may never call bpf_d_path (§5 R9/R10) — from the parent directory's (dev, ino) plus the final
// component. A hit yields the declared entry and <canonical rule path>/<name>, spelled as bpf_d_path
// spells an open's path (§2.4); a miss yields the raw
// dev:ino/name identifier the kernel gave us and no rule, which the caller records as
// unattributed rather than guessing a verdict.
func (ri *ruleIndex) matchDir(dev uint64, ino uint64, name string) (path string, m fsMatch, ok bool) {
	if ri == nil {
		return "", fsMatch{Rule: RuleUnmatched}, false
	}
	i, hit := ri.dirs[dirKey(dev, ino)]
	if !hit {
		return fmt.Sprintf("%d:%d/%s", dev, ino, name), fsMatch{Rule: RuleUnmatched}, false
	}
	e := &ri.fs[i]
	path = filepath.Join(e.path, name)
	// The nearest entry of the full path names the event (§5 R9): a watch or deny_read child of the
	// indexed directory outranks the directory's own entry.
	if m := ri.matchFS(path); m.Rule != RuleUnmatched {
		return path, m, true
	}
	return path, ri.newFSMatch(path, e), true
}

// inferFS is R9's userspace inference (decide.InferFS): the verdict an fs action implies given the entries
// that decide it (fsMatch.Read, fsMatch.Write). It runs only for record-only samples (the kernel's own verdict
// wins whenever the producing program was an enforcing one). op is the record.FS* constant of the action.
func (ri *ruleIndex) inferFS(op string, write bool, m fsMatch) (record.Verdict, record.Reason) {
	if ri == nil {
		return decide.InferFS(nil, op, write, m)
	}
	return ri.fx.InferFS(op, write, m) // nil-safe: a nil table has no index, and InferFS(nil) answers
}

// absentRead is m for a read of path, or, where no deny_read decides that read and path is at or beneath the name
// the inherited Landlock ruleset leaves ungranted for an absent built-in row (decide.AbsentRead, ADR 0067 D3), the
// match that row's deny decides: the ruleset refused the read, so the chain's -EACCES is Tego's own, read_denied and
// named by the row, never another LSM's, and a sample without a chain return is inferred refused, not aggregated as
// an allowed read.
func (ri *ruleIndex) absentRead(path string, m fsMatch) fsMatch {
	if ri == nil || ri.rt == nil || m.DenyRead {
		return m
	}
	name, ok := decide.AbsentRead(ri.rt, ri.rt.Tier, path)
	if !ok {
		return m
	}
	a, _ := ri.rt.AbsentRowOf(path)
	rule := &agent.FSRule{Path: a.Path, Resolved: a.Resolved, Kind: agent.FSDenyRead, BuiltIn: true}
	m.Rule, m.Read, m.DenyRead = name, rule, true
	if m.Entry == nil {
		m.Entry, m.Path = rule, path
	}
	return m
}

// landlockLinkRefusal is decide.LandlockLinkRefusal on the index: how the Landlock ruleset every enforcing tier keeps
// answers a hard link of src to the new name dst (hook_path_link), and the entry its refusal is recorded under. An
// observe run installs no ruleset and refuses nothing.
func (ri *ruleIndex) landlockLinkRefusal(src, dst string) (string, bool) {
	if ri == nil || ri.rt == nil || ri.fx == nil || ri.rt.Tier == backend.TierObserve {
		return RuleUnmatched, false
	}
	return ri.fx.LandlockLinkRefusalBy(src, dst, ri.execGrants())
}

// landlockRenameRefusal is decide.LandlockRenameRefusal on the index: how the Landlock ruleset every enforcing tier
// keeps answers a rename of src to the name dst (hook_path_rename: REFER on both directories, then the no-gain rule),
// and the entry its refusal is recorded under. A rename sample does not say whether it moved a directory, so the
// object is compared as one, every right counting: the model explains a refusal the chain returned, or decides a
// sample with no return, and no compiled table differs between the two readings, since every write entry carries the
// whole write set (agent.AccessWriteSet). An observe run installs no ruleset and refuses nothing.
func (ri *ruleIndex) landlockRenameRefusal(src, dst string) (string, bool) {
	if ri == nil || ri.rt == nil || ri.fx == nil || ri.rt.Tier == backend.TierObserve {
		return RuleUnmatched, false
	}
	return ri.fx.LandlockRenameRefusalBy(src, dst, true, ri.execGrants())
}

// landlockDeleteRefusal is decide.LandlockDeleteRefusal on the index: the ruleset's REMOVE_* on an unlinked name's
// directory. An observe run installs no ruleset.
func (ri *ruleIndex) landlockDeleteRefusal(p string) (string, bool) {
	if ri == nil || ri.rt == nil || ri.fx == nil || ri.rt.Tier == backend.TierObserve {
		return RuleUnmatched, false
	}
	return ri.fx.LandlockDeleteRefusal(p)
}

// matchNet finds the declared net entry covering an address and port by the decision core's exact-before-LPM
// matcher (decide.MatchNetLPM), which mirrors the kernel's precedence, and names it.
func (ri *ruleIndex) matchNet(addr netip.Addr, port uint16, proto string) (string, *agent.NetRule) {
	if ri == nil {
		return RuleUnmatched, nil
	}
	i, ok := decide.MatchNetLPM(ri.net, addr, port, proto)
	if !ok {
		return RuleUnmatched, nil
	}
	return ri.net[i].RuleName(), &ri.net[i]
}

// unmapped is an address as every matcher compares it (decide.Unmapped).
func unmapped(a netip.Addr) netip.Addr { return decide.Unmapped(a) }

// protoRaw is what protoName calls a socket that is neither TCP nor UDP.
const protoRaw = decide.ProtoRaw

// execMatch is what the contract says about one exec: the entry that names it and the verdict it implies.
type execMatch struct {
	Rule    string
	Verdict record.Verdict
	Reason  record.Reason
}

// matchExec asks the decision core, through decide.Evaluate in the run's own tier (on the fs index, as matchFS
// asks: FSIndex.EvaluateExec), which entry an exec of path belongs to and what it implies. The recorder used to keep its own matcher, and it had drifted
// from Evaluate's: its basename arm matched any entry by final component, so with an entry declared by path
// a same-named binary elsewhere was stamped with that entry and allow, and drift never saw the undeclared
// exec. Evaluate matches by name only an entry the author wrote as a name, and only in the root tiers
// (SEMANTICS §4).
//
// An exec no entry names is observed: the exec happened — the record comes from sched_process_exec — and
// the contract has no entry to attribute it to.
//
// path is absolute. A relative one is the name a process passed to execve, which names a file under its working
// directory, and Evaluate reads "./git" as the bare name git, which an entry declared as /usr/bin/git answers:
// the exec of a ./git beside the agent was recorded exec[/usr/bin/git] allow (§2.4). The recorder
// resolves such a name before it asks (Recorder.resolveExec), and one it could not resolve names nothing here.
func (ri *ruleIndex) matchExec(path string) execMatch {
	if ri == nil || ri.rt == nil || !filepath.IsAbs(path) {
		return execMatch{Rule: RuleUnmatched, Verdict: record.VerdictObserved}
	}
	res := ri.fx.EvaluateExec(agent.Action{Kind: agent.ActionExec, Path: path}, ri.rt.Tier)
	switch {
	case res.Rule == agent.UnmatchedRule || res.Rule == agent.InvalidActionRule || res.Rule == "":
		return execMatch{Rule: RuleUnmatched, Verdict: record.VerdictObserved}
	case res.Verdict == agent.VerdictAllow:
		return execMatch{Rule: res.Rule, Verdict: record.VerdictAllow}
	default:
		reason := res.Reason
		if reason == "" {
			reason = record.ReasonExecNotAllowed
		}
		return execMatch{Rule: res.Rule, Verdict: record.VerdictRefused, Reason: reason}
	}
}

// selfMountinfo is this process's mount table.
const selfMountinfo = "/proc/self/mountinfo"

// rowsFrom translates the immutable prepared mount facts without reading procfs.
func rowsFrom(mt *agent.MountTable) []mountRow {
	if mt == nil {
		return nil
	}
	var rows []mountRow
	for _, m := range mt.Records() {
		rows = append(rows, mountRow{id: uint64(m.ID), point: m.Point, dev: unix.Mkdev(m.Major, m.Minor)})
	}
	return rows
}

// applyMounts enriches the index's launch-pinned identities with prepared mount facts.
// It does not restat paths or replace the exec grants captured at construction.
func (ri *ruleIndex) applyMounts(rows []mountRow) {
	if ri.rt == nil {
		return
	}
	devices := mountDevsFrom(rows)
	for key, i := range ri.dirs {
		if sb, ok := devices[ri.mounts[key]]; ok && sb != key.Dev {
			ri.unindexed = append(ri.unindexed, ri.fs[i].rule.Path)
			delete(ri.dirs, key)
		}
	}
	ri.marked = markedDevicesFrom(ri.rt, rows)
}
