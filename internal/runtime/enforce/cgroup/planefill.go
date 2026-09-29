// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
)

// The plane's fill (docs/p0/enforce-plane.md R16; ADR 0025 (2); TIER3-PLAN T4). A slot's rows are keyed by the
// inode pointer of each keyed path, which userspace never sees: Prepare holds one O_PATH descriptor per keyed path,
// hands bpf/decide_fill.bpf.c the descriptor numbers with their row templates, and an iter/task_file pass over this
// process's own descriptor table writes each row in the kernel with the run's gen. The fill reports the (mnt_id,
// ino) it saw at each descriptor; Prepare compares that with the identity it recorded when it made the plan (one
// statx of the descriptor), and fails on any difference, so a descriptor number that another open took in between
// fails Prepare instead of keying a row at the wrong inode. A number reused after the pass keys nothing: the row was
// written at the inode the kernel reported, the one planned. The config and the templates are keyed by the
// launcher's tgid, so launchers of one build fill at once.
//
// A slot keeps its row maps across runs (ADR 0025 (1) as T0 amended it, ADR 0026 (6)): the previous run's rows stay
// in the map with their own gen, and the walk counts them absent. The fill replaces them where a key repeats and
// deletes nothing on the run's path; only when a map is too full of them to take this run's rows does it clear the
// stale ones (tego_plane_clear, in the kernel, keeping this gen) and fill once more.

// planeFillEntry is one row the fill writes: the held descriptor, the row's template, and the identity the
// descriptor had when the plan was made.
type planeFillEntry struct {
	// FD is the held O_PATH descriptor, borrowed from its owner for the fill.
	FD int
	// Path is the canonical path the row is for, for errors.
	Path string
	What ebpfbindings.PlaneFillWhat
	// Kind is an fs row's decide.PlaneKind; RuleIdx the row's rule_idx (an fs row's position in PlaneRows.FS, an
	// exec row's entry in RuleTable.Exec).
	Kind     uint8
	RuleIdx  uint16
	ExecRule uint16
	// Scope is an fs row's scope bit (ADR 0043 D4, decide.PlaneRow.Scopes), which the fill copies into the row.
	Scope uint8
	// Name is an exec row's final component, Parent its directory.
	Name, Parent string
	// MntID and Ino are statx's mnt_id and ino for FD when the plan was made (fdinfo's, where statx has no mount
	// id); ParentIno an exec row's directory's inode number then. Dev is the descriptor's st_dev then (a btrfs
	// subvolume's own), which with Ino names the keyed file as a stat of it does (Handle.PlaneKeyed).
	MntID, Ino, ParentIno, Dev uint64
}

// planeFillPlan is one run's fill: the slot, the run's gen and every row, ordered by (What, FD).
type planeFillPlan struct {
	RunIdx, Gen uint32
	Entries     []planeFillEntry
	// Absent are the keyed paths that did not exist when the plan was made: no row keys them.
	Absent []string
}

// fdIdentity is what the plan asks the host. The real one is statx and lstat; unit tests stand in their own.
type fdIdentity interface {
	// fd returns a descriptor's (st_dev, ino, mnt_id): one statx(AT_EMPTY_PATH, STATX_INO|STATX_MNT_ID), st_dev as
	// fstat gives it (a btrfs subvolume's own), mnt_id real_mount(f_path.mnt)->mnt_id, the one the fill reads.
	fd(fd int) (dev, ino, mntID uint64, err error)
	// path returns lstat(path)'s (st_dev, ino).
	path(path string) (dev, ino uint64, err error)
}

// hostIdentity is fdIdentity on this process.
type hostIdentity struct{}

func (hostIdentity) fd(fd int) (uint64, uint64, uint64, error) {
	var sx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_INO|unix.STATX_MNT_ID, &sx); err != nil {
		return 0, 0, 0, err
	}
	dev := unix.Mkdev(sx.Dev_major, sx.Dev_minor)
	if sx.Mask&unix.STATX_MNT_ID != 0 {
		return dev, sx.Ino, sx.Mnt_id, nil
	}
	// A kernel before 5.8 reports no mount id through statx: fdinfo prints the same one.
	b, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return 0, 0, 0, err
	}
	mnt, ino, err := parseFDInfo(b)
	if err != nil {
		return 0, 0, 0, err
	}
	if ino != sx.Ino {
		return 0, 0, 0, fmt.Errorf("fdinfo says ino %d, statx %d", ino, sx.Ino)
	}
	return dev, sx.Ino, mnt, nil
}

func (hostIdentity) path(path string) (uint64, uint64, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, 0, err
	}
	return st.Dev, st.Ino, nil
}

// parseFDInfo reads the mnt_id and ino lines of an fdinfo file (fs/proc/fd.c: both printed since 5.8 and 3.15,
// from real_mount(f_path.mnt)->mnt_id and file_inode(file)->i_ino, the fields the fill reads).
func parseFDInfo(b []byte) (mntID, ino uint64, err error) {
	var haveMnt, haveIno bool
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		k, v, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			continue
		}
		switch string(k) {
		case "mnt_id":
			mntID, err = strconv.ParseUint(string(bytes.TrimSpace(v)), 10, 64)
			haveMnt = err == nil
		case "ino":
			ino, err = strconv.ParseUint(string(bytes.TrimSpace(v)), 10, 64)
			haveIno = err == nil
		}
		if err != nil {
			return 0, 0, fmt.Errorf("fdinfo %s: %w", k, err)
		}
	}
	if !haveMnt || !haveIno {
		return 0, 0, errors.New("fdinfo has no mnt_id or no ino line")
	}
	return mntID, ino, nil
}

// heldFD returns the held O_PATH descriptor of a canonical path.
type heldFD func(path string) (fd int, ok bool)

// planPlaneFill turns a compiled table's rows into the fill's plan: one entry per fs row and per exec row, each at
// the descriptor held for its path. It refuses a table over the slot's maps (decide.ErrPlaneCap), a path nothing
// holds, one descriptor for two rows of one kind (two fs entries on one inode, which the Landlock set's E7 dedupe
// folds into one number, where one row would lose; two exec entries on one link, which the set holds at one
// descriptor: hard links of one inode each have their own, enforce-landlock's plane link descriptors, enforce-plane §6 E15), a name
// longer than a row holds, and a descriptor that does not name its path now.
func planPlaneFill(rows *decide.PlaneRows, runIdx, gen uint32, held heldFD, id fdIdentity) (*planeFillPlan, error) {
	if rows.FSMapEntries() > decide.PlaneRowsMax || rows.ExecMapEntries() > decide.PlaneExecRowsMax {
		return nil, &decide.ErrPlaneCap{FSRows: rows.FSMapEntries(), ExecRows: rows.ExecMapEntries()}
	}
	if gen == 0 {
		return nil, errors.New("plane fill: gen 0 is no run's")
	}
	plan := &planeFillPlan{RunIdx: runIdx, Gen: gen, Entries: make([]planeFillEntry, 0, len(rows.FS)+len(rows.Exec))}
	type key struct {
		what ebpfbindings.PlaneFillWhat
		fd   int
	}
	seen := make(map[key]string, cap(plan.Entries))
	add := func(e planeFillEntry) error {
		fd, ok := held(e.Path)
		if !ok {
			if _, _, err := id.path(e.Path); errors.Is(err, os.ErrNotExist) {
				// A keyed path that does not exist (an implicit entry not made yet, a deny target gone since compile)
				// has no inode to key, and keys no row, as the Landlock plan skips it (enforce-landlock E9).
				plan.Absent = append(plan.Absent, e.Path)
				return nil
			}
			return fmt.Errorf("plane fill: %s is keyed by the plane and no descriptor holds it", e.Path)
		}
		e.FD = fd
		k := key{e.What, fd}
		if other, dup := seen[k]; dup {
			if e.What == ebpfbindings.PlaneFillExec {
				return fmt.Errorf("plane fill: two exec entries, %s and %s, are held at one descriptor (%d), one link; the plane keys one exec row per link", other, e.Path, fd)
			}
			return fmt.Errorf("plane fill: two fs rows, %s and %s, name one inode (descriptor %d); the plane keys one row per inode", other, e.Path, fd)
		}
		seen[k] = e.Path
		if err := identify(&e, id); err != nil {
			return err
		}
		plan.Entries = append(plan.Entries, e)
		return nil
	}
	for i, r := range rows.FS {
		execRule := ebpfbindings.PlaneRuleNone
		if r.Exec >= 0 {
			execRule = uint16(r.Exec)
		}
		if err := add(planeFillEntry{Path: r.Path, What: ebpfbindings.PlaneFillFS, Kind: uint8(r.Kind), RuleIdx: uint16(i), ExecRule: execRule, Scope: r.Scopes}); err != nil {
			return nil, err
		}
	}
	// A mounted root below a deny_write target (enforce-plane R12): the nearest row's answer, for the attribute hooks'
	// walk inside the superblock only. A mounted root that is an fs row's inode already (a bind mount of a keyed
	// directory, which the Landlock set's E7 dedupe holds under one descriptor) keeps that row, which decides the
	// same there.
	for _, m := range rows.Mounts {
		if m.Row < 0 || m.Row >= len(rows.FS) {
			return nil, fmt.Errorf("plane fill: mount row %s names no fs row (%d)", m.Path, m.Row)
		}
		if fd, ok := held(m.Path); ok {
			if _, dup := seen[key{ebpfbindings.PlaneFillFS, fd}]; dup {
				continue
			}
		}
		kind := rows.FS[m.Row].Kind | decide.PlaneMountOnly
		execRule := ebpfbindings.PlaneRuleNone
		if rows.FS[m.Row].Exec >= 0 {
			execRule = uint16(rows.FS[m.Row].Exec)
		}
		if err := add(planeFillEntry{Path: m.Path, What: ebpfbindings.PlaneFillFS, Kind: uint8(kind), RuleIdx: uint16(m.Row), ExecRule: execRule}); err != nil {
			return nil, err
		}
	}
	for _, r := range rows.Exec {
		if r.Rule < 0 || r.Rule > int(ebpfbindings.PlaneRuleMax) {
			return nil, fmt.Errorf("plane fill: exec entry %d of %s is past a row's rule_idx (%d is TEGO_PLANE_RULE_NONE)", r.Rule, r.Path, ebpfbindings.PlaneRuleNone)
		}
		if len(r.Name) == 0 || len(r.Name) >= ebpfbindings.NameMax {
			return nil, fmt.Errorf("plane fill: exec entry %s has a final name of %d bytes; a row holds 1 to %d", r.Path, len(r.Name), ebpfbindings.NameMax-1)
		}
		if err := add(planeFillEntry{Path: r.Path, What: ebpfbindings.PlaneFillExec, RuleIdx: uint16(r.Rule), Name: r.Name, Parent: r.Parent}); err != nil {
			return nil, err
		}
	}
	sort.Slice(plan.Entries, func(i, j int) bool {
		a, b := plan.Entries[i], plan.Entries[j]
		if a.What != b.What {
			return a.What < b.What
		}
		return a.FD < b.FD
	})
	return plan, nil
}

// identify records the identity e's descriptor has now, after checking that it names e's path: statx of the
// descriptor and lstat of the path are one (st_dev, ino). An exec row also records its directory's inode number.
func identify(e *planeFillEntry, id fdIdentity) error {
	fdDev, fdIno, mnt, err := id.fd(e.FD)
	if err != nil {
		return fmt.Errorf("plane fill: descriptor %d held for %s: %w", e.FD, e.Path, err)
	}
	pDev, pIno, err := id.path(e.Path)
	if err != nil {
		return fmt.Errorf("plane fill: %s: %w", e.Path, err)
	}
	if fdDev != pDev || fdIno != pIno {
		return fmt.Errorf("plane fill: descriptor %d held for %s names another file (%d:%d, the path is %d:%d): the number was reused or the path replaced", e.FD, e.Path, fdDev, fdIno, pDev, pIno)
	}
	e.MntID, e.Ino, e.Dev = mnt, fdIno, fdDev
	if e.What == ebpfbindings.PlaneFillExec {
		if _, e.ParentIno, err = id.path(e.Parent); err != nil {
			return fmt.Errorf("plane fill: %s's directory %s: %w", e.Path, e.Parent, err)
		}
	}
	if e.What == ebpfbindings.PlaneFillListen {
		e.ParentIno = fdIno
	}
	return nil
}

// wants is the plan as the fill map's keys and templates, for the launcher tgid: each template carries the plan's
// gen, which the program requires of it.
func (p *planeFillPlan) wants(tgid uint32) ([]uint64, []ebpfbindings.PlaneFillRow) {
	keys := make([]uint64, len(p.Entries))
	vals := make([]ebpfbindings.PlaneFillRow, len(p.Entries))
	for i, e := range p.Entries {
		keys[i] = ebpfbindings.PlaneFillKey(tgid, e.What, uint32(e.FD))
		v := &vals[i]
		v.What, v.Kind, v.RuleIdx, v.Gen = e.What, e.Kind, e.RuleIdx, p.Gen
		v.ExecRule, v.Scope = e.ExecRule, e.Scope
		v.NameLen = uint8(len(e.Name))
		copy(v.Name[:], e.Name)
	}
	return keys, vals
}

// ErrPlaneFill is a fill Prepare must fail on: one entry per row that did not come out as planned.
type ErrPlaneFill struct {
	Problems []string
}

func (e *ErrPlaneFill) Error() string {
	const show = 5
	msg := fmt.Sprintf("plane fill: %d row(s) not written as planned: ", len(e.Problems))
	for i, p := range e.Problems {
		if i == show {
			msg += fmt.Sprintf("; and %d more", len(e.Problems)-show)
			break
		}
		if i > 0 {
			msg += "; "
		}
		msg += p
	}
	return msg
}

// checkPlaneFill is the check the fill must pass: every row written (status OK), at the identity the plan
// recorded, as the kernel reported it at the pass; an exec row's directory is the planned one. got is the fill map's
// value for each plan entry, in plan order. rows names the other entry of a duplicate. A number reused after the
// pass is not asked about: the row was written at the inode the kernel reported, the planned one, and the Landlock
// set's own identity check (owns) holds the descriptor from then on.
func checkPlaneFill(p *planeFillPlan, got []ebpfbindings.PlaneFillRow, rows *decide.PlaneRows) error {
	if len(got) != len(p.Entries) {
		return fmt.Errorf("plane fill: %d results for %d rows", len(got), len(p.Entries))
	}
	var probs []string
	for i, e := range p.Entries {
		g := got[i]
		switch {
		case g.Status == ebpfbindings.PlaneFillDup:
			probs = append(probs, fmt.Sprintf("%s: %s (%s)", e.Path, g.Status, otherRow(rows, e.What, g.OtherRule)))
			continue
		case g.Status == ebpfbindings.PlaneFillUpdate:
			probs = append(probs, fmt.Sprintf("%s: %s (%s)", e.Path, g.Status, unix.Errno(-g.Err)))
			continue
		case g.Status != ebpfbindings.PlaneFillOK:
			probs = append(probs, fmt.Sprintf("%s (descriptor %d): %s", e.Path, e.FD, g.Status))
			continue
		}
		if g.MntID != e.MntID || g.Ino != e.Ino {
			probs = append(probs, fmt.Sprintf("%s: descriptor %d named mount %d inode %d at the fill, %d/%d when planned: the number was reused", e.Path, e.FD, g.MntID, g.Ino, e.MntID, e.Ino))
			continue
		}
		if (e.What == ebpfbindings.PlaneFillExec || e.What == ebpfbindings.PlaneFillListen) && g.ParentIno != e.ParentIno {
			probs = append(probs, fmt.Sprintf("%s: its directory at the fill is inode %d, not %s (%d): it moved", e.Path, g.ParentIno, e.Parent, e.ParentIno))
		}
	}
	if len(probs) > 0 {
		return &ErrPlaneFill{Problems: probs}
	}
	return nil
}

// otherRow names the row a duplicate collided with.
func otherRow(rows *decide.PlaneRows, what ebpfbindings.PlaneFillWhat, idx uint16) string {
	if rows != nil {
		if what == ebpfbindings.PlaneFillFS && int(idx) < len(rows.FS) {
			return "the same inode as " + rows.FS[idx].Path
		}
		if what == ebpfbindings.PlaneFillExec {
			for _, r := range rows.Exec {
				if r.Rule == int(idx) {
					return "the same link as " + r.Path
				}
			}
		}
	}
	return fmt.Sprintf("the same inode as rule_idx %d", idx)
}

// planeFillReport is what one fill did, for the timing record.
type planeFillReport struct {
	Rows, ExecRows, ListenRows int
	// Keyed are the files the fs rows were written at (mount-only rows left out), each row's path with the device and
	// inode its descriptor had when the plan was made, which the check found the row written at.
	Keyed []PlaneKeyed
	// Visited is the descriptors the iterator showed the program over every pass; Matched the launcher's.
	Visited, Matched uint64
	// Scoped says the task-scoped link was accepted; on a kernel before 6.1 it is accepted and ignored, which
	// Visited > Matched shows.
	Scoped bool
	// Cleared is the stale rows a full map made the fill delete, fs and exec; zero when it deleted none.
	Cleared int
	// Wants, Fill and Check split the time: writing the templates, the iterator passes with the read-back, and
	// the check. The programs' load is the filler's (planeFiller.Load), paid once per filler.
	Wants, Fill, Check time.Duration
}

// planeFillOptions are the fill's knobs; the zero value is Prepare's.
type planeFillOptions struct {
	// Unscoped iterates every task's descriptors even where the kernel can scope the iteration, to measure what a
	// kernel before 6.1 pays.
	Unscoped bool
}

// planeFiller is a fill build loaded over one plane's row maps: the fill and clear programs and the fill's two
// maps, which newPlaneFiller creates for this process and the plane pins per build and mode (pinPlaneFiller), so
// every launcher of the build adopts them (adoptPlaneFiller). Loading it costs 60-220 ms in the guests, most of a
// fill's time (enforce-plane §2.6), so a process loads it once and fills every run's slot through it. The config and
// the templates are keyed by the launcher's tgid, so launchers fill at once, with no lock between them; one process's
// fills are serialized (mu), since they share its tgid.
type planeFiller struct {
	obj            ebpfbindings.Object
	prog, clear    *ebpf.Program
	config, wants  *ebpf.Map
	rows, execRows *ebpf.Map
	// Load is what loading took.
	Load time.Duration
	mu   sync.Mutex
	// runClear replaces running the clear program (unit tests).
	runClear func(in ebpfbindings.PlaneClearCtx) (ebpfbindings.PlaneClearCtx, error)
}

// errPlaneNoRows is a clear of a slot that has no rows map in this plane mode: one no run of the mode has prepared
// (a tier-2 or fanotify run's slot, the other mode's, a run that died before prepareSlot). It has no rows to clear.
var errPlaneNoRows = errors.New("plane clear: the slot has no rows map")

// newPlaneFiller loads fill (a fill build, bpf.PlaneFillFor the plane build loaded) over rows and execRows, the
// plane's tego_plane_rows and tego_plane_exec_rows, which it writes and never owns.
func newPlaneFiller(fill ebpfbindings.Object, rows, execRows *ebpf.Map, listeners ...*ebpf.Map) (*planeFiller, error) {
	if len(listeners) != 1 || listeners[0] == nil {
		return nil, fmt.Errorf("plane fill: %s requires an owned %s replacement", fill, ebpfbindings.MapPlaneListenRows)
	}
	start := time.Now()
	spec, err := ebpfbindings.Load(fill)
	if err != nil {
		return nil, err
	}
	var objs struct {
		Fill   *ebpf.Program `ebpf:"tego_plane_fill"`
		Clear  *ebpf.Program `ebpf:"tego_plane_clear"`
		Config *ebpf.Map     `ebpf:"tego_plane_fill_config"`
		Wants  *ebpf.Map     `ebpf:"tego_plane_fill_wants"`
	}
	replacements := map[string]*ebpf.Map{
		ebpfbindings.MapPlaneRows:     rows,
		ebpfbindings.MapPlaneExecRows: execRows,
	}
	replacements[ebpfbindings.MapPlaneListenRows] = listeners[0]
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{MapReplacements: replacements}); err != nil {
		return nil, fmt.Errorf("plane fill: load %s: %w", fill, err)
	}
	return &planeFiller{obj: fill, prog: objs.Fill, clear: objs.Clear, config: objs.Config, wants: objs.Wants,
		rows: rows, execRows: execRows, Load: time.Since(start)}, nil
}

// Close releases the programs and the fill's own maps; the plane's row maps and their rows stay.
func (f *planeFiller) Close() error {
	return errors.Join(f.prog.Close(), f.clear.Close(), f.config.Close(), f.wants.Close())
}

// fill writes plan's rows into the slot's inner maps, which must exist, and fails, and Prepare with it, unless
// every row is written as checkPlaneFill requires. table names the other entry of a duplicate.
//
// The config and the templates are this launcher's, keyed by its tgid, and the templates carry the plan's gen: a
// launcher killed between its templates and the end of its pass (SIGKILL, an OOM kill) left them in the pinned map,
// and a later launcher given its tgid applies none of them, since their gen is not its fill's. They are removed when
// the map has no room (purgeStaleWants).
func (f *planeFiller) fill(plan *planeFillPlan, table *decide.PlaneRows, opts planeFillOptions) (rep planeFillReport, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	start := time.Now()
	tgid := uint32(os.Getpid())
	cfg := ebpfbindings.PlaneFillCfg{Tgid: tgid, RunIdx: plan.RunIdx, Gen: plan.Gen}
	if err := putRoom(func() error { return f.config.Put(tgid, &cfg) }, f.purgeStale); err != nil {
		return rep, fmt.Errorf("plane fill: config: %w", err)
	}
	defer func() {
		if derr := f.config.Delete(tgid); derr != nil && !errors.Is(derr, ebpf.ErrKeyNotExist) && err == nil {
			err = fmt.Errorf("plane fill: remove the config: %w", derr)
		}
	}()
	keys, vals := plan.wants(tgid)
	// The templates are this fill's: none may outlive it. Registered before the write, which can leave some of them
	// in the map when it fails part way.
	defer func() {
		if derr := deleteWants(f.wants, keys); derr != nil && err == nil {
			err = derr
		}
	}()
	if err := putRoom(func() error { return putWants(f.wants, keys, vals) }, f.purgeStale); err != nil {
		return rep, err
	}
	rep.Wants = time.Since(start)

	start = time.Now()
	if rep.Scoped, err = runFillPass(f.prog, opts.Unscoped); err != nil {
		return rep, err
	}
	got, err := readWants(f.wants, keys)
	if err != nil {
		return rep, err
	}
	if full := fullRows(got); len(full) > 0 {
		// The slot's maps are full of a previous run's rows: clear them in the kernel, keeping this gen's, and
		// fill what did not fit once more.
		fsDel, execDel, err := f.clearLocked(plan.RunIdx, plan.Gen)
		if err != nil {
			return rep, err
		}
		rep.Cleared = fsDel + execDel
		for _, i := range full {
			v := vals[i] // the template, status unseen again
			if err := f.wants.Put(keys[i], &v); err != nil {
				return rep, fmt.Errorf("plane fill: reset a row for the second pass: %w", err)
			}
		}
		if _, err = runFillPass(f.prog, opts.Unscoped); err != nil {
			return rep, err
		}
		if got, err = readWants(f.wants, keys); err != nil {
			return rep, err
		}
	}
	if err := f.config.Lookup(tgid, &cfg); err != nil {
		return rep, fmt.Errorf("plane fill: read the counts: %w", err)
	}
	rep.Visited, rep.Matched = cfg.Visited, cfg.Matched
	rep.Fill = time.Since(start)

	start = time.Now()
	err = checkPlaneFill(plan, got, table)
	rep.Check = time.Since(start)
	if err != nil {
		return rep, err
	}
	for _, e := range plan.Entries {
		switch e.What {
		case ebpfbindings.PlaneFillExec:
			rep.ExecRows++
		case ebpfbindings.PlaneFillListen:
			rep.ListenRows++
		case ebpfbindings.PlaneFillFS:
			rep.Rows++
		default:
			// Preserve the report's fallback for an unexpected entry kind;
			// fill status and identity have already passed checkPlaneFill.
			rep.Rows++
		}
	}
	rep.Keyed = plan.keyed()
	return rep, nil
}

// PlaneKeyed is one file a run's fs row is written at: the row's canonical path and the device and inode of the
// descriptor the fill keyed it by.
type PlaneKeyed struct {
	Path     string
	Dev, Ino uint64
}

// keyed is the plan's fs rows as the files they key, in plan order; a mount-only row (a mounted root below a
// deny_write target, PlaneRows.Mounts) is left out, as it decides only the attribute hooks' walk inside its superblock.
func (p *planeFillPlan) keyed() []PlaneKeyed {
	var out []PlaneKeyed
	for _, e := range p.Entries {
		if e.What != ebpfbindings.PlaneFillFS || e.Kind&uint8(decide.PlaneMountOnly) != 0 {
			continue
		}
		out = append(out, PlaneKeyed{Path: e.Path, Dev: e.Dev, Ino: e.Ino})
	}
	return out
}

// fillRoomWait is how long a fill waits for room in the build's fill maps, which hold PlaneFillLaunchers whole fills
// at once: the other fills take milliseconds (enforce-plane §2.6), so running out of it means the maps are held by
// something else, and the fill fails (Prepare with it) rather than wait on.
var fillRoomWait = 10 * time.Second

// putRoom runs put, and when a map has no room for it (E2BIG, ENOSPC, ENOMEM) removes the stale entries dead
// launchers left (purge) and tries again, waiting for the other fills to finish, up to fillRoomWait.
func putRoom(put func() error, purge func() error) error {
	deadline := time.Now().Add(fillRoomWait)
	purged := false
	for {
		err := put()
		if err == nil || !(errors.Is(err, unix.E2BIG) || errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.ENOMEM)) {
			return err
		}
		if !purged {
			if perr := purge(); perr != nil {
				return errors.Join(err, perr)
			}
			purged = true
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the build's fill maps stayed full for %s: %w", fillRoomWait, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// purgeStale removes the templates and configs of launchers that are gone (purgeStaleWants).
func (f *planeFiller) purgeStale() error {
	return errors.Join(purgeStaleWants(f.wants, uint32(os.Getpid()), launcherGone),
		purgeStaleConfigs(f.config, uint32(os.Getpid()), launcherGone))
}

// launcherGone reports whether no process has the tgid (kill(tgid, 0) answers ESRCH).
func launcherGone(tgid uint32) bool {
	return tgid == 0 || errors.Is(unix.Kill(int(tgid), 0), unix.ESRCH)
}

// clearSlot deletes the slot's rows of every gen but keepGen (0 keeps none), fs and exec, in the kernel
// (tego_plane_clear through BPF_PROG_TEST_RUN), so no key reaches userspace. It is how a slot's stale rows leave
// the map off the run's path (Detach, purgeSlot, the reaper: T6) and how a fill makes room.
func (f *planeFiller) clearSlot(runIdx, keepGen uint32) (fsDeleted, execDeleted int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clearLocked(runIdx, keepGen)
}

func (f *planeFiller) clearLocked(runIdx, keepGen uint32) (int, int, error) {
	in := ebpfbindings.PlaneClearCtx{RunIdx: runIdx, KeepGen: keepGen}
	var out ebpfbindings.PlaneClearCtx
	var err error
	if f.runClear != nil {
		out, err = f.runClear(in)
	} else {
		_, err = f.clear.Run(&ebpf.RunOptions{Context: in, ContextOut: &out})
	}
	if err != nil {
		return 0, 0, fmt.Errorf("plane clear: run: %w", err)
	}
	if out.Status != 0 {
		return 0, 0, fmt.Errorf("%w (slot %d)", errPlaneNoRows, runIdx)
	}
	return int(out.Deleted), int(out.ExecDeleted), nil
}

// fullRows returns the positions of rows a map refused for want of room.
func fullRows(got []ebpfbindings.PlaneFillRow) []int {
	var out []int
	for i, g := range got {
		if g.Status == ebpfbindings.PlaneFillUpdate && unix.Errno(-g.Err) == unix.E2BIG {
			out = append(out, i)
		}
	}
	return out
}

// putWants writes the templates, in one batch where the kernel has map batch operations (5.6+).
func putWants(m *ebpf.Map, keys []uint64, vals []ebpfbindings.PlaneFillRow) error {
	if len(keys) == 0 {
		return nil
	}
	if _, err := m.BatchUpdate(keys, vals, nil); err == nil {
		return nil
	} else if !errors.Is(err, ebpf.ErrNotSupported) {
		return fmt.Errorf("plane fill: write the wanted rows: %w", err)
	}
	for i := range keys {
		if err := m.Put(keys[i], &vals[i]); err != nil {
			return fmt.Errorf("plane fill: write the wanted row of descriptor %d: %w", uint32(keys[i]), err)
		}
	}
	return nil
}

// deleteWants removes the templates after a fill.
func deleteWants(m *ebpf.Map, keys []uint64) error {
	if len(keys) == 0 {
		return nil
	}
	if _, err := m.BatchDelete(keys, nil); err == nil {
		return nil
	} else if !errors.Is(err, ebpf.ErrNotSupported) {
		return fmt.Errorf("plane fill: remove the wanted rows: %w", err)
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("plane fill: remove the wanted row of descriptor %d: %w", uint32(k), err)
		}
	}
	return nil
}

// wantsKeys is what the purges ask of the fill's maps (*ebpf.Map; a fake in unit tests).
type wantsKeys interface {
	NextKey(key, nextKeyOut any) error
	Delete(key any) error
}

// purgeBound bounds a purge's listing: the wants map's size.
const purgeBound = ebpfbindings.PlaneFillMax*ebpfbindings.PlaneFillLaunchers + 1

// purgeStaleWants deletes the templates of launchers that are gone, and this process's own, which no fill of it has
// running while it holds the filler's lock: a dead fill's leftovers, which take room and nothing else (the program
// applies no template of another gen). The keys are listed first and deleted after, since a hash map's listing
// restarts at a key that is gone. The map's size bounds the listing.
func purgeStaleWants(m wantsKeys, self uint32, gone func(uint32) bool) error {
	var stale []uint64
	var key, next uint64
	var prev any // nil: the first key
	for range purgeBound {
		err := m.NextKey(prev, &next)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return fmt.Errorf("plane fill: list the wanted rows: %w", err)
		}
		if t := ebpfbindings.PlaneFillKeyTgid(next); t == self || gone(t) {
			stale = append(stale, next)
		}
		key = next
		prev = key
	}
	for _, k := range stale {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("plane fill: remove a dead fill's wanted row (descriptor %d): %w", uint32(k)&(1<<30-1), err)
		}
	}
	return nil
}

// purgeStaleConfigs deletes the configs of launchers that are gone.
func purgeStaleConfigs(m wantsKeys, self uint32, gone func(uint32) bool) error {
	var stale []uint32
	var next uint32
	var prev any
	for range ebpfbindings.PlaneFillCfgs + 1 {
		err := m.NextKey(prev, &next)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return fmt.Errorf("plane fill: list the fill configs: %w", err)
		}
		if next != self && gone(next) {
			stale = append(stale, next)
		}
		k := next
		prev = k
	}
	for _, k := range stale {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("plane fill: remove a dead launcher's fill config (%d): %w", k, err)
		}
	}
	return nil
}

// readWants reads back each template's result, in plan order.
func readWants(m *ebpf.Map, keys []uint64) ([]ebpfbindings.PlaneFillRow, error) {
	out := make([]ebpfbindings.PlaneFillRow, len(keys))
	for i, k := range keys {
		if err := m.Lookup(k, &out[i]); err != nil {
			return nil, fmt.Errorf("plane fill: read the result of descriptor %d: %w", uint32(k), err)
		}
	}
	return out, nil
}

// runFillPass links the fill program to the task_file iterator and reads it to its end, which runs the program
// on each descriptor. The link is task-scoped to this process where the kernel has it (bpf_iter_link_info.task,
// 6.1+); scoped says the scoped link was accepted.
func runFillPass(prog *ebpf.Program, unscoped bool) (scoped bool, err error) {
	var it *link.Iter
	if !unscoped {
		if it, err = attachTaskIter(prog, uint32(os.Getpid())); err == nil {
			scoped = true
		}
	}
	if it == nil {
		if it, err = link.AttachIter(link.IterOptions{Program: prog}); err != nil {
			return false, fmt.Errorf("plane fill: link the iterator: %w", err)
		}
	}
	defer func() { _ = it.Close() }()
	r, err := it.Open()
	if err != nil {
		return scoped, fmt.Errorf("plane fill: open the iterator: %w", err)
	}
	defer func() { _ = r.Close() }()
	buf := make([]byte, 64)
	for {
		_, err := r.Read(buf)
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return scoped, nil
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			// bpf_seq_read gives up a read after a million objects that printed nothing; the next read goes on.
		default:
			return scoped, fmt.Errorf("plane fill: read the iterator: %w", err)
		}
	}
}

// bpfLinkCreateIter is union bpf_attr's link_create member for an iterator (include/uapi/linux/bpf.h).
type bpfLinkCreateIter struct {
	ProgFD      uint32
	TargetFD    uint32
	AttachType  uint32
	Flags       uint32
	IterInfo    uint64
	IterInfoLen uint32
	_           uint32
}

// bpfIterLinkInfoTask is union bpf_iter_link_info's task member, padded to the union's 16 bytes (6.1+).
type bpfIterLinkInfoTask struct {
	Tid, Pid, PidFD uint32
	_               uint32
}

const (
	bpfLinkCreate = 28 // BPF_LINK_CREATE
	bpfTraceIter  = 28 // BPF_TRACE_ITER
)

// attachTaskIter links prog to the task_file iterator scoped to the process pid (every thread of it; the
// iterator shows a descriptor table shared by threads once). cilium/ebpf's AttachIter passes only a map, so the
// link is made here and handed to it by descriptor.
func attachTaskIter(prog *ebpf.Program, pid uint32) (*link.Iter, error) {
	info := bpfIterLinkInfoTask{Pid: pid}
	attr := bpfLinkCreateIter{
		ProgFD:      uint32(prog.FD()),
		AttachType:  bpfTraceIter,
		IterInfo:    uint64(uintptr(unsafe.Pointer(&info))),
		IterInfoLen: uint32(unsafe.Sizeof(info)),
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, bpfLinkCreate, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&attr)
	if errno != 0 {
		return nil, fmt.Errorf("task-scoped iterator link: %w", errno)
	}
	l, err := link.NewFromFD(int(fd)) // owns fd from here, closing it on its own failure
	if err != nil {
		return nil, fmt.Errorf("task-scoped iterator link: %w", err)
	}
	it, ok := l.(*link.Iter)
	if !ok {
		_ = l.Close()
		return nil, fmt.Errorf("task-scoped iterator link: the kernel made a %T", l)
	}
	return it, nil
}
