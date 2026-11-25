// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
)

// A run's live path, read and write blocks in its kernel decision plane (ADR 0124, amendment 2026-11-21). On a run
// whose plane decides file changes in the kernel the seccomp filter no longer notifies them, so the supervisor's Set
// alone refused only what still reached it. planeBlocks puts the same entries the Set is compiled from in force in the
// plane too: it walks each block's path as the kernel's lookup does, holds an O_PATH descriptor of every object the walk
// passes, and has the plane's fill key a row at each (enforce.PlaneBlockWriter), in the kernel. It runs in the live-block
// goroutine only (liveBlocks.store and the poll's tick), so it needs no lock but against the run's teardown (close).

// blockWalkCalls and blockWalkLinks bound one walk of a block's path, as liveblock.RealPath's budget does: a governed
// agent can plant the folders and links a path runs through. A walk past either is a block the plane cannot key whole,
// which refuses its class whole (overflow).
const (
	blockWalkCalls = 512
	blockWalkLinks = 40
)

// liveRules is the run's live-block ids and their rules, which the plane's refusals carry (bpf.PlaneRuleLiveBlock) and
// the kernel recorder names them by (observe.Recorder.SetLiveBlockRule). An id is given once and kept for the run, so a
// line read after its block was removed still names it.
type liveRules struct {
	mu    sync.RWMutex
	rules map[uint16]string
}

// rule is the rule of id, false for one never given.
func (l *liveRules) rule(id uint16) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	r, ok := l.rules[id]
	return r, ok
}

func (l *liveRules) set(id uint16, rule string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rules == nil {
		l.rules = map[uint16]string{}
	}
	l.rules[id] = rule
}

// blockKey names one keyed object: an inode (dev, ino), or a name row's directory and name key.
type blockKey struct {
	name     bool
	dev, ino uint64
	nameKey  uint64
}

// blockRow is what one object's row asks: the blocks refusing reads and changes at or beneath it, the one whose path
// runs through it, its flags and its instant (bpf.PlaneBlockRow's).
type blockRow struct {
	read, write, guard uint16
	flags              uint8
	from               uint64
}

// merge is r and o as one row: every id (the first given kept for each class), every flag, the earlier instant.
func (r blockRow) merge(o blockRow) blockRow {
	if r.read == 0 {
		r.read = o.read
	}
	if r.write == 0 {
		r.write = o.write
	}
	if r.guard == 0 {
		r.guard = o.guard
	}
	r.flags |= o.flags
	if o.from < r.from {
		r.from = o.from
	}
	return r
}

// changeID is the block a refusal of a change at the row's object is named by: its write block, else its guard.
func (r blockRow) changeID() uint16 {
	if r.write != 0 {
		return r.write
	}
	return r.guard
}

// blockObj is one keyed object: the descriptor that pins it, its inode number when opened, and its row.
type blockObj struct {
	fd  *sys.FD
	ino uint64
	row blockRow
}

// planeBlocks is the run's live blocks in its plane slot.
type planeBlocks struct {
	w     enforce.PlaneBlockWriter
	rules *liveRules
	// ids are the blocks' ids by Entry.Key, given once for the run.
	ids  map[string]uint16
	next uint16
	// applied is what the kernel holds: each object's row and the descriptor that pins it.
	applied map[blockKey]*blockObj
	// pending are the objects a block keyed whose rows the kernel did not take (a full map): their descriptors are
	// held, their blocks' classes refused whole, and each pass tries their rows again.
	pending map[blockKey]*blockObj
	// held is, per block (Entry.Key), every object any of its walks keyed and the row it asked there. An object stays
	// keyed until its block is removed, wherever it has moved since (ADR 0124, amendment 2026-11-21: a block follows
	// the file): a pass's walk only adds to it.
	held map[string]map[blockKey]blockRow
	// chased is the overflow a sync that ran out of passes set (blockSyncPasses): the classes of every block, each by
	// its first block's id, refused whole by every pass until a sync ends with a pass that put no row.
	chased want
	// state is the slot's block state as last written.
	state bpf.PlaneBlockState
	// bootOK says this launcher's CLOCK_BOOTTIME is the kernel's (no time namespace offset), so a dormant block's pin
	// can be its rows' instant; without it a dormant block refuses until it begins.
	bootOK bool
	// mounts are the mount points of the launcher's table at Prepare, for the rows at mounted roots beneath a target.
	mounts []string
	// failed is set once the state could not be written: the run is ended (end) and nothing more is tried.
	failed error
	end    func(error)
	mu     sync.Mutex
	closed bool
}

func newPlaneBlocks(w enforce.PlaneBlockWriter, rules *liveRules, mounts []string, bootOK bool, end func(error)) *planeBlocks {
	return &planeBlocks{w: w, rules: rules, ids: map[string]uint16{}, applied: map[blockKey]*blockObj{},
		pending: map[blockKey]*blockObj{}, held: map[string]map[blockKey]blockRow{}, mounts: mounts, bootOK: bootOK, end: end}
}

// openPath is one element of a walk: name in the directory dir, not followed.
func openPath(dir *sys.FD, name string) (*sys.FD, error) {
	return dir.Openat(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func fstatFD(fd *sys.FD) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := fd.Fstat(&st)
	return st, err
}

// readlinkFD is the target of the link fd pins (an O_PATH descriptor of the link itself).
func readlinkFD(fd *sys.FD) (string, error) {
	buf := make([]byte, unix.PathMax)
	var n int
	err := fd.Borrow(func(num int) error {
		var err error
		n, err = unix.Readlinkat(num, "", buf)
		return err
	})
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// fsBlock reports whether e is a block the plane holds: a person's path, read or write block (a fence entry is the
// contract's, already in the plane's own rows).
func fsBlock(e liveblock.Entry) bool { return !e.Fence && e.Kind.Access() != 0 }

// idOf is the block's id, given the first time it is asked for; 0 once the run has given PlaneBlockIDMax of them.
func (p *planeBlocks) idOf(e liveblock.Entry) uint16 {
	k := e.Key()
	if id, ok := p.ids[k]; ok {
		return id
	}
	if p.next >= bpf.PlaneBlockIDMax {
		return 0
	}
	p.next++
	p.ids[k] = p.next
	p.rules.set(p.next, e.Rule())
	return p.next
}

// classes are the overflow bits of a block of kind k.
func classes(k liveblock.Kind) uint32 {
	var c uint32
	if k.Access()&liveblock.AccessRead != 0 {
		c |= bpf.PlaneBlockRead
	}
	if k.Access()&liveblock.AccessWrite != 0 {
		c |= bpf.PlaneBlockWrite
	}
	return c
}

// want is one sync's wanted rows and overflow.
type want struct {
	rows map[blockKey]*blockObj
	// fds are every descriptor this sync opened, each closed once the sync is done unless applied took it.
	fds       map[*sys.FD]bool
	over      uint32
	overRead  uint16
	overWrite uint16
}

func (w *want) overflow(c uint32, id uint16) {
	if c&bpf.PlaneBlockRead != 0 && w.overRead == 0 {
		w.overRead = id
	}
	if c&bpf.PlaneBlockWrite != 0 && w.overWrite == 0 {
		w.overWrite = id
	}
	w.over |= c
}

// add keys row at the object fd names (key), or merges it into the row an earlier block wanted there; the descriptor
// stays open for the sync either way.
func (w *want) add(key blockKey, fd *sys.FD, ino uint64, row blockRow) {
	w.fds[fd] = true
	if o, ok := w.rows[key]; ok {
		o.row = o.row.merge(row)
		return
	}
	w.rows[key] = &blockObj{fd: fd, ino: ino, row: row}
}

// absorb adds another want's overflow to w's.
func (w *want) absorb(o *want) {
	if o.over&bpf.PlaneBlockRead != 0 {
		w.overflow(bpf.PlaneBlockRead, o.overRead)
	}
	if o.over&bpf.PlaneBlockWrite != 0 {
		w.overflow(bpf.PlaneBlockWrite, o.overWrite)
	}
}

// blockSyncPasses bounds one sync's walks. A pass that puts no row met only objects already keyed, which cannot be
// moved or replaced, so the path's object is keyed; an agent that replaces the object at a blocked path by rename
// during every fill keeps each pass putting rows, and past the bound its blocks' classes are refused whole.
const blockSyncPasses = 8

// sync puts entries' path, read and write blocks in force in the plane, as the Set compiled from the same entries is:
// rows for what they name now and for everything they keyed before (a block follows the object it landed on until it
// is removed), the state that makes the hooks read them, and an overflow for a block it cannot key whole. partial is
// the values whose other names the mount table could not list in full, which the plane cannot key whole either. It
// tightens before it loosens: the state on and every new row in before an old row is deleted, an overflow set before a
// row is given up and cleared only after the rows it stood for are in. It walks again until a pass puts no row, so an
// object moved to, made at or renamed over a blocked path while the rows were landing is keyed before sync returns, and
// so before its live-block line; a sync that reaches blockSyncPasses still putting rows refuses every block's classes
// whole (chased) before it returns, and the next sync that settles clears that. A state it cannot write ends the run
// (end): the run could not be told what the person blocked.
func (p *planeBlocks) sync(entries []liveblock.Entry, others map[string][]string, partial map[string]string,
	pins map[string]time.Duration, now liveblock.Clock) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < blockSyncPasses; i++ {
		if !p.syncPass(entries, others, partial, pins, now) {
			if p.chased.over == 0 {
				return
			}
			// Settled: what the chase refused whole is keyed now; the next pass writes the state without it.
			p.chased = want{}
		}
	}
	if p.closed || p.failed != nil {
		return
	}
	// Still putting rows: the object at a blocked path kept changing under the fill. Refuse every block's classes
	// whole, now and in every pass, until a sync settles.
	for _, e := range entries {
		if fsBlock(e) {
			if id, ok := p.ids[e.Key()]; ok {
				p.chased.overflow(classes(e.Kind), id)
			}
		}
	}
	st := p.state
	st.Over |= p.chased.over
	if st.OverRead == 0 {
		st.OverRead = p.chased.overRead
	}
	if st.OverWrite == 0 {
		st.OverWrite = p.chased.overWrite
	}
	p.setState(st)
}

// syncPass is one walk of every block and one fill; true when it put a row.
func (p *planeBlocks) syncPass(entries []liveblock.Entry, others map[string][]string, partial map[string]string,
	pins map[string]time.Duration, now liveblock.Clock) bool {
	if p.closed || p.failed != nil {
		return false
	}
	w := &want{rows: map[blockKey]*blockObj{}, fds: map[*sys.FD]bool{}}
	defer func() {
		keep := make(map[*sys.FD]bool, len(p.applied)+len(p.pending))
		for _, a := range p.applied {
			keep[a.fd] = true
		}
		for _, a := range p.pending {
			keep[a.fd] = true
		}
		for fd := range w.fds {
			if !keep[fd] {
				_ = fd.Close()
			}
		}
	}()
	w.absorb(&p.chased)
	held := make(map[string]map[blockKey]blockRow, len(p.held))
	for _, e := range entries {
		if !fsBlock(e) {
			continue
		}
		k := e.Key()
		we := &want{rows: map[blockKey]*blockObj{}, fds: w.fds}
		p.wantBlock(we, e, others, partial, pins, now)
		w.absorb(we)
		cur := make(map[blockKey]blockRow, len(we.rows)+len(p.held[k]))
		for key, o := range we.rows {
			cur[key] = o.row
			w.add(key, o.fd, o.ino, o.row)
		}
		// What the block keyed before stays keyed, by the descriptor that pins it, wherever its object is now, with the
		// row it asked there: a later walk that meets the object in a weaker role (a moved target met as a guard) adds
		// its row to it and never replaces it. The row's instant is the block's now, not the one it was keyed with: an
		// unblock for a while is always of a block already in force, whose held rows carry from 0, and the earlier of two
		// instants would keep that 0 and the block in force through the whole window.
		from := p.fromOf(e, pins, now)
		for key, row := range p.held[k] {
			row.from = from
			if fresh, ok := cur[key]; ok {
				cur[key] = fresh.merge(row)
				w.add(key, w.rows[key].fd, w.rows[key].ino, row)
				continue
			}
			a, ok := p.applied[key]
			if !ok {
				a, ok = p.pending[key]
			}
			if !ok {
				continue
			}
			cur[key] = row
			w.add(key, a.fd, a.ino, row)
		}
		held[k] = cur
	}
	p.held = held
	names := false
	for k := range w.rows {
		names = names || k.name
	}
	// Tighten the state: on (and names) before any row goes in, the new overflow at once.
	tight := p.state
	if len(w.rows) > 0 {
		tight.On = 1
	}
	if names {
		tight.Names = 1
	}
	tight.Over |= w.over
	if tight.OverRead == 0 {
		tight.OverRead = w.overRead
	}
	if tight.OverWrite == 0 {
		tight.OverWrite = w.overWrite
	}
	if !p.setState(tight) {
		return false
	}
	// The rows that are new or changed (a pending one is tried again), then those no block names any more.
	var put, gone []blockKey
	for k, o := range w.rows {
		if a, ok := p.applied[k]; !ok || a.row != o.row {
			put = append(put, k)
		}
	}
	for k := range p.applied {
		if _, ok := w.rows[k]; !ok {
			gone = append(gone, k)
		}
	}
	for k, a := range p.pending {
		if _, ok := w.rows[k]; !ok {
			_ = a.fd.Close() // no block wants it any more, and the kernel never held it
			delete(p.pending, k)
		}
	}
	if len(put) > 0 {
		objs := make([]*blockObj, len(put))
		for i, k := range put {
			objs[i] = w.rows[k]
		}
		res, err := p.fill(put, objs, false)
		for i, k := range put {
			o := w.rows[k]
			if err == nil && res[i].Err == nil {
				if a, ok := p.applied[k]; ok && a.fd != o.fd {
					_ = a.fd.Close() // the new descriptor pins the same object
				}
				if a, ok := p.pending[k]; ok && a.fd != o.fd {
					_ = a.fd.Close()
				}
				delete(p.pending, k)
				p.applied[k] = o
				continue
			}
			// Held for the next pass's retry, wherever the object moves meanwhile.
			if _, ok := p.applied[k]; !ok {
				if a, ok := p.pending[k]; ok && a.fd != o.fd {
					_ = a.fd.Close()
				}
				p.pending[k] = o
			}
			// The row is not in: its blocks' classes are refused whole.
			c := uint32(0)
			if o.row.read != 0 {
				c |= bpf.PlaneBlockRead
			}
			if o.row.write != 0 || o.row.guard != 0 || k.name {
				c |= bpf.PlaneBlockWrite
			}
			if c&bpf.PlaneBlockRead != 0 && w.overRead == 0 {
				w.overRead = o.row.read
			}
			if c&bpf.PlaneBlockWrite != 0 && w.overWrite == 0 {
				w.overWrite = o.row.changeID()
			}
			w.over |= c
		}
		if w.over&^tight.Over != 0 {
			tight.Over |= w.over
			if tight.OverRead == 0 {
				tight.OverRead = w.overRead
			}
			if tight.OverWrite == 0 {
				tight.OverWrite = w.overWrite
			}
			if !p.setState(tight) {
				return false
			}
		}
	}
	if len(gone) > 0 {
		objs := make([]*blockObj, len(gone))
		for i, k := range gone {
			objs[i] = p.applied[k]
		}
		res, err := p.fill(gone, objs, true)
		for i, k := range gone {
			if err == nil && res[i].Err == nil {
				_ = p.applied[k].fd.Close()
				delete(p.applied, k)
			}
			// A row whose delete failed stays, refusing, with its descriptor; the next sync tries again.
		}
	}
	// Loosen the state to what the kernel now holds and this sync wants refused whole.
	loose := bpf.PlaneBlockState{Over: w.over, OverRead: w.overRead, OverWrite: w.overWrite}
	for k := range p.applied {
		loose.On = 1
		if k.name {
			loose.Names = 1
		}
	}
	if loose.Over&bpf.PlaneBlockRead == 0 {
		loose.OverRead = 0
	}
	if loose.Over&bpf.PlaneBlockWrite == 0 {
		loose.OverWrite = 0
	}
	p.setState(loose)
	return len(put) > 0
}

// setState writes st when it differs from the state last written; false, with the run ended, when it cannot be.
func (p *planeBlocks) setState(st bpf.PlaneBlockState) bool {
	st.Gen = p.state.Gen
	if st == p.state {
		return true
	}
	if err := p.w.SetState(st); err != nil {
		p.failed = err
		if p.end != nil {
			p.end(err)
		}
		return false
	}
	p.state = st
	return true
}

// fill writes (or, del, deletes) the rows of objs at keys in one pass of the plane's fill, which lends their
// descriptors' numbers for the pass (cgroup's fillBlocks, sys.LendAll); one that lends nothing (closed) fails the
// pass, whose rows then stay as they were.
func (p *planeBlocks) fill(keys []blockKey, objs []*blockObj, del bool) ([]enforce.PlaneBlockResult, error) {
	fills := make([]enforce.PlaneBlockFill, len(keys))
	for i, k := range keys {
		fills[i] = blockFill(k, objs[i], del)
	}
	return p.w.Fill(fills)
}

// blockFill is the fill of one object's row, or its deletion.
func blockFill(k blockKey, o *blockObj, del bool) enforce.PlaneBlockFill {
	return enforce.PlaneBlockFill{FD: o.fd, Ino: o.ino, Name: k.name, NameKey: k.nameKey, Delete: del, From: o.row.from,
		Read: o.row.read, Write: o.row.write, Guard: o.row.guard, Flags: o.row.flags}
}

// wantBlock adds the rows block e asks for to w: for each of its spellings (its value, its Real and every other name the
// mount table gave either) the objects its path passes through as guards, the object it leads to as the target, the
// missing name where it leads nowhere yet, and the mounted roots beneath the target. A block it cannot key whole
// overflows its classes.
func (p *planeBlocks) wantBlock(w *want, e liveblock.Entry, others map[string][]string, partial map[string]string,
	pins map[string]time.Duration, now liveblock.Clock) {
	id := p.idOf(e)
	c := classes(e.Kind)
	if id == 0 {
		w.overflow(c, bpf.PlaneBlockIDMax) // no id is left to name it by: its classes are refused whole
		return
	}
	from := p.fromOf(e, pins, now)
	target := blockRow{flags: bpf.PlaneBlockSelf | bpf.PlaneBlockBeneath, guard: id, from: from}
	if c&bpf.PlaneBlockRead != 0 {
		target.read = id
	}
	if c&bpf.PlaneBlockWrite != 0 {
		target.write = id
	}
	guard := blockRow{guard: id, from: from}
	seen := map[string]bool{}
	var spellings []string
	for _, v := range []string{e.Value, e.Real} {
		if v == "" {
			continue
		}
		if partial[v] != "" {
			// The mount table could not list every other name of the file (ADR 0124 amendment item 5): a name the
			// plane has not keyed may reach it, so the block's classes are refused whole.
			w.overflow(c, id)
		}
		spellings = append(spellings, v)
		spellings = append(spellings, others[v]...)
	}
	for _, s := range spellings {
		if seen[s] || !strings.HasPrefix(s, "/") {
			continue
		}
		seen[s] = true
		if err := p.walk(w, s, target, guard); err != nil {
			w.overflow(c, id)
		}
	}
}

// fromOf is the from_ns of block e's rows at now: its from's CLOCK_BOOTTIME pin while it has not begun (a dormant
// block, ADR 0125 decision 4), else 0 (in force). Without a pin, or where the launcher's boot clock is not the kernel's,
// a dormant block's rows refuse now.
func (p *planeBlocks) fromOf(e liveblock.Entry, pins map[string]time.Duration, now liveblock.Clock) uint64 {
	if e.From.IsZero() {
		return 0
	}
	pin, ok := pins[liveblock.DeadlineKey(e.Key(), e.From)]
	if !liveblock.Begun(e.From, pin, ok, now) && ok && p.bootOK && pin > 0 {
		return uint64(pin)
	}
	return 0
}

// frame is one directory a walk stands in: its path as reached (no link in it) and its descriptor.
type frame struct {
	path string
	fd   *sys.FD
	key  blockKey
	ino  uint64
}

// walk is one spelling's walk, element by element from "/", each opened O_PATH|O_NOFOLLOW from the directory before it
// (so the walk names what the kernel's lookup reaches, links followed by hand within blockWalkLinks, ".." taken in the
// directories walked): every directory and link it passes is keyed as a guard (the root excepted), the object it ends at
// as the target, and the first element that does not exist as a name row in the directory it would be made in. A file
// with elements after it ends the walk there: the path cannot exist while the file stands, and the file is guarded.
func (p *planeBlocks) walk(w *want, value string, target, guard blockRow) error {
	root, err := sys.Own(unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return err
	}
	w.fds[root] = true
	stack := []frame{{path: "/", fd: root}}
	todo := strings.FieldsFunc(value, func(r rune) bool { return r == '/' })
	calls, links := 0, 0
	last := func() bool {
		for _, t := range todo {
			if t != "" && t != "." {
				return false
			}
		}
		return true
	}
	for len(todo) > 0 {
		elem := todo[0]
		todo = todo[1:]
		switch elem {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if calls++; calls > blockWalkCalls {
			return errors.New("the path's walk took more calls than a block waits for")
		}
		cur := stack[len(stack)-1]
		fd, err := openPath(cur.fd, elem)
		if errors.Is(err, unix.ENOENT) {
			// Nothing exists here yet: refuse making this name in the directory it would be made in.
			nk, ok := bpf.PlaneBlockNameKey(elem)
			if !ok {
				return fmt.Errorf("the name %q cannot be keyed", elem)
			}
			dup, err := cur.fd.Dup()
			if err != nil {
				return err
			}
			st, err := fstatFD(dup)
			if err != nil {
				w.fds[dup] = true
				return err
			}
			row := target
			row.flags = bpf.PlaneBlockSelf // refused at the name itself: its creation
			if !last() {
				// A folder of the block's path that does not exist: making it is refused too (the plane cannot follow a
				// file it has not seen); the next sync keys the real objects once they exist.
				row.read, row.write = 0, 0
				if target.read != 0 || target.write != 0 {
					row.write = target.guard
				}
			}
			w.add(blockKey{name: true, dev: uint64(st.Dev), ino: st.Ino, nameKey: nk}, dup, st.Ino, row) //nolint:unconvert // Dev's type differs by platform
			return nil
		}
		if err != nil {
			return err
		}
		st, err := fstatFD(fd)
		if err != nil {
			w.fds[fd] = true
			return err
		}
		key := blockKey{dev: uint64(st.Dev), ino: st.Ino} //nolint:unconvert // Dev's type differs by platform
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			w.add(key, fd, st.Ino, guard)
			if links++; links > blockWalkLinks {
				return errors.New("the path runs through more links than the kernel follows")
			}
			if calls++; calls > blockWalkCalls {
				return errors.New("the path's walk took more calls than a block waits for")
			}
			t, err := readlinkFD(fd)
			if err != nil || t == "" {
				return fmt.Errorf("a link of the path cannot be read: %v", err)
			}
			if strings.HasPrefix(t, "/") {
				stack = stack[:1]
			}
			todo = append(strings.FieldsFunc(t, func(r rune) bool { return r == '/' }), todo...)
		case unix.S_IFDIR:
			// Every directory the walk stands in is a guard, one it leaves by ".." or a link to "/" included; the last
			// one is the target too (below).
			w.add(key, fd, st.Ino, guard)
			stack = append(stack, frame{path: filepath.Join(cur.path, elem), fd: fd, key: key, ino: st.Ino})
		default:
			if !last() {
				w.add(key, fd, st.Ino, guard) // a file with elements after it: the path cannot exist while it stands
				return nil
			}
			w.add(key, fd, st.Ino, target)
			p.mountRoots(w, filepath.Join(cur.path, elem), target)
			return nil
		}
	}
	// The walk ended at a directory: it is the target, every other directory it stood in a guard.
	top := stack[len(stack)-1]
	if len(stack) == 1 {
		// The block names "/": a target at the root, which every walk meets.
		st, err := fstatFD(top.fd)
		if err != nil {
			return err
		}
		dup, err := top.fd.Dup()
		if err != nil {
			return err
		}
		w.add(blockKey{dev: uint64(st.Dev), ino: st.Ino}, dup, st.Ino, target) //nolint:unconvert // Dev's type differs by platform
		return nil
	}
	w.add(top.key, top.fd, top.ino, target)
	p.mountRoots(w, top.path, target)
	return nil
}

// mountRoots keys, for the attribute hooks' walk inside one superblock, the root of every mount whose mount point lies
// beneath target's path, with the target's ids (MOUNT_ONLY: the walk that crosses mounts meets the target itself). A
// mount point gone since Prepare holds nothing to key; one that cannot be opened or read otherwise (a FUSE mount
// without allow_other) is a block the plane cannot key whole, which refuses the target's classes whole.
func (p *planeBlocks) mountRoots(w *want, at string, target blockRow) {
	var c uint32
	if target.read != 0 {
		c |= bpf.PlaneBlockRead
	}
	if target.write != 0 {
		c |= bpf.PlaneBlockWrite
	}
	row := target
	row.flags |= bpf.PlaneBlockMountOnly
	row.guard = 0
	for _, mp := range p.mounts {
		if mp == at || !strings.HasPrefix(mp, strings.TrimSuffix(at, "/")+"/") {
			continue
		}
		fd, err := sys.Own(unix.Open(mp, unix.O_PATH|unix.O_CLOEXEC, 0))
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			continue
		}
		if err != nil {
			w.overflow(c, target.guard)
			continue
		}
		st, err := fstatFD(fd)
		if err != nil {
			w.fds[fd] = true
			w.overflow(c, target.guard)
			continue
		}
		w.add(blockKey{dev: uint64(st.Dev), ino: st.Ino}, fd, st.Ino, row) //nolint:unconvert // Dev's type differs by platform
	}
}

// close releases every descriptor the plane's rows were pinned by. The run's teardown calls it after Detach cleared
// the slot's rows; nothing is synced after it.
func (p *planeBlocks) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for k, a := range p.applied {
		_ = a.fd.Close()
		delete(p.applied, k)
	}
	for k, a := range p.pending {
		_ = a.fd.Close()
		delete(p.pending, k)
	}
}
