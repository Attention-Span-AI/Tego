// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A replacement cannot inherit the old pin's identity. A file installed at a
// protected name, or in a denied directory, is pinned in turn when the queue is
// read: it is opened through the watched directory's retained descriptor, and
// one more barrier and drain must show that name unchanged since its event, or
// the object opened may not be the one installed. Anything that cannot be
// certified that way (a second install or a removal of the same name in one
// round, a directory installed at a launch name, an ancestor replaced, a lost
// event, an open that fails) latches uncertainty and refuses held reads until
// the run is restarted. Watches are armed before enumeration, drained after
// pinning and again on the opened descriptor. Retained O_PATH pins prevent inode
// reuse after unlink.
const maxHeldReadPins = 8192
const ruleHeldIdentityUnknown = "held-read-identity-unknown"

type heldReadWatch struct {
	directory *sys.FD
	path      string // the directory's canonical path, for the rule of an object installed in it
	all       bool   // a denied directory: every entry is protected
	// names are the protected entries a launch walk named (a target, a denied directory's children); ancestors are
	// the directories on a target's canonical path, whose replacement a pin cannot follow.
	names     map[string]bool
	ancestors map[string]bool
	gone      bool // removed after launch (IN_DELETE_SELF): empty, as rmdir leaves it; dropped at its IN_IGNORED
}

// heldReadPlace is a canonical path the snapshot relies on resolving where it did at launch: its mount id, device
// and inode then (statx).
type heldReadPlace struct {
	path          string
	mnt, dev, ino uint64
	// file is a target file's place: its placement (the mount and device it lies on) is checked, never its inode, which
	// a certified replacement changes; the pins keep the identities (review round 4).
	file bool
}

// addPlace records path's place, read from fd, once per canonical path: every view of a directory that bind mounts
// share is a place of its own, though inotify gives them one watch (review round 4).
func (p *heldReadPins) addPlace(path string, fd *sys.FD, file bool) error {
	if p.placed[path] {
		return nil
	}
	place, err := heldReadPlaceOf(path, fd)
	if err != nil {
		return err
	}
	place.file = file
	if p.placed == nil {
		p.placed = map[string]bool{}
	}
	p.placed[path] = true
	p.places = append(p.places, place)
	return nil
}

// heldReadMountTableChanged polls the kept mountinfo (mountsChanged); tests stand in for a mount elsewhere without
// seeing a leased number (ADR 0023).
var heldReadMountTableChanged = mountsChanged

// mountsChanged is mountTableChanged on the kept mountinfo; one that cannot be polled reads as a change.
func mountsChanged(f *sys.FD) bool {
	changed := true
	_ = f.Borrow(func(n int) error {
		changed = mountTableChanged(n)
		return nil
	})
	return changed
}

// heldReadPlaceOf reads a place's identity from fd (fd's own path is the caller's): statx's mount id, device and
// inode, or an error where the kernel gives no mount id (STATX_MNT_ID, Linux 5.8).
func heldReadPlaceOf(path string, fd *sys.FD) (heldReadPlace, error) {
	var stx unix.Statx_t
	err := fd.Borrow(func(n int) error {
		return unix.Statx(n, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_MNT_ID, &stx)
	})
	if err == nil && stx.Mask&unix.STATX_MNT_ID == 0 {
		err = errors.New("the kernel reports no mount id")
	}
	return heldReadPlace{path: path, mnt: stx.Mnt_id, dev: unix.Mkdev(stx.Dev_major, stx.Dev_minor), ino: stx.Ino}, err
}

// topologyChanged answers, when the mount table changed since it was last asked, whether any place now resolves to
// another object (a mount made over a watched directory or a target, a work volume detached lazily): an inotify watch
// sees neither, since it stays on the inodes it was armed on and an unmount kept alive by a descriptor raises no
// IN_UNMOUNT. A place that names nothing now was renamed or removed, and anything put at its name again raises an
// event of its own parent's watch. A change made and undone between two held reads is not seen: the mount topology
// of the protected places is a support condition (only a process outside the run, with the privilege to mount,
// changes it; ADR 0069).
func (p *heldReadPins) topologyChanged() bool {
	if p.mounts == nil {
		return false
	}
	if !heldReadMountTableChanged(p.mounts) {
		return false
	}
	for _, at := range p.places {
		var stx unix.Statx_t
		err := unix.Statx(unix.AT_FDCWD, at.path, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_INO|unix.STATX_MNT_ID, &stx)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil || stx.Mask&unix.STATX_MNT_ID == 0 || stx.Mnt_id != at.mnt || unix.Mkdev(stx.Dev_major, stx.Dev_minor) != at.dev ||
			(!at.file && stx.Ino != at.ino) {
			return true
		}
	}
	return false
}

// heldInstall is an object a drained event placed in a watched directory, to pin in this round.
type heldInstall struct {
	w    *heldReadWatch
	wd   int
	name string
	rule string // set for an object followed out of a protected name: the rule of the name it left
	left bool   // the object installed here was followed out in the same round: the name may be empty now
}

type heldReadKey struct {
	wd   int
	name string
}

type heldReadPins struct {
	mu      sync.Mutex
	watch   *sys.FD
	pins    []*sys.FD
	watches map[int]*heldReadWatch
	unknown bool
	sealed  bool // removals during enumeration can hide objects not pinned yet
	// index and rules decide the rule of an installed object (the table's held-read floor); pinned is every identity
	// pinned after launch, to its rule.
	index  *decide.HeldReadIndex
	rules  *decide.AdvisoryList
	pinned map[decide.HeldReadID]string
	// installs is the round's objects to pin, round the names a round touched, pending the names the previous
	// round pinned: an event of a pending name means its open may have met another object.
	installs []heldInstall
	round    map[heldReadKey]bool
	pending  map[heldReadKey]bool
	// mounts is this process's /proc/self/mountinfo, opened before any watch was armed: the kernel flags it POLLPRI
	// when the namespace's mount table changes (the run makes no mount namespace of its own, topology.go, so its
	// lookups resolve in this one). places are the canonical paths a watch or a target was taken at, with the mount,
	// device and inode they resolved to then.
	mounts *sys.FD
	places []heldReadPlace
	placed map[string]bool
	// follow is the round's moves in flight out of a name the round tracks (by cookie, to the rule the object
	// carries): its IN_MOVED_TO, at any name of a watched directory, makes that name tracked in turn, so a chain of
	// moves is followed to where the object is when the round ends.
	follow map[uint32]string
}

// heldReadBeforePin, set by tests alone, runs between a round's drain and the open of an object it installed: what
// another process does in that gap.
var heldReadBeforePin func(name string)

// Tests stand in for filesystems unavailable on the test host without exposing
// a leased descriptor number to an indirect call (ADR 0023).
var heldReadFSType = func(fd *sys.FD) (uint32, error) {
	var st unix.Statfs_t
	err := fd.Fstatfs(&st)
	return uint32(st.Type), err
}

func (p *heldReadPins) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unknown = true
	_ = p.watch.Close()
	_ = p.mounts.Close()
	for _, fd := range p.pins {
		_ = fd.Close()
	}
	p.pins = nil
	for _, w := range p.watches {
		_ = w.directory.Close()
	}
}

// heldReadAncestorFS is the check of a directory above a target's parent, whose replacement only a rename of a
// whole directory makes: heldReadLocalFS's list, and overlayfs. Below such an overlay ancestor lies a mount of a local
// filesystem (the parent passed heldReadLocalFS), so the ancestor can be replaced only through the VFS (the mountpoint
// itself cannot be renamed, EBUSY), which raises the event in the overlay's own view. A change of the mounts
// themselves raises no inotify event (a lazy unmount kept alive by a descriptor raises no IN_UNMOUNT, and a mount over
// a watched directory raises nothing): topologyChanged re-resolves every place when the mount table changes, and the
// topology is a support condition beyond that (ADR 0069). A container whose / is overlayfs and whose work folder is a
// volume or bind mount of a local filesystem holds its reads (docs/user/container.md). Remote, FUSE and unknown
// filesystems stay refused.
func heldReadAncestorFS(fd *sys.FD) error {
	if magic, err := heldReadFSType(fd); err == nil && magic == unix.OVERLAYFS_SUPER_MAGIC {
		return nil
	}
	return heldReadLocalFS(fd)
}

func heldReadLocalFS(fd *sys.FD) error {
	// A server or FUSE daemon can replace a name without a local VFS event.
	// inotify(7)'s remote-filesystem limitation must refuse launch, rather than
	// let an apparently empty queue certify an incomplete identity history.
	// Overlayfs can also renumber a retained file on copy-up (ADR 0010).
	magic, err := heldReadFSType(fd)
	if err != nil {
		return err
	}
	switch magic {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC,
		unix.F2FS_SUPER_MAGIC, unix.BCACHEFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.RAMFS_MAGIC,
		unix.SQUASHFS_MAGIC, unix.EROFS_SUPER_MAGIC_V1,
		unix.ISOFS_SUPER_MAGIC, unix.MSDOS_SUPER_MAGIC, unix.EXFAT_SUPER_MAGIC:
		return nil
	default:
		return fmt.Errorf("held-read stable identities/replacement events unavailable on filesystem %#x", magic)
	}
}

// watchDir watches the directory open at fd (canonical path dir): name is a protected entry of it ("" for none), an
// ancestor's next component when ancestor is set; all makes every entry protected.
func (p *heldReadPins) watchDir(fd *sys.FD, dir, name string, all, ancestor bool) (*heldReadWatch, error) {
	check := heldReadLocalFS // a target's parent, or a denied directory: their entries are protected
	if ancestor {
		check = heldReadAncestorFS
	}
	if err := check(fd); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if err := p.addPlace(dir, fd, false); err != nil {
		return nil, err
	}
	wd, err := p.watch.InotifyWatch(fd, unix.IN_ONLYDIR|unix.IN_MASK_ADD|unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_MOVED_FROM|unix.IN_DELETE|unix.IN_DELETE_SELF|unix.IN_UNMOUNT)
	if err != nil {
		return nil, err
	}
	w := p.watches[wd]
	if w == nil {
		if len(p.watches) >= maxHeldReadPins {
			return nil, errors.New("held-read watch limit")
		}
		directory, err := fd.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		w = &heldReadWatch{directory: directory, path: dir, names: map[string]bool{}, ancestors: map[string]bool{}}
		p.watches[wd] = w
	}
	w.all = w.all || all
	switch {
	case name == "":
	case ancestor:
		w.ancestors[name] = true
	default:
		w.names[name] = true
	}
	return w, nil
}

// Watch every directory entry on the canonical walk, including ancestors: a
// directory containing the target can itself be replaced. No event uses a path
// as evidence that the replacement is the object pinned previously.
func (p *heldReadPins) watchParents(path string) error {
	if path == "/" {
		return nil
	}
	at, err := sys.Own(unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return err
	}
	defer func() { _ = at.Close() }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		// Arm the parent before looking up its next entry. A canonical ancestor
		// replaced by a symlink since compile is uncertain, never followed into
		// an unwatched chain of directories.
		if _, err := p.watchDir(at, "/"+strings.Join(parts[:i], "/"), name, false, i < len(parts)-1); err != nil {
			return err
		}
		if i == len(parts)-1 {
			return nil
		}
		next, err := at.Openat(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		_ = at.Close()
		at = next
	}
	return nil
}

func (l *Loop) pinHeldReadIdentities(c *compiled) error {
	if c.heldReads == nil || l.deputy == nil {
		return nil
	}
	watch, err := sys.Own(unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC))
	if err != nil {
		return err
	}
	p := &heldReadPins{watch: watch, watches: map[int]*heldReadWatch{}, index: c.heldReads, rules: c.fsResolved,
		pinned: map[decide.HeldReadID]string{}}
	// Before any watch is armed: a mount change from here on is flagged on it.
	if p.mounts, err = sys.Own(unix.Open("/proc/self/mountinfo", unix.O_RDONLY|unix.O_CLOEXEC, 0)); err != nil {
		p.close()
		return fmt.Errorf("mountinfo: %w", err)
	}
	var pins []decide.HeldReadPin
	seen := map[decide.HeldReadID]bool{}
	walked := 0
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		// Count every visited name, including symlinks and duplicate hard links:
		// otherwise a tree retaining few pins could still take unbounded work.
		walked++
		if depth >= agent.MaxWalk || walked > maxHeldReadPins {
			return errors.New("held-read walk limit")
		}
		fd, err := sys.Own(unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := fd.Fstat(&st); err != nil {
			_ = fd.Close()
			return err
		}
		if st.Nlink == 0 || st.Ino == 0 {
			_ = fd.Close()
			return errors.New("held-read target has no live identity")
		}
		id := decide.HeldReadID{Dev: st.Dev, Ino: st.Ino}
		dir := st.Mode&unix.S_IFMT == unix.S_IFDIR
		rule, denied := c.heldReads.Refusal(c.fsResolved, path, dir)
		if depth == 0 && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = fd.Close()
			return errors.New("held-read target changed to a symlink")
		}
		if depth == 0 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			if err := p.addPlace(path, fd, true); err != nil { // a directory target is placed by its watch
				_ = fd.Close()
				return err
			}
		}
		if !denied || st.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = fd.Close()
			return nil
		}
		if !dir {
			if err := heldReadLocalFS(fd); err != nil {
				_ = fd.Close()
				return err
			}
			// A stacked file view can initially report its lower inode. Validate
			// the view before deduplicating, or copy-up could evade this snapshot.
			if seen[id] {
				_ = fd.Close()
				return nil
			}
		}
		if !seen[id] {
			seen[id] = true
			pins = append(pins, decide.HeldReadPin{ID: id, Rule: rule})
		}
		// Bind aliases of a directory can expose different submounts. Walk each
		// view; the depth/name bounds, rather than inode deduplication, bound cycles.
		p.pins = append(p.pins, fd)
		if !dir {
			return nil
		}
		w, err := p.watchDir(fd, path, "", true, false)
		if err != nil {
			return err
		}
		read, err := fd.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f, err := read.Release(path)
		if err != nil {
			_ = read.Close()
			return err
		}
		defer func() { _ = f.Close() }() // read-only enumeration; cleanup cannot change the snapshot's result
		for {
			names, err := f.Readdirnames(128)
			for _, name := range names {
				w.names[name] = true // a directory installed later at a launch name is a replacement
				if e := walk(filepath.Join(path, name), depth+1); e != nil {
					return e
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
	for _, r := range c.pol.Rules.FS {
		if r.Kind != agent.FSDenyRead || r.AskRead || !slices.ContainsFunc(c.pol.Rules.FS, func(w agent.FSRule) bool {
			return w.Kind == agent.FSWrite && agent.Covers(w.Canonical(), r.Canonical())
		}) {
			continue
		}
		path := r.Canonical()
		if !filepath.IsAbs(path) {
			err = errors.New("held-read target is not absolute")
		} else if err = p.watchParents(path); err == nil {
			err = walk(path, 0)
		}
		if err != nil {
			p.close()
			return fmt.Errorf("pin %s: %w", path, err)
		}
	}
	if !p.certain(true) {
		p.close()
		return errors.New("held-read targets changed during launch")
	}
	p.sealed = true
	c.heldReads = decide.NewHeldReadIndex(c.pol.Rules, pins...)
	l.heldPins = p
	return nil
}

// events reads one batch of the queue into the round: a lost or unreadable event, a removal while the launch walk
// may not have pinned the object yet, a replaced ancestor, a directory installed at a launch name, a second event of a
// name installed in this round or pinned in the last latch uncertainty; an object installed at a protected name (or
// in a denied directory) is queued to pin.
func (p *heldReadPins) events(buf []byte) {
	if p.round == nil {
		p.round, p.follow = map[heldReadKey]bool{}, map[uint32]string{}
	}
	for len(buf) >= unix.SizeofInotifyEvent {
		wd := int(int32(binary.NativeEndian.Uint32(buf)))
		mask := binary.NativeEndian.Uint32(buf[4:])
		cookie := binary.NativeEndian.Uint32(buf[8:])
		n := int(binary.NativeEndian.Uint32(buf[12:]))
		if n > len(buf)-unix.SizeofInotifyEvent {
			p.unknown = true
			return
		}
		name := strings.TrimRight(string(buf[unix.SizeofInotifyEvent:unix.SizeofInotifyEvent+n]), "\x00")
		buf = buf[unix.SizeofInotifyEvent+n:]
		w := p.watches[wd]
		switch {
		case w != nil && p.sealed && mask&(unix.IN_DELETE_SELF|unix.IN_Q_OVERFLOW|unix.IN_UNMOUNT) == unix.IN_DELETE_SELF:
			// A watched directory removed after launch held nothing then (rmdir needs it empty, and what left it had
			// its own events); one made again at its name is a directory installed at a launch name, uncertain.
			w.gone = true
			continue
		case w != nil && w.gone && mask&(unix.IN_IGNORED|unix.IN_Q_OVERFLOW|unix.IN_UNMOUNT) == unix.IN_IGNORED:
			_ = w.directory.Close()
			delete(p.watches, wd)
			continue
		case mask&(unix.IN_Q_OVERFLOW|unix.IN_IGNORED|unix.IN_UNMOUNT|unix.IN_DELETE_SELF) != 0 || w == nil:
			p.unknown = true
			continue
		}
		key := heldReadKey{wd, name}
		install := mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0
		if rule, moving := p.follow[cookie]; moving && cookie != 0 && mask&unix.IN_MOVED_TO != 0 {
			// The arrival of an object the round follows, wherever the name: tracked from here on.
			delete(p.follow, cookie)
			if p.round[key] || p.pending[key] {
				p.unknown = true // a name the round already touched: which object is there is not known
				continue
			}
			p.round[key] = true
			p.installs = append(p.installs, heldInstall{w: w, wd: wd, name: name, rule: rule})
			continue
		}
		if !w.all && !w.names[name] && !w.ancestors[name] && !p.round[key] && !p.pending[key] {
			// An entry beside the watched ones that neither this round tracks nor the last one pinned. A name the last
			// round pinned stays relevant through its verification however unprotected it is: an install there means
			// the pin's open may have met another object (review round 3).
			continue
		}
		switch {
		case install && (p.pending[key] || p.round[key]):
			// The object a pin opened, or will open, may not be the one installed; a tracked name made again after
			// its object left (the object followed, another one put in its place) is not guessed at either.
			p.unknown = true
		case !install && p.round[key]:
			// A tracked object left before it was pinned: followed to where it goes, or, deleted (another name of it
			// may remain) or moved with no cookie, uncertain.
			if mask&unix.IN_MOVED_FROM == 0 || cookie == 0 || mask&unix.IN_ISDIR != 0 {
				p.unknown = true
				continue
			}
			rule := ""
			for i := range p.installs {
				if p.installs[i].wd == wd && p.installs[i].name == name {
					p.installs[i].left = true
					if p.installs[i].rule != "" {
						rule = p.installs[i].rule
					}
				}
			}
			if rule == "" {
				r, denied := p.index.Refusal(p.rules, filepath.Join(w.path, name), false)
				if !denied {
					p.unknown = true
					continue
				}
				rule = r
			}
			p.follow[cookie] = rule
		case !install:
			if !p.sealed {
				p.unknown = true // the launch walk may not have pinned what left
			}
		case w.ancestors[name] || mask&unix.IN_ISDIR != 0 && w.names[name]:
			p.unknown = true // a replaced directory: its tree cannot be followed
		case mask&unix.IN_ISDIR != 0:
			// A directory made under a new name in a denied directory: not followed (a file made in it later and
			// moved out before a held read is the created-later residual, ADR 0069).
		default:
			p.round[key] = true
			p.installs = append(p.installs, heldInstall{w: w, wd: wd, name: name})
		}
	}
	if len(buf) != 0 {
		p.unknown = true
	}
}

// settleFollows ends a drained round: a followed object whose move has no arrival in a watched directory is out of
// sight, uncertain.
func (p *heldReadPins) settleFollows() {
	if len(p.follow) != 0 {
		p.unknown = true
	}
}

// pinInstalled pins an object an event installed, opened through the watched directory's own descriptor. An
// object that is gone, a directory, on an unsupported filesystem or past the bound latches uncertainty; a symlink
// reads nothing and is left, as the launch walk leaves one; an entry no held-read rule refuses is left.
func (p *heldReadPins) pinInstalled(in heldInstall) {
	if heldReadBeforePin != nil {
		heldReadBeforePin(in.name)
	}
	fd, err := in.w.directory.Openat(in.name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if !in.left || !errors.Is(err, unix.ENOENT) {
			p.unknown = true
		}
		return
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil || st.Nlink == 0 || st.Ino == 0 || st.Mode&unix.S_IFMT == unix.S_IFDIR {
		_ = fd.Close()
		p.unknown = true
		return
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = fd.Close()
		return
	}
	rule, denied := in.rule, in.rule != ""
	if !denied {
		rule, denied = p.index.Refusal(p.rules, filepath.Join(in.w.path, in.name), false)
	}
	if !denied {
		_ = fd.Close()
		if in.w.names[in.name] {
			p.unknown = true // a protected name the floor no longer names: never guess
		}
		return
	}
	if err := heldReadLocalFS(fd); err != nil || len(p.pins) >= 2*maxHeldReadPins {
		_ = fd.Close()
		p.unknown = true
		return
	}
	id := decide.HeldReadID{Dev: st.Dev, Ino: st.Ino}
	if _, dup := p.pinned[id]; !dup {
		p.pinned[id] = rule
	}
	p.pins = append(p.pins, fd)
}

func (p *heldReadPins) certain(opened bool) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unknown {
		return false
	}
	if p.topologyChanged() {
		p.unknown = true
		return false
	}
	p.pending = nil
	barrier := opened
	for range 64 {
		if barrier {
			// VFS can expose a new dentry before queuing fsnotify. An alias in a
			// different directory can be opened during that gap. getdents64 takes
			// each watched directory's i_rwsem, even at EOF, so mutations visible
			// before this descriptor (or a pin of the last round) was opened have
			// published their events before the drain below. An empty queue alone
			// would not prove that history.
			var names [4096]byte
			for _, w := range p.watches {
				err := w.directory.Borrow(func(fd int) error {
					_, err := unix.ReadDirent(fd, names[:])
					return err
				})
				// ENOENT is a removed directory's (IS_DEADDIR): empty, and its parent's barrier settles the removal.
				if err != nil && !(p.sealed && errors.Is(err, unix.ENOENT)) {
					p.unknown = true
					return false
				}
			}
		}
		p.installs, p.round, p.follow = nil, nil, nil
		if !p.drain() || p.unknown {
			p.unknown = true
			return false
		}
		p.settleFollows()
		if p.unknown {
			return false
		}
		if len(p.installs) == 0 {
			p.pending = nil
			return true
		}
		p.pending = map[heldReadKey]bool{}
		for _, in := range p.installs {
			p.pinInstalled(in)
			if p.unknown {
				return false
			}
			p.pending[heldReadKey{in.wd, in.name}] = true
		}
		barrier = true // the pins were opened: settle what reached their names before them
	}
	p.unknown = true // churn past the bounded rounds
	return false
}

// drain reads the queue until it is empty, at most 64 batches; false on a read error or churn past the bound.
func (p *heldReadPins) drain() bool {
	var buf [64 * 1024]byte
	for range 64 {
		var n int
		err := p.watch.Borrow(func(fd int) error {
			var err error
			n, err = unix.Read(fd, buf[:])
			return err
		})
		if errors.Is(err, unix.EAGAIN) {
			return true
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n <= 0 {
			return false
		}
		p.events(buf[:n])
		if p.unknown {
			return false
		}
	}
	return false
}

// pinnedRule is the rule of an identity pinned after launch.
func (p *heldReadPins) pinnedRule(id decide.HeldReadID) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rule, ok := p.pinned[id]
	return rule, ok
}

// heldAskIdentityRefusal is the protected-identity floor of an approval on this loop's own pin (fs.ask, fs.ask_read,
// a copied gate's ask), on the descriptor at fd: the pin before the person is asked, the reopened descriptor before
// it is delivered (opened). It holds whatever the access mode: an approval never grants an object the contract
// denies (the denied name is refused for a write too, askOpen), so a write-only alias of a protected file is refused
// as its name would be. A descriptor that cannot be stat'ed refuses.
func (l *Loop) heldAskIdentityRefusal(fd int, opened bool) (string, bool) {
	c := l.table.Load()
	if c.heldReads == nil {
		return "", false
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return ruleHeldIdentityUnknown, true
	}
	return l.heldIdentityFloor(c, decide.HeldReadID{Dev: st.Dev, Ino: st.Ino}, opened)
}

// heldReadIdentityRefusal is the floor for a held open that is not an approval: a read-capable one only (a write-only
// open reads nothing, and the write entry grants writing the target).
func (l *Loop) heldReadIdentityRefusal(c *compiled, flags int, id decide.HeldReadID, opened bool) (string, bool) {
	if c.heldReads == nil || !readCapable(flags) {
		return "", false
	}
	return l.heldIdentityFloor(c, id, opened)
}

// heldIdentityFloor refuses id when the history of the protected names is uncertain or id is a protected identity
// (pinned at launch, or since, as an object put in a protected place).
func (l *Loop) heldIdentityFloor(c *compiled, id decide.HeldReadID, opened bool) (string, bool) {
	if c.heldReads == nil {
		return "", false
	}
	if !l.heldPins.certain(opened) {
		return ruleHeldIdentityUnknown, true
	}
	if rule, ok := l.heldPins.pinnedRule(id); ok {
		return rule, true
	}
	return c.heldReads.RefusalOn(c.fsResolved, "", false, id)
}
