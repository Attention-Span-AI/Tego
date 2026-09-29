// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The walk cache (R15b's fast path). Every notified fs syscall's verdict is taken where its path lands, and on
// the common shape — an absolute spelling with no ".." whose directory is reached from the root through no
// symlink and whose final component is not a symlink the syscall follows — it lands on the spelling itself
// (fsTargetIsSpelling). Asked of the kernel each time, that costs a lookup of the whole path and a stat of the
// final name per notification, the largest share of the fast path's round trip. What it asks changes only
// when a directory entry on the way changes, and the run's own tasks change one only by a syscall the filter
// notifies (rename, unlink, rmdir, symlink and link, and their *at forms: enforce-landlock R11), so a
// directory's answer is kept, and every such notification invalidates the whole cache before it is answered.
// A run whose filter leaves some of those mutations to the kernel decision plane unnotified (Options.PlaneFS,
// TIER3-PLAN T16) keeps no directory at all.
//
// A directory is kept as scanned (Kernel.ScanDir): reached with no symlink (RESOLVE_NO_SYMLINKS), not on
// procfs, and the names of the symlinks in it. A path in it then lands on its spelling unless its final name
// is one of those symlinks and the syscall follows it; everything else goes to the walk, as before.
//
// A scan races with a mutation in flight: the mutation's notification comes before the kernel runs it, and a
// scan made between the two sees the old entries. So a mutation's notification marks its thread pending, and
// nothing is kept while any thread is: a thread's syscalls run one at a time, so the thread's next notification
// says its mutation has run (and invalidates again), and so does a thread that is gone, a zombie, or asleep in
// another syscall (mutationMayRun).
//
// What no notification reports is a change made outside the run — another process of the user's, a package
// manager — which no Landlock rule of the run limits. A kept directory is trusted for walkCacheTTL at most, so
// such a change goes unseen for that long at most; the kernel's own lookup after CONTINUE races the walk in the
// same way, for a shorter window (denyWrite's "best effort").

// walkCacheTTL bounds how long a scanned directory is trusted without a scan (see above).
const walkCacheTTL = 100 * time.Millisecond

// walkCacheDirs bounds the directories kept; a full cache is emptied and fills again.
const walkCacheDirs = 1024

// scanDirMax bounds the entries a scan reads, so that emptying the cache — every notified mutation does —
// costs at most a short read per directory the run touches again. A larger directory is kept without its
// symlinks (dirScan.big), and a path in it that follows its final name asks the kernel for that name alone.
const scanDirMax = 256

// pendingCheck is how old a pending mutation must be before its thread is looked up (a thread that exited or
// went quiet after a mutation would otherwise keep the cache from filling for good), and how long after one
// look it is looked up again: a thread busy in userspace after its mutation stays pending until its next
// notification, and looking it up on every miss cost more than the walk the cache saves.
const pendingCheck = 20 * time.Millisecond

// dirScan is one directory as Kernel.ScanDir found it.
type dirScan struct {
	// links are the names of the symlinks in the directory; nil when there are none, or when big.
	links map[string]struct{}
	// big is a directory with more than scanDirMax entries, whose names were not all read: only that it is
	// reached with no symlink is known.
	big bool
}

// cachedDir is a kept scan, or with unscannable set a directory whose scan failed: its paths go to the walk
// without a scan for as long as a scan would be kept. That is kept whatever is pending, since it only ever sends
// a path to the walk.
type cachedDir struct {
	scan        dirScan
	unscannable bool
	gen         uint64
	at          time.Time
}

// walkCache is one Loop's cache. The zero value is empty and enabled.
type walkCache struct {
	mu      sync.Mutex
	gen     uint64
	pending map[int]pendingMutation
	dirs    map[string]cachedDir
	// off disables the cache: the fake kernel's tests of the walk itself.
	off bool
}

// pendingMutation is a notified mutation the kernel may not have run yet: its syscall, when it was notified,
// and when its thread was last looked up (zero before the first look).
type pendingMutation struct {
	nr      int32
	since   time.Time
	checked time.Time
}

// saw notes one notification of tid, for syscall nr, before it is handled: a pending mutation of that thread has
// run, and a notified mutation marks it pending. Either invalidates every kept directory.
func (c *walkCache) saw(tid int, nr int32, mutates bool) {
	c.mu.Lock()
	if _, ok := c.pending[tid]; ok {
		delete(c.pending, tid)
		c.gen++
	}
	if mutates {
		if c.pending == nil {
			c.pending = map[int]pendingMutation{}
		}
		c.pending[tid] = pendingMutation{nr: nr, since: time.Now()}
		c.gen++
	}
	c.mu.Unlock()
}

// lookup is the kept entry of dir, and the generation a scan of it would be kept under otherwise.
func (c *walkCache) lookup(dir string, now time.Time) (cachedDir, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.dirs[dir]
	if ok && d.gen == c.gen && now.Sub(d.at) < walkCacheTTL {
		return d, c.gen, true
	}
	return cachedDir{}, c.gen, false
}

// keep stores a scan of dir made after lookup returned gen, unless a mutation was notified since or is still
// pending: the scan may then have seen entries the mutation changes.
func (c *walkCache) keep(dir string, gen uint64, at time.Time, s dirScan, mayRun func(tid int, nr int32) bool) {
	c.mu.Lock()
	if gen != c.gen {
		c.mu.Unlock()
		return
	}
	if len(c.pending) > 0 {
		due := c.due(at)
		c.mu.Unlock()
		c.reap(due, mayRun)
		return // a scan that raced with a pending mutation is not kept, even once it is reaped
	}
	c.put(dir, cachedDir{scan: s, gen: gen, at: at})
	c.mu.Unlock()
}

// keepUnscannable notes that dir could not be scanned (keep's unscannable entry).
func (c *walkCache) keepUnscannable(dir string, gen uint64, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen == c.gen {
		c.put(dir, cachedDir{unscannable: true, gen: gen, at: at})
	}
}

// put stores one entry, emptying a full cache first. Called with c.mu held.
func (c *walkCache) put(dir string, d cachedDir) {
	if c.dirs == nil || len(c.dirs) >= walkCacheDirs {
		c.dirs = make(map[string]cachedDir, 64)
	}
	c.dirs[dir] = d
}

// dueMutation is one pending mutation reap looks up: its thread and the entry as due found it.
type dueMutation struct {
	tid int
	m   pendingMutation
}

// due returns the pending mutations whose threads are to be looked up now: pending for pendingCheck, and not
// looked up in the last pendingCheck. Each is marked looked up at now. Called with c.mu held.
func (c *walkCache) due(now time.Time) []dueMutation {
	var out []dueMutation
	for tid, m := range c.pending {
		last := m.since
		if m.checked.After(last) {
			last = m.checked
		}
		if now.Sub(last) < pendingCheck {
			continue
		}
		out = append(out, dueMutation{tid: tid, m: m})
		m.checked = now
		c.pending[tid] = m
	}
	return out
}

// reap drops the due pending mutations that have run, as far as their threads say (mutationMayRun). The /proc
// reads are made without c.mu, which every notification takes (saw); an entry is dropped only if it is still
// the one due found, since a new notification of its thread already dropped or replaced it.
func (c *walkCache) reap(due []dueMutation, mayRun func(tid int, nr int32) bool) {
	var ran []dueMutation
	for _, d := range due {
		if !mayRun(d.tid, d.m.nr) {
			ran = append(ran, d)
		}
	}
	if len(ran) == 0 {
		return
	}
	c.mu.Lock()
	for _, d := range ran {
		if m, ok := c.pending[d.tid]; ok && m.nr == d.m.nr && m.since.Equal(d.m.since) {
			delete(c.pending, d.tid)
			c.gen++
		}
	}
	c.mu.Unlock()
}

// mutating reports whether a notified syscall changes what a directory entry names (walkCache.saw).
func mutating(name string) bool {
	switch name {
	case "rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir", "symlink", "symlinkat", "link", "linkat":
		return true
	}
	return false
}

// mutationMayRun reports whether thread tid may still be about to run its notified syscall nr. It may not when
// the thread is gone or a zombie, or when it is asleep in another syscall (/proc/<tid>/syscall names the syscall
// a blocked thread is in): a thread runs one syscall at a time, so it left nr behind. A running thread, one
// asleep in nr again, or one this process cannot read may.
func mutationMayRun(tid int, nr int32) bool {
	base := "/proc/" + strconv.Itoa(tid)
	b, err := os.ReadFile(base + "/stat")
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return false
	}
	if err != nil {
		return true
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return true
	}
	if st := s[i+2]; st == 'Z' || st == 'X' {
		return false
	}
	b, err = os.ReadFile(base + "/syscall")
	if err != nil {
		return true
	}
	f, _, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	in, err := strconv.Atoi(f)
	return err != nil || in < 0 || in == int(nr)
}

// cachedTarget answers FSTarget for q from the walk cache when q lands on its spelling there: ok false sends
// q to the walk. Only the shape fsTargetIsSpelling answers is asked.
func (l *Loop) cachedTarget(q pathQuery) (string, bool) {
	c := &l.walks
	if c.off || !spellingShape(q) {
		return "", false
	}
	dir, base := splitFinal(q.joined)
	if base == "" || base == "." || base == ".." {
		return "", false
	}
	now := time.Now()
	d, gen, ok := c.lookup(dir, now)
	if ok && d.unscannable {
		return "", false
	}
	if !ok {
		var err error
		if d.scan, err = l.k.ScanDir(dir); err != nil {
			c.keepUnscannable(dir, gen, now)
			return "", false
		}
		c.keep(dir, gen, now, d.scan, l.mayRun)
	}
	if q.nofollow {
		return q.joined, true
	}
	if d.scan.big {
		// The directory is reached with no symlink, so a stat of the whole spelling asks about its final name.
		if link, err := l.k.FinalIsLink(q.joined); err != nil || link {
			return "", false
		}
		return q.joined, true
	}
	if _, link := d.scan.links[base]; link {
		return "", false
	}
	return q.joined, true
}

// spellingShape reports whether q has the shape whose landing its spelling can say: an absolute spelling of a
// pathname with no ".." component, no trailing slash and no final "." (finalDot), not a descriptor's own file.
// It is the one test of that shape for all three shortcuts past the walk (cachedTarget, fsTargetIsSpelling and
// fsTargetInRoot): an exclusion added to one copy and missed in another would let that shortcut answer "lands on
// its spelling" where the walk would not (TestSpellingShortcutsAgreeOnShape). A path joined to a " (deleted)"
// directory link is never of the shape (pathQuery.deletedBase).
func spellingShape(q pathQuery) bool {
	if q.empty || q.deletedBase || q.path == "" || !strings.HasPrefix(q.joined, "/") || strings.HasSuffix(q.path, "/") || finalDot(q.path) {
		return false
	}
	for p := q.path; p != ""; {
		c, rest, _ := strings.Cut(p, "/")
		if c == ".." {
			return false
		}
		p = rest
	}
	return true
}

// ScanDir opens dir with no symlink followed on the way (RESOLVE_NO_SYMLINKS, magic links included) and reads
// which of its entries are symlinks. It fails for a directory on procfs, whose entries change with every
// process and descriptor and whose "self" names this process. A directory with more than scanDirMax entries is
// big, its symlinks unread.
// A directory open raises no fanotify permission event (tier 2's listener marks files, not FAN_ONDIR).
func (k sysKernel) ScanDir(dir string) (dirScan, error) {
	how := unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	var fd int
	var err error
	for {
		if fd, err = unix.Openat2(unix.AT_FDCWD, dir, &how); err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return dirScan{}, err
	}
	defer unix.Close(fd) //nolint:errcheck // a descriptor this call opened
	var sf unix.Statfs_t
	if err := unix.Fstatfs(fd, &sf); err != nil {
		return dirScan{}, err
	}
	if sf.Type == unix.PROC_SUPER_MAGIC {
		return dirScan{}, unix.EXDEV
	}
	var s dirScan
	// The buffer does not escape, so it is on this goroutine's stack, not garbage per scan (Go keeps a
	// non-escaping make of a constant size under 64 KiB on the stack); TestScanDirMakesNoGarbageBuffer holds it.
	buf := make([]byte, 32<<10)
	entries := 0
	for {
		n, err := unix.Getdents(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return dirScan{}, err
		}
		if n == 0 {
			return s, nil
		}
		for off := 0; off < n; {
			// struct linux_dirent64: ino u64, off s64, reclen u16, type u8, name (NUL-terminated), in the
			// native byte order, which is little-endian on both supported architectures.
			reclen := int(binary.LittleEndian.Uint16(buf[off+16:]))
			typ := buf[off+18]
			name := buf[off+19 : off+reclen]
			if i := indexNUL(name); i >= 0 {
				name = name[:i]
			}
			off += reclen
			if entries++; entries > scanDirMax {
				return dirScan{big: true}, nil
			}
			if typ != unix.DT_LNK && typ != unix.DT_UNKNOWN {
				continue
			}
			nm := string(name)
			if typ == unix.DT_UNKNOWN {
				// A filesystem that does not fill d_type: the entry itself says what it is.
				var st unix.Stat_t
				if err := unix.Fstatat(fd, nm, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK {
					if err != nil && !errors.Is(err, unix.ENOENT) {
						return dirScan{}, err
					}
					continue
				}
			}
			if s.links == nil {
				s.links = map[string]struct{}{}
			}
			s.links[nm] = struct{}{}
		}
	}
}

// FinalIsDir reports whether p's final component is a directory (fstatat with AT_SYMLINK_NOFOLLOW, as a rename does
// not follow it); a missing name is not one.
func (k sysKernel) FinalIsDir(p string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(unix.AT_FDCWD, p, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return st.Mode&unix.S_IFMT == unix.S_IFDIR, nil
}

// FinalIsLink reports whether p's final component is a symlink (fstatat with AT_SYMLINK_NOFOLLOW); a missing name
// is not one.
func (k sysKernel) FinalIsLink(p string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(unix.AT_FDCWD, p, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return st.Mode&unix.S_IFMT == unix.S_IFLNK, nil
}
