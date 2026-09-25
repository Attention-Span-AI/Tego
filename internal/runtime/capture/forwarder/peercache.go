// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// procAdmitter is the production admitter (R19a), shaped so that admitting one connection does not cost more for
// every other connection already open. procPeerAdmitter read the whole of /proc/net/tcp, every
// process's cgroup file on the host and every descriptor link of the run's processes for each new connection:
// 4.8 ms with none open and 28.6 ms with 4000, which an agent's pool pays on every connection it opens. Here:
//
//   - the peer's socket inode is one exact sock_diag lookup (sockDiagInode), with the tcp tables as the fallback,
//     where a kernel without TCP sock_diag goes straight away once a lookup showed it (tcpDiag);
//   - the run's processes are the cgroup.procs files of the run's cgroup subtree, not a walk of /proc; the
//     subtree's directory is found once, by its id, and kept while that directory still has the id;
//   - each process's descriptor links are remembered. The kernel gives a new descriptor the lowest number free, so
//     a new connection's socket is first looked for in the processes that opened the last few, at a number the
//     process was seen to free (a connection this listener saw close, whose peer's descriptor is then forgotten:
//     forget) and just past its highest one; only then is each process's descriptor table listed and the
//     descriptors not known as sockets read, and, since a number closed and reused is remembered with its old
//     socket, a miss there reads the remembered ones too before refusing, each descriptor once. That search is
//     what a peer outside the run always costs, so it runs outside the mutex, one at a time for every connection
//     then waiting on one, and one that leaves a socket unfound holds the next back for searchPace times as long
//     as it took (find, searchLoop).
//
// What decides admission is unchanged: a process listed in the run's cgroup subtree holds the socket, and that
// process's own /proc/<pid>/cgroup still places it there when it is named, so a pid that exited and was reused
// between the listing and the answer is not taken for the run's. Anything this cannot answer falls back to
// procPeerAdmitter, and anything that cannot answer refuses.
type procAdmitter struct {
	mu sync.Mutex
	// dirs is the run cgroup's directory by its id; a cgroup's id is fixed for the boot, and a directory whose
	// inode is no longer the id is looked for again.
	dirs map[uint64]string
	// fds is each run process's descriptors as last read.
	fds map[int]*procFDs
	// holder is where a socket inode was last seen, and conns where each admitted connection's peer was.
	holder map[uint64]fdRef
	conns  map[connKey]fdRef
	// recent is the processes that held the last few admitted connections, most recent first (recentCap).
	recent []int
	// links counts descriptor links read, which is what the cache saves; a test reads it.
	links atomic.Int64
	// wait is the finds waiting for the next search of the descriptor tables, and running whether searchLoop is
	// running them; calm is when the next search may start (searchPace).
	wait    []*searchReq
	running bool
	calm    time.Time
	// searches counts the table searches run; a test reads it.
	searches atomic.Int64
	// searching, when set, is called as a search of the descriptor tables begins; a test holds a search there.
	searching func()
	// linked, when set, is called with the pid of each descriptor link read; a test counts one process's own.
	linked func(pid int)
	// pause waits out the time until calm, and now is the clock searches are timed by; a test replaces both.
	pause func(time.Duration)
	now   func() time.Time
	// diag and fallback are the two kernel reads that are replaced in a test; diag is the run's tcpDiag.inode.
	diag     func(peer, local netip.AddrPort) (uint64, error)
	fallback peerAdmitter
}

// procFDs is one process's descriptors as last read: name to socket inode, 0 for one that is not a socket; the
// highest number among its sockets, not its files (a file opened and closed, this admitter's own listing of the
// table among them, would leave the next socket below it); and the numbers of sockets this listener saw the
// process's connections close on.
type procFDs struct {
	names map[string]uint64
	top   int
	freed []string
}

// freedCap bounds the numbers remembered as freed per process: the next socket takes the lowest of them, so only
// the few most recent are worth a probe.
const freedCap = 8

// recentCap is how many processes' likely descriptors are probed before any table is listed: an agent's calls
// come from a handful of its processes, and a probe of one that opened nothing costs topProbe failed reads.
const recentCap = 4

// topProbe is how many numbers past a process's highest descriptor are probed for a new socket.
const topProbe = 4

// fdRef is one descriptor of one process.
type fdRef struct {
	pid int
	fd  string
	ino uint64
}

// connKey is one connection by its two ends.
type connKey struct{ peer, local netip.AddrPort }

// admitterCacheCap bounds the connections and socket inodes remembered: past it the memory starts over rather
// than grow. It is well past DefaultMaxConns, so it is reached only by a run whose processes hold that many
// sockets besides their connections to this listener.
const admitterCacheCap = 1 << 16

// newProcAdmitterOn is an admitter whose exact lookup is d, the run's (Options.tcpDiag).
func newProcAdmitterOn(d *tcpDiag) *procAdmitter {
	return &procAdmitter{
		dirs: map[uint64]string{}, fds: map[int]*procFDs{},
		holder: map[uint64]fdRef{}, conns: map[connKey]fdRef{},
		diag: d.inode, fallback: procPeerAdmitter, pause: time.Sleep, now: time.Now,
	}
}

// admit is a peerAdmitter.
func (a *procAdmitter) admit(peer, local netip.AddrPort, runCgroup uint64) (int, error) {
	inode, err := a.diag(peer, local)
	if err != nil {
		if inode, err = peerSocketInode(peer, local); err != nil {
			return 0, err
		}
	}
	if inode == 0 {
		// No live socket has inode 0: an orphaned one reads as 0, and so does every descriptor that is not a socket.
		return 0, fmt.Errorf("%w: the socket for %s -> %s has no inode: no process holds it", ErrPeer, peer, local)
	}
	mount, err := cgroup2Mount()
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	pids, err := a.runPIDs(mount, runCgroup)
	a.mu.Unlock()
	var ref fdRef
	found := false
	if err == nil {
		ref, found = a.find(inode, pids)
	}
	if err != nil {
		// The run's cgroup could not be listed; the walk of /proc asks the same question another way.
		return a.fallback(peer, local, runCgroup)
	}
	if !found {
		return 0, fmt.Errorf("%w: socket inode %d is held by no process in cgroup %d", ErrPeer, inode, runCgroup)
	}
	if cg, err := procCgroupPath(ref.pid); err != nil || !cgroupInSubtree(mount, cg, runCgroup) {
		return 0, fmt.Errorf("%w: process %d holding socket inode %d is not in cgroup %d", ErrPeer, ref.pid, inode,
			runCgroup)
	}
	a.mu.Lock()
	if len(a.conns) >= admitterCacheCap {
		clear(a.conns)
	}
	a.conns[connKey{peer, local}] = ref
	a.recent = slices.DeleteFunc(a.recent, func(p int) bool { return p == ref.pid })
	a.recent = slices.Insert(a.recent, 0, ref.pid)
	if len(a.recent) > recentCap {
		a.recent = a.recent[:recentCap]
	}
	a.mu.Unlock()
	return ref.pid, nil
}

// forget is told that a connection has closed: the descriptor its peer held is likely to be closed too, and the
// next socket the process opens likely to be given its number, so that descriptor is read afresh next time.
func (a *procAdmitter) forget(peer, local netip.AddrPort) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := connKey{peer, local}
	ref, ok := a.conns[k]
	if !ok {
		return
	}
	delete(a.conns, k)
	if fds := a.fds[ref.pid]; fds != nil && fds.names[ref.fd] == ref.ino {
		delete(fds.names, ref.fd)
		if len(fds.freed) == freedCap {
			fds.freed = fds.freed[1:]
		}
		fds.freed = append(fds.freed, ref.fd)
	}
	if a.holder[ref.ino] == ref {
		delete(a.holder, ref.ino)
	}
}

// runPIDs lists the processes of the run's cgroup subtree, lowest pid first, and forgets the descriptors of any
// process no longer in it.
func (a *procAdmitter) runPIDs(mount string, runCgroup uint64) ([]int, error) {
	dir, ok := a.dirs[runCgroup]
	if ok {
		if id, err := cgroupIDOf(dir); err != nil || id != runCgroup {
			ok = false
		}
	}
	if !ok {
		var err error
		if dir, err = findCgroupDir(mount, runCgroup); err != nil {
			delete(a.dirs, runCgroup)
			return nil, err
		}
		a.dirs[runCgroup] = dir
	}
	pids, err := readCgroupProcs(dir, nil)
	if err == nil && hasDescendants(dir) {
		// A nested cgroup's processes are the run's too (cgroupInSubtree); most runs have none, and
		// cgroup.stat says so without listing the directory.
		err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() || p == dir {
				return nil // a nested cgroup removed while it was walked, or one already read
			}
			pids, _ = readCgroupProcs(p, pids)
			return nil
		})
	}
	if err != nil {
		return nil, fmt.Errorf("%w: list the run's cgroup %s: %w", ErrPeer, dir, err)
	}
	slices.Sort(pids)
	for pid := range a.fds {
		if _, live := slices.BinarySearch(pids, pid); !live {
			delete(a.fds, pid)
		}
	}
	return pids, nil
}

// readCgroupProcs appends the pids one cgroup directory's cgroup.procs lists.
func readCgroupProcs(dir string, pids []int) ([]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return pids, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if pid, err := strconv.Atoi(line); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// hasDescendants reports whether a cgroup has cgroups beneath it, by its cgroup.stat; true when that cannot be
// read, so the directory is walked.
func hasDescendants(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.stat"))
	if err != nil {
		return true
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if n, ok := strings.CutPrefix(line, "nr_descendants "); ok {
			return n != "0"
		}
	}
	return true
}

// findCgroupDir is the directory under the cgroup2 mount whose inode, a cgroup's id, is id. It walks the
// hierarchy, which is why its answer is kept.
func findCgroupDir(mount string, id uint64) (string, error) {
	var found string
	err := filepath.WalkDir(mount, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil // a subtree this process may not read, or one removed while it was walked
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == id {
			found = p
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: walk %s: %w", ErrPeer, mount, err)
	}
	if found == "" {
		return "", fmt.Errorf("%w: no cgroup with id %d under %s", ErrPeer, id, mount)
	}
	return found, nil
}

// find names a descriptor among the run's processes that holds the socket, reading as few descriptor links as it
// can: where the socket was last seen, then the likely numbers in the processes that opened the last connections
// (probe), then every descriptor not read before, then, before giving up, the remembered ones too, since a
// number closed and reused carries its old socket in the memory. The tables are read lowest pid first, so a socket
// a process shares with the children it forked is named by the parent that opened it, as procPeerAdmitter names
// it; one found by a probe is named by the process that opened the connection before it, usually the same one.
//
// The first two are a few reads each and run under the mutex. The table search is one read per descriptor of every
// run process, and it is what a peer outside the run always costs, a peer that chooses how often it connects. So it
// runs outside the mutex, over a copy of what is remembered, and the run's own connections the memory answers are
// not queued behind it; and it is not run once per connection: every find the memory cannot answer waits for
// searchLoop, which runs one search at a time for all the sockets waiting when it starts, paced by searchPace.
func (a *procAdmitter) find(inode uint64, pids []int) (fdRef, bool) {
	if inode == 0 {
		return fdRef{}, false // what a descriptor that is not a socket reads as, never a socket's own
	}
	a.mu.Lock()
	if ref, ok := a.cached(inode, pids); ok {
		a.mu.Unlock()
		return ref, true
	}
	req := &searchReq{inode: inode, pids: pids, done: make(chan struct{})}
	a.wait = append(a.wait, req)
	if !a.running {
		a.running = true
		go a.searchLoop()
	}
	a.mu.Unlock()
	<-req.done
	return req.ref, req.ok
}

// searchPace bounds the table searches that leave a socket unfound, which is what every peer outside the run costs,
// a peer that chooses how often it connects: after one, the next search starts no sooner than searchPace times as
// long as it took, so those searches take at most a quarter of one core of the launcher however fast or however
// many outsiders connect (one search of about 4000 descriptors was measured at 7-18 ms). A connection of the run's
// that the memory cannot answer waits at most for the search in progress, that pause and one search more, which
// looks for every socket waiting by then at once.
const searchPace = 3

// searchReq is one find waiting for a table search: the socket it looks for, the run's processes as its admission
// listed them, and the answer, given when done is closed.
type searchReq struct {
	inode uint64
	pids  []int
	ref   fdRef
	ok    bool
	done  chan struct{}
}

// searchLoop runs the table searches waiting finds need, one at a time, until none waits. Each takes every find
// waiting as it starts, answers from the memory those an earlier search has since placed, and searches for the rest
// at once, over the run's processes their admissions listed; what it read is merged back after. One that leaves any
// socket unfound sets calm.
func (a *procAdmitter) searchLoop() {
	for {
		a.mu.Lock()
		if len(a.wait) == 0 {
			a.running = false
			a.mu.Unlock()
			return
		}
		pause := a.calm.Sub(a.now())
		a.mu.Unlock()
		if pause > 0 {
			a.pause(pause)
		}
		a.mu.Lock()
		batch := a.wait
		a.wait = nil
		want := make(map[uint64]bool, len(batch))
		var pids []int
		var rest []*searchReq
		for _, r := range batch {
			if ref, ok := a.held(r.inode, r.pids); ok {
				r.ref, r.ok = ref, true
				close(r.done)
				continue
			}
			want[r.inode] = true
			pids = append(pids, r.pids...)
			rest = append(rest, r)
		}
		if len(rest) == 0 {
			a.mu.Unlock()
			continue
		}
		slices.Sort(pids)
		pids = slices.Compact(pids)
		known := make(map[int]map[string]uint64, len(pids))
		for _, pid := range pids {
			if fds := a.fds[pid]; fds != nil {
				known[pid] = maps.Clone(fds.names)
			}
		}
		a.mu.Unlock()
		if a.searching != nil {
			a.searching()
		}
		before := make(map[int]map[string]uint64, len(known))
		for pid, names := range known {
			before[pid] = maps.Clone(names)
		}
		a.searches.Add(1)
		start := a.now()
		tables, found := a.search(want, pids, known)
		took := a.now().Sub(start)
		a.mu.Lock()
		a.merge(tables, before)
		missed := false
		for _, r := range rest {
			r.ref, r.ok = found[r.inode]
			missed = missed || !r.ok
		}
		if missed {
			a.calm = a.now().Add(searchPace * took)
		}
		a.mu.Unlock()
		for _, r := range rest {
			close(r.done)
		}
	}
}

// cached is find's answer from the memory alone: where the socket was last seen, then a probe of the processes
// that opened the last connections. The caller holds the mutex.
func (a *procAdmitter) cached(inode uint64, pids []int) (fdRef, bool) {
	if ref, ok := a.held(inode, pids); ok {
		return ref, true
	}
	if len(a.holder) >= admitterCacheCap {
		clear(a.holder)
	}
	for _, pid := range a.recent {
		if _, live := slices.BinarySearch(pids, pid); !live {
			continue
		}
		if ref, ok := a.probe(pid, inode); ok {
			return ref, true
		}
	}
	return fdRef{}, false
}

// held is where the socket was last seen, read again to confirm it is still there and forgotten if not. The caller
// holds the mutex.
func (a *procAdmitter) held(inode uint64, pids []int) (fdRef, bool) {
	ref, ok := a.holder[inode]
	if !ok {
		return fdRef{}, false
	}
	link := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	if _, live := slices.BinarySearch(pids, ref.pid); live && a.readlink(ref.pid, ref.fd) == link {
		return ref, true
	}
	delete(a.holder, inode)
	return fdRef{}, false
}

// fdTable is one process's descriptor table as a search listed it: every listed name with its socket inode (0 for
// one that is not a socket, or that was remembered and not read again), or gone when the table could not be listed.
type fdTable struct {
	names map[string]uint64
	gone  bool
}

// search reads the run's descriptor tables for the sockets wanted, touching no memory of the admitter's but the
// count of links read: known is its own copy of what was remembered, updated in place and returned per process. The
// first pass reads each process's descriptors not read before and the ones that were not sockets when they were:
// such a descriptor is the one a number is most often freed from and reused by unseen, a file or a directory opened
// and closed between two connections, this admitter's own read of /proc/<pid>/fd among them. The second, for the
// sockets still unfound, reads the ones the first skipped as remembered sockets, since a number closed and reused
// carries its old socket in the memory; each descriptor is read once per search. A socket is named by the first
// descriptor it is read at, and the search ends once each wanted is named. Descriptors a process no longer has are
// dropped.
func (a *procAdmitter) search(want map[uint64]bool, pids []int, known map[int]map[string]uint64) (map[int]*fdTable,
	map[uint64]fdRef) {
	tables := make(map[int]*fdTable, len(pids))
	found := make(map[uint64]fdRef, len(want))
	name := func(pid int, fd string, ino uint64) {
		if _, dup := found[ino]; ino != 0 && want[ino] && !dup {
			found[ino] = fdRef{pid: pid, fd: fd, ino: ino}
		}
	}
	skipped := make(map[int][]string, len(pids))
	for _, pid := range pids {
		f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/fd")
		if err != nil {
			tables[pid] = &fdTable{gone: true}
			continue
		}
		listed, err := f.Readdirnames(-1)
		_ = f.Close()
		if err != nil {
			continue
		}
		names := known[pid]
		if names == nil {
			names = make(map[string]uint64, len(listed))
		}
		if len(names) > len(listed) {
			keep := make(map[string]uint64, len(listed))
			for _, n := range listed {
				if ino, ok := names[n]; ok {
					keep[n] = ino
				}
			}
			names = keep
		}
		tables[pid] = &fdTable{names: names}
		for _, fd := range listed {
			if old, seen := names[fd]; seen && old != 0 {
				skipped[pid] = append(skipped[pid], fd)
				continue
			}
			ino := socketInode(a.readlink(pid, fd))
			names[fd] = ino
			name(pid, fd, ino)
		}
		if len(found) == len(want) {
			return tables, found
		}
	}
	for _, pid := range pids {
		t := tables[pid]
		for _, fd := range skipped[pid] {
			ino := socketInode(a.readlink(pid, fd))
			t.names[fd] = ino
			name(pid, fd, ino)
			if len(found) == len(want) {
				return tables, found
			}
		}
	}
	return tables, found
}

// merge keeps what a search read: each listed table replaces the process's remembered descriptors, a table that
// could not be listed forgets the process, and every socket read names its holder, the lowest pid first. before is
// what the search started from, so a socket remembered at a descriptor that now holds another is no longer named
// there. A connection closed while the search ran may be remembered as open; the holder is read again before it is
// believed, and the table search is what catches the rest. The caller holds the mutex.
func (a *procAdmitter) merge(tables map[int]*fdTable, before map[int]map[string]uint64) {
	for pid, t := range tables {
		if t.gone {
			delete(a.fds, pid)
			continue
		}
		for name, old := range before[pid] {
			if old != 0 && t.names[name] != old && a.holder[old] == (fdRef{pid: pid, fd: name, ino: old}) {
				delete(a.holder, old)
			}
		}
		fds := a.fds[pid]
		if fds == nil {
			fds = &procFDs{}
			a.fds[pid] = fds
		}
		fds.names = t.names
		fds.freed = fds.freed[:0]
		if len(a.holder) >= admitterCacheCap {
			clear(a.holder)
		}
		for name, ino := range t.names {
			if ino == 0 {
				continue
			}
			if n, err := strconv.Atoi(name); err == nil && n > fds.top {
				fds.top = n
			}
			if h, ok := a.holder[ino]; !ok || h.pid > pid {
				a.holder[ino] = fdRef{pid: pid, fd: name, ino: ino}
			}
		}
	}
}

// probe reads the few descriptors of one process a new socket most likely has: a number it freed, or one just
// past its highest. A process whose table has not been listed yet has nothing to go on.
func (a *procAdmitter) probe(pid int, inode uint64) (fdRef, bool) {
	fds := a.fds[pid]
	if fds == nil {
		return fdRef{}, false
	}
	try := func(name string) (fdRef, bool) {
		ino := socketInode(a.readlink(pid, name))
		if ino == 0 {
			return fdRef{}, false
		}
		fds.names[name] = ino
		if n, err := strconv.Atoi(name); err == nil && n > fds.top {
			fds.top = n
		}
		ref := fdRef{pid: pid, fd: name, ino: ino}
		if h, ok := a.holder[ino]; !ok || h.pid > pid {
			a.holder[ino] = ref
		}
		return ref, ino == inode
	}
	// A freed number is read once: what it holds now is remembered like any other descriptor's.
	for len(fds.freed) > 0 {
		name := fds.freed[len(fds.freed)-1]
		fds.freed = fds.freed[:len(fds.freed)-1]
		if ref, ok := try(name); ok {
			return ref, true
		}
	}
	// try raises top for every socket it finds. Keep this attempt's upper bound fixed: otherwise each
	// unrelated socket advances the bound, and a missing inode scans every newly opened descriptor.
	top := fds.top
	for n := top + 1; n <= top+topProbe; n++ {
		if ref, ok := try(strconv.Itoa(n)); ok {
			return ref, true
		}
	}
	return fdRef{}, false
}

// readlink is one descriptor's link, "" when it cannot be read.
func (a *procAdmitter) readlink(pid int, fd string) string {
	a.links.Add(1)
	if a.linked != nil {
		a.linked(pid)
	}
	target, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/" + fd)
	if err != nil {
		return ""
	}
	return target
}

// socketInode is the inode a "socket:[N]" link names, 0 for any other link.
func socketInode(link string) uint64 {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
