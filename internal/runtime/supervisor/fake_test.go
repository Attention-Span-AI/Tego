// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"hash/fnv"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// testListener is the listener a Loop built over a fake kernel is given: New takes an owner, and the fake answers
// every listener call, so it is an inert owner whose Close closes nothing (sys.InertForTest), never a real
// descriptor of the test process.
func testListener() *sys.FD { return sys.InertForTest(3) }

// region is one mapping of the fake target's address space; a read that runs off its end returns a short
// count, which is how a real process_vm_readv behaves at the edge of a mapping (E19).
type region struct {
	addr uint64
	data []byte
}

// fakeKernel is the whole syscall seam under test control: a queue of notifications, an address space,
// the /proc links, and a record of everything the loop answered and did.
type fakeKernel struct {
	mu sync.Mutex

	pending []sysNotif
	regions []region
	links   map[string]string
	live    map[string]bool // links whose file still has a link: Unlinked is false for them, true for others
	stale   map[uint64]bool // notification ids the kernel reports as gone
	tgid    map[int]int
	stats   map[int]procStat
	// cgroups and pgrps are what ProcCgroup and ProcPgrp answer per pid (signal.go); a pid in neither is
	// gone (ESRCH).
	cgroups map[int]string
	pgrps   map[int]int
	// pgrpErrs fails ProcPgrp for a pid, as a /proc read the supervisor cannot make (EMFILE) would.
	pgrpErrs map[int]error
	// groupScans counts ProcessGroups calls, the whole-host /proc scans groupCache saves.
	groupScans int
	sockType   int
	// sockDomain is what SO_DOMAIN answers (AF_INET unless a test says otherwise), and sockDomainErr fails
	// the read.
	sockDomain    int
	sockDomainErr error
	// sourceRouted is what SourceRouted answers (a socket carrying an IP_OPTIONS or IPV6_RTHDR source route),
	// and sourceRoutedErr fails the read; sourceRouteReads counts the reads.
	sourceRouted     bool
	sourceRoutedErr  error
	sourceRouteReads int
	// udpCorked is what UDPCorked answers (a UDP socket with UDP_CORK set), and udpCorkedErr fails the read.
	udpCorked    bool
	udpCorkedErr error
	// sendHook, when set, runs at the start of every SendToRaw, outside mu, so a test can hold a relayed send in
	// flight while the loop handles another notification.
	sendHook func()
	// sockProto is what SO_PROTOCOL answers; 0, the default, names no protocol, so the socket type decides.
	sockProto int
	// sockProtoErr fails SO_PROTOCOL.
	sockProtoErr error
	// staleAfter makes ID_VALID start reporting the id gone once that many checks have been answered,
	// which is how a test places the target's death inside a specific bracket rather than before it.
	staleAfter int

	dupErr error
	// leadersOnly makes OpenPidFD behave like a kernel without PIDFD_THREAD; pidfdOpenedFor records
	// every id it was asked for, in order, so a test can see the fallback happen.
	leadersOnly bool
	// ownFiles names the tids that have a descriptor table of their own (a thread made without CLONE_FILES,
	// or one that unshared it), and kcmpErr fails every SameFiles, as a kernel without CONFIG_KCMP does.
	ownFiles       map[int]bool
	kcmpErr        error
	pidfdOpenedFor []int
	// signalled records every SignalPidFD: the pidfd, the signal, and how many responses preceded it.
	signalled []pidfdSignal
	sendErrno error
	// tgidReads counts Tgid calls, the /proc/<tid>/status reads tgidOf's cache saves.
	tgidReads int
	// sendFails and idValidFails fail the next Send or ID_VALID calls, one error each, in order;
	// idValidFailAll fails every ID_VALID.
	sendFails      []error
	idValidFails   []error
	idValidFailAll error
	waitErr        error
	recvErr        error
	// waitOn, when set, has Wait poll that real fd as the production kernel would (a closed one, say).
	waitOn     *sysKernel
	connected  bool
	peerChecks int
	sockTypErr error
	connectErr error
	sendErr    error
	readErr    error

	// syncWakeUps counts SetSyncWakeUp calls, and syncWakeUpErr is what each one returns.
	syncWakeUps   int
	syncWakeUpErr error

	// The unix relay (unixrelay.go). symlinks maps a sun_path the target passes onto the path it resolves
	// to, standing in for the O_PATH walk the real kernel makes as the task; a path with no entry resolves
	// to itself, or, relative, against the fake /proc/<tid>/cwd link. resolveErrs fails the walk of a
	// path with the errno the task's own lookup would get. taskErr fails TaskOf, credsErr the thread that
	// takes the task's credentials, and otherRoot gives the task a root of its own. otherView names the
	// resolved paths that, looked up in this process's own view, reach another inode than the task's walk
	// did (a mount tree that is not this process's, sameInodeHere). evalLinks is the filesystem
	// EvalSymlinks sees when the loop is built, for exec entries; a unix path is placed by PlaceLink over
	// links (placeLinks counts its reads), and racedDirs are directories an agent's thread made symlinks after a
	// placement's walk passed them: PlaceLink fails ELOOP below one, as agent.ReadPlaceLink's RESOLVE_NO_SYMLINKS
	// read does. unixConnects records, per relayed unix connect, the socket it reached: the resolved path, or
	// "@" and the abstract name.
	placeLinks   int
	racedDirs    map[string]bool
	symlinks     map[string]string
	resolveErrs  map[string]error
	taskErr      error
	credsErr     error
	otherRoot    bool
	otherView    map[string]bool
	taskCreds    sys.TaskCreds
	tasksOpened  []int
	evalLinks    map[string]string
	evals        int // EvalSymlinks calls
	unixConnects []string
	// unixSends are the sockets SendUnixAs sent to, as unixConnects names them.
	unixSends []string
	// sendsAs are the credentials each SendToRawAs ran with; its send is recorded in sends too.
	sendsAs []sys.TaskCreds
	// abstractNames are the abstract names sockets hold now, for UnixAbstractName.
	abstractNames map[sockID]string
	// R11a (unixorigin.go). sockID is what SocketID answers for any descriptor, the socket a bind names;
	// boundFiles is the kernel's socket table as UNIX_DIAG_VFS reports it, each live socket's file (a socket with
	// no entry is gone); diagErr fails every lookup, a kernel with no sock_diag for AF_UNIX. diagLookups counts them.
	// unboundSocks are live sockets bound to no file: a bind the run made that failed, or one not made yet.
	sockID       sockID
	boundFiles   map[sockID]fileID
	unboundSocks map[sockID]bool
	diagErr      error
	diagLookups  int
	// births is each file's birth time (STATX_BTIME, ns), by identity: a file a test binds a socket to is born when
	// it does (bindsSocket, takes); any other reads as born long before the run (fakeOldBirth), and a file in
	// noBirth reports none. foreignSocks are live sockets of this network namespace that no process of the run bound,
	// each bound to a file (UnixDump lists them beside boundFiles'); a foreign socket with no entry here is one in
	// another network namespace, or none at all. dumpErr fails UnixDump, and dumps counts the dumps. connectedSocks
	// are sockets of either map that are connected (TCP_ESTABLISHED), which a dump lists only when its need asks for
	// connected sockets; dumpSplit is a namespace whose sockets do not fit one pass of the kernel's walk, so a dump
	// whose need asks for one fails errUnixDumpSplit; dumpNeeds are the needs the dumps were made for.
	births         map[fileID]int64
	noBirth        map[fileID]bool
	foreignSocks   map[sockID]fileID
	dumpErr        error
	dumps          int
	connectedSocks map[sockID]bool
	dumpSplit      bool
	dumpNeeds      []dumpNeed
	// walkHook runs as UnixTarget walks q, before it answers: what another process does while a name is walked.
	walkHook func(q unixQuery)
	// walkDone runs once UnixTarget has walked q, before it answers: what the agent does between the loop's walk of a
	// name and the relay's.
	walkDone func(q unixQuery)
	// finalErrs fail a walk of the whole name (UnixTarget, ConnectUnixAs) at its last component — ENOENT for one
	// that names nothing yet, ELOOP for a magic link — while a walk of its directory (a bind's) lands. resolveErrs
	// fails both.
	finalErrs map[string]error
	// unixWalks counts UnixTarget calls, the walks of a unix name as the task.
	unixWalks int
	// sdevs maps a stat device to the superblock device UNIX_DIAG_VFS and mountinfo report for it, where a test
	// models btrfs (a subvolume's st_dev is its own); a device with no entry is its own superblock's. mountErr fails
	// MountDev; mountLookups counts it.
	sdevs        map[uint64]uint64
	mountErr     error
	mountLookups int

	// headless names exec images whose head the walk cannot read (withHead).
	headless map[string]bool
	// kidless names the images whose identity as the plane holds it cannot be read (pathQuery.kid); every other
	// image asked for one has its fake id on the device 8:1 in the kernel's encoding.
	kidless map[string]bool
	// The exec walk (ExecImage, R16b). images maps an exec query onto the image the task's own lookup
	// reaches, keyed by the query's R6 spelling or, for the descriptor form, "fd:<n>"; imageErrs fails the
	// walk with the errno that lookup meets. A query with no entry resolves as a plain, existing binary
	// would: to the file its spelling names, or to what the /proc/<tid>/fd/<n> link of the descriptor form
	// names (fakeImage). statIDs and statErrs answer StatID, fakeID of the path by default, so an entry
	// and the spelling that names it share an identity; statCounted counts the StatID calls for paths under
	// statCountPrefix (R11a's stats of unrecorded binds' paths). execQueries records every walk asked for.
	images          map[string]execImage
	imageErrs       map[string]error
	statIDs         map[string]fileID
	statErrs        map[string]error
	statCountPrefix string
	statCounted     int
	execQueries     []pathQuery
	// fsTargets maps an fs path's R6 spelling onto where the task's own lookup lands (FSTarget); a path
	// with no entry lands on itself. fsQueries records every walk asked for.
	fsTargets map[string]string
	// fsTargetErrs makes FSTarget fail for a spelling.
	fsTargetErrs map[string]error
	// quietWalks keeps FSTarget from recording its queries: a benchmark measures the loop's own work, and
	// every notified fs syscall is walked (R15b), so the slice would grow by one query per iteration.
	quietWalks bool
	fsQueries  []pathQuery
	// realWalks has FSTarget and ScanDir resolve with the real kernel, as this process: a benchmark's tree is
	// real. afterWalk, when set, runs after each real FSTarget walk: a test changes the tree between two walks of one
	// notification, as an agent racing its own syscall can.
	realWalks bool
	afterWalk func()
	// goneOnSend has an answered notification's id read gone from then on, as the kernel's does once
	// SECCOMP_IOCTL_NOTIF_SEND took the answer: a walk made after the answer cannot vouch for the task.
	goneOnSend bool
	// scans answers ScanDir by directory; a directory with no entry is not cached (ENOENT), so the walk cache
	// stays out of every test that does not ask for it. scanned counts the scans.
	scans   map[string]dirScan
	scanned int
	// finalLinks answers FinalIsLink, and finalStats counts its calls.
	finalLinks map[string]bool
	finalStats int
	// finalDirs answers FinalIsDir, finalDirErrs fails it for a name, and dirStats counts its calls.
	finalDirs    map[string]bool
	finalDirErrs map[string]error
	dirStats     int

	responses  []sysResp
	readlinks  int
	connects   [][]byte
	sends      []sentMsg
	idValid    int
	memReads   int
	memReadVs  int
	openFDs    int
	closedFDs  int
	closedList bool
	hup        bool
	nextFD     int
	waitCalled int
}

// procStat is one fake /proc/<pid>/stat answer.
type procStat struct {
	ppid  int
	start uint64
}

// sentMsg is one relayed send.
type sentMsg struct {
	payload []byte
	flags   int
	addr    []byte
}

// newFake builds an empty fake kernel.
func newFake() *fakeKernel {
	return &fakeKernel{
		links: map[string]string{}, stale: map[uint64]bool{},
		tgid: map[int]int{}, stats: map[int]procStat{},
		sockType: unix.SOCK_STREAM, sockDomain: unix.AF_INET, nextFD: 100,
		symlinks: map[string]string{}, resolveErrs: map[string]error{}, evalLinks: map[string]string{},
		otherView: map[string]bool{},
		images:    map[string]execImage{}, imageErrs: map[string]error{},
		statIDs: map[string]fileID{}, statErrs: map[string]error{}, fsTargets: map[string]string{}, fsTargetErrs: map[string]error{},
	}
}

// put maps data at addr in the fake address space.
func (f *fakeKernel) put(addr uint64, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.regions = append(f.regions, region{addr: addr, data: data})
}

// queue adds one notification for the loop to receive.
func (f *fakeKernel) queue(n sysNotif) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, n)
}

func (f *fakeKernel) Wait(wake, timeoutMS int) (waitState, error) {
	f.mu.Lock()
	f.waitCalled++
	if f.waitOn != nil {
		k := *f.waitOn
		f.mu.Unlock()
		return k.Wait(wake, timeoutMS)
	}
	if f.waitErr != nil {
		err := f.waitErr
		f.mu.Unlock()
		return waitTimeout, err
	}
	switch {
	case len(f.pending) > 0:
		f.mu.Unlock()
		return waitReady, nil
	case f.hup:
		f.mu.Unlock()
		return waitHup, nil
	}
	f.mu.Unlock()
	// An idle poll in the real kernel sleeps for the whole timeout; sleeping a slice of it here keeps a
	// Run test from spinning a core while it waits for its context to be cancelled.
	time.Sleep(time.Millisecond)
	return waitTimeout, nil
}

func (f *fakeKernel) Recv(n *sysNotif) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recvErr != nil {
		return f.recvErr
	}
	if len(f.pending) == 0 {
		return unix.ENOENT
	}
	*n = f.pending[0]
	f.pending = f.pending[1:]
	return nil
}

func (f *fakeKernel) Send(r *sysResp) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stale[r.ID] {
		return unix.ENOENT
	}
	if f.sendErrno != nil {
		return f.sendErrno
	}
	if len(f.sendFails) > 0 {
		err := f.sendFails[0]
		f.sendFails = f.sendFails[1:]
		return err
	}
	f.responses = append(f.responses, *r)
	if f.goneOnSend {
		f.stale[r.ID] = true
	}
	return nil
}

func (f *fakeKernel) IDValid(id uint64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idValid++
	if f.idValidFailAll != nil {
		return false, f.idValidFailAll
	}
	if len(f.idValidFails) > 0 {
		err := f.idValidFails[0]
		f.idValidFails = f.idValidFails[1:]
		return false, err
	}
	if f.staleAfter > 0 && f.idValid > f.staleAfter {
		return false, nil
	}
	return !f.stale[id], nil
}

func (f *fakeKernel) SetSyncWakeUp() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncWakeUps++
	return f.syncWakeUpErr
}

func (f *fakeKernel) CloseListener() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closedList = true
	return nil
}

func (f *fakeKernel) ReadMem(pid int, addr uint64, buf []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.memReads++
	if f.readErr != nil {
		return 0, f.readErr
	}
	for _, r := range f.regions {
		if addr < r.addr || addr >= r.addr+uint64(len(r.data)) {
			continue
		}
		off := int(addr - r.addr)
		n := copy(buf, r.data[off:])
		return n, nil
	}
	return 0, unix.EFAULT
}

// ReadMemV is the fake batched read: each segment from the regions in turn, stopping at the first one not read
// whole, as a fault ends a process_vm_readv at the segment it hit. It counts as one memory read.
func (f *fakeKernel) ReadMemV(pid int, segs []memSeg, buf []byte) (int, error) {
	f.mu.Lock()
	f.memReads++
	f.memReadVs++
	readErr := f.readErr
	f.mu.Unlock()
	if readErr != nil {
		return 0, readErr
	}
	off := 0
	for _, s := range segs {
		f.mu.Lock()
		got := 0
		for _, r := range f.regions {
			if s.addr < r.addr || s.addr >= r.addr+uint64(len(r.data)) {
				continue
			}
			got = copy(buf[off:off+s.n], r.data[int(s.addr-r.addr):])
			break
		}
		f.mu.Unlock()
		off += got
		if got < s.n {
			break
		}
	}
	return off, nil
}

// Readlink reads the /proc magic links in links, as the kernel interface's Readlink is for; a name outside /proc is
// refused EINVAL, read as no link, so a unix placement that read its names here instead of through PlaceLink follows
// none of their links and fails every placement test that follows one.
func (f *fakeKernel) Readlink(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readlinks++
	if !strings.HasPrefix(name, "/proc/") {
		return "", unix.EINVAL
	}
	if f.dupErr == unix.EPERM && ptraceGuardedLink(name) {
		return "", unix.EACCES
	}
	if v, ok := f.links[name]; ok {
		return v, nil
	}
	return "", unix.ENOENT
}

// ptraceGuardedLink reports whether name is one of the /proc/<pid> links the kernel reads only past
// proc_fd_access_allowed, ptrace_may_access(PTRACE_MODE_READ_FSCREDS): exe, cwd, root and fd/<n>. The check that
// answers a non-dumpable target's pidfd_getfd EPERM refuses these too, so a fake whose dupErr is EPERM, the fake of
// that target, refuses them EACCES.
func ptraceGuardedLink(name string) bool {
	pid, link, ok := strings.Cut(strings.TrimPrefix(name, "/proc/"), "/")
	if !ok || pid == "" || strings.Trim(pid, "0123456789") != "" {
		return false
	}
	return link == "exe" || link == "cwd" || link == "root" || strings.HasPrefix(link, "fd/")
}

// PlaceLink reads one name of a unix path being placed from links, failing ELOOP when a directory before it is in
// racedDirs: agent.ReadPlaceLink's read, which follows no symlink before the name.
func (f *fakeKernel) PlaceLink(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.placeLinks++
	for d := path.Dir(name); d != "/" && d != "."; d = path.Dir(d) {
		if f.racedDirs[d] {
			return "", unix.ELOOP
		}
	}
	if v, ok := f.links[name]; ok {
		return v, nil
	}
	return "", unix.ENOENT
}

func (f *fakeKernel) Unlinked(name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.links[name]; !ok {
		return false, unix.ENOENT
	}
	return !f.live[name], nil
}

func (f *fakeKernel) ProcStat(pid int) (int, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.stats[pid]; ok {
		return s.ppid, s.start, nil
	}
	return 0, 0, unix.ESRCH
}

func (f *fakeKernel) ProcCgroup(pid int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cg, ok := f.cgroups[pid]; ok {
		return cg, nil
	}
	return "", unix.ESRCH
}

func (f *fakeKernel) ProcPgrp(pid int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pgrpLocked(pid)
}

func (f *fakeKernel) pgrpLocked(pid int) (int, error) {
	if err, ok := f.pgrpErrs[pid]; ok {
		return 0, err
	}
	if g, ok := f.pgrps[pid]; ok {
		return g, nil
	}
	return 0, unix.ESRCH
}

// ProcessGroups scans the fake's pids through groupsOf, the scan sysKernel runs over /proc.
func (f *fakeKernel) ProcessGroups() (map[int][]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groupScans++
	var pids []int
	for pid := range f.pgrps {
		pids = append(pids, pid)
	}
	for pid := range f.pgrpErrs {
		if _, ok := f.pgrps[pid]; !ok {
			pids = append(pids, pid)
		}
	}
	return groupsOf(pids, f.pgrpLocked)
}

func (f *fakeKernel) Tgid(pid int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tgidReads++
	if t, ok := f.tgid[pid]; ok {
		return t, nil
	}
	return pid, nil
}

func (f *fakeKernel) InGroup(tgid, tid int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.tgid[tid]; ok {
		return t == tgid
	}
	return tid == tgid
}

func (f *fakeKernel) OpenPidFD(pid int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dupErr != nil {
		return -1, f.dupErr
	}
	// leadersOnly reproduces pidfd_open(2) without PIDFD_THREAD, which is what a kernel below 6.9
	// gives: pidfd_prepare requires a thread-group leader, so a secondary thread's tid is ENOENT.
	if f.leadersOnly {
		if tg, ok := f.tgid[pid]; ok && tg != pid {
			f.pidfdOpenedFor = append(f.pidfdOpenedFor, pid)
			return -1, unix.ENOENT
		}
	}
	f.pidfdOpenedFor = append(f.pidfdOpenedFor, pid)
	f.openFDs++
	f.nextFD++
	return f.nextFD, nil
}

// OpenPidFDProcess is the fallback a kernel below 6.9 forces: a process-scoped pidfd, which the real
// one only accepts for a thread-group leader. The fake models exactly that in OpenPidFD's leadersOnly
// branch, so the two share one implementation and a test can watch which id each was asked for.
func (f *fakeKernel) OpenPidFDProcess(pid int) (int, error) { return f.OpenPidFD(pid) }

// pidfdSignal is one SignalPidFD call; afterResponses is how many answers the loop had sent by then.
type pidfdSignal struct {
	pidfd          int
	sig            unix.Signal
	afterResponses int
}

func (f *fakeKernel) SignalPidFD(pidfd int, sig unix.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signalled = append(f.signalled, pidfdSignal{pidfd: pidfd, sig: sig, afterResponses: len(f.responses)})
	return nil
}

func (f *fakeKernel) SameFiles(a, b int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.kcmpErr != nil {
		return false, f.kcmpErr
	}
	return a == b || (!f.ownFiles[a] && !f.ownFiles[b]), nil
}

func (f *fakeKernel) GetFD(pidfd, fd int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dupErr != nil {
		return -1, f.dupErr
	}
	f.openFDs++
	f.nextFD++
	return f.nextFD, nil
}

func (f *fakeKernel) SockType(fd int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sockTypErr != nil {
		return 0, f.sockTypErr
	}
	return f.sockType, nil
}

func (f *fakeKernel) SockProtocol(fd int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sockProtoErr != nil {
		return 0, f.sockProtoErr
	}
	return f.sockProto, nil
}

func (f *fakeKernel) SockDomain(fd int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sockDomainErr != nil {
		return 0, f.sockDomainErr
	}
	return f.sockDomain, nil
}

func (f *fakeKernel) SourceRouted(fd, domain int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sourceRouteReads++
	return f.sourceRouted, f.sourceRoutedErr
}

func (f *fakeKernel) UDPCorked(int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.udpCorked, f.udpCorkedErr
}

func (f *fakeKernel) Connected(fd int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peerChecks++
	return f.connected
}

func (f *fakeKernel) ConnectRaw(fd int, sa []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connects = append(f.connects, append([]byte(nil), sa...))
	return f.connectErr
}

func (f *fakeKernel) SendToRaw(fd int, p []byte, flags int, sa []byte) (int, error) {
	f.mu.Lock()
	hook := f.sendHook
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends = append(f.sends, sentMsg{payload: append([]byte(nil), p...), flags: flags, addr: append([]byte(nil), sa...)})
	if f.sendErr != nil {
		return 0, f.sendErr
	}
	return len(p), nil
}

// SendToRawAs is SendToRaw that also records the credentials it ran with.
func (f *fakeKernel) SendToRawAs(fd int, task taskView, p []byte, flags int, sa []byte) (int, error) {
	f.mu.Lock()
	f.sendsAs = append(f.sendsAs, task.creds)
	f.mu.Unlock()
	return f.SendToRaw(fd, p, flags, sa)
}

func (f *fakeKernel) TaskOf(tid int) (taskView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.taskErr != nil {
		return taskView{}, f.taskErr
	}
	f.tasksOpened = append(f.tasksOpened, tid)
	f.openFDs += 2
	f.nextFD += 2
	return taskView{tid: tid, creds: f.taskCreds, root: f.nextFD - 1, cwd: f.nextFD, sameRoot: !f.otherRoot}, nil
}

// ConnectUnixAs mirrors the real one's order: take the credentials, resolve the path as the task, ask
// admit about what it resolved to, and only then connect.
func (f *fakeKernel) ConnectUnixAs(fd int, task taskView, sa []byte, sunPath string, admit func(string, unixFile) bool) (unixOutcome, error) {
	reached, to, out, err := f.reachUnix(task, sa, sunPath, admit)
	if out != unixConnected {
		return out, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unixConnects = append(f.unixConnects, reached)
	f.connects = append(f.connects, to)
	return unixConnected, f.connectErr
}

// SendUnixAs is ConnectUnixAs's order with a send in place of the connect: the datagram is recorded in sends, to
// the address the inode reached stands for, and the socket it reached in unixSends.
func (f *fakeKernel) SendUnixAs(fd int, task taskView, sa []byte, sunPath string, p []byte, flags int, admit func(string, unixFile) bool) (unixOutcome, int, error) {
	reached, to, out, err := f.reachUnix(task, sa, sunPath, admit)
	if out != unixConnected {
		return out, 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unixSends = append(f.unixSends, reached)
	f.sends = append(f.sends, sentMsg{payload: append([]byte(nil), p...), flags: flags, addr: to})
	if f.sendErr != nil {
		return unixConnected, 0, f.sendErr
	}
	return unixConnected, len(p), nil
}

// reachUnix is the fake relay's walk and admit: the socket a unix name reaches as the task, and the sockaddr the
// relay then connects or sends to; out is unixConnected when admit admitted it.
func (f *fakeKernel) reachUnix(task taskView, sa []byte, sunPath string, admit func(string, unixFile) bool) (string, []byte, unixOutcome, error) {
	f.mu.Lock()
	credsErr := f.credsErr
	f.mu.Unlock()
	if credsErr != nil {
		return "", nil, unixNoCredentials, credsErr
	}
	if sunPath == "" {
		if !admit("", unixFile{}) {
			return "", nil, unixRefused, nil
		}
		return "@" + string(sa[min(len(sa), sunPathOff+1):]), append([]byte(nil), sa...), unixConnected, nil
	}
	if err := f.finalErr(sunPath); err != nil {
		return "", nil, unixWalkOutcome(err), err
	}
	resolved, out, err := f.resolveUnix(task, sunPath)
	if err != nil {
		return "", nil, out, err
	}
	file, err := f.UnixFile(resolved) // the inode the walk reached, as the real relay statx-es it
	if err != nil {
		return "", nil, unixUnresolved, err
	}
	if !admit(resolved, file) {
		return "", nil, unixRefused, nil
	}
	if len(resolved) < sunPathMax {
		return resolved, sockaddrUn(resolved), unixConnected, nil
	}
	// No sockaddr_un names a path this long; the real relay reaches it through a descriptor.
	return resolved, []byte(resolved), unixConnected, nil
}

// resolveUnix is the fake O_PATH walk.
func (f *fakeKernel) resolveUnix(task taskView, sunPath string) (string, unixOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.resolveErrs[sunPath]; ok {
		if err == unix.ELOOP {
			return "", unixUnreliable, err // a magic link, refused rather than followed (openSocketPath)
		}
		return "", unixUnresolved, err
	}
	resolved := ""
	switch r, ok := f.symlinks[sunPath]; {
	case ok:
		resolved = r
	case strings.HasPrefix(sunPath, "/"):
		resolved = cleanPath(sunPath)
	}
	if resolved != "" {
		if f.otherView[resolved] {
			return "", unixUnreliable, errOtherView
		}
		return resolved, unixConnected, nil
	}
	if !task.sameRoot {
		return "", unixOtherRoot, errOtherRoot
	}
	cwd, ok := f.links["/proc/"+strconv.Itoa(task.tid)+"/cwd"]
	if !ok {
		return "", unixUnresolved, unix.ENOENT
	}
	return cleanPath(cwd + "/" + sunPath), unixConnected, nil
}

func (f *fakeKernel) EvalSymlinks(p string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evals++
	if r, ok := f.evalLinks[p]; ok {
		return r, nil
	}
	return "", unix.ENOENT
}

// ExecImage is the fake exec walk: the image a test mapped for the query, or the default fakeImage.
func (f *fakeKernel) ExecImage(q pathQuery) (execImage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execQueries = append(f.execQueries, q)
	key := q.joined
	if q.empty {
		key = "fd:" + strconv.Itoa(int(q.dirfd))
	}
	if err, ok := f.imageErrs[key]; ok {
		return execImage{}, err
	}
	if img, ok := f.images[key]; ok {
		if img.name == "" && namedByWalk(q) {
			img.name = q.joined // a test's image named by its spelling's directory, as a walk through real directories names it
		}
		return f.withHead(q, key, img), nil
	}
	name := q.joined
	if q.empty {
		f.readlinks++
		link, ok := f.links["/proc/"+strconv.Itoa(q.tid)+"/fd/"+strconv.Itoa(int(q.dirfd))]
		if !ok {
			return execImage{}, unix.EBADF
		}
		name = link
	}
	if name == "" {
		return execImage{}, unix.ENOENT
	}
	img := fakeImage(name)
	if namedByWalk(q) {
		img.name = q.joined
	}
	return f.withHead(q, key, img), nil
}

// withHead gives an image an ELF's first bytes when the query asks for its head and the test gave it none, as the
// real walk reads them from any readable file; headless names the images whose head cannot be read (an execute-only
// file at tier 1). Called with f.mu held.
func (f *fakeKernel) withHead(q pathQuery, key string, img execImage) execImage {
	switch {
	case !q.head:
		img.head = nil
	case f.headless[key]:
		img.head = nil
	case img.head == nil:
		img.head = []byte("\x7fELF")
	}
	if q.kid && !f.kidless[key] {
		img.kid, img.kidOK = fileID{dev: 8<<20 | 1, ino: img.id.ino}, true
	}
	return img
}

// fakeImage is the image a name resolves to when a test says nothing else: a file, linked unless
// the name carries the kernel's spelling of an unlinked or anonymous one, identified by fakeID of the name
// without the " (deleted)" marker.
func fakeImage(link string) execImage {
	bare := strings.TrimSuffix(link, deletedSuffix)
	linked := bare == link && !strings.HasPrefix(link, "/memfd:")
	return execImage{
		id: fakeID(bare), linked: linked, link: link,
		here: linked && strings.HasPrefix(link, "/"),
	}
}

// fakeID is the fake identity of a path: one device, the path's 32-bit hash as the inode (the width ext4 and tmpfs
// give, which R11a's implicit admit needs; a test that wants a wider one sets statIDs).
func fakeID(p string) fileID {
	h := fnv.New32a()
	_, _ = h.Write([]byte(p))
	return fileID{dev: 1, ino: uint64(h.Sum32())}
}

// fakeMountBase turns a device into the fake id of the mount it lies on (UnixFile, MountDev).
const fakeMountBase = 1000

// sdevOf is the superblock device of a file on stat device dev: sdevs[dev] where a test models a btrfs subvolume,
// else dev itself.
func (f *fakeKernel) sdevOfLocked(dev uint64) uint64 {
	if sb, ok := f.sdevs[dev]; ok {
		return sb
	}
	return dev
}

// UnixTarget is the fake walk of a unix name as the task (unixname.go), the relay's own (resolveUnix): resolveErrs
// fails it with the errno the task's lookup meets (ELOOP for a magic link), symlinks maps a sun_path onto where the
// walk lands, a name with no entry lands on its cleaned self (a relative one on the fake cwd joined with it, refused
// with otherRoot), and otherView names landings this process cannot see. A bind's (q.parent) is the directory of
// where its file lands. The identity is StatID's (statErrs fail it), on a mount named after its device.
func (f *fakeKernel) UnixTarget(q unixQuery) (unixPlace, error) {
	f.mu.Lock()
	f.unixWalks++
	hook := f.walkHook
	f.mu.Unlock()
	if hook != nil {
		hook(q)
	}
	if q.parent {
		if _, ok := bindParent(q.path); !ok {
			return unixPlace{}, errNoFinal
		}
	} else if err := f.finalErr(q.path); err != nil {
		return unixPlace{}, err
	}
	at, _, err := f.resolveUnix(taskView{tid: q.tid, sameRoot: !f.otherRoot}, q.path)
	if err != nil {
		return unixPlace{}, err
	}
	if q.parent {
		at = path.Dir(at)
	}
	file, err := f.UnixFile(at)
	if err != nil {
		return unixPlace{}, err
	}
	f.mu.Lock()
	done := f.walkDone
	f.mu.Unlock()
	if done != nil {
		done(q)
	}
	return unixPlace{at: at, file: file}, nil
}

// finalErr is what a walk of the whole name sunPath meets at its last component (finalErrs), nil when it lands.
func (f *fakeKernel) finalErr(sunPath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.finalErrs[sunPath]
}

// fakeOldBirth is when a fake file no test bound a socket to was born: 2026-01-01, long before any run.
const fakeOldBirth = int64(1767225600) * int64(time.Second)

// UnixFile answers StatID's identity, on a mount named after its device, born when births says (fakeOldBirth by
// default; none when noBirth says so).
func (f *fakeKernel) UnixFile(p string) (unixFile, error) {
	id, err := f.StatID(p)
	if err != nil {
		return unixFile{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	born, ok := f.births[id]
	switch {
	case f.noBirth[id]:
		born = 0
	case !ok:
		born = fakeOldBirth
	}
	return unixFile{dev: id.dev, ino: id.ino, mnt: fakeMountBase + id.dev, born: born}, nil
}

// bornLocked has the file id born at `at` (ns), as a bind making it now would. Called with f.mu held.
func (f *fakeKernel) bornLocked(id fileID, at int64) {
	if f.births == nil {
		f.births = map[fileID]int64{}
	}
	f.births[id] = at
}

// UnixDump lists the fake namespace's sockets bound to a file (R11a): boundFiles', the run's and any other a test
// put there, and foreignSocks', each as UNIX_DIAG_VFS reports it, the connected ones (connectedSocks) only when need
// asks for them; dumpErr fails it, past limit it fails closed, and a namespace too big for one pass (dumpSplit) fails
// a dump that needs one.
func (f *fakeKernel) UnixDump(limit int, need dumpNeed) ([]unixDumpEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dumps++
	f.dumpNeeds = append(f.dumpNeeds, need)
	if f.dumpErr != nil {
		return nil, f.dumpErr
	}
	if len(f.boundFiles)+len(f.foreignSocks) > limit {
		return nil, errUnixDumpCap
	}
	if need.onePass && f.dumpSplit {
		return nil, errUnixDumpSplit
	}
	var out []unixDumpEntry
	for _, socks := range []map[sockID]fileID{f.boundFiles, f.foreignSocks} {
		for id, file := range socks {
			if f.connectedSocks[id] && !need.connected {
				continue
			}
			out = append(out, unixDumpEntry{id: id, b: f.bindingLocked(file)})
		}
	}
	return out, nil
}

// bindingLocked is what UNIX_DIAG_VFS reports of a socket bound to file. Called with f.mu held.
func (f *fakeKernel) bindingLocked(file fileID) unixBinding {
	sb := f.sdevOfLocked(file.dev)
	return unixBinding{bound: true, major: unix.Major(sb), minor: unix.Minor(sb), ino32: uint32(file.ino)}
}

// MountDev answers the superblock device of the fake mount (sdevs), or mountErr.
func (f *fakeKernel) MountDev(mnt uint64) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mountLookups++
	if f.mountErr != nil {
		return 0, f.mountErr
	}
	return f.sdevOfLocked(mnt - fakeMountBase), nil
}

// FSTarget is the fake fs walk: where a test says the path lands, or the path itself. A pathname with a ".." component
// is named where it lands, as the real walk names an end it does not follow.
func (f *fakeKernel) FSTarget(q pathQuery) (fsLanding, error) {
	if f.realWalks {
		q.tid = os.Getpid()
		if f.afterWalk != nil {
			defer f.afterWalk()
		}
		return sysKernel{}.FSTarget(q)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.quietWalks {
		f.fsQueries = append(f.fsQueries, q)
	}
	if err, ok := f.fsTargetErrs[q.joined]; ok {
		return fsLanding{}, err
	}
	at := q.joined
	if to, ok := f.fsTargets[q.joined]; ok {
		at = to
	}
	if namedByWalk(q) {
		return fsLanding{at: at, name: at}, nil
	}
	return fsLanding{at: at}, nil
}

// ScanDir is the fake directory scan (walkcache.go).
func (f *fakeKernel) ScanDir(dir string) (dirScan, error) {
	if f.realWalks {
		return sysKernel{}.ScanDir(dir)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.scans[dir]
	if !ok {
		return dirScan{}, unix.ENOENT
	}
	f.scanned++
	return s, nil
}

// FinalIsLink is the fake final-name stat: a name in links is a symlink.
func (f *fakeKernel) FinalIsLink(p string) (bool, error) {
	if f.realWalks {
		return sysKernel{}.FinalIsLink(p)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalStats++
	_, ok := f.finalLinks[p]
	return ok, nil
}

// FinalIsDir is the fake final-name stat: a name in finalDirs is a directory.
func (f *fakeKernel) FinalIsDir(p string) (bool, error) {
	if f.realWalks {
		return sysKernel{}.FinalIsDir(p)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirStats++
	if err := f.finalDirErrs[p]; err != nil {
		return false, err
	}
	return f.finalDirs[p], nil
}

// SocketID answers the socket every descriptor stands for in this fake (R11a).
func (f *fakeKernel) SocketID(int) (sockID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sockID == (sockID{}) {
		return sockID{ino: 4242, cookie: 77}, nil
	}
	return f.sockID, nil
}

// UnixBound answers from boundFiles, as UNIX_DIAG_VFS would (R11a).
func (f *fakeKernel) UnixBound(id sockID) (unixBinding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.diagLookups++
	if f.diagErr != nil {
		return unixBinding{}, f.diagErr
	}
	file, ok := f.boundFiles[id]
	if !ok {
		if f.unboundSocks[id] {
			return unixBinding{}, nil
		}
		return unixBinding{}, errSocketGone
	}
	return f.bindingLocked(file), nil
}

// UnixAbstractName answers from abstractNames: "" for a socket bound to no abstract name, errSocketGone for one the
// fake knows nothing of.
func (f *fakeKernel) UnixAbstractName(id sockID) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.diagErr != nil {
		return "", f.diagErr
	}
	if name, ok := f.abstractNames[id]; ok {
		return name, nil
	}
	if _, ok := f.boundFiles[id]; ok || f.unboundSocks[id] {
		return "", nil
	}
	return "", errSocketGone
}

// bindsAbstract has the run bind a socket to the abstract name (ADR 0070): a bind notification the loop records, and
// the kernel's table then naming the socket's name. It returns the socket.
func (f *fakeKernel) bindsAbstract(t testing.TB, l *Loop, id sockID, name string) sockID {
	t.Helper()
	at := uint64(0x7e000 + (id.ino%64)*0x100)
	sa := sockaddrUn("@" + name)
	f.mu.Lock()
	f.sockID = id
	f.mu.Unlock()
	f.put(at, sa)
	handleBind(l, notifFor(connectNR(), 4242, 5, at, uint64(len(sa))))
	f.mu.Lock()
	if f.abstractNames == nil {
		f.abstractNames = map[sockID]string{}
	}
	f.abstractNames[id] = name
	f.mu.Unlock()
	return id
}

// bindsSocket has the run bind a socket to path p (R11a): a bind notification the loop records, and the kernel's
// table then naming the socket's file as StatID names p's. It returns the socket.
func (f *fakeKernel) bindsSocket(t testing.TB, l *Loop, id sockID, p string) sockID {
	t.Helper()
	at := uint64(0x7f000 + (id.ino%64)*0x100) // the fake reads the first region at an address: one per socket
	sa := sockaddrUn(p)
	f.mu.Lock()
	f.sockID = id
	f.mu.Unlock()
	f.put(at, sa)
	handleBind(l, notifFor(connectNR(), 4242, 5, at, uint64(len(sa))))
	file, err := f.StatID(p)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.boundFiles == nil {
		f.boundFiles = map[sockID]fileID{}
	}
	f.boundFiles[id] = file
	f.bornLocked(file, time.Now().UnixNano())
	f.mu.Unlock()
	return id
}

// bindNow is the moment a test's bind of a socket is answered, as recordRunSocket takes it (R11a).
func bindNow() int64 { return time.Now().UnixNano() }

// LstatID answers as StatID: the fake has no symlinks to leave unfollowed.
func (f *fakeKernel) LstatID(p string) (fileID, error) { return f.StatID(p) }

// StatID answers a declared exec entry's identity.
func (f *fakeKernel) StatID(p string) (fileID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statCountPrefix != "" && strings.HasPrefix(p, f.statCountPrefix) {
		f.statCounted++
	}
	if err, ok := f.statErrs[p]; ok {
		return fileID{}, err
	}
	if id, ok := f.statIDs[p]; ok {
		return id, nil
	}
	return fakeID(p), nil
}

func (f *fakeKernel) CloseFD(fd int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closedFDs++
	return nil
}

// lastResp is the most recent response, or false when the loop answered nothing.
func (f *fakeKernel) lastResp() (sysResp, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.responses) == 0 {
		return sysResp{}, false
	}
	return f.responses[len(f.responses)-1], true
}

// respCount is how many responses the loop has sent.
func (f *fakeKernel) respCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.responses)
}

// fdBalance reports the descriptors the loop took and did not close.
func (f *fakeKernel) fdBalance() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.openFDs - f.closedFDs
}

// testSink collects events.
type testSink struct {
	mu     sync.Mutex
	events []*record.Event
}

func (s *testSink) Emit(ev *record.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *testSink) all() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*record.Event(nil), s.events...)
}

func (s *testSink) one(t *testing.T) *record.Event {
	t.Helper()
	evs := s.all()
	if len(evs) != 1 {
		t.Fatalf("want exactly one event, got %d: %+v", len(evs), evs)
	}
	return evs[0]
}

// staticResolver is a Resolver over a fixed rule list, standing in for a *dns.Set where the test does not
// need TTL behaviour.
type staticResolver struct {
	set       *dns.Set
	resolvers []netip.AddrPort
}

func (r staticResolver) Match(dst netip.AddrPort, proto string) *NetMatch {
	return r.set.Match(dst, proto)
}

func (r staticResolver) ResolverAddrs() []netip.AddrPort { return r.resolvers }

// testPolicy builds a policy over the given net and fs rules.
func testPolicy(net []agent.NetRule, fs []agent.FSRule, resolvers []netip.AddrPort) *Policy {
	rt := &agent.RuleTable{Net: net, FS: fs, Record: agent.RecordSummary}
	return &Policy{
		Rules:    rt,
		Resolver: staticResolver{set: dns.NewSet(net, resolvers, dns.Options{}), resolvers: resolvers},
		RunID:    "2026-09-22T00-00-00Z-abcd",
		Agent:    "claude-code",
	}
}

// netRule is one compiled inet allow entry. It carries no name of its own: agent.NetRule.RuleName
// derives one from Raw, the entry as the contract declared it.
func netRule(raw, host string, port int, ips ...string) agent.NetRule {
	r := agent.NetRule{
		Raw: raw, Host: host, Port: port, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
		Static: true, TTL: time.Minute, ResolvedAt: time.Now(),
	}
	for _, ip := range ips {
		r.IPs = append(r.IPs, netip.MustParseAddr(ip))
	}
	return r
}

// unixRuleOf is one compiled unix: allow entry.
func unixRuleOf(raw, path string, abstract bool) agent.NetRule {
	return agent.NetRule{
		Raw: raw, Proto: agent.ProtoUnix, UnixPath: path, Abstract: abstract,
		Verdict: agent.VerdictAllow, Static: true,
	}
}

// newTestLoop builds a Loop over the fake kernel.
func newTestLoop(t *testing.T, f *fakeKernel, pol *Policy) (*Loop, *testSink) {
	t.Helper()
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, sink
}

// notifFor builds a notification for the native architecture.
func notifFor(nr int32, pid int, args ...uint64) *notif {
	n := &notif{id: 7, pid: pid, arch: nativeAuditArch(), nr: nr, recvAt: time.Now()}
	copy(n.args[:], args)
	return n
}

// sockaddrIn4 is a sockaddr_in for ip:port.
func sockaddrIn4(ip string, port uint16) []byte {
	b := make([]byte, 16)
	b[0], b[1] = unix.AF_INET, 0
	b[2], b[3] = byte(port>>8), byte(port)
	copy(b[4:8], netip.MustParseAddr(ip).AsSlice())
	return b
}

// sockaddrIn6 is a sockaddr_in6 for [ip]:port.
func sockaddrIn6(ip string, port uint16) []byte {
	b := make([]byte, 28)
	b[0], b[1] = unix.AF_INET6, 0
	b[2], b[3] = byte(port>>8), byte(port)
	copy(b[8:24], netip.MustParseAddr(ip).AsSlice())
	return b
}

// sockaddrUn is a sockaddr_un for a pathname or (with a leading @) an abstract name.
func sockaddrUn(path string) []byte {
	b := make([]byte, 2+sunPathMax)
	b[0], b[1] = unix.AF_UNIX, 0
	if len(path) > 0 && path[0] == '@' {
		copy(b[3:], path[1:])
		return b[:3+len(path)-1]
	}
	copy(b[2:], path)
	return b[:2+len(path)+1]
}
