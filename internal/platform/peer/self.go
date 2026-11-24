// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
)

// Self is the run-membership answer for this process (runscope.Decide over the kernel's reads): whether it is
// outside every tego run made inside its own cgroup namespace. Only Answer.Outside permits what a governed agent
// must not do; Inside and Unknown both refuse. It is computed afresh on every call: the process's own cgroup path,
// its namespace file and, outside the kernel's first cgroup namespace, its ids, capabilities, seccomp mode and the
// anchored path are read each time, and only the proof of step 8 (runscope.Prove) is remembered, in this process's
// memory, for its namespace and uid. Nothing of the answer is written to a file, the environment, an argument or a
// pipe: a process that needs the answer asks for itself.
//
// In the first cgroup namespace (ordinary Linux) it opens /proc/self/cgroup and /proc/self/ns/cgroup, and when the
// path shows no run asks the gate whether the machine is WSL (withheld: uname, and lstat of WSL's marks). In any
// other it may connect once to the user's service manager (/run/user/<uid>/systemd/private), sends
// nothing, and waits at most ProbeLimit.
func Self() runscope.Answer {
	k := &selfReads{host: machine, prover: selfProver}
	defer k.close()
	return runscope.Decide(k)
}

// The limits of the proof (the signed rule's steps 7 and 8).
const (
	// ProbeLimit is the longest a caller waits for a probe. A probe still running then is abandoned and its
	// result discarded.
	ProbeLimit = 500 * time.Millisecond
	// probeBackoff is how long a failed probe's answer is returned without probing again.
	probeBackoff = time.Second
	// connectEvery is the pause between two connects while the manager's accept queue is full, and connectReserve
	// what the retries leave of ProbeLimit for the reads that follow, so that a queue that stays full reads as
	// manager-busy and not as the caller's own timeout.
	connectEvery   = 20 * time.Millisecond
	connectReserve = 60 * time.Millisecond
	// procReadLimit caps every read of a /proc file the rule makes.
	procReadLimit = 64 << 10
)

// The kernel's magic numbers for the two filesystems the rule reads (include/uapi/linux/magic.h).
const (
	nsfsMagic   = 0x6e736673
	procMagic   = 0x9fa0
	procRootIno = 1
)

// selfHost is where Self reads: the absolute paths of the kernel's files and the manager's socket, and the reads of
// the gate. machine is the running system; tests point single paths at fixtures.
type selfHost struct {
	selfCgroup string                         // /proc/self/cgroup
	selfNS     string                         // /proc/self/ns/cgroup
	proc       string                         // /proc
	socket     func(uid int) string           // the user manager's private socket
	release    func() (string, error)         // the kernel release, uname's
	exists     func(path string) bool         // whether a path is there, true when that cannot be told
	nsOwner    func(*sys.FD) (*sys.FD, error) // NS_GET_USERNS
	uids       func() (int, int, int)
	permitted  func() (uint64, error)
	seccomp    func() (int, error)
}

var machine = selfHost{
	selfCgroup: "/proc/self/cgroup",
	selfNS:     "/proc/self/ns/cgroup",
	proc:       "/proc",
	socket:     runscope.ManagerSocket,
	release:    kernelRelease,
	exists:     pathExists,
	nsOwner:    (*sys.FD).NamespaceOwner,
	uids:       unix.Getresuid,
	permitted: func() (uint64, error) {
		_, permitted, _, err := sys.Capabilities()
		return permitted, err
	},
	seccomp: sys.SeccompMode,
}

func kernelRelease() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Release[:]), nil
}

// pathExists reports whether path is there, without following a final link. Anything but "no such file" counts as
// there: the gate that asks fails closed.
func pathExists(path string) bool {
	var st unix.Stat_t
	err := unix.Lstat(path, &st)
	return err == nil || !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR)
}

// wslMarks are the files a WSL 2 distribution has: the folder of its launcher's sockets and the binfmt_misc entries
// that hand Windows programs to its launcher. The two binfmt_misc entries are one mark (the same registration, made
// early or late); the folder is another; the kernel release a third.
var wslMarks = []string{"/run/WSL", "/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late"}

// Detection of WSL is asymmetric (ADR 0100, amended 2026-11-19, round 5), by facts and never by an environment
// variable (wslMarkCount counts three independent marks):
//   - any ONE mark is enough to hold or restrict: the gate withholds an outside answer, tego doctor and
//     tego setup withhold WSL readiness (WSLGateHolds), compile refuses WSL's launcher sockets. A distribution with
//     interop off may show its kernel release alone, and a mark that cannot be looked at counts as there, so a
//     machine that shows one mark is treated as WSL wherever that makes tego more careful;
//   - a RELAXATION needs two: the rule's answer of outside on WSL, and every step marked ready because of it,
//     is given only where two marks show the machine is the WSL whose launcher refusal was proven, never on one.
//
// An ordinary Linux machine shows none and keeps its answers; one whose /run/WSL a security module refuses to show
// gives one mark and is held as WSL is (the fail-closed side).
func (h selfHost) wslMarks() int {
	release, err := h.release()
	return wslMarkCount(release, err == nil, h.exists)
}

// wslMarkCount counts the independent marks of WSL that hold: the kernel release names Microsoft or WSL (a release
// that cannot be read counts as this mark), WSL's launcher folder is there, and one of WSL's binfmt_misc entries is
// there. A mark whose file cannot be looked at counts as there (exists fails closed), so a refusal to look at one
// file adds one mark, never two.
func wslMarkCount(release string, releaseRead bool, exists func(string) bool) int {
	n := 0
	release = strings.ToLower(release)
	if !releaseRead || strings.Contains(release, "microsoft") || strings.Contains(release, "wsl") {
		n++
	}
	if exists(wslMarks[0]) {
		n++
	}
	if exists(wslMarks[1]) || exists(wslMarks[2]) {
		n++
	}
	return n
}

// WSLGateHolds reports whether the gate holds an outside answer back here because of WSL: any one of WSL's marks holds
// (the careful side), and the rule's relaxation on WSL does not apply (it needs two marks and this build's
// switch, wslRuleOn). tego doctor and tego setup withhold WSL readiness for exactly as long (internal/doctor's WSL
// qualification), so one switch decides both: the commit that turns the rule on for WSL in every build turns readiness
// on with it, and is made only when the guest has proven the launcher, home-folder alias, Windows drive and GUI and
// audio socket rows (ADR 0100, amendments of 2026-11-19, rounds 4 and 5). A test build lifts both with its switch
// (wslgate_testhook.go) on a machine that shows two marks, never on one.
func WSLGateHolds() bool { return machine.wslHolds() }

// wslHolds is WSLGateHolds on h's facts.
func (h selfHost) wslHolds() bool { return h.wslHoldsAt(h.wslMarks()) }

// wslHoldsAt is wslHolds with the number of marks already counted: any one holds, unless two do and the switch is on.
func (selfHost) wslHoldsAt(n int) bool { return n >= 1 && !(n >= 2 && wslRuleOn()) }

// selfReads is runscope.Facts over the kernel, for one call of Self. It holds the two descriptors the later steps
// reuse: the verified namespace file and the anchored /proc.
type selfReads struct {
	host   selfHost
	prover *prover
	nsfd   *sys.FD
	procfd *sys.FD
}

func (k *selfReads) close() {
	_ = k.nsfd.Close()
	_ = k.procfd.Close()
}

func (k *selfReads) OwnCgroup() ([]byte, error) { return os.ReadFile(k.host.selfCgroup) }

// CgroupNS opens this process's cgroup namespace file for reading (not O_PATH: the probe's ioctls need a real open),
// and takes its identity from that descriptor once fstatfs has shown it to be the kernel's namespace filesystem. A
// file of any other filesystem with a chosen inode number (FUSE, tmpfs) is an error.
func (k *selfReads) CgroupNS() (runscope.Namespace, error) {
	fd, ns, err := openNamespace(k.host.selfNS)
	if err != nil {
		return runscope.Namespace{}, err
	}
	k.nsfd = fd
	return ns, nil
}

// openNamespace opens the namespace file at path for reading and verifies it: fstatfs must say nsfs, and fstat
// gives its device and inode.
func openNamespace(path string) (*sys.FD, runscope.Namespace, error) {
	fd, err := sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, runscope.Namespace{}, fmt.Errorf("open %s: %w", path, err)
	}
	ns, err := namespaceOf(fd)
	if err != nil {
		_ = fd.Close()
		return nil, runscope.Namespace{}, fmt.Errorf("%s: %w", path, err)
	}
	return fd, ns, nil
}

// errNotNSFS is a descriptor that is not a file of the kernel's namespace filesystem.
var errNotNSFS = errors.New("not a kernel namespace file (fstatfs is not nsfs)")

// namespaceOf is the device and inode of a descriptor fstatfs shows to be a namespace file.
func namespaceOf(fd *sys.FD) (runscope.Namespace, error) {
	var fs unix.Statfs_t
	if err := fd.Fstatfs(&fs); err != nil {
		return runscope.Namespace{}, fmt.Errorf("fstatfs: %w", err)
	}
	if int64(fs.Type) != nsfsMagic {
		return runscope.Namespace{}, errNotNSFS
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return runscope.Namespace{}, fmt.Errorf("fstat: %w", err)
	}
	return runscope.Namespace{Dev: st.Dev, Ino: st.Ino}, nil
}

func (k *selfReads) UIDs() (int, int, int)      { return k.host.uids() }
func (k *selfReads) Permitted() (uint64, error) { return k.host.permitted() }
func (k *selfReads) Seccomp() (int, error)      { return k.host.seccomp() }

// AnchoredCgroup anchors /proc and reads this process's cgroup file again through it.
func (k *selfReads) AnchoredCgroup() ([]byte, error) {
	fd, err := anchorProc(k.host.proc)
	if err != nil {
		return nil, err
	}
	k.procfd = fd
	return anchoredRead(fd, "self/cgroup")
}

// anchorProc opens the directory at path without following it and proves it is the root of a procfs: fstatfs says
// procfs and fstat says inode 1. Anything else wraps runscope.ErrUnanchored: an overmounted /proc, a bind of one of
// its subdirectories, a FUSE or tmpfs tree that imitates it.
func anchorProc(path string) (*sys.FD, error) {
	fd, err := sys.Own(unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", runscope.ErrUnanchored, path, err)
	}
	var fs unix.Statfs_t
	var st unix.Stat_t
	switch err1, err2 := fd.Fstatfs(&fs), fd.Fstat(&st); {
	case err1 != nil || err2 != nil:
		err = fmt.Errorf("%w: %s: %w", runscope.ErrUnanchored, path, errors.Join(err1, err2))
	case int64(fs.Type) != procMagic:
		err = fmt.Errorf("%w: %s is not a procfs", runscope.ErrUnanchored, path)
	case st.Ino != procRootIno:
		err = fmt.Errorf("%w: %s is not the root of its procfs (inode %d)", runscope.ErrUnanchored, path, st.Ino)
	}
	if err != nil {
		_ = fd.Close()
		return nil, err
	}
	return fd, nil
}

// anchoredRead reads the file at the relative path beneath the anchored /proc, to its end and at most
// procReadLimit: openat2 with RESOLVE_BENEATH, RESOLVE_NO_XDEV and RESOLVE_NO_MAGICLINKS, so the walk cannot leave
// the procfs, cross a mount laid over part of it, or follow a link the kernel resolves outside the tree. A failed
// open wraps runscope.ErrUnanchored with its errno; a failed read is the read's own error.
func anchoredRead(procfd *sys.FD, rel string) ([]byte, error) {
	f, err := procfd.Openat2(rel, anchoredHow())
	if err != nil {
		return nil, fmt.Errorf("%w: openat2 %s: %w", runscope.ErrUnanchored, rel, err)
	}
	defer func() { _ = f.Close() }()
	b, err := f.ReadLimited(procReadLimit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	return b, nil
}

// anchoredHow is how every read beneath the anchor is opened.
func anchoredHow() *unix.OpenHow {
	return &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS}
}

// Proof is steps 6 to 9: the proof held for this namespace and uid, a recent failure, or one bounded probe, which
// runs on a goroutine of its own with its own copies of the two descriptors.
func (k *selfReads) Proof(ns runscope.Namespace, uid int) runscope.Answer {
	return k.prover.prove(proofKey{dev: ns.Dev, ino: ns.Ino, uid: uid}, func() (func() runscope.Answer, error) {
		nsfd, err := k.nsfd.Dup()
		if err != nil {
			return nil, err
		}
		procfd, err := k.procfd.Dup()
		if err != nil {
			_ = nsfd.Close()
			return nil, err
		}
		p := &selfProbe{host: k.host, nsfd: nsfd, procfd: procfd, socket: k.host.socket(uid),
			connectBy: k.prover.now().Add(ProbeLimit - connectReserve), now: k.prover.now, sleep: k.prover.sleep}
		return func() runscope.Answer {
			defer p.close()
			return runscope.Prove(p, ns, uid)
		}, nil
	})
}

// Withheld is the gate for Decide: selfHost.withheld.
func (k *selfReads) Withheld(first bool) (runscope.Cause, bool) { return k.host.withheld(first) }

// withheld is the gate (ADR 0100, amended 2026-11-19): where the rule is not proven yet, an answer of outside that
// every fact supports is still not given, and the cause says why. first says the answer came from the kernel's
// first cgroup namespace.
//
// Where any one of WSL's marks holds (detection is asymmetric, see wslMarks) every such answer is withheld,
// in the first cgroup namespace too, where a distribution with
// isolateDistroCgroup=false sits: there the safety of an outside answer rests on a tego run refusing WSL's own
// program launcher, through which a process inside a run could start one that is truly outside it, and that refusal
// has no guest proof yet. Outside WSL, an answer made beyond the first cgroup namespace (a container, a nested
// system) is withheld, since no guest has measured the rule there: the answer is the one tego gave before the rule.
// In the first cgroup namespace outside WSL nothing is withheld, so ordinary Linux keeps its answers; it pays the
// gate's reads (uname and up to three lstat calls) and nothing more. wslRuleOn and nestedRuleOn are the gate's two
// switches: in an ordinary build the WSL one is on (wslgate.go; ADR 0100, amended when it was switched on) and the
// nested one off, and the proof's own builds set both from their test variables (wslgate_testhook.go, starting off).
// The WSL switch relaxes the hold only on a machine that shows two marks: on one (interop off, a release alone) the
// answer stays withheld in every build.
func (h selfHost) withheld(first bool) (runscope.Cause, bool) {
	switch n := h.wslMarks(); {
	case n >= 1 && h.wslHoldsAt(n):
		return runscope.CauseWSLLauncherUnproven, true
	case n >= 1:
		return "", false // two marks and this build's switch: the rule's relaxation on WSL
	case first, nestedRuleOn():
		return "", false
	}
	return runscope.CauseSystemUnproven, true
}

// selfProbe is runscope.Prober over the kernel, for one probe. It owns its descriptors and closes them all when the
// probe ends, the socket included: nothing is ever written to or read from it.
type selfProbe struct {
	host      selfHost
	nsfd      *sys.FD
	procfd    *sys.FD
	socket    string
	sock      *sys.FD
	pidfd     *sys.FD
	connectBy time.Time
	now       func() time.Time
	sleep     func(time.Duration)
}

func (p *selfProbe) close() {
	_ = p.sock.Close()
	_ = p.pidfd.Close()
	_ = p.nsfd.Close()
	_ = p.procfd.Close()
}

func (p *selfProbe) NSType() (int, error) { return p.nsfd.NamespaceType() }

// Owner asks the verified namespace descriptor for its owning user namespace and reads what came back; the returned
// descriptor is closed on every path. /proc/self/ns/user is never read: a path can be a bind of another namespace's
// file, and ns_get_owner's answer cannot.
func (p *selfProbe) Owner() (runscope.Owner, error) {
	ufd, err := p.host.nsOwner(p.nsfd)
	if err != nil {
		return runscope.Owner{}, fmt.Errorf("NS_GET_USERNS: %w", err)
	}
	defer func() { _ = ufd.Close() }()
	ns, err := namespaceOf(ufd)
	if errors.Is(err, errNotNSFS) {
		return runscope.Owner{}, nil
	}
	if err != nil {
		return runscope.Owner{}, err
	}
	return runscope.Owner{NSFS: true, Dev: ns.Dev, Ino: ns.Ino}, nil
}

// InitCgroup reads pid 1's cgroup file through the anchor. A pid 1 that is hidden or not there (ENOENT, EACCES,
// EPERM, as under hidepid) is that errno alone; any other failed open stays an anchoring failure.
func (p *selfProbe) InitCgroup() ([]byte, error) {
	b, err := anchoredRead(p.procfd, "1/cgroup")
	for _, hidden := range []error{unix.ENOENT, unix.EACCES, unix.EPERM} {
		if errors.Is(err, hidden) {
			return nil, fmt.Errorf("1/cgroup: %w", hidden)
		}
	}
	return b, err
}

// Connect makes the one connection of the probe: a non-blocking, close-on-exec stream socket to the manager's
// private socket. A non-blocking unix connect never waits; a full accept queue is EAGAIN at once, retried every
// connectEvery until connectBy.
func (p *selfProbe) Connect() error {
	s, err := sys.Own(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0))
	if err != nil {
		return err
	}
	p.sock = s
	for {
		err := s.ConnectUnix(p.socket)
		if !errors.Is(err, unix.EAGAIN) || !p.now().Add(connectEvery).Before(p.connectBy) {
			return err
		}
		p.sleep(connectEvery)
	}
}

func (p *selfProbe) PeerCred() (uid, pid int, err error) {
	c, err := p.sock.PeerCred()
	if err != nil {
		return 0, 0, err
	}
	return int(c.Uid), int(c.Pid), nil
}

// PeerPidfd takes the listener's pidfd from the socket. There is no fallback to opening a pidfd on the number:
// where the kernel has no SO_PEERPIDFD the number may already belong to another process.
func (p *selfProbe) PeerPidfd() error {
	fd, err := p.sock.PeerPidfd()
	if err != nil {
		return err
	}
	p.pidfd = fd
	return nil
}

// PidfdPID is the pid the anchored /proc shows for the pidfd's process: the Pid: line of the pidfd's fdinfo, opened
// beneath the anchor as every other read is. procfs looks the descriptor's number up when the fdinfo is read, so the
// open and the read both run while the number is lent.
func (p *selfProbe) PidfdPID() (int, error) {
	var b []byte
	if err := p.pidfd.Borrow(func(n int) error {
		f, err := p.procfd.Openat2("self/fdinfo/"+strconv.Itoa(n), anchoredHow())
		if err != nil {
			return fmt.Errorf("%w: openat2 of the pidfd's fdinfo: %w", runscope.ErrUnanchored, err)
		}
		defer func() { _ = f.Close() }()
		b, err = f.ReadLimited(procReadLimit)
		return err
	}); err != nil {
		return 0, err
	}
	return runscope.FdinfoPid(b)
}

// PeerCgroup reads the listener's cgroup file through the anchor: the one file of the peer the probe opens.
func (p *selfProbe) PeerCgroup(pid int) ([]byte, error) {
	return anchoredRead(p.procfd, strconv.Itoa(pid)+"/cgroup")
}

func (p *selfProbe) PeerExited() (bool, error) { return sys.PollPidfdFD(p.pidfd, 0) }

// proofKey is what a proof is of: a cgroup namespace (the nsfs device and the inode) and a uid.
type proofKey struct {
	dev, ino uint64
	uid      int
}

// prover holds the proofs of this process and runs its probes: one at a time, waiters sharing the result, each
// caller waiting at most limit. Only a proof is kept; a failure is remembered for backoff, so that a caller who
// asks again at once is not made to wait again, and then forgotten. The proof cannot go stale: a cgroup namespace's
// root and owner are fixed when it is made, and this process never enters or makes another (tego calls unshare for
// CLONE_NEWNS and CLONE_FS only, on threads it never hands back to the runtime).
type prover struct {
	mu     sync.Mutex
	proved map[proofKey]runscope.Answer
	failed map[proofKey]failure
	flight *flight

	limit, backoff time.Duration
	now            func() time.Time
	sleep          func(time.Duration)
	after          func(time.Duration) (<-chan time.Time, func())
}

type failure struct {
	at     time.Time
	answer runscope.Answer
}

// flight is one running probe.
type flight struct {
	key       proofKey
	done      chan struct{}
	answer    runscope.Answer
	abandoned bool
}

func newProver() *prover {
	return &prover{proved: map[proofKey]runscope.Answer{}, failed: map[proofKey]failure{}, limit: ProbeLimit, backoff: probeBackoff,
		now: time.Now, sleep: time.Sleep, after: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTimer(d)
			return t.C, func() { t.Stop() }
		}}
}

// selfProver holds this process's proofs.
var selfProver = newProver()

func timedOut() runscope.Answer {
	return runscope.Unproven(runscope.CauseProbeTimeout, nil)
}

// prove answers for key: Outside from a proof held; a failure younger than backoff as it was; otherwise the result
// of the running probe, or of a new one made by start when none runs, waited for at most limit. A caller that
// gives up abandons the probe: its result is discarded when it comes, and until it ends no other probe starts.
func (v *prover) prove(key proofKey, start func() (func() runscope.Answer, error)) runscope.Answer {
	v.mu.Lock()
	if a, ok := v.proved[key]; ok {
		v.mu.Unlock()
		return a
	}
	if f, ok := v.failed[key]; ok {
		if v.now().Sub(f.at) < v.backoff {
			v.mu.Unlock()
			return f.answer
		}
		delete(v.failed, key)
	}
	fl := v.flight
	switch {
	case fl == nil:
		run, err := start()
		if err != nil {
			v.mu.Unlock()
			return runscope.Unproven(runscope.CauseProbeError, err)
		}
		fl = &flight{key: key, done: make(chan struct{})}
		v.flight = fl
		go v.fly(fl, run)
	case fl.key != key:
		v.mu.Unlock()
		return runscope.Unproven(runscope.CauseProbeTimeout, errors.New("a probe for another namespace or uid is still running"))
	}
	v.mu.Unlock()

	expired, stop := v.after(v.limit)
	defer stop()
	select {
	case <-fl.done:
	case <-expired:
		v.mu.Lock()
		select {
		case <-fl.done: // it ended as the limit passed: its result stands
		default:
			fl.abandoned = true
			v.failed[key] = failure{at: v.now(), answer: timedOut()}
			v.mu.Unlock()
			return timedOut()
		}
		v.mu.Unlock()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return fl.answer
}

// fly runs one probe to its end and records it, with the time the probe took (runscope.WithProbeTime, a diagnostic
// that tego doctor prints): a proof is kept, a failure noted with its time, and the result of an abandoned probe is
// discarded, whatever it was.
func (v *prover) fly(fl *flight, run func() runscope.Answer) {
	start := v.now()
	a := run()
	a = runscope.WithProbeTime(a, v.now().Sub(start))
	v.mu.Lock()
	switch {
	case fl.abandoned:
		a = timedOut()
	case a.Outside():
		v.proved[fl.key] = a
	default:
		v.failed[fl.key] = failure{at: v.now(), answer: a}
	}
	fl.answer = a
	v.flight = nil
	v.mu.Unlock()
	close(fl.done)
}
