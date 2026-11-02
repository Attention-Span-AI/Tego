// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	rcgroup "github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	specid "github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Capture probes shared per (build, library) (ADR 0026 (7) and (9)).
//
// A uprobe belongs to a file, and the capture programs filter by the build's run set and stamp each chunk with
// the run's slot, so one set of probes on a libssl serves every run of the build: which run a chunk is, is the
// drain's question (mine), never the probe's. What made the probes per run was only who placed and removed
// them, and removing them is what cost a run its time: the kernel detaches a perf-event uprobe one at a time,
// each close waiting out an RCU grace period, and a libssl carries six. Measured in the 1536M/2-vCPU guest on
// 6.17 (kill test 4, tier cgroup): placing the six took 4-18 ms, removing them 0.40-0.55 s, on every run.
//
// So a run places a library's probes once and pins each link under the build's pin directory,
// <pins>/<hash>/uprobes/<dev>-<ino>-<build id>/<n>, and holds the library's lock in the state directory,
// bpf-<hash>-lib-<dev>-<ino>-<build id>.lock, shared for as long as it wants them. A run that finds the pins
// complete, and running this build's programs over its pinned maps, adopts them and places nothing. A complete
// set that is not (one pinned before the build's maps were re-created) is never adopted: individual probes are
// placed again when no other run holds the library, and the library is refused while one does (adoptProbes); a
// multi pair is refused (adoptMulti). The run that leaves last (its exclusive attempt on the lock
// succeeds) stamps the lock's mtime and hands the removal to a process of its own (DetachCommand), which waits
// out ProbeGrace from that stamp and then, if no run holds the library, moves the directory aside
// (detaching-<...>, a rename, under the exclusive lock) and unpins it, which is what detaches. No removal is on
// a run's path.
//
// The grace is short on purpose. An attached probe costs every process on the host about 2.4 µs per TLS call
// even when it filters the call out (ADR 0026 (9)), so probes do not linger with the build. But removed at
// once, they were still being detached when kill test 4's next run placed its own on the same library, and the
// kernel made that placement wait for the detach: 75-340 ms on 6.17, where an uncontended one takes 4-18 ms.
// Two seconds covers back-to-back runs, and costs a host making 5,000 TLS calls a second about 24 ms of its time
// over the whole grace.
//
// Everything stays visible to root and removable by it: the links are bpffs pins (bpftool link list shows
// them, rm removes them), `tego doctor` lists them per build, and the build's removal (enforce/cgroup's sweep,
// `tego gc --builds`) removes the directory with the rest of the build.

// DetachCommand is the hidden first argument cmd/tego dispatches to DetachMain: the removal of a library's
// probes after the last run holding them has left.
const DetachCommand = "__uprobe-detach"

// UprobePinDir is the directory under a build's pin root that holds one directory of pinned probe links per
// library.
const UprobePinDir = "uprobes"

// ProbeGrace is how long a library's probes stay attached after the last run holding them has left (see
// above; ADR 0026 (9) as amended).
const ProbeGrace = 2 * time.Second

// maxProbeGrace bounds the grace DetachMain accepts on its command line.
const maxProbeGrace = time.Minute

// detachingPrefix names a library's directory once its removal has begun: nothing adopts it, and the detacher
// or the build's removal unpins it.
const detachingPrefix = "detaching-"

// libKey names a library in the pin tree and in the lock names: its (device, inode) and, as R7 requires of any
// key a stale file could reach, its build id.
func libKey(id identity) string {
	b := id.BuildID
	if b == "" {
		b = "none"
	}
	if len(b) > 40 {
		b = b[:40]
	}
	return fmt.Sprintf("%d-%d-%s", id.Dev, id.Ino, b)
}

// sharedAttacher places a binary's probes once per build and pins them (see above). It wraps the per-probe
// EBPFAttacher, which places each probe.
type sharedAttacher struct {
	*EBPFAttacher
	// root is the build's pin directory, <pins>/<hash>.
	root string
	// state is the state directory the library locks live in; hash names the build in their names.
	state, hash string
	// detach removes a library's probes after the grace, off the run's path (spawnDetach).
	detach func(detachJob)
	logf   func(format string, args ...any)
}

// AttachBinary places the probes on one library, or adopts the ones another run of the build pinned, and
// returns the closers the attach cache closes at refcount zero: the links, then the library's hold, whose
// Close lets the probes go if no other run still holds the library.
func (s *sharedAttacher) AttachBinary(path string, id identity, probes []Probe) ([]io.Closer, error) {
	key := libKey(id)
	job := detachJob{root: s.root, state: s.state, hash: s.hash, key: key}
	d, err := openStateDir(s.state)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrAttachFailed, path, err)
	}
	defer func() { _ = d.Close() }()
	hold, err := d.OpenFile(job.lockName(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: library lock: %w", ErrAttachFailed, path, err)
	}
	if err := unix.Flock(int(hold.Fd()), unix.LOCK_SH); err != nil {
		_ = hold.Close()
		return nil, fmt.Errorf("%w: %s: library lock: %w", ErrAttachFailed, path, err)
	}
	// The pin lock makes one run the placer of a library's probes while another looks at them: a run finds
	// either nothing, a complete set, or a partial one that a placer who died left.
	pin, err := d.OpenFile("bpf-"+s.hash+"-lib-"+key+".pin", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		_ = hold.Close()
		return nil, fmt.Errorf("%w: %s: pin lock: %w", ErrAttachFailed, path, err)
	}
	defer func() { _ = pin.Close() }()
	if err := unix.Flock(int(pin.Fd()), unix.LOCK_EX); err != nil {
		_ = hold.Close()
		return nil, fmt.Errorf("%w: %s: pin lock: %w", ErrAttachFailed, path, err)
	}
	dir := filepath.Join(s.root, UprobePinDir, key)
	release := &libHold{f: hold, job: job, detach: s.detach}
	if plan, err := planMulti(probes); err == nil {
		links, adopted, err := s.adoptMulti(dir, path, plan)
		if err != nil {
			_ = hold.Close()
			return nil, err
		}
		if adopted {
			s.logf("uprobe: adopted two multi links on %s (%s)", path, dir)
			return append(links, release), nil
		}
	}
	links, adopted, err := s.adoptProbes(dir, probes, hold)
	if err != nil {
		_ = hold.Close()
		return nil, err
	}
	if adopted {
		s.logf("uprobe: adopted the %d pinned probes on %s (%s)", len(links), path, dir)
		return append(links, release), nil
	}
	links, pinned, err := s.place(path, dir, probes)
	if err != nil {
		_ = hold.Close()
		return nil, err
	}
	if !pinned {
		// This kernel cannot pin the links (no BPF perf link): the probes are this run's own, removed as the
		// run gives them back, as before (ADR 0026 (8)'s last sentence).
		_ = hold.Close()
		return links, nil
	}
	return append(links, release), nil
}

// place attaches every probe and pins its link at dir/<n>, clearing whatever a placer that died left there
// first. It reports pinned=false, with the links unpinned and live, when the kernel refuses to pin them.
func (s *sharedAttacher) place(path, dir string, probes []Probe) ([]io.Closer, bool, error) {
	return s.placeKind(path, dir, probes, true)
}

func (s *sharedAttacher) placeKind(path, dir string, probes []Probe, tryMulti bool) ([]io.Closer, bool, error) {
	if err := os.Mkdir(filepath.Join(s.root, UprobePinDir), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, false, fmt.Errorf("%w: %s: %w", ErrAttachFailed, path, err)
	}
	_ = removePinTree(dir)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, false, fmt.Errorf("%w: %s: %w", ErrAttachFailed, path, err)
	}
	var out []io.Closer
	multi := false
	if tryMulti {
		if plan, err := planMulti(probes); err == nil {
			links, err := s.attachMulti(path, plan)
			if err == nil && s.validMultiLinks(links, path, plan) {
				out, multi = links, true
			} else {
				closeProbes(links)
				if !errors.Is(err, errNoMulti) {
					s.logf("uprobe: multi attachment unavailable on %s (%v); using individual probes", path, err)
				}
			}
		}
	}
	pinned := true
	fail := func(err error) ([]io.Closer, bool, error) {
		for _, l := range out {
			_ = l.Close()
		}
		_ = removePinTree(dir)
		return nil, false, err
	}
	if !multi {
		for _, p := range probes {
			c, err := s.Attach(path, p)
			if err != nil {
				return fail(err)
			}
			out = append(out, c)
		}
	}
	for i, c := range out {
		if !pinned {
			continue
		}
		l, ok := c.(link.Link)
		if !ok {
			pinned = false
			continue
		}
		if err := l.Pin(filepath.Join(dir, strconv.Itoa(i))); err != nil {
			if !errors.Is(err, ebpf.ErrNotSupported) {
				return fail(fmt.Errorf("%w: pin probe %d: %w", ErrAttachFailed, i, err))
			}
			pinned = false
		}
	}
	if !pinned {
		for _, c := range out {
			if l, ok := c.(link.Link); ok {
				_ = l.Unpin()
			}
		}
		_ = removePinTree(dir)
		if multi {
			closeProbes(out)
			return s.placeKind(path, dir, probes, false)
		}
		s.logf("uprobe: this kernel cannot pin uprobe links; the probes on %s are this run's own", path)
	}
	if multi {
		s.logf("uprobe: placed two shared multi links on %s", path)
	}
	return out, pinned, nil
}

// adoptLinks opens a complete set of n pinned links, 0..n-1, and nothing else: anything else is a set a placer
// that died left part way, which the caller replaces. A complete set is not yet the build's: the caller proves
// that (validMultiLinks, probeLinksDiffer) before it keeps one.
func adoptLinks(dir string, n int) ([]io.Closer, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != n || n == 0 {
		return nil, false
	}
	out := make([]io.Closer, 0, n)
	for i := 0; i < n; i++ {
		l, err := loadPinnedProbe(filepath.Join(dir, strconv.Itoa(i)))
		if err != nil {
			closeProbes(out)
			return nil, false
		}
		out = append(out, l)
	}
	return out, true
}

// loadPinnedProbe opens one pinned probe link. A variable, so that the unit tests can lay a library's pins out as
// plain files; production never replaces it.
var loadPinnedProbe = func(path string) (io.Closer, error) { return link.LoadPinnedLink(path, nil) }

// adoptProbes adopts the complete set of individual probes pinned at dir (adoptLinks) when it is this build's
// probes for the library (probeLinksDiffer), and reports adopted with its links. A complete set can be another's:
// one pinned before the build's maps were re-created (a build removal that failed part way at the probes, or a
// removal made by hand) runs programs over a run set that names no run of the build now, and adopted, as it was
// on its count alone, it left the run's TLS captured by nothing, with no gap to say so. Such a set is never
// adopted, and never left in use with a second set beside it (adoptMulti's rule): when no run but this one holds
// the library (aloneOnLibrary), nothing captures through it, so it is unpinned for this run to place its own;
// while another run holds it, the library is refused, a gap that says why, as a multi pair is refused that this
// run cannot prove is the build's.
func (s *sharedAttacher) adoptProbes(dir string, probes []Probe, hold *os.File) ([]io.Closer, bool, error) {
	links, ok := adoptLinks(dir, len(probes))
	if !ok {
		return nil, false, nil
	}
	why := s.probeLinksDiffer(links, probes, s.pinnedMapIDs())
	if why == "" {
		return links, true, nil
	}
	alone, err := aloneOnLibrary(hold)
	if err != nil || !alone {
		closeProbes(links)
		if err != nil {
			return nil, false, fmt.Errorf("%w: the probes pinned at %s are not this build's (%s): library lock: %w",
				ErrAttachFailed, dir, why, err)
		}
		return nil, false, fmt.Errorf(
			"%w: the probes pinned at %s are not this build's (%s), and another run holds the library",
			ErrAttachFailed, dir, why)
	}
	// Unpinned while this run still holds them, the probes go at its close rather than at the bpf filesystem's
	// later release of the pins, so they are off the library before this run's own are placed (enforce/cgroup's
	// teardown.unpinLink orders a removal the same way).
	err = removePinTree(dir)
	closeProbes(links)
	if err != nil {
		return nil, false, fmt.Errorf("%w: unpin the probes at %s, which are not this build's (%s): %w",
			ErrAttachFailed, dir, why, err)
	}
	s.logf("uprobe: the %d probes pinned at %s were not this build's (%s); placing this run's own",
		len(probes), dir, why)
	return nil, false, nil
}

// probeLinksDiffer says why links, a complete set pinned for a library, are not this build's individual probes
// for probes, or "" when they are. The placer pinned probes[i]'s link as <i> (placeKind), so link i must be a
// perf-event link running probes[i]'s program: this run's own, or the same code over the build's pinned maps
// (pinned), as a run that loaded its programs on its own places it (sameProgram, which validMultiLinks asks of a
// multi pair). Where the kernel reports the probe itself (6.6 and later), it must be the probe's kind at the
// probe's offset. The file is not compared, as validMultiLinks compares a pair's: for a single probe the kernel
// reports the path the placer gave it, the placer's own /proc/self/fd link (R39), which names nothing here. The
// directory's key, the file's (device, inode) and build id, is what names the file.
func (a *EBPFAttacher) probeLinksDiffer(links []io.Closer, probes []Probe, pinned map[ebpf.MapID]bool) string {
	if len(links) != len(probes) {
		return fmt.Sprintf("%d links for %d probes", len(links), len(probes))
	}
	for i, p := range probes {
		program := a.coll.Programs[p.Program]
		if program == nil {
			return fmt.Sprintf("this run has no program %s", p.Program)
		}
		f, err := pinnedLinkFacts(links[i])
		switch {
		case err != nil:
			return fmt.Sprintf("link %d: %v", i, err)
		case f.typ != link.PerfEventType:
			return fmt.Sprintf("link %d is of link type %d, not a single probe's", i, f.typ)
		case !sameProgram(program, f.program, pinned):
			return fmt.Sprintf("link %d runs program %d, which is not %s over the build's maps", i, f.program, p.Program)
		case f.event != eventUnreported && (f.event != eventOf(p) || f.offset != uint32(p.Offset)):
			return fmt.Sprintf("link %d is not the %s", i, p)
		}
	}
	return ""
}

// linkFacts is what probeLinksDiffer compares of one pinned link, as the kernel reports it.
type linkFacts struct {
	typ     link.Type
	program ebpf.ProgramID
	// event is the kind of probe the link is on and offset its file offset, which the kernel reports in 32 bits:
	// both from 6.6, and eventUnreported before.
	event  probeEvent
	offset uint32
}

// probeEvent is the kind of perf event a link is on.
type probeEvent uint8

const (
	eventUnreported probeEvent = iota
	eventUprobe
	eventUretprobe
	eventOther
)

// eventOf is the kind of probe p is placed as.
func eventOf(p Probe) probeEvent {
	if p.Return {
		return eventUretprobe
	}
	return eventUprobe
}

// pinnedLinkFacts reads a pinned link's facts from the kernel. A variable, so that the unit tests can give the
// facts a kernel would; production never replaces it.
var pinnedLinkFacts = func(c io.Closer) (linkFacts, error) {
	l, ok := c.(link.Link)
	if !ok {
		return linkFacts{}, fmt.Errorf("%T is not a link", c)
	}
	info, err := l.Info()
	if err != nil {
		return linkFacts{}, err
	}
	f := linkFacts{typ: info.Type, program: info.Program}
	if pe := info.PerfEvent(); pe != nil && pe.Type != link.PerfEventUnspecified {
		f.event = eventOther
		if u := pe.Uprobe(); u != nil {
			f.event, f.offset = eventUprobe, u.Offset
			if pe.Type == link.PerfEventUretprobe {
				f.event = eventUretprobe
			}
		}
	}
	return f, nil
}

// aloneOnLibrary reports whether no run but this one holds the library: hold, this run's shared hold on the
// library's lock, is converted to exclusive without waiting, and back to shared. Linux converts an flock by
// dropping the shared hold before it tries the exclusive one (libHold.Close), so a conversion that fails has let
// go of it, and it is taken back. The way back from exclusive is made under the kernel's own lock of the file's
// locks, so no detacher's or sweep's exclusive attempt gets in between. An error is a hold this run may have lost.
func aloneOnLibrary(hold *os.File) (bool, error) {
	if err := sys.Flock(hold, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		back := sys.Flock(hold, unix.LOCK_SH)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, back
		}
		return false, errors.Join(err, back)
	}
	return true, sys.Flock(hold, unix.LOCK_SH)
}

// detachJob names one library's probes for their removal after the grace.
type detachJob struct {
	// root is the build's pin directory, state the state directory, hash and key the build and the library.
	root, state, hash, key string
}

// lockName is the library's lock file in the state directory.
func (j detachJob) lockName() string { return "bpf-" + j.hash + "-lib-" + j.key + ".lock" }

// libHold is one run's shared hold on a library's probes. Close gives it back; the last hold to go stamps the
// lock and hands the library to detach, which removes its probes after ProbeGrace unless a run holds it again.
type libHold struct {
	f      *os.File
	job    detachJob
	detach func(detachJob)
}

// Close releases the hold. Linux converts an flock by dropping the shared hold before it tries the exclusive
// one, so a hold that fails the exclusive attempt already holds nothing, and of two runs leaving together the
// second finds the lock free (enforce/cgroup's lastOut says the same of the build lock).
func (h *libHold) Close() error {
	if h.f == nil {
		return nil
	}
	f := h.f
	h.f = nil
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil // another run holds the library; its probes stay
	}
	tv := unix.NsecToTimeval(time.Now().UnixNano())
	stamped := unix.Futimes(int(f.Fd()), []unix.Timeval{tv, tv}) == nil
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	if !stamped || h.detach == nil {
		// Without the stamp the grace would count from an older one: remove now, which is still correct.
		return detachAfter(h.job, 0)
	}
	h.detach(h.job)
	return nil
}

// detachAfter removes a library's probes once its lock's mtime is grace old and no run holds it: it moves the
// directory aside under the exclusive lock, so no run adopts probes that are going, lets the lock go, and
// unpins what it moved. A run that holds the library, or one that came and went and moved the stamp, keeps
// them: the first returns at once (its own last-out hands them on again), the second makes it wait again.
func detachAfter(j detachJob, grace time.Duration) error {
	d, err := openStateDir(j.state)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	f, err := d.OpenFile(j.lockName(), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for {
		var st unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &st); err != nil {
			return err
		}
		if wait := time.Until(time.Unix(st.Mtim.Unix()).Add(grace)); wait > 0 {
			time.Sleep(wait)
		}
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil // a run holds the library again
		}
		if err := unix.Fstat(int(f.Fd()), &st); err != nil {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			return err
		}
		if time.Until(time.Unix(st.Mtim.Unix()).Add(grace)) > 0 {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			continue // a run came and went: the grace counts from its own stamp
		}
		dir := filepath.Join(j.root, UprobePinDir, j.key)
		aside := filepath.Join(j.root, UprobePinDir, detachingPrefix+j.key+"-"+
			strconv.FormatInt(time.Now().UnixNano(), 36))
		err := os.Rename(dir, aside)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			// A bpffs without rename: unpin in place, under the lock, which is still correct.
			err = removePinTree(dir)
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			return err
		}
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		if err != nil {
			return nil // removed already, by another detacher or with the build
		}
		return removePinTree(aside)
	}
}

// removePinTree unpins every link in dir and removes it. Unpinning a link nobody else holds detaches its probe.
func removePinTree(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// openStateDir opens the directory the library locks live in: the verified /run/tego (ADR 0034), or the one a
// caller chose (a test's).
func openStateDir(dir string) (*hoststate.Dir, error) {
	if dir == "" || dir == hoststate.Path {
		return hoststate.Open()
	}
	return hoststate.OpenAt(dir)
}

// pending are the libraries whose last run out was a source of this process, waiting for StartDetaches.
var pending struct {
	sync.Mutex
	jobs []detachJob
}

// queueDetach is the default Options.Detach: the library's removal is started by StartDetaches, not here. A
// source stops while its run's enforcement may still hold fanotify marks, and while any mark of its group
// exists the launcher starts no process (ADR 0021 (3)): a vfork then was one side of E39's freeze.
func queueDetach(j detachJob) {
	pending.Lock()
	defer pending.Unlock()
	pending.jobs = append(pending.jobs, j)
}

// StartDetaches starts the removal of every library whose last run out was a source of this process
// (spawnDetach). `tego run` calls it once the run is over and its enforcement released, so no fanotify mark of
// this process exists (ADR 0021 (3)). A launcher that dies first leaves the probes pinned: the build's own
// removal takes them (ADR 0022), and `tego doctor` shows them until then.
func StartDetaches() {
	pending.Lock()
	jobs := pending.jobs
	pending.jobs = nil
	pending.Unlock()
	for _, j := range jobs {
		spawnDetach(j)
	}
}

// spawnDetach runs this tego as DetachCommand in a session of its own and does not wait for it: the grace and
// the unpinning, which takes the kernel hundreds of milliseconds per library, are not the run's to wait out.
// It runs in tego's helper cgroup (internal/runtime/cgroup.StartHelper), not the launcher's: in the launcher's,
// stopping the unit, the CI job or the scope the launcher ran in killed it inside its grace, and the probes
// stayed attached to every process on the host. One that cannot be put there starts in the launcher's cgroup
// with the reason in its environment; one killed all the same leaves the library to the next run's start,
// doctor or gc (SweepLibraries). A process that is not tego (a Go test binary, which re-executed would run its
// whole suite) removes them in place instead, without the grace.
func spawnDetach(j detachJob) {
	self, err := os.Executable()
	if err != nil || strings.HasSuffix(self, ".test") {
		_ = detachAfter(j, 0)
		return
	}
	state := j.state
	if state == "" {
		state = hoststate.Path
	}
	if _, err := rcgroup.StartHelperExec("/proc/self/exe", DetachCommand, j.root, state, j.hash, j.key,
		ProbeGrace.String()); err != nil {
		_ = detachAfter(j, 0)
	}
}

// SweepLibraries removes, in every build under pinRoot (PinDir when empty), the probes of each library whose
// removal is overdue: no run holds the library (its lock, in stateDir, is taken exclusively without waiting),
// and ProbeGrace has passed since the last run out stamped it, or it has no lock at all. That is the removal a
// DetachCommand process makes; this is for one that never made it (killed with its launcher's cgroup, by an
// operator, or never started). A library directory a detacher moved aside and did not finish unpinning goes
// too. A run's uprobe source calls it as it starts, and `tego doctor` and `tego gc` as root. It returns how
// many libraries it removed. Best effort: a library it cannot remove stays for the next pass.
func SweepLibraries(pinRoot, stateDir string, now time.Time) (int, error) {
	if pinRoot == "" {
		pinRoot = PinDir
	}
	builds, err := os.ReadDir(pinRoot)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	d, err := openStateDir(stateDir)
	if err != nil {
		return 0, err
	}
	defer func() { _ = d.Close() }()
	removed := 0
	var errs []error
	for _, b := range builds {
		if !b.IsDir() || !pinName(b.Name()) {
			continue
		}
		root := filepath.Join(pinRoot, b.Name())
		libs, err := os.ReadDir(filepath.Join(root, UprobePinDir))
		if err != nil {
			continue
		}
		for _, l := range libs {
			if !l.IsDir() || !pinName(l.Name()) {
				continue
			}
			if strings.HasPrefix(l.Name(), detachingPrefix) {
				if err := removePinTree(filepath.Join(root, UprobePinDir, l.Name())); err != nil {
					errs = append(errs, err)
				} else {
					removed++
				}
				continue
			}
			j := detachJob{root: root, state: stateDir, hash: b.Name(), key: l.Name()}
			ok, err := sweepLibrary(d, j, now)
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				removed++
			}
		}
	}
	return removed, errors.Join(errs...)
}

// sweepLibrary removes one library's probes when no run holds it and its grace is over (SweepLibraries), under
// the exclusive lock as detachAfter does, so no run adopts probes that are going.
func sweepLibrary(d *hoststate.Dir, j detachJob, now time.Time) (bool, error) {
	dir := filepath.Join(j.root, UprobePinDir, j.key)
	f, err := d.OpenFile(j.lockName(), os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		// No lock: no run placed these through this state directory's locks (a reboot's fresh /run under an old
		// bpffs cannot happen, both are gone), or a run that died between the two; nothing holds them.
		return true, removePinTree(dir)
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return false, nil // a run holds the library
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return false, err
	}
	if time.Unix(st.Mtim.Unix()).Add(ProbeGrace).After(now) {
		return false, nil // inside its grace: a detacher may still be waiting it out
	}
	aside := filepath.Join(j.root, UprobePinDir, detachingPrefix+j.key+"-"+strconv.FormatInt(now.UnixNano(), 36))
	if err := os.Rename(dir, aside); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return true, removePinTree(dir) // a bpffs without rename: unpin in place, under the lock
	}
	return true, removePinTree(aside)
}

// pinName reports whether s is one path element of the characters a build hash or a library key is made of.
func pinName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// DetachMain is `tego __uprobe-detach <build pin dir> <state dir> <hash> <library key> <grace>`: it removes one
// library's capture probes once the grace has passed since the last run holding them left, unless a run holds
// them again (detachAfter). It touches nothing but that library's directory under the build's pin directory in
// the bpf filesystem's tego tree, and its lock in the verified /run/tego. It returns the process's exit code.
func DetachMain(args []string) int {
	usage := func(why string) int {
		fmt.Fprintf(os.Stderr, "usage: tego %s <build pin dir> <state dir> <hash> <library key> <grace>: %s\n",
			DetachCommand, why)
		return specid.ExitUsage
	}
	if len(args) != 5 {
		return usage("five arguments")
	}
	j := detachJob{root: args[0], state: args[1], hash: args[2], key: args[3]}
	grace, err := time.ParseDuration(args[4])
	switch {
	case err != nil || grace < 0 || grace > maxProbeGrace:
		return usage("grace " + args[4])
	case !pinName(j.hash) || !pinName(j.key):
		return usage("the hash and the key are one path element each")
	case j.root != filepath.Join(PinDir, j.hash):
		return usage(j.root + " is not the build's pin directory under " + PinDir)
	case j.state != hoststate.Path:
		return usage(j.state + " is not " + hoststate.Path)
	}
	if err := detachAfter(j, grace); err != nil {
		fmt.Fprintf(os.Stderr, "tego %s: %v\n", DetachCommand, err)
		return specid.ExitError
	}
	return specid.ExitOK
}
