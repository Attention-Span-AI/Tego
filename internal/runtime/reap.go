// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The reaper (ADR 0020). A tier-2 run's launcher starts `tego __reap` right after Prepare, and at any tier one
// holding an owned DNS broker endpoint starts it as soon as the endpoint is bound (ADR 0020's 2026-10-05 notes),
// before the child stage exists, and never waits on it. The reaper waits for its launcher's pidfd to become
// readable. A launcher that ended the run itself leaves nothing to do, and the reaper exits. One that died leaves
// an orphan: its fanotify group went with it (§6 E15), while the run's cgroup links, pinned, and its rows still
// enforce the network (§6 E38 closed). The reaper then ends the run at once rather than at the next `tego run`,
// `stop` or `gc`: it kills the run's cgroup, waits for it to empty, appends run_end reason=orphaned, removes the
// cgroup, and only then purges the run's kernel state (cgroupenforce.PurgeRun), so rows and links outlive every
// process they govern. Last, it does the build's duties a last launcher out would have done (ADR 0022 (2)-(3)).
//
// It runs as root in tego's helper cgroup (cgroup.HelperScope), not the run's, which it kills, nor the
// launcher's, which a unit stop takes. Its standard streams are /dev/null. Ordinary runs inherit two other
// descriptors: a pidfd of the launcher, which the launcher opens on itself (pidfd_open(getpid()) — one opened by
// the reaper on its parent would race the launcher's death), at reapPidFD, and an O_PATH descriptor of the run
// directory, opened through the ledger Writer's own descriptor, at reapDirFD. Every other descriptor it finds is
// closed first. A cooperating DNS broker adds only its held socket directory and verified /tmp parent;
// these are cleaned after the run tree is empty, preserving their exact identities. Everything else it is
// told is its argv, fixed by the launcher before the child stage exists.
//
// Amended 2026-10-05: a DNS broker's run starts its reaper as soon as the endpoint is bound,
// before Prepare (startDNSReaper), since a launcher killed while Prepare loads and attaches left the endpoint
// with no reaper. Prepare's tier state is not known then, so that reaper has one more descriptor, the read end
// of a pipe at reapHandoffFD, through which startReaper hands it the tier's ReapTarget after Prepare. A
// launcher that dies before handing one over leaves the tier's state to the sweep, as a reaper that could not
// start does (ADR 0020 (4)); the reaper still ends the run and removes the endpoint.
// All ledger I/O goes through the run directory's descriptor (ledger.OpenAt); /run/tego is opened, and
// verified, by the enforce/cgroup state functions as for every launcher (ADR 0034).

// ReapCommand is the hidden first argument cmd/tego dispatches to ReapMain.
const ReapCommand = "__reap"

// The reaper's inherited descriptors: ExtraFiles 0 and 1 of the launcher's exec, and 2 to 4 only for a run with
// an owned DNS broker endpoint.
const (
	reapPidFD       = 3
	reapDirFD       = 4
	reapDNSDirFD    = 5
	reapDNSParentFD = 6
	reapHandoffFD   = 7
)

// reapHandoffMax bounds the target a launcher hands its reaper: one write of at most PIPE_BUF bytes is atomic, so
// a launcher that dies mid-handoff leaves all of it or none in the pipe.
const reapHandoffMax = 4096

// reapArgCount is the number of arguments after ReapCommand (reapSpec.args).
const reapArgCount = 13

// reapSpec is everything a reaper is told, as argv.
type reapSpec struct {
	ID, Agent string
	// Dir names the run directory in messages; the reaper never resolves it (reapDirFD is the directory).
	Dir string
	// CgroupMount is the cgroup2 mount; CgroupPath the run's scope, absolute; CgroupID its id, which a scope at
	// that path must have to be the run's.
	CgroupMount, CgroupPath string
	CgroupID                uint64
	// Target is the tier-2 build and pins the run's programs live in.
	Target cgroupenforce.ReapTarget
	// Anchor is the chain.log the launcher anchors in (runner.anchorFile).
	Anchor string
	// DNS cleanup is optional; ordinary reapers retain the original argv/FD contract.
	DNSName        string
	DNSDev, DNSIno uint64
}

// args is the spec as the reaper's argv, after ReapCommand.
func (s reapSpec) args() []string {
	args := []string{s.ID, s.Agent, s.Dir, s.CgroupMount, s.CgroupPath, strconv.FormatUint(s.CgroupID, 10),
		s.Target.Hash, s.Target.BPFFS, s.Target.StateDir, s.Target.Linger.String(), s.Anchor,
		strconv.FormatUint(uint64(s.Target.Slot), 10), s.Target.PlaneMode}
	if s.DNSName != "" {
		args = append(args, s.DNSName, strconv.FormatUint(s.DNSDev, 10), strconv.FormatUint(s.DNSIno, 10))
	}
	return args
}

// parseReapSpec reads args back; any malformed field is an error, and the reaper then does nothing.
func parseReapSpec(args []string) (reapSpec, error) {
	if len(args) != reapArgCount && len(args) != reapArgCount+3 {
		return reapSpec{}, fmt.Errorf("want %d arguments, got %d", reapArgCount, len(args))
	}
	s := reapSpec{ID: args[0], Agent: args[1], Dir: args[2], CgroupMount: args[3], CgroupPath: args[4], Anchor: args[10]}
	if !ledger.IsRunID(s.ID) || !record.IsAgentID(s.Agent) {
		return reapSpec{}, fmt.Errorf("run %q agent %q", s.ID, s.Agent)
	}
	if !filepath.IsAbs(s.CgroupPath) || filepath.Base(s.CgroupPath) != identity.RunScope(identity.RunID(s.ID)) {
		return reapSpec{}, fmt.Errorf("cgroup %q is not run %s's scope", s.CgroupPath, s.ID)
	}
	id, err := strconv.ParseUint(args[5], 10, 64)
	if err != nil {
		return reapSpec{}, fmt.Errorf("cgroup id %q: %w", args[5], err)
	}
	s.CgroupID = id
	if s.Target, err = parseReapTarget([6]string{args[6], args[7], args[8], args[9], args[11], args[12]}); err != nil {
		return reapSpec{}, err
	}
	if len(args) == reapArgCount+3 {
		s.DNSName = args[13]
		if !validDNSDirectoryName(s.DNSName) {
			return reapSpec{}, errors.New("invalid DNS cleanup directory name")
		}
		if s.DNSDev, err = strconv.ParseUint(args[14], 10, 64); err != nil {
			return reapSpec{}, fmt.Errorf("DNS socket device: %w", err)
		}
		if s.DNSIno, err = strconv.ParseUint(args[15], 10, 64); err != nil || s.DNSIno == 0 {
			return reapSpec{}, errors.New("invalid DNS socket inode")
		}
	}
	return s, nil
}

// reapTargetFields is t as the six fields parseReapTarget reads: hash, bpffs, state dir, linger, slot, plane mode.
func reapTargetFields(t cgroupenforce.ReapTarget) [6]string {
	return [6]string{t.Hash, t.BPFFS, t.StateDir, t.Linger.String(), strconv.FormatUint(uint64(t.Slot), 10), t.PlaneMode}
}

// parseReapTarget reads reapTargetFields back, from argv or a handoff; any malformed field is an error.
func parseReapTarget(f [6]string) (cgroupenforce.ReapTarget, error) {
	t := cgroupenforce.ReapTarget{Hash: f[0], BPFFS: f[1], StateDir: f[2]}
	if t.Hash != "" && !cgroupenforce.IsBuildHash(t.Hash) {
		return cgroupenforce.ReapTarget{}, fmt.Errorf("%q is not a build hash", t.Hash)
	}
	var err error
	if t.Linger, err = time.ParseDuration(f[3]); err != nil {
		return cgroupenforce.ReapTarget{}, fmt.Errorf("linger %q: %w", f[3], err)
	}
	slot, err := strconv.ParseUint(f[4], 10, 32)
	if err != nil {
		return cgroupenforce.ReapTarget{}, fmt.Errorf("slot %q: %w", f[4], err)
	}
	t.Slot = uint32(slot)
	switch f[5] {
	case "", record.DecisionPlaneLSM, record.DecisionPlaneFmodRet:
		t.PlaneMode = f[5]
	default:
		return cgroupenforce.ReapTarget{}, fmt.Errorf("%q is no plane mode", f[5])
	}
	return t, nil
}

// handOffReapTarget writes t to a DNS reaper's handoff pipe in one write, so it arrives whole or not at all.
func handOffReapTarget(w *os.File, t cgroupenforce.ReapTarget) error {
	f := reapTargetFields(t)
	line := strings.Join(f[:], "\x00")
	if len(line) > reapHandoffMax {
		return fmt.Errorf("the reaper's target is %d bytes, over the pipe's atomic %d", len(line), reapHandoffMax)
	}
	_, err := w.Write([]byte(line))
	return err
}

// readReapTarget reads what the launcher handed the reaper at fd, once the launcher is gone: the tier's target,
// or ok false when it died, or ran a tier with no kernel state, before handing one over. It never blocks: a
// handoff is written whole before the launcher can die, so an empty pipe is no handoff.
func readReapTarget(fd int) (t cgroupenforce.ReapTarget, ok bool, err error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return t, false, err
	}
	buf := make([]byte, reapHandoffMax+1)
	n, err := unix.Read(fd, buf)
	if errors.Is(err, unix.EAGAIN) || err == nil && n == 0 {
		return t, false, nil
	}
	if err != nil {
		return t, false, err
	}
	f := strings.Split(string(buf[:n]), "\x00")
	if len(f) != 6 {
		return t, false, fmt.Errorf("handed-over target has %d fields, want 6", len(f))
	}
	t, err = parseReapTarget([6]string(f))
	return t, err == nil, err
}

// reaped is the optional Handle extension of a tier whose kernel state outlives its launcher and so wants a
// reaper: tier 2 (cgroupenforce.Handle.ReapTarget).
type reaped interface {
	ReapTarget() cgroupenforce.ReapTarget
}

// startReaper is §4.1's step after Prepare at tiers 2 and 3 (ADR 0020 (2)): it starts the run's reaper,
// without waiting for it. A run with neither a tier-2 handle (reaped) nor a DNS directory starts none. A reaper
// that cannot be started fails the run in the fanotify fallback, where it is the only narrowing of E15
// (ADR 0020 (4)); a plane mode (ADR 0024), where the kernel decides and the reaper is promptness and the record,
// is to record gap what=enforce why=reaper-unavailable and go on, and none is built yet, so it fails there too.
// A run that holds an owned DNS broker endpoint has its reaper already, at every tier (startDNSReaper, ADR
// 0020's 2026-10-05 notes): this hands it the tier's target, if the tier has one, and closes the handoff.
func (r *runner) startReaper() error {
	t, ok := r.handle.(reaped)
	if r.dnsDirectory != nil {
		handoff := r.reapHandoff
		if handoff == nil {
			return nil // a test binary's run, which starts no reaper (reaperExe)
		}
		r.reapHandoff = nil
		defer func() { _ = handoff.Close() }()
		if !ok {
			return nil
		}
		if err := handOffReapTarget(handoff, t.ReapTarget()); err != nil {
			return fmt.Errorf("runtime: hand the run's reaper its tier's kernel state, without which a launcher's "+
				"death leaves the run's opens unenforced until the next sweep (enforce-cgroup-observe E15): %w", err)
		}
		return nil
	}
	if !ok {
		return nil
	}
	exe, start := r.reaperExe()
	if !start {
		return nil
	}
	if err := startReaperProcess(exe, r.reapSpec(t.ReapTarget()), r.writer, nil); err != nil {
		return fmt.Errorf("runtime: start the run's reaper, without which a launcher's death leaves the "+
			"run's opens unenforced until the next sweep (enforce-cgroup-observe E15): %w", err)
	}
	return nil
}

// startDNSReaper starts a DNS broker's run's reaper as soon as setupDNSBroker has bound the endpoint, before
// Prepare, with no tier target yet: Prepare loads and attaches for up to a second at tiers 2 and 3, and a
// launcher SIGKILLed or OOM-killed there left /tmp/tego-dns-N and its socket with no reaper to remove them.
// startReaper hands it the target through the pipe whose write end r.reapHandoff keeps. A
// reaper that cannot start fails the run before Prepare.
func (r *runner) startDNSReaper() error {
	if r.dnsDirectory == nil {
		return nil
	}
	exe, start := r.reaperExe()
	if !start {
		return nil
	}
	rd, wr, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("runtime: start the run's reaper for owned DNS endpoint cleanup: %w", err)
	}
	spec := r.reapSpec(cgroupenforce.ReapTarget{})
	spec.DNSName, spec.DNSDev, spec.DNSIno = r.dnsDirectory.name, r.dnsDirectory.socketDev, r.dnsDirectory.socketIno
	err = startReaperProcess(exe, spec, r.writer, &reapDNS{dir: r.dnsDirectory, handoff: rd})
	_ = rd.Close()
	if err != nil {
		_ = wr.Close()
		return fmt.Errorf("runtime: start the run's reaper for owned DNS endpoint cleanup: %w", err)
	}
	r.reapHandoff = wr
	return nil
}

// reaperExe is the binary a reaper runs, and whether to start one at all: a Go test binary is never tego.
func (r *runner) reaperExe() (string, bool) {
	exe := r.stageExe()
	if exe == "" {
		// Re-executed with ReapCommand, a test binary would run its whole suite, detached.
		if self, err := os.Executable(); err == nil && strings.HasSuffix(self, ".test") {
			return "", false
		}
		exe = "/proc/self/exe"
	}
	return exe, true
}

// reapSpec is the reaper's argv for this run with target as its tier's.
func (r *runner) reapSpec(target cgroupenforce.ReapTarget) reapSpec {
	mount, _ := splitCgroupPath(r.cg.Path)
	if mount == "" {
		mount = identity.SystemCgroupRoot
	}
	return reapSpec{ID: string(r.id), Agent: string(r.agentID), Dir: r.dir, CgroupMount: mount,
		CgroupPath: r.cg.Path, CgroupID: r.cg.ID, Target: target, Anchor: r.anchorFile()}
}

// reapDNS is what a DNS broker's run's reaper inherits beyond an ordinary reaper's two descriptors: the
// endpoint's held directory and /tmp parent, and the read end of its target handoff.
type reapDNS struct {
	dir     *dnsDirectory
	handoff *os.File
}

// startReaperProcess starts exe as the reaper of spec's run, in tego's helper cgroup when this process can put
// it there (cgroup.StartHelper), in a session of its own, with the launcher's pidfd and the run directory, from
// w, and for a DNS broker's run the exact DNS socket directory and parent and the handoff's read end, as its
// only descriptors beyond /dev/null.
func startReaperProcess(exe string, spec reapSpec, w *ledger.Writer, dns *reapDNS) error {
	if spec.DNSName != "" && (dns == nil || dns.dir == nil || dns.handoff == nil || dns.dir.name != spec.DNSName || dns.dir.socketIno != spec.DNSIno || dns.dir.socketDev != spec.DNSDev) {
		return errors.New("DNS cleanup descriptors do not match the reaper specification")
	}
	if reapStartFails() {
		return errors.New("the test hook refuses the reaper's start")
	}
	// The launcher's own pidfd goes to the reaper as ExtraFiles 0, released from its owner into the File the
	// exec passes on (ADR 0020 (2), ADR 0023 C9).
	self, err := sys.PidfdOpenProcessFD(os.Getpid())
	if err != nil {
		return fmt.Errorf("pidfd_open(self): %w", err)
	}
	pidfd, err := self.Release("launcher-pidfd")
	if err != nil {
		_ = self.Close()
		return fmt.Errorf("pidfd_open(self): %w", err)
	}
	defer func() { _ = pidfd.Close() }()
	if w == nil {
		return errors.New("the run has no ledger writer")
	}
	dir, err := w.OpenDirPath()
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	_, err = cgroup.StartHelper(func(extra []string) *proc.Cmd {
		return reaperCommand(exe, spec, pidfd, dir, extra, dns)
	})
	return err
}

// reaperCommand is the reaper's exec: argv, environment, descriptors and session. Stdin, stdout and stderr are
// left nil, which os/exec opens on /dev/null.
func reaperCommand(exe string, spec reapSpec, pidfd, dir *os.File, extraEnv []string, dns *reapDNS) *proc.Cmd {
	cmd := proc.Command(exe, append([]string{ReapCommand}, spec.args()...)...)
	cmd.Dir = "/"
	cmd.Env = append(append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, reapTestEnv()...), extraEnv...)
	cmd.ExtraFiles = []*os.File{pidfd, dir}
	if spec.DNSName != "" && dns != nil && dns.dir != nil && dns.handoff != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, dns.dir.file, dns.dir.parent, dns.handoff)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}

// ReapMain is `tego __reap <run id> <agent> <run dir> <cgroup mount> <cgroup path> <cgroup id> <hash> <bpffs>
// <state dir> <linger> <anchor> <slot> <plane mode> [<dns dir name> <dns socket dev> <dns socket ino>]`, with the
// launcher's pidfd at descriptor 3 and the run directory at 4: the run's reaper. A run with an owned DNS broker
// endpoint passes the three bracketed fields (16 in all, else 13) and three more descriptors, the held DNS socket
// directory at 5, the verified root-owned /tmp parent at 6 and the target handoff pipe's read end at 7 (ADR
// 0020's 2026-10-05 notes). It returns the process's exit code.
func ReapMain(args []string) int {
	spec, err := parseReapSpec(args)
	firstStray := reapDirFD + 1
	if err == nil && spec.DNSName != "" {
		firstStray = reapHandoffFD + 1
	}
	// The sweep and the owners of what the launcher passed on purpose are this process's first descriptor
	// operations (ADR 0023 C9): sys refuses both once anything else owns a number.
	if serr := sys.CloseInheritedFrom(firstStray); serr != nil {
		fmt.Fprintf(os.Stderr, "tego %s: %v\n", ReapCommand, serr)
		return identity.ExitError
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tego %s: %v\n", ReapCommand, err)
		return identity.ExitUsage
	}
	fds, err := inheritReapFDs(spec.DNSName != "")
	defer fds.close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tego %s: %v\n", ReapCommand, err)
		return identity.ExitError
	}
	// Below the kernel's OOM choice of any other process where this one may say so (CAP_SYS_RESOURCE); under the
	// file-capability path it cannot, and an OOM kill that takes it with its launcher leaves the run to the next
	// sweep (ADR 0020 (7)).
	_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("run", spec.ID)
	if err := fds.pid.Borrow(waitPidfd); err != nil {
		log.Error("reap: wait for the launcher", "err", err)
		return identity.ExitError
	}
	_ = fds.pid.Close()
	if spec.DNSName != "" {
		// Started before Prepare (startDNSReaper): the tier's target is what the launcher handed over, if anything.
		var target cgroupenforce.ReapTarget
		var ok bool
		err := fds.handoff.Borrow(func(n int) error {
			var err error
			target, ok, err = readReapTarget(n)
			return err
		})
		_ = fds.handoff.Close()
		if err != nil {
			log.Error("reap: the launcher's handed-over target; the tier's kernel state is left to the sweep", "err", err)
		} else if ok {
			spec.Target = target
		}
	}
	reapHold()
	purged, err := sweepRun(context.Background(), spec, fds.dir, log)
	_ = fds.dir.Close()
	// A false/nil result is an already-ended run with an absent scope.
	// Every other false result keeps resources while the tree may remain.
	if spec.DNSName != "" && (purged || err == nil) {
		err = errors.Join(err, fds.cleanupDNS(spec))
	}
	if err != nil {
		log.Error("reap", "err", err)
	}
	code := identity.ExitOK
	if err != nil {
		code = identity.ExitError
	}
	if !purged || spec.Target.Hash == "" {
		return code
	}
	if err := reapBuild(spec.Target, spec.CgroupMount, nil); err != nil {
		log.Error("reap: the build's duties", "err", err)
		return identity.ExitError
	}
	return code
}

// reapBuild is cgroupenforce.ReapBuild; a variable so a test sees whether the reaper does the build's duties.
var reapBuild = cgroupenforce.ReapBuild

// reapFDs owns the reaper's inherited descriptors, each through sys.Inherited with the kind its launcher passed
// (ADR 0023 C9): the launcher's pidfd and the run directory, and for a run with an owned DNS broker endpoint the
// held socket directory, its /tmp parent and the handoff's read end (nil otherwise).
type reapFDs struct {
	pid, dir, dnsDir, dnsParent, handoff *sys.FD
}

// inheritReapFDs owns the numbers ReapMain's doc names. A number that is not open, or not the kind its launcher
// passed, is an error, and the reaper fails closed on it before it acts on anything: what it would have waited
// on, read, swept or unlinked could be another file.
func inheritReapFDs(dns bool) (reapFDs, error) {
	var f reapFDs
	var err error
	if f.pid, err = sys.Inherited(reapPidFD, sys.KindPidfd, "launcher-pidfd"); err != nil {
		return f, err
	}
	if f.dir, err = sys.Inherited(reapDirFD, sys.KindDir, "run-dir"); err != nil || !dns {
		return f, err
	}
	if f.dnsDir, err = sys.Inherited(reapDNSDirFD, sys.KindDir, "dns-dir"); err != nil {
		return f, err
	}
	if f.dnsParent, err = sys.Inherited(reapDNSParentFD, sys.KindDir, "dns-parent"); err != nil {
		return f, err
	}
	f.handoff, err = sys.Inherited(reapHandoffFD, sys.KindFIFO, "target-handoff")
	return f, err
}

// close closes every descriptor f still owns; Close of one already closed, or nil, is a no-op.
func (f reapFDs) close() {
	for _, d := range []*sys.FD{f.pid, f.dir, f.dnsDir, f.dnsParent, f.handoff} {
		_ = d.Close()
	}
}

// cleanupDNS is cleanupReapDNS on the held DNS socket directory and its parent, each lent for the call.
func (f reapFDs) cleanupDNS(spec reapSpec) error {
	dir, err := f.dnsDir.Hold()
	if err != nil {
		return err
	}
	defer dir.Return()
	parent, err := f.dnsParent.Hold()
	if err != nil {
		return err
	}
	defer parent.Return()
	return cleanupReapDNS(spec, dir.Num(), parent.Num())
}

// closeStrayFDs closes every descriptor from first on that the reaper did not inherit on purpose, keeping the Go
// runtime's own poller should it exist: an exec from the Go launcher passes only what ExtraFiles names, and this
// makes the reaper's descriptor set exactly that whatever its parent was.
func closeStrayFDs(first int) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < first {
			continue
		}
		link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue // the listing's own descriptor, closed by now
		}
		if link == "anon_inode:[eventpoll]" || link == "anon_inode:[eventfd]" {
			continue
		}
		_ = unix.Close(fd)
	}
}

// waitPidfd blocks until the pidfd at fd is readable: its process has exited.
func waitPidfd(fd int) error {
	for {
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll(pidfd): %w", err)
		}
		if n > 0 {
			return nil
		}
	}
}

// reapKillRound bounds one cgroup.kill's wait for populated 0; the reaper then writes cgroup.kill again, for as
// long as the run's cgroup holds a process: a task in uninterruptible sleep keeps the run's links and rows,
// and the reaper keeps at it.
const reapKillRound = 5 * time.Second

// reapLockWait bounds the wait for a run's lock that another process held when the reaper came to end the run:
// a process of the run's tree that took it after its launcher died, which the kill ended, or a sweep that ends
// the run itself.
const reapLockWait = 5 * time.Second

// sweepRun ends one run whose launcher is gone (ADR 0020 (3)): the ledger through the run directory's
// descriptor dir, the run's own scope (at spec's path, with spec's id), then its kernel state. It reports
// whether it purged it: false when the launcher had ended the run and removed its scope itself, or when the
// scope could not be removed, whose kernel state is then kept. Once the scope is gone it is true whatever else the
// purge met (a run-set scrub, a slot or a ring it could not release): the reaper still owes the build its duties
// (ADR 0022 (3)), which refuse a build whose run set names a live cgroup, and only ErrRunAlive, a cgroup still
// listed, keeps them from it.
func sweepRun(ctx context.Context, spec reapSpec, dir sys.Lender, log *slog.Logger) (purged bool, err error) {
	ref := record.RunRef{ID: spec.ID, Agent: spec.Agent}
	open := func() (*ledger.Writer, error) {
		// The launcher's Writer made every file, so the reaper makes none. It wakes as its launcher exits, and an
		// ended run's directory can be going by then (TestRootAskUnix's t.TempDir once met a lock made behind its
		// RemoveAll): a file missing is a run being removed, ended by what removes it.
		opts := []ledger.Option{ledger.WithLogger(log), ledger.WithExistingFiles()}
		if spec.Anchor != "" {
			opts = append(opts, ledger.WithAnchor(ledger.NewFileChainAnchor(spec.Anchor)))
		}
		return ledger.OpenAt(dir, spec.Dir, ref, opts...)
	}
	w, werr := open()
	ended := errors.Is(werr, ledger.ErrRunEnded) || errors.Is(werr, os.ErrNotExist)
	fs, err := cgroup.NewAt(spec.CgroupMount)
	if err != nil {
		abandon(w)
		return false, err
	}
	c := cgroup.Cgroup{Path: spec.CgroupPath}
	present := runScopePresent(fs, c, spec.CgroupID)
	if ended && !present {
		return false, nil // the launcher ended the run and removed its scope
	}
	if werr != nil && !ended && !errors.Is(werr, ledger.ErrRunLocked) {
		log.Warn("reap: the run's ledger cannot be ended; its tree is killed all the same", "err", werr)
	}
	if present {
		for round := 0; ; round++ {
			populated, err := cgroup.Populated(c)
			if err != nil || !populated {
				break
			}
			if err := fs.Kill(c); err != nil {
				log.Warn("reap: cgroup.kill", "path", c.Path, "err", err)
			}
			wait, cancel := context.WithTimeout(ctx, reapKillRound)
			err = fs.WaitEmpty(wait, c)
			cancel()
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				abandon(w)
				return false, ctx.Err()
			}
			if round == 0 {
				log.Warn("reap: the run's tree outlives cgroup.kill; its kernel state is kept while it does",
					"path", c.Path, "err", err)
			}
		}
	}
	if errors.Is(werr, ledger.ErrRunLocked) {
		deadline := time.Now().Add(reapLockWait)
		for errors.Is(werr, ledger.ErrRunLocked) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			w, werr = open()
		}
	}
	var lerr error
	if w != nil {
		if w.Seq() == 0 {
			// No run_start: a run that never started has nothing to end, and is left for retention, as a sweep
			// leaves it (ledger's sweepEmpty).
			lerr = w.Abandon()
		} else {
			// The run's tree is gone and its scope not yet removed, so the run-set rows still hold its slot and the
			// plane's counters there are this run's, final (enforce-plane §2.8). A scope that was already gone
			// may have lost its slot to another run, whose counters these would be.
			if present {
				for _, ev := range orphanPlaneGaps(spec.Target, spec.CgroupID, readPlaneCounters, log) {
					if err := w.Append(ev); err != nil {
						log.Warn("reap: write a plane counter's gap", "err", err)
					}
				}
			}
			// As for GC's sweep, report launcher failure rather than an unknown
			// child wait status or the reaper's own process exit.
			lerr = w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned, ExitCode: identity.ExitLauncher})
		}
	}
	if present {
		if err := fs.Remove(ctx, c); err != nil {
			return false, errors.Join(lerr, fmt.Errorf("remove the run's cgroup; its links, rows and slot are kept: %w", err))
		}
		if os.Geteuid() == 0 {
			removeRootMark(spec.ID)
		}
	}
	if spec.Target.Hash == "" {
		return true, lerr
	}
	res, err := purgeRun(cgroupenforce.PurgeOptions{BPFFS: spec.Target.BPFFS,
		StateDir: spec.Target.StateDir, CgroupMount: spec.CgroupMount, Hash: spec.Target.Hash, RunID: spec.ID,
		CgroupID: spec.CgroupID})
	if res.Links || len(res.Slots) > 0 || res.Rings > 0 {
		log.Info("reap: purged", "links", res.Links, "slots", res.Slots, "rings", res.Rings)
	}
	return !errors.Is(err, cgroupenforce.ErrRunAlive), errors.Join(lerr, err)
}

// readPlaneCounters is cgroupenforce.ReadPlaneCounters, a variable so a test can see what the reaper asks.
var readPlaneCounters = cgroupenforce.ReadPlaneCounters

// orphanPlaneGaps are the lines the plane's counters of an orphaned run's slot give (enforce-plane §2.8), as the
// launcher would have written them at its run end (runner.emitPlaneGaps): one gap what=enforce per non-zero counter,
// naming the mode; one plane-counters-unread when the slot cannot be read; none for a run on the listener.
func orphanPlaneGaps(t cgroupenforce.ReapTarget, cgroupID uint64,
	read func(cgroupenforce.ReapTarget) ([]cgroupenforce.PlaneCount, error), log *slog.Logger) []*record.Event {
	if t.PlaneMode == "" {
		return nil
	}
	gap := func(why string, n uint64) *record.Event {
		count := uint64(math.MaxInt32)
		if n < count {
			count = n
		}
		ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: os.Getpid(), TID: os.Getpid(),
			Cgroup: cgroupID}
		if err := ev.SetPayload(record.GapPayload{What: record.GapEnforce, Why: why, Count: int(count),
			DecisionPlane: t.PlaneMode}); err != nil {
			return nil
		}
		return ev
	}
	counts, err := read(t)
	if err != nil {
		log.Warn("reap: read the decision plane's counters", "err", err)
		if ev := gap(record.GapPlaneCountersUnread, 0); ev != nil {
			return []*record.Event{ev}
		}
		return nil
	}
	var out []*record.Event
	for _, c := range counts {
		if c.Count == 0 {
			continue
		}
		if ev := gap(c.Why, c.Count); ev != nil {
			out = append(out, ev)
		}
	}
	return out
}

// abandon releases a Writer that will write nothing, if there is one.
func abandon(w *ledger.Writer) {
	if w != nil {
		_ = w.Abandon()
	}
}

// runScopePresent reports whether the run's own scope exists: a directory at c.Path whose cgroup id is id (any,
// for 0). A scope of that name with another id is another run's, and the reaper never touches it.
func runScopePresent(fs *cgroup.FS, c cgroup.Cgroup, id uint64) bool {
	if _, err := os.Lstat(c.Path); err != nil {
		return false
	}
	if id == 0 {
		return true
	}
	got, err := fs.ID(c)
	return err == nil && got == id
}

// openLedgerAt is ledger.OpenAt for the run directory open at the inherited number dirfd: OpenAt takes a
// sys.Lender (ADR 0023), so the directory is reopened into an owner of its own for the open and closed after
// it; the Writer keeps a descriptor of its own, reopened from that one.
func openLedgerAt(dirfd int, dir string, ref record.RunRef, opts ...ledger.Option) (*ledger.Writer, error) {
	d, err := sys.Own(unix.Openat(dirfd, ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, fmt.Errorf("ledger: reopen run dir %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	return ledger.OpenAt(d, dir, ref, opts...)
}
