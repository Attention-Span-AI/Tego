// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A descriptor number is process-wide. When code elsewhere in the launcher closes a number the
// builder holds, the kernel hands it to the next open anywhere in the process, and a landlock_add_rule
// through it lands on that file. These tests play that stray closer through the syscall seam, at the
// moment the builder passes the number to the kernel.

// thievingSyscalls is a syscall seam with a stray closer in the process, which strikes once: steal just
// before the path rule whose descriptor names victim, stealNet just before the first net rule, stealProbe
// just before the ruleset number is first probed, which is after the last rule went in. steal and
// stealNet may return the errno the kernel would then answer.
type thievingSyscalls struct {
	landlockSyscalls
	victim     devIno
	steal      func(rulesetFD int, attr *unix.LandlockPathBeneathAttr) error
	stealNet   func(rulesetFD int) error
	stealProbe func(rulesetFD int)
	stolen     bool
}

func (s *thievingSyscalls) AddPathRule(rulesetFD int, attr *unix.LandlockPathBeneathAttr, flags int) error {
	var st unix.Stat_t
	if !s.stolen && s.steal != nil && unix.Fstat(int(attr.Parent_fd), &st) == nil && (devIno{st.Dev, st.Ino}) == s.victim {
		s.stolen = true
		if err := s.steal(rulesetFD, attr); err != nil {
			return err
		}
	}
	return s.landlockSyscalls.AddPathRule(rulesetFD, attr, flags)
}

func (s *thievingSyscalls) AddNetPortRule(rulesetFD int, attr *netPortAttr, flags int) error {
	if !s.stolen && s.stealNet != nil {
		s.stolen = true
		if err := s.stealNet(rulesetFD); err != nil {
			return err
		}
	}
	return s.landlockSyscalls.AddNetPortRule(rulesetFD, attr, flags)
}

func (s *thievingSyscalls) ProbeRuleset(rulesetFD int) error {
	if !s.stolen && s.stealProbe != nil {
		s.stolen = true
		s.stealProbe(rulesetFD)
	}
	return s.landlockSyscalls.ProbeRuleset(rulesetFD)
}

func identityOf(t *testing.T, path string) devIno {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return devIno{st.Dev, st.Ino}
}

// sentinel is an unrelated open descriptor: the next open anywhere in the process that the kernel hands a
// freed number to. Its identity is what the number must still name after the builder has finished.
func sentinel(t *testing.T) (fd int, id devIno) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) })
	var st unix.Stat_t
	if err := unix.Fstat(p[0], &st); err != nil {
		t.Fatal(err)
	}
	return p[0], devIno{st.Dev, st.Ino}
}

// opathSentinel is an unrelated O_PATH descriptor, the kind of open the builder itself makes for every
// held path: in the original trace a later Prepare's sibling open was handed a number freed under a Handle.
// Its file is its own, in a directory of its own, so no held number can name it.
func opathSentinel(t *testing.T) (fd int, id devIno) {
	t.Helper()
	p := filepath.Join(tempDir(t), "other-owner")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd, identityOf(t, p)
}

// standIn is a kind of file another owner's open can leave at a freed ruleset number, with the answer the
// ruleset probe gets for it. The kernel looks the ruleset number up with fdget, which does not see O_PATH
// files, so an O_PATH file there answers EBADF, as a closed number does, and any other file EBADFD.
type standIn struct {
	name  string
	open  func(t *testing.T) (int, devIno)
	errno unix.Errno
	said  string // what rulesetStill's error says the number names
}

var standIns = []standIn{
	{"pipe", sentinel, unix.EBADFD, "names a file that is not a Landlock ruleset"},
	{"O_PATH", opathSentinel, unix.EBADF, "is not open, or names an O_PATH file"},
}

// checkProbeAnswers is the table the kernel's ProbeRuleset is held to on the real kernel
// (TestProbeRulesetAnswersOnTheKernel) and the fake's on every run (TestFakeProbeRulesetAnswersAsTheKernel):
// ENOMSG for the live ruleset rulesetFD, each stand-in's errno for that file, EBADF for a closed number.
func checkProbeAnswers(t *testing.T, sc landlockSyscalls, rulesetFD int) {
	t.Helper()
	if err := sc.ProbeRuleset(rulesetFD); !errors.Is(err, unix.ENOMSG) {
		t.Errorf("probe of a live ruleset = %v, want ENOMSG", err)
	}
	for _, s := range standIns {
		fd, _ := s.open(t)
		if err := sc.ProbeRuleset(fd); !errors.Is(err, s.errno) {
			t.Errorf("probe of an open %s file = %v, want %v", s.name, err, s.errno)
		}
	}
	// A number well above the lowest free one, closed: nothing else in the test binary reopens it. It is
	// dup3'd and closed here, not through standAt, whose cleanup would close it a second time.
	const closed = 1000
	pipe, _ := sentinel(t)
	if err := unix.Dup3(pipe, closed, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(closed); err != nil {
		t.Fatal(err)
	}
	if err := sc.ProbeRuleset(closed); !errors.Is(err, unix.EBADF) {
		t.Errorf("probe of a closed number = %v, want EBADF", err)
	}
}

// TestFakeProbeRulesetAnswersAsTheKernel holds the fake to the kernel's answers, so the fake-kernel
// ruleset tests below see what the kernel would say about each file left at the ruleset number.
func TestFakeProbeRulesetAnswersAsTheKernel(t *testing.T) {
	sc := &fakeSyscalls{abi: 7}
	attr := unix.LandlockRulesetAttr{Handled_access_fs: uint64(profileFor(7).FS)}
	fd, err := sc.CreateRuleset(&attr, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	checkProbeAnswers(t, sc, fd)
}

// standAt dup3s the sentinel onto number, atomically closing whatever the number named: the stray
// close and the reuse in one step, so nothing else in the test can take the number in between.
func standAt(t *testing.T, sentinelFD, number int) {
	t.Helper()
	if err := unix.Dup3(sentinelFD, number, unix.O_CLOEXEC); err != nil {
		t.Fatalf("dup3 onto %d: %v", number, err)
	}
	t.Cleanup(func() { _ = unix.Close(number) })
}

// stillNames fails unless number is open and names the sentinel.
func stillNames(t *testing.T, number int, id devIno, what string) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(number, &st); err != nil {
		t.Fatalf("%s closed fd %d, which another owner held: %v", what, number, err)
	}
	if (devIno{st.Dev, st.Ino}) != id {
		t.Fatalf("fd %d names dev %d ino %d after %s, want the other owner's file (ino %d)", number, st.Dev, st.Ino, what, id.ino)
	}
}

// heldTable is one deny_read target with two enumerated siblings beside it.
func heldTable(t *testing.T) (*agent.RuleTable, string) {
	t.Helper()
	root := tempDir(t)
	mkTree(t, root, "secret/key", "public/", "note")
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS:       []agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(root, "secret"))},
	}
	return rt, root
}

// TestRuleOnAReusedNumberFailsTheBuild is the consequence of a double close: the sibling's number is closed by
// another owner and handed to an unrelated file just before its rule goes in, so the kernel would add the
// sibling's read rights to that file. The build must fail rather than return that ruleset, and the
// cleanup must leave the number alone, because it is the other owner's now.
//
// Spec: docs/p0/enforce-landlock.md I12.
func TestRuleOnAReusedNumberFailsTheBuild(t *testing.T) {
	rt, root := heldTable(t)
	public := filepath.Join(root, "public")
	sfd, sid := sentinel(t)
	var number int
	sc := &thievingSyscalls{landlockSyscalls: &fakeSyscalls{abi: 7}, victim: identityOf(t, public)}
	sc.steal = func(_ int, attr *unix.LandlockPathBeneathAttr) error {
		number = int(attr.Parent_fd)
		standAt(t, sfd, number)
		return nil // the kernel takes the rule: it lands on the sentinel
	}
	before := openFDs(t)
	h, err := New(Options{syscalls: sc}).Prepare(context.Background(), rt, Run{})
	if err == nil {
		_ = h.Close()
		t.Fatal("Prepare returned a ruleset with a rule added through a number another owner had reopened")
	}
	if !sc.stolen {
		t.Fatal("no rule went in for the sibling: the test did not exercise the reuse")
	}
	if !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), public) || !strings.Contains(err.Error(), "not closed again") {
		t.Errorf("error %v, want ErrRulesetBuild naming %q as lost and not closed again", err, public)
	}
	stillNames(t, number, sid, "Prepare's cleanup")
	// The sentinel's own number stands at the stolen one: one more descriptor than before, no leak besides.
	if after := openFDs(t); after != before+1 {
		t.Errorf("fds %d -> %d, want one more (the other owner's): a held fd leaked or an extra one was closed", before, after)
	}
}

// TestClosedHeldNumberNamesTheLostEntry is the shape observed under full-suite load: the number was closed
// and not yet reused, so the kernel answers EBADF for the sibling. The error says which held descriptor was
// lost, instead of reading as a broken ruleset.
//
// Spec: docs/p0/enforce-landlock.md I12.
func TestClosedHeldNumberNamesTheLostEntry(t *testing.T) {
	rt, root := heldTable(t)
	public := filepath.Join(root, "public")
	sc := &thievingSyscalls{landlockSyscalls: &fakeSyscalls{abi: 7}, victim: identityOf(t, public)}
	sc.steal = func(_ int, attr *unix.LandlockPathBeneathAttr) error {
		if err := unix.Close(int(attr.Parent_fd)); err != nil {
			t.Fatalf("stray close: %v", err)
		}
		return unix.EBADF
	}
	before := openFDs(t)
	h, err := New(Options{syscalls: sc}).Prepare(context.Background(), rt, Run{})
	if err == nil {
		_ = h.Close()
		t.Fatal("Prepare succeeded with a closed held fd")
	}
	if !errors.Is(err, ErrRulesetBuild) || !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), public+`" is not open any more`) {
		t.Errorf("error %v, want the EBADF and the lost entry %q named", err, public)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak: %d -> %d", before, after)
	}
}

// TestRulesetNumberClosedByAnotherOwnerIsLeftOpen: when every held number still names its own file and the
// kernel answers EBADF, the number that was closed is the ruleset's. Whatever the process opened next may
// hold it by the time the builder cleans up, so the builder must not close it.
func TestRulesetNumberClosedByAnotherOwnerIsLeftOpen(t *testing.T) {
	rt, root := heldTable(t)
	sfd, sid := sentinel(t)
	var number int
	sc := &thievingSyscalls{landlockSyscalls: &fakeSyscalls{abi: 7}, victim: identityOf(t, filepath.Join(root, "public"))}
	sc.steal = func(rulesetFD int, _ *unix.LandlockPathBeneathAttr) error {
		number = rulesetFD
		standAt(t, sfd, number) // the stray close, then the next open, right after the kernel's EBADF
		return unix.EBADF
	}
	h, err := New(Options{syscalls: sc}).Prepare(context.Background(), rt, Run{})
	if err == nil {
		_ = h.Close()
		t.Fatal("Prepare succeeded after the ruleset fd was lost")
	}
	if !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), "the ruleset fd") {
		t.Errorf("error %v, want the ruleset fd named as the closed number", err)
	}
	stillNames(t, number, sid, "Prepare's cleanup")
}

// TestCloseLeavesAStolenNumberOpen: Close is the one release path of every held number (§9). A number that
// another owner closed and the kernel handed out again after Prepare returned is reported by Close, not
// closed a second time.
func TestCloseLeavesAStolenNumberOpen(t *testing.T) {
	rt, root := heldTable(t)
	public := filepath.Join(root, "public")
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatal(err)
	}
	e, ok := h.entry(public)
	if !ok {
		t.Fatalf("no entry for %s", public)
	}
	sfd, sid := sentinel(t)
	standAt(t, sfd, e.FD)
	held, before := len(h.fds.open), openFDs(t)
	err = h.Close()
	if err == nil || !strings.Contains(err.Error(), public) {
		t.Errorf("Close = %v, want the lost entry %q reported", err, public)
	}
	stillNames(t, e.FD, sid, "Close")
	// Every other held fd and the ruleset fd are closed: held-1 entries plus the ruleset.
	if after := openFDs(t); after != before-held {
		t.Errorf("fds %d -> %d, want %d: Close left a held fd open or closed one more", before, after, before-held)
	}
}

// rulesetLeftOpen checks the shape every stolen-ruleset test expects: the build or Close failed naming the
// ruleset number with the probe's answer for the stand-in s now there, as not closed again, and that file
// is still open at the number.
func rulesetLeftOpen(t *testing.T, err error, s standIn, number int, id devIno, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded with the ruleset fd %d reopened on another file (%s)", what, number, s.name)
	}
	if !errors.Is(err, s.errno) || !strings.Contains(err.Error(), "the ruleset fd") || !strings.Contains(err.Error(), s.said) ||
		!strings.Contains(err.Error(), "not closed again") {
		t.Errorf("%s: %v, want the ruleset fd named as one that %s (%v), not closed again", what, err, s.said, s.errno)
	}
	stillNames(t, number, id, what)
}

// TestRulesetNumberReopenedBeforeAnAddIsLeftOpen is the order the EBADF test above cannot see: the ruleset
// number is closed and reopened before the kernel looks it up, while every held number still names its
// own file. The kernel answers the add as the probe does, EBADFD for a pipe and EBADF for an O_PATH file.
// Prepare's cleanup must not close the file standing at the number.
func TestRulesetNumberReopenedBeforeAnAddIsLeftOpen(t *testing.T) {
	for _, s := range standIns {
		t.Run(s.name, func(t *testing.T) {
			rt, root := heldTable(t)
			sfd, sid := s.open(t)
			var number int
			sc := &thievingSyscalls{landlockSyscalls: &fakeSyscalls{abi: 7}, victim: identityOf(t, filepath.Join(root, "public"))}
			sc.steal = func(rulesetFD int, _ *unix.LandlockPathBeneathAttr) error {
				number = rulesetFD
				standAt(t, sfd, number)
				return s.errno
			}
			before := openFDs(t)
			h, err := New(Options{syscalls: sc}).Prepare(context.Background(), rt, Run{})
			if err == nil {
				_ = h.Close()
			}
			rulesetLeftOpen(t, err, s, number, sid, "Prepare's cleanup")
			if after := openFDs(t); after != before+1 {
				t.Errorf("fds %d -> %d, want one more (the other owner's): a held fd leaked or an extra one was closed", before, after)
			}
		})
	}
}

// TestRulesetNumberReopenedBeforeANetRuleIsLeftOpen: the same theft, landing before a port rule (R6), goes
// through the net-rule failure path, which closes the ruleset number no more than the path-rule one does.
func TestRulesetNumberReopenedBeforeANetRuleIsLeftOpen(t *testing.T) {
	rt, _ := heldTable(t)
	rt.Net = []agent.NetRule{inet(443)}
	sfd, sid := sentinel(t)
	var number int
	sc := &thievingSyscalls{landlockSyscalls: &fakeSyscalls{abi: 7}}
	sc.stealNet = func(rulesetFD int) error {
		number = rulesetFD
		standAt(t, sfd, number)
		return unix.EBADFD
	}
	h, err := New(Options{syscalls: sc}).Prepare(context.Background(), rt, Run{})
	if err == nil {
		_ = h.Close()
	}
	if !sc.stolen {
		t.Fatal("no net rule went in: the test did not exercise the net-rule path")
	}
	rulesetLeftOpen(t, err, standIns[0], number, sid, "Prepare's cleanup after a net rule")
}

// TestRulesetNumberReopenedAfterTheLastRuleFailsTheBuild: a theft after the last rule went in fails no
// landlock_add_rule, so only the ruleset probe sees it. Without it the Handle would carry a number that
// names another owner's file, which the launcher would hand the child and Close would close.
//
// Spec: docs/p0/enforce-landlock.md I12.
func TestRulesetNumberReopenedAfterTheLastRuleFailsTheBuild(t *testing.T) {
	for _, s := range standIns {
		t.Run(s.name, func(t *testing.T) {
			rt, _ := heldTable(t)
			sfd, sid := s.open(t)
			var number int
			sc := &thievingSyscalls{landlockSyscalls: &fakeSyscalls{abi: 7}}
			sc.stealProbe = func(rulesetFD int) {
				number = rulesetFD
				standAt(t, sfd, number)
			}
			h, err := New(Options{syscalls: sc}).Prepare(context.Background(), rt, Run{})
			if err == nil {
				_ = h.Close()
			}
			if !errors.Is(err, ErrRulesetBuild) {
				t.Errorf("error %v, want ErrRulesetBuild", err)
			}
			rulesetLeftOpen(t, err, s, number, sid, "Prepare")
		})
	}
}

// TestHeldAndRulesetNumbersBothReopened is the path where the held-number check fails after the last rule:
// its cleanup closes the ruleset number only after probing it, so a ruleset number taken in the same
// stray close stays with its new owner too.
func TestHeldAndRulesetNumbersBothReopened(t *testing.T) {
	rt, root := heldTable(t)
	public := filepath.Join(root, "public")
	heldFD, heldID := sentinel(t)
	rsFD, rsID := sentinel(t)
	var held, number int
	sc := &thievingSyscalls{landlockSyscalls: &fakeSyscalls{abi: 7}, victim: identityOf(t, public)}
	sc.steal = func(rulesetFD int, attr *unix.LandlockPathBeneathAttr) error {
		held, number = int(attr.Parent_fd), rulesetFD
		standAt(t, heldFD, held)
		standAt(t, rsFD, number)
		return nil // the fake takes the rule; the kernel would answer EBADFD, the other test's path
	}
	h, err := New(Options{syscalls: sc}).Prepare(context.Background(), rt, Run{})
	if err == nil {
		_ = h.Close()
	}
	if err == nil || !strings.Contains(err.Error(), public) {
		t.Errorf("error %v, want the lost entry %q named", err, public)
	}
	rulesetLeftOpen(t, err, standIns[0], number, rsID, "Prepare's cleanup")
	stillNames(t, held, heldID, "Prepare's cleanup")
}

// TestCloseLeavesAReopenedRulesetNumberOpen is the shape the closer first took, a finalizer closing
// the ruleset number while the Handle still owned it, with the number reused before Close: Close reports
// it and leaves the new file open, and still closes every held number.
func TestCloseLeavesAReopenedRulesetNumberOpen(t *testing.T) {
	for _, s := range standIns {
		t.Run(s.name, func(t *testing.T) {
			rt, _ := heldTable(t)
			h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{})
			if err != nil {
				t.Fatal(err)
			}
			number, _ := h.LandlockRuleset()
			sfd, sid := s.open(t)
			standAt(t, sfd, number)
			held, before := len(h.fds.open), openFDs(t)
			rulesetLeftOpen(t, h.Close(), s, number, sid, "Close")
			if after := openFDs(t); after != before-held {
				t.Errorf("fds %d -> %d, want %d: Close left a held fd open or closed the other owner's", before, after, before-held)
			}
		})
	}
}

// failingStatx answers errno for victim's number while *failing, and asks the kernel otherwise.
func failingStatx(victim devIno, errno error, failing *bool) func(int, *unix.Statx_t) error {
	return func(fd int, sx *unix.Statx_t) error {
		var st unix.Stat_t
		if *failing && unix.Fstat(fd, &st) == nil && (devIno{st.Dev, st.Ino}) == victim {
			return errno
		}
		return statxHeld(fd, sx)
	}
}

// TestUnknownIdentityFailsClosedWithoutDisowning: a statx failure other than EBADF does not show that the
// number was lost, so it is not reported as closed by another owner and the entry stays held. It still
// fails the build, since the rule that went in through the number cannot be vouched for. The cleanup asks
// again: once the answer is the entry's own file the number is closed as usual, and while it stays
// unknown the number is left open and said to be unknown.
func TestUnknownIdentityFailsClosedWithoutDisowning(t *testing.T) {
	for _, recovers := range []bool{true, false} {
		rt, root := heldTable(t)
		public := filepath.Join(root, "public")
		failing := true
		before := openFDs(t)
		bd := newBuilder(context.Background(), rt, Run{}, profileFor(7), &fakeSyscalls{abi: 7})
		bd.fds.statx = failingStatx(identityOf(t, public), unix.EIO, &failing)
		h, err := bd.build()
		if err == nil {
			_ = h.Close()
			t.Fatal("build succeeded while a held number's identity was unknown")
		}
		if !errors.Is(err, ErrRulesetBuild) || !errors.Is(err, unix.EIO) || !strings.Contains(err.Error(), "is unknown") ||
			strings.Contains(err.Error(), "something else in this process closed") {
			t.Errorf("error %v, want ErrRulesetBuild with the EIO and the identity of %q unknown, not called lost", err, public)
		}
		e, ok := func() (openPath, bool) {
			for _, p := range bd.fds.open {
				if p.Path == public {
					return p, true
				}
			}
			return openPath{}, false
		}()
		if !ok || e.FD < 0 {
			t.Fatalf("entry %+v held=%v: an unknown identity disowned the number", e, ok)
		}
		failing = !recovers
		err = bd.fds.closeAll()
		if recovers {
			if err != nil {
				t.Errorf("closeAll once statx answers again: %v", err)
			}
			if after := openFDs(t); after != before {
				t.Errorf("fds %d -> %d: the number was not closed once its identity was known", before, after)
			}
			continue
		}
		if err == nil || !errors.Is(err, unix.EIO) || !strings.Contains(err.Error(), "is unknown") {
			t.Errorf("closeAll = %v, want the identity of %q still unknown", err, public)
		}
		if after := openFDs(t); after != before+1 {
			t.Errorf("fds %d -> %d, want the one number of unknown identity left open", before, after)
		}
		_ = unix.Close(e.FD)
	}
}
