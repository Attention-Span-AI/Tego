// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// TestProbeSeccompHere is D5 against this kernel. It needs no privilege: the filter goes on a
// throwaway thread of this process, and the round trip is between two of its own goroutines.
func TestProbeSeccompHere(t *testing.T) {
	// D1's reading of this kernel, which is what decides whether an EINVAL here is the kernel's
	// answer or the probe's own failure (seccompSkipReason).
	_, release, kernel := probeKernelVersion()
	r, pt, roundTrip := probeSeccomp()
	t.Logf("%+v %+v round trip: %v; kernel %q", r, pt, roundTrip, release)
	if r.ID != CheckSeccomp {
		t.Fatalf("id %q", r.ID)
	}
	if !r.OK {
		if why := seccompSkipReason(roundTrip, pt, kernel); why != "" {
			t.Skipf("%s: %s", why, r.Detail)
		}
		t.Fatalf("the self-test failed: %s (fix: %s)", r.Detail, r.Fix)
	}
	// D5 reports the supervisor's ptrace access mode alongside the round trip: a filter this kernel
	// installs is worth nothing if Yama then refuses the supervisor's process_vm_readv/pidfd_getfd.
	if !strings.Contains(r.Detail, "yama") && pt.Scope != yamaAbsent {
		t.Errorf("detail %q does not say what Yama's ptrace_scope is", r.Detail)
	}
	if r.Fix != "" {
		t.Errorf("a passing probe carries a fix: %q", r.Fix)
	}
	if !strings.Contains(r.Detail, "ADDFD(SEND)") {
		t.Errorf("detail %q does not name what was tested", r.Detail)
	}
}

// seccompSkipReason is why TestProbeSeccompHere may skip a failed D5 rather than fail it, "" when
// it may not. kernel is D1's parsed release, the zero Version when D1 could not parse it. Two
// failures are properties of the machine rather than of the probe:
//
//   - An EINVAL from the round trip on a kernel D1 reads as below 5.14 (addfdSendSince). The round
//     trip cannot say which of its calls returned the EINVAL — seccomp(2), prctl or the ADDFD ioctl
//     all wrap theirs the same way — so the predicate does not try: below 5.14 the kernel lacks
//     SECCOMP_ADDFD_FLAG_SEND (and below 5.9 and 5.0, ADDFD and NEW_LISTENER as well), and an EINVAL
//     from any of the calls is that kernel refusing what it lacks. At or above 5.14 a kernel built
//     with CONFIG_SECCOMP_FILTER has every piece the round trip uses, so an EINVAL there is the
//     probe's own defect (a bad flag, a malformed struct) or a kernel without that option, and either
//     fails the test: the box cannot run tier 1, and the test says so rather than skipping. So does an
//     EINVAL on a kernel whose release D1 could not parse: an unknown kernel excuses nothing.
//   - A Yama scope that blocks the supervisor while the round trip itself worked.
//
// Anything else — EACCES from an outer filter, EBUSY, a timeout, an unexpected errno — fails the
// test, whatever the box's ptrace_scope happens to be: Yama is a global sysctl with no bearing on
// whether the round trip worked, so "Yama blocks" alone must not excuse a round trip that failed on
// its own.
//
// It decides from the round trip's own error rather than from the Result's prose. The EINVAL arm used
// to look for "EINVAL" in the detail, which never matched: an errno prints as "invalid argument".
func seccompSkipReason(roundTrip error, pt PtraceState, kernel Version) string {
	known := kernel != Version{}
	switch {
	case errors.Is(roundTrip, unix.EINVAL) && known && !kernel.AtLeast(addfdSendSince):
		return fmt.Sprintf("kernel %s is below %s and has no SECCOMP_ADDFD_FLAG_SEND", kernel, addfdSendSince)
	case roundTrip == nil && pt.Blocked != "":
		return "this box's Yama scope blocks the supervisor"
	}
	return ""
}

// TestSeccompSkipReasonExcusesOnlyYamaAlone holds TestProbeSeccompHere's skip to its word, which no
// run on a box at the distribution default (ptrace_scope=1, D5 green) can do, since nothing there
// reaches the skip. On a scope-2 box whose round trip also failed with EACCES, the skip it replaced
// (`pt.Blocked != ""`) reported SKIP for a real D5 failure; this asks the same question with a
// hand-built blocked PtraceState and each kind of round-trip failure. The EINVAL rows are the other
// half: an EINVAL excused on any kernel let a probe broken on this 6.17 box (an ADDFD flag the kernel
// rejects) report SKIP, "no SECCOMP_ADDFD_FLAG_SEND", on a kernel that has it. Only a kernel D1 reads
// as below 5.14 excuses one. Each case also runs through seccompVerdict, so the skip and the Result
// doctor prints agree about whose failure it was.
func TestSeccompSkipReasonExcusesOnlyYamaAlone(t *testing.T) {
	detail, blocked, remedy := yamaConsequence(yamaAdminOnly, false)
	yama := PtraceState{Scope: yamaAdminOnly, Detail: detail, Blocked: blocked, Fix: remedy}
	fine := PtraceState{Scope: yamaRelational, Detail: "yama ptrace_scope=1"}
	wrap := func(err error) error { return fmt.Errorf("%w: %w", ErrSeccompSelfTest, err) }
	current, old := Version{6, 17, 0}, Version{5, 10, 0}
	cases := []struct {
		name      string
		fd        int
		roundTrip error
		pt        PtraceState
		kernel    Version
		skip      bool
	}{
		{"Yama alone, the round trip worked", 3, nil, yama, current, true},
		{"EACCES from an outer filter on a Yama-blocked box", -1, wrap(unix.EACCES), yama, current, false},
		{"a timeout on a Yama-blocked box", -1,
			fmt.Errorf("%w: no answer within %s", ErrSeccompSelfTest, seccompSelfTestTimeout), yama, current, false},
		{"EBUSY under another supervisor on a Yama-blocked box", -1, wrap(unix.EBUSY), yama, current, false},
		{"EACCES with Yama at the default", -1, wrap(unix.EACCES), fine, current, false},
		{"EINVAL on 5.10, which has no ADDFD_FLAG_SEND", -1, wrap(unix.EINVAL), fine, old, true},
		// The kernel has every piece the round trip uses, so the EINVAL is the probe's own.
		{"EINVAL on 6.17", -1, wrap(unix.EINVAL), fine, current, false},
		{"EINVAL on 5.14.0 exactly", -1, wrap(unix.EINVAL), fine, addfdSendSince, false},
		{"EINVAL on a kernel D1 could not parse", -1, wrap(unix.EINVAL), fine, Version{}, false},
		// An old kernel excuses EINVAL only: it is no licence for a round trip failing another way.
		{"EACCES on 5.10", -1, wrap(unix.EACCES), fine, old, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := seccompSkipReason(tc.roundTrip, tc.pt, tc.kernel); (got != "") != tc.skip {
				t.Errorf("seccompSkipReason = %q, want skip=%v", got, tc.skip)
			}
			r := seccompVerdictOn(tc.fd, tc.roundTrip, tc.pt, tc.kernel)
			if r.OK {
				t.Fatalf("every case here is a D5 failure, got OK: %+v", r)
			}
			// The remedy agrees with the skip: only a kernel the skip excuses is told to upgrade.
			if upgrade := strings.Contains(r.Fix, "boot a kernel >= "+addfdSendSince.String()); errors.Is(tc.roundTrip, unix.EINVAL) &&
				upgrade != (tc.kernel == Version{} || !tc.kernel.AtLeast(addfdSendSince)) {
				t.Errorf("EINVAL on kernel %s: fix %q", tc.kernel, r.Fix)
			}
			yamaOnly := tc.roundTrip == nil
			if carries := tc.pt.Blocked != "" && strings.Contains(r.Detail, tc.pt.Blocked); carries != yamaOnly {
				t.Errorf("detail %q carries Yama's sentence=%v, want %v", r.Detail, carries, yamaOnly)
			}
		})
	}
}

// TestSeccompVerdictFoldsYamaInOnlyWhenTheRoundTripWorked pins D5's two-source verdict, branch by
// branch. Yama's scope is a global sysctl and the round-trip failures need a kernel or an outer
// filter this box does not have, so none of the failing branches fires here. seccompVerdict is pure
// over the round trip's outcome and the PtraceState, which reaches each of them without a sysctl or
// a kernel this test has no business changing.
//
// The invariant: a failure attributable to Yama names Yama's own sentence and the sysctl, and a round
// trip that fails for its own reasons names only that, with the remedy for that reason.
func TestSeccompVerdictFoldsYamaInOnlyWhenTheRoundTripWorked(t *testing.T) {
	detail, blocked, remedy := yamaConsequence(yamaAdminOnly, false)
	yama := PtraceState{Scope: yamaAdminOnly, Detail: detail, Blocked: blocked, Fix: remedy}

	r := seccompVerdict(3, nil, yama)
	if r.OK {
		t.Errorf("a round trip the supervisor could never use is reported OK: %+v", r)
	}
	if !strings.Contains(r.Detail, "ADDFD(SEND)") || !strings.Contains(r.Detail, blocked) {
		t.Errorf("detail %q does not carry both the round trip and the Yama reason %q", r.Detail, blocked)
	}
	if r.Fix != remedy {
		t.Errorf("fix %q, want the sysctl %q", r.Fix, remedy)
	}

	failures := []struct {
		name    string
		err     error
		wantFix string
	}{
		{"EINVAL: no ADDFD_FLAG_SEND", unix.EINVAL, ">= 5.14.0"},
		{"EACCES: an outer filter", unix.EACCES, "CAP_SYS_ADMIN"},
		// The kernel is fine here; a "boot a newer kernel" fix would send the operator the wrong way.
		{"EBUSY: a listener already on this chain", unix.EBUSY, "outside any seccomp user-notification supervisor"},
	}
	for _, f := range failures {
		r := seccompVerdict(-1, fmt.Errorf("%w: %w", ErrSeccompSelfTest, f.err), yama)
		if r.OK {
			t.Errorf("%s: reported OK", f.name)
		}
		if strings.Contains(r.Detail, blocked) {
			t.Errorf("%s: a self-test that failed on its own (%q) was reported as Yama's doing", f.name, r.Detail)
		}
		if !strings.Contains(r.Fix, f.wantFix) {
			t.Errorf("%s: fix %q, want one naming %q", f.name, r.Fix, f.wantFix)
		}
	}

	// Yama at the distribution default leaves D5's own verdict alone and adds its clause.
	detail, blocked, remedy = yamaConsequence(yamaRelational, false)
	if blocked != "" || remedy != "" {
		t.Fatalf("scope 1 is not supposed to block: %q / %q", blocked, remedy)
	}
	clean := seccompVerdict(3, nil, PtraceState{Scope: yamaRelational, Detail: detail})
	if !clean.OK {
		t.Errorf("a working round trip with Yama at scope 1 is not OK: %+v", clean)
	}
	if !strings.Contains(clean.Detail, detail) {
		t.Errorf("a passing D5 does not report the scope it read: %q", clean.Detail)
	}
	if clean.Fix != "" {
		t.Errorf("a passing probe carries a fix: %q", clean.Fix)
	}
}

// TestSeccompSelfTestLeavesNoFilteredThread runs the probe repeatedly and then checks that ordinary
// syscalls still work on every thread of this process: a leaked filter would make the notified
// syscall hang or fail on whichever goroutine inherited the thread.
func TestSeccompSelfTestLeavesNoFilteredThread(t *testing.T) {
	roundTripOrSkip(t)
	for i := 0; i < 8; i++ {
		if _, _, err := seccompRoundTrip(); err != nil {
			t.Fatalf("round trip %d: %v", i, err)
		}
	}
	runtime.GC()
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			// A thread that still carried the probe's filter would see this notified with no
			// listener left, which the kernel answers with ENOSYS.
			fd, err := unix.MemfdCreate("tego-doctor-probe", unix.MFD_CLOEXEC)
			if err != nil {
				done <- err
				return
			}
			_ = unix.Close(fd)
			done <- nil
		}()
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatalf("a goroutine inherited the probe's filter: %v", err)
		}
	}
}

// TestSeccompProbeLeavesNoThreadFiltered probes D5 repeatedly, every other time from the main thread,
// and after each probe reads every thread of this process: none may show more seccomp filters, or a
// no_new_privs, than the thread running this test did before any probe, so with no filter inherited
// each reads "Seccomp: 0", and the thread the probe's filter went on must have ended by the time the
// probe returns. Before onThrowawayThread, the first D5 of a test binary ran on the main thread, which
// Go parks for good rather than ends, and /proc/self/status said "Seccomp: 2" and "NoNewPrivs: 1"
// for the rest of the process.
func TestSeccompProbeLeavesNoThreadFiltered(t *testing.T) {
	before, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Skipf("no /proc/thread-self: %v", err)
	}
	want := statusLines(before, "Seccomp", "Seccomp_filters", "NoNewPrivs")
	roundTripOrSkip(t)
	pid := unix.Getpid()
	for i := 0; i < 16; i++ {
		var thread int
		probe := func() { _, thread, err = seccompRoundTrip() }
		if i%2 == 0 {
			// Let go of the main thread just before probing: the prober blocks as soon as it has started
			// the probe's goroutine, and the thread it blocked on runs that goroutine next.
			onMainThread(t, func() {
				runtime.UnlockOSThread()
				probe()
			})
		} else {
			probe()
		}
		if err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
		if thread == pid {
			t.Fatalf("probe %d put its filter on the main thread", i)
		}
		if err := unix.Tgkill(pid, thread, 0); !errors.Is(err, unix.ESRCH) {
			t.Errorf("probe %d returned while its filtered thread %d was still a thread of this process (tgkill: %v)",
				i, thread, err)
		}
		for _, task := range append([]string{"/proc/self"}, taskDirs(t)...) {
			b, err := os.ReadFile(filepath.Join(task, "status"))
			if err != nil {
				continue // a thread that ended between the listing and the read
			}
			if got := statusLines(b, "Seccomp", "Seccomp_filters", "NoNewPrivs"); got != want {
				t.Fatalf("after probe %d, %s reads %q; this process started with %q", i, task, got, want)
			}
		}
	}
}

// TestThrowawayThreadIsNeverTheMainThread: called on the main thread, as D5's goroutine can be,
// onThrowawayThread runs fn on another thread, one that ends with fn, and returns its caller on the
// main thread it came in on. Started with go from any thread, as D5 starts it, the thread fn ran on
// ends when fn returns.
func TestThrowawayThreadIsNeverTheMainThread(t *testing.T) {
	pid := unix.Getpid()
	var ran, back int
	onMainThread(t, func() {
		tid := make(chan int, 1)
		onThrowawayThread(func() { tid <- unix.Gettid() })
		ran, back = <-tid, unix.Gettid()
	})
	if ran == pid {
		t.Fatal("onThrowawayThread ran fn on the main thread, which Go parks with whatever fn left on it")
	}
	if back != pid {
		t.Errorf("onThrowawayThread returned its caller on thread %d, not the main thread %d it was called on", back, pid)
	}
	if err := awaitThreadEnd(ran, 5*time.Second); err != nil {
		t.Errorf("called on the main thread: %v", err)
	}
	tid := make(chan int, 1)
	go onThrowawayThread(func() { tid <- unix.Gettid() })
	if err := awaitThreadEnd(<-tid, 5*time.Second); err != nil {
		t.Errorf("started with go: %v", err)
	}
}

// roundTripOrSkip is the first D5 round trip of a test that needs one to work. Only what
// seccompSkipReason excuses, an EINVAL on a kernel D1 reads as below 5.14, skips the test; any other
// failure fails it. A test that skipped on any failure would pass a D5 whose filtered thread never
// ended, since the round trip then fails (awaitThreadEnd), and that thread is what these tests are for.
func roundTripOrSkip(t *testing.T) {
	t.Helper()
	_, _, err := seccompRoundTrip()
	if err == nil {
		return
	}
	_, _, kernel := probeKernelVersion()
	if why := seccompSkipReason(err, PtraceState{}, kernel); why != "" {
		t.Skipf("%s: %v", why, err)
	}
	t.Fatalf("D5's round trip failed: %v", err)
}

// onMainThread runs fn on a goroutine locked to this process's main thread, the thread group leader
// whose status /proc/self shows. Go lends the main thread to any goroutine while main is blocked, as it
// is under go test, but which goroutine lands there is the scheduler's choice. So this starts goroutines
// one at a time, each locked to the thread it lands on and holding it until this returns: a new goroutine
// usually runs on the thread of the one that started it and then waited for it, and that one moves on to
// an idle thread, so the next lands on a thread none before it had, until one is the main thread. The main
// thread can be the one the runtime left blocked in epoll_pwait(2) until the next timer is due, taking
// no goroutine until it wakes (found here: the test binary's ten-minute timeout was that timer), so each
// step first sleeps, which sets an earlier timer and wakes it. At most maxMainThreadSteps goroutines, and
// so threads, are taken; they are idle again for the next call, which reuses them.
func onMainThread(t *testing.T, fn func()) {
	t.Helper()
	release := make(chan struct{})
	defer close(release)
	onMain := make(chan bool)
	for step := 0; step < maxMainThreadSteps; step++ {
		time.Sleep(50 * time.Microsecond)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ran := unix.Gettid() == unix.Getpid()
			if ran {
				fn()
			}
			onMain <- ran
			<-release
		}()
		if <-onMain {
			return
		}
	}
	status, _ := os.ReadFile("/proc/self/status")
	wchan, _ := os.ReadFile("/proc/self/wchan")
	t.Fatalf("none of %d goroutines, each locked to a thread of its own, ran on the main thread, which is in %s "+
		"and says %q", maxMainThreadSteps, wchan, statusLines(status, "State", "Seccomp", "NoNewPrivs"))
}

// maxMainThreadSteps bounds the goroutines onMainThread starts, each of which keeps a thread until it
// returns.
const maxMainThreadSteps = 256

// taskDirs is /proc/self/task/<tid> for each thread of this process.
func taskDirs(t *testing.T) []string {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skipf("no /proc/self/task: %v", err)
	}
	dirs := make([]string, 0, len(tasks))
	for _, task := range tasks {
		dirs = append(dirs, filepath.Join("/proc/self/task", task.Name()))
	}
	return dirs
}

// statusLines is the named lines of a /proc status file, in the order named, one per line.
func statusLines(status []byte, names ...string) string {
	var out []string
	for _, name := range names {
		for _, line := range strings.Split(string(status), "\n") {
			if n, _, ok := strings.Cut(line, ":"); ok && n == name {
				out = append(out, line)
			}
		}
	}
	return strings.Join(out, "\n")
}

// TestNotifyOneSyscallProgram checks the throwaway filter's shape: an architecture guard first, then
// the syscall test, then the two returns. A filter without the arch guard would decide on a syscall
// number from another ABI (docs/p0/enforce-landlock.md R13).
func TestNotifyOneSyscallProgram(t *testing.T) {
	raw, err := notifyOneSyscall(probeSyscall)
	if err != nil {
		t.Skipf("no architecture guard for %s: %v", runtime.GOARCH, err)
	}
	prog, allDecoded := bpf.Disassemble(raw)
	if !allDecoded {
		t.Fatalf("the assembled filter does not disassemble: %v", prog)
	}
	if len(prog) != 6 {
		t.Fatalf("%d instructions: %v", len(prog), prog)
	}
	first, ok := prog[0].(bpf.LoadAbsolute)
	if !ok || first.Off != 4 || first.Size != 4 {
		t.Errorf("the filter does not start by loading seccomp_data.arch: %v", prog[0])
	}
	arch, err := auditArch()
	if err != nil {
		t.Fatal(err)
	}
	guard, ok := prog[1].(bpf.JumpIf)
	if !ok || guard.Val != arch {
		t.Errorf("instruction 1 is not the architecture guard: %v", prog[1])
	}
	notify, ok := prog[4].(bpf.RetConstant)
	if !ok || notify.Val != retUserNotif {
		t.Errorf("instruction 4 does not return SECCOMP_RET_USER_NOTIF: %v", prog[4])
	}
	allow, ok := prog[5].(bpf.RetConstant)
	if !ok || allow.Val != retAllow {
		t.Errorf("instruction 5 does not return SECCOMP_RET_ALLOW: %v", prog[5])
	}
}

func TestSeccompErrorsAreWrapped(t *testing.T) {
	if _, err := notifyOneSyscall(probeSyscall); err != nil && !errors.Is(err, ErrSeccompSelfTest) {
		t.Errorf("error %v does not wrap ErrSeccompSelfTest", err)
	}
}

// TestSeccompEINVALRemedyFollowsTheRelease: an EINVAL used to be answered "boot a kernel >= 5.14.0"
// whatever D1 read, and that string became doctor's one fix line, so a 6.17 kernel built without
// CONFIG_SECCOMP_FILTER — whose seccomp(SET_MODE_FILTER) is the kernel's EINVAL stub on any release —
// or a probe with a malformed flag, was told to upgrade to a kernel older than itself. The release
// decides the remedy; an unreadable one names both causes.
// supervisor.md E27: the seccomp self-test (NEW_LISTENER, SEND+CONTINUE, pidfd_getfd) gates tier 1 before the supervisor runs.
func TestSeccompEINVALRemedyFollowsTheRelease(t *testing.T) {
	einval := fmt.Errorf("%w: %w", ErrSeccompSelfTest, unix.EINVAL)
	fine := PtraceState{Scope: yamaRelational, Detail: "yama ptrace_scope=1"}
	cases := []struct {
		name   string
		kernel Version
		fix    string
		notFix string
		detail string
	}{
		{"below 5.14, the missing feature", Version{5, 10, 0}, "boot a kernel >= 5.14.0", "CONFIG_SECCOMP_FILTER", "5.10.0 is below 5.14.0"},
		{"at 5.14, configuration or a defect", addfdSendSince, "CONFIG_SECCOMP_FILTER=y", "boot a kernel >=", "has SECCOMP_ADDFD_FLAG_SEND"},
		{"6.17, configuration or a defect", Version{6, 17, 0}, "CONFIG_SECCOMP_FILTER=y", "boot a kernel >=", "or a defect in this probe"},
		{"a release D1 could not read", Version{}, ">= 5.14.0 built with CONFIG_SECCOMP_FILTER=y", "", "could not read the release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := seccompVerdictOn(-1, einval, fine, tc.kernel)
			if r.OK || r.ID != CheckSeccomp {
				t.Fatalf("an EINVAL round trip = %+v", r)
			}
			if !strings.Contains(r.Fix, tc.fix) || (tc.notFix != "" && strings.Contains(r.Fix, tc.notFix)) {
				t.Errorf("fix %q, want %q and not %q", r.Fix, tc.fix, tc.notFix)
			}
			if !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("detail %q, want it to say %q", r.Detail, tc.detail)
			}
		})
	}
	// Another failure on a kernel with every piece is not answered with an upgrade either.
	timeout := fmt.Errorf("%w: no answer within %s", ErrSeccompSelfTest, seccompSelfTestTimeout)
	if r := seccompVerdictOn(-1, timeout, fine, Version{6, 17, 0}); strings.Contains(r.Fix, "boot a kernel") {
		t.Errorf("a timeout on 6.17 is answered %q", r.Fix)
	}
	if r := seccompVerdictOn(-1, timeout, fine, Version{5, 10, 0}); !strings.Contains(r.Fix, ">= 5.14.0") {
		t.Errorf("a timeout on 5.10 is answered %q, want the kernel floor", r.Fix)
	}
}

// TestSeccompENOSYSNamesTheKernelConfig: seccomp(2) is a cond_syscall, so a kernel built without
// CONFIG_SECCOMP answers ENOSYS on every release — at the layout check's GET_NOTIF_SIZES, before any
// filter. That is configuration, like the CONFIG_SECCOMP_FILTER=n EINVAL, and D5's remedy reaches the
// doctor fix line (everyTierFixes), so it must name the options rather than a newer kernel or a tego
// bug, whatever release D1 read.
func TestSeccompENOSYSNamesTheKernelConfig(t *testing.T) {
	enosys := fmt.Errorf("%w: %w", ErrSeccompSelfTest, fmt.Errorf("seccomp(SECCOMP_GET_NOTIF_SIZES): %w", unix.ENOSYS))
	fine := PtraceState{Scope: yamaRelational, Detail: "yama ptrace_scope=1"}
	for _, kernel := range []Version{{5, 10, 0}, addfdSendSince, {6, 17, 0}, {}} {
		t.Run(kernel.String(), func(t *testing.T) {
			r := seccompVerdictOn(-1, enosys, fine, kernel)
			if r.OK || r.ID != CheckSeccomp {
				t.Fatalf("an ENOSYS round trip = %+v", r)
			}
			if !strings.Contains(r.Fix, "CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y") {
				t.Errorf("fix %q, want the seccomp kernel options", r.Fix)
			}
			for _, wrong := range []string{"tego bug", "boot a kernel >="} {
				if strings.Contains(r.Fix, wrong) {
					t.Errorf("fix %q says %q for a kernel built without seccomp(2)", r.Fix, wrong)
				}
			}
			if !strings.Contains(r.Detail, "without CONFIG_SECCOMP") {
				t.Errorf("detail %q does not say why", r.Detail)
			}
		})
	}
}
