// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// previewBound is how long one governed Preview may take in this test, loopBound all of them: the time a person's
// check had before the start-up budget was split off, and a minute of them. A starved Preview fails at its bound and
// counts as starved, so the test's running time is not the host's.
const (
	previewBound = 5 * time.Second * testRaceScale
	loopBound    = time.Minute * testRaceScale
)

// previewWithin is f.get with a request that ends at bound.
func previewWithin(f *changeFix, target string, bound time.Duration) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
	r.Host = "127.0.0.1:8484"
	r.AddCookie(f.c)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	return w.Code, unmarked(w.Body.String())
}

func TestBuilderGovernedPreviewsCannotEvictPersonsReview(t *testing.T) {
	for _, route := range []string{"structured", "new"} {
		t.Run(route, func(t *testing.T) {
			skipWhenIdleWorkStarves(t)
			f := newChangeFix(t)
			c := f.ref(t, f.source)
			q := url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"add"}, "key": {"exec.allow"}, "v": {"/bin/echo"}}
			target := "/rules/change/preview?" + q.Encode()
			// Inspect only the count, without adding a production store-inspection API.
			// Requests and inspection are sequential; the real service owns this store.
			count := func() int { return reflect.ValueOf(f.svc).Elem().FieldByName("drafts").FieldByName("entries").Len() }
			personPreview := func() time.Duration { // the person's own check, outside every governed request
				begun := time.Now()
				if code, body := f.get(t, target); code != http.StatusOK {
					if strings.Contains(body, "context deadline exceeded") {
						return contracts.CheckTimeout // the host was too slow for even the person's check
					}
					t.Fatalf("person Preview: %d %s", code, body)
				}
				return time.Since(begun)
			}
			// The wall-clock parts below need a host on which the person's own check is quick: a slow one is slow for
			// every test and is not what this one holds, so it is found out first, before the long part.
			if quiet, took := hostQuiet(personPreview); !quiet {
				t.Skipf("the host is too busy to judge a governed load: a person's Preview alone took %v (limit %v)", took, quietLimit)
			}
			probed := count() // each Preview keeps its own entry; the probes' are not the review under test
			code, body := f.get(t, target)
			if code != http.StatusOK {
				t.Fatalf("person Preview: %d %s", code, body)
			}
			form := builderLostStructuredForm(t, body)
			if form.Get("ack") == "" {
				t.Fatal("person has no acknowledgement")
			}
			before := count()
			if before != probed+1 {
				t.Fatalf("person retained %d entries, want %d (the probes' %d and one)", before, probed+1, probed)
			}
			if route == "new" {
				dir := filepath.Join(filepath.Dir(f.proj), "readonly-new")
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				f.s.cfg.Setup = f.svc
				target = "/rules/new?" + url.Values{"mode": {"blank"}, "dir": {dir}, "name": {"readonly-new"}, "cmd": {"/bin/echo"}, "preview": {"1"}, "to": {"project"}}.Encode()
			}
			f.s.governed = func(*http.Request) error { return &governedError{Run: rulesRunB} }
			// The running time of the loop does not depend on the host's speed: each Preview has its own bound
			// (previewBound, what a person's check was given before the start-up budget was split off), and the
			// whole loop has one (loopBound). A governed request's checks run at the lowest CPU priority, so on a
			// busy host one waits for a CPU, and with the start-up budget of 30 s (contracts.StartTimeout) a
			// starved Preview alone could take 35 s: 200 of them were longer than the package's timeout. A Preview
			// that is not answered in its bound is starved, and what it did answer is still held to the property.
			started := time.Now()
			invalidResponses, starved, attempted := 0, 0, 0
			for i := 0; i < 200 && time.Since(started) < loopBound; i++ {
				attempted++
				code, body = previewWithin(f, target, previewBound)
				if (code == http.StatusUnprocessableEntity && strings.Contains(body, "nothing was written") && (strings.Contains(body, "context deadline exceeded") || strings.Contains(body, contracts.CompileUnfinished)) ||
					code == http.StatusServiceUnavailable) && !strings.Contains(body, rulesCanary) {
					// A governed request's checks run at the lowest CPU priority by design (contracts.helperProcess), so on a
					// host whose CPUs are busy with other work one can miss the check deadline (422: nothing was written) or
					// find no helper slot free in its wait (503), which is the outcome this test holds for every Preview. It must
					// still hand out nothing to Save: no acknowledgement of a reviewed change.
					starved++
					if strings.Contains(body, `name="ack"`) {
						invalidResponses++
					}
					if starved == attempted && starved >= 5 {
						break // nothing but starved ones so far: judge what they handed out, below, and skip
					}
					continue
				}
				if code != http.StatusOK || !(strings.Contains(body, "What changes") || strings.Contains(body, "Preview: readonly-new")) || !strings.Contains(body, "/bin/echo") || strings.Contains(body, rulesCanary) {
					t.Fatalf("governed Preview %d lost redacted change: %d %s", i, code, body)
				}
				if strings.Contains(body, `name="ack"`) || strings.Contains(body, `action="/rules/change"`) || strings.Contains(body, `name="base"`) || !strings.Contains(body, "Saving is not available") {
					invalidResponses++
				}
			}
			if starved > 0 {
				t.Logf("%d of %d governed Previews missed their check deadline: the host's CPUs were busy with other work", starved, attempted)
			}
			// The property holds for every Preview that was answered, starved or not, whatever the host's speed.
			if invalidResponses != 0 {
				t.Errorf("%d governed Previews offer Save or acknowledgement, or lack explanation", invalidResponses)
			}
			if after := count(); after != before {
				t.Errorf("governed Previews moved store count: %d -> %d", before, after)
			}
			if attempted < 200 || starved*2 > attempted {
				t.Skipf("%d of %d governed Previews were tried in %v and %d missed their check deadline: the host is too busy to judge them", attempted, 200, time.Since(started).Round(time.Second), starved)
			}
			w := post(f.s, "/rules/change", form, own, "", f.c)
			if w.Code != http.StatusForbidden || readText(t, c.Path) != rulesSource || count() != before {
				t.Errorf("governed Save changed source or store: %d count=%d", w.Code, count())
			}
			// The person Saves while governed programs keep the one CPU busy with their own checks: holding a helper slot
			// is not enough, the person's check must also win the CPU, so a governed request's helpers run at the lowest
			// CPU priority the system allows (contracts.helperProcess). Two things are held, and only one of them is a
			// clock: the governed helpers that are running right now have that priority (a fact about the processes, the
			// same on a busy host), and the person's Save, which costs a fraction of a second here, completes inside the
			// product's own check deadline. Unrelated load on the host can eat that deadline, which says nothing about
			// governed programs: when the Save misses it, a person's Preview timed again with the governed load stopped
			// says whether the host alone was too slow (the test then skips, naming the numbers), and when the host is
			// quick the miss is the governed load's and fails.
			trustPeer(f.s)
			stop := governedLoad(t, f, target)
			assertGovernedWorkersLowPriority(t)
			// The Save is a durable write (write, fsync, rename), and a disk whose journal commits stall holds it in
			// the kernel for as long as it stalls, whatever the CPU priorities are: the helper then sits in
			// uninterruptible sleep with almost no CPU time wanted or waited for, and the product rightly says its
			// location did not answer. A small durable write of the same kind, made over and over in the same
			// filesystem while the Save runs, says whether the disk was the one stalling.
			endProbe := testutil.ProbeDurableWrites(t.TempDir(), testutil.DurableWrite)
			begun := time.Now()
			w = post(f.s, "/rules/change", form, own, "", f.c)
			took := time.Since(begun)
			diskWorst := endProbe()
			t.Logf("person Save took %v under governed load on one CPU; the slowest small durable write beside it took %v", took, diskWorst)
			stop()
			// Saved is the person's Save having saved: a 303 that goes back to the preview with a refusal is not.
			saved := w.Code == http.StatusSeeOther && strings.HasPrefix(w.Header().Get("Location"), "/rules/change/saved")
			if !saved && diskWorst >= testutil.StalledDisk {
				t.Skipf("the person's Save missed its deadline (%d, %v) while the disk was stalled: a small durable write in the same filesystem took %v (limit %v), which is not what governed load does to the CPU",
					w.Code, took, diskWorst, testutil.StalledDisk)
			}
			if !saved {
				if quiet, alone := hostQuiet(personPreview); !quiet {
					t.Skipf("the person's Save missed its deadline (%d, %v) while the host alone was slow: a person's Preview took %v with no governed load (limit %v)",
						w.Code, took, alone, quietLimit)
				}
			}
			if !saved || !strings.Contains(readText(t, c.Path), "/bin/echo") {
				// Say which refusal sent the person back to the preview: the page the redirect names shows it once.
				said := ""
				if loc := w.Header().Get("Location"); loc != "" {
					_, page := f.get(t, loc)
					said = regexp.MustCompile(`(Nothing was written|Not saved|Already in the contract)[^<]{0,300}`).FindString(page)
				}
				t.Fatalf("person pending review did not save after 200 governed Previews and under governed load: %d %s (the page says %q): %s", w.Code, w.Header().Get("Location"), said, w.Body.String())
			}
			if count() != before-1 {
				t.Fatal("person Save did not consume exactly its review")
			}
		})
	}
}

// governedSeen records whether each Preview's helper checks run as a governed caller's.
type governedSeen struct {
	*rules.Service
	seen []bool
}

func (s *governedSeen) PlanChange(ctx context.Context, req rules.ChangeReq) (*rules.ChangePlan, error) {
	s.seen = append(s.seen, contracts.GovernedCaller(ctx))
	return s.Service.PlanChange(ctx, req)
}

// A request from inside a run, or one the dashboard cannot show comes from outside every run, makes its helper
// checks as a governed caller's, which never take the helper slots kept for the person's own checks
// (contracts.personHelperReserve); the person's request makes them as its own.
func TestGovernedRequestsCheckAsGovernedCallers(t *testing.T) {
	// The dashboard's own membership comes first (contracts.GovernedCaller): a test process inside a run, or one that
	// cannot tell, makes every request governed, the person's too.
	if a := peer.Self(); !a.Outside() {
		t.Skipf("this test process is inside a run or cannot tell (%s): every helper request it makes is governed", runscope.Describe(a).Verdict)
	}
	f := newChangeFix(t)
	c := f.ref(t, f.source)
	target := "/rules/change/preview?" + url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"add"}, "key": {"exec.allow"},
		"v": {"/bin/echo"}}.Encode()
	seen := &governedSeen{Service: f.svc}
	f.s.cfg.Rules = seen
	for _, who := range []error{nil, &governedError{Run: rulesRunB}, errGovernedUnknown} {
		f.s.governed = func(*http.Request) error { return who }
		// What is held is who the check was made for, which governedSeen records before the check runs. Whether the
		// check then finishes is the machine's: on one starved of CPU the product gives a governed check more time
		// (ADR 0144) and, when even that runs out, answers with its typed 503 page saying the dashboard is busy, which
		// is a right answer here and not this test's failure. Any other answer is.
		code, body := f.get(t, target)
		if code != http.StatusOK && !(code == http.StatusServiceUnavailable && strings.Contains(body, "The dashboard is busy")) {
			t.Fatalf("Preview as %v: %d %s", who, code, body)
		}
		if code != http.StatusOK {
			t.Logf("Preview as %v: the machine was too busy for the check to finish (503, the product's busy words)", who)
		}
	}
	if want := []bool{false, true, true}; !reflect.DeepEqual(seen.seen, want) {
		t.Fatalf("governed callers per Preview (person, governed, unknown) = %v, want %v", seen.seen, want)
	}
}

// pinToOneCPU confines this test process, and every process it starts afterwards, to one CPU until the test ends: the
// CPU contention a loaded machine has, by construction, whatever the machine. The CPU is the least busy of the
// allowed ones over a quarter of a second, not the first: the first is where a host's interrupts and its other jobs
// pile up, and the test is about governed programs against the person's, not about that. An affinity mask is per
// thread and a child takes the mask of the thread that forked it, so every thread of the process is pinned, and
// restored at the end.
func pinToOneCPU(t *testing.T) {
	t.Helper()
	var all unix.CPUSet
	if err := unix.SchedGetaffinity(0, &all); err != nil {
		t.Skipf("no CPU mask: %v", err)
	}
	var one unix.CPUSet
	one.Set(quietestCPU(&all))
	apply := func(set *unix.CPUSet) {
		tasks, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatalf("threads: %v", err)
		}
		for _, task := range tasks {
			if tid, err := strconv.Atoi(task.Name()); err == nil {
				_ = unix.SchedSetaffinity(tid, set) // a thread that ended meanwhile has nothing to pin
			}
		}
	}
	apply(&one)
	t.Cleanup(func() { apply(&all) })
}

// cpuTimes reads each CPU's (busy, total) clock ticks from /proc/stat.
func cpuTimes() map[int][2]uint64 {
	out := map[int][2]uint64{}
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		n, err := strconv.Atoi(f[0][3:])
		if err != nil {
			continue
		}
		var total, idle uint64
		for i, v := range f[1:] {
			x, _ := strconv.ParseUint(v, 10, 64)
			if i < 8 { // user nice system idle iowait irq softirq steal; guest time is already in user
				total += x
			}
			if i == 3 || i == 4 {
				idle += x
			}
		}
		out[n] = [2]uint64{total - idle, total}
	}
	return out
}

// quietestCPU is the allowed CPU with the least busy share of a quarter of a second, the lowest number among equals;
// the lowest allowed one when /proc/stat cannot be read.
func quietestCPU(all *unix.CPUSet) int {
	first := -1
	for cpu := 0; cpu < 1024; cpu++ {
		if all.IsSet(cpu) {
			first = cpu
			break
		}
	}
	before := cpuTimes()
	time.Sleep(250 * time.Millisecond)
	after := cpuTimes()
	best, bestShare := first, 2.0
	for cpu := first; cpu >= 0 && cpu < 1024; cpu++ {
		if !all.IsSet(cpu) {
			continue
		}
		b, a := before[cpu], after[cpu]
		if a[1] <= b[1] {
			continue
		}
		if share := float64(a[0]-b[0]) / float64(a[1]-b[1]); share < bestShare {
			best, bestShare = cpu, share
		}
	}
	return best
}

// quietLimit is how long a person's Preview, alone, may take for the host to count as quiet enough to judge a
// governed load by wall clock: the product gives the person's check contracts.CheckTimeout (five seconds), a governed
// load that takes the CPU makes the person's Save take about that long (a twenty-fold slowdown measured without the
// lowered priority), and a Preview within a fifth of the deadline leaves the deadline five times over for one that
// does not.
const quietLimit = time.Second

// hostQuiet times a person's check (do) three times, with no governed load running, and reports whether the median
// is within quietLimit, and the median.
func hostQuiet(do func() time.Duration) (bool, time.Duration) {
	d := []time.Duration{do(), do(), do()}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[1] <= quietLimit, d[1]
}

// skipWhenIdleWorkStarves skips a test that needs a governed request's checks to finish: they run at the lowest CPU
// priority by design (contracts.helperProcess), so on a host whose every CPU is busy with unrelated work they get no
// CPU at all and miss the product's check deadline, which is that design working and says nothing about what this
// test holds. The probe is what a governed worker is, a thread at the lowest priority, asked for 50 ms of CPU: it
// runs in 50 ms on a host with room, and the test goes on whenever it finishes within a second.
func skipWhenIdleWorkStarves(t *testing.T) {
	t.Helper()
	const work, limit = 50 * time.Millisecond, time.Second
	took := make(chan time.Duration, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the lowered thread is retired with this goroutine
		if _, err := proc.LowerPriority(); err != nil {
			took <- 0 // cannot lower here: nothing starves it
			return
		}
		cpu := func() time.Duration {
			var ts unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts); err != nil {
				return 0
			}
			return time.Duration(ts.Nano())
		}
		begun, used := time.Now(), cpu()
		for cpu()-used < work && time.Since(begun) < limit {
		}
		took <- time.Since(begun)
	}()
	if d := <-took; d >= limit {
		t.Skipf("the host's CPUs are all busy with other work: 50 ms of CPU at the lowest priority, which is what a governed request's checks get, took %v", d)
	}
}

// workerPIDs are the processes now running a governed request's worker (contracts.HelperCommand "idle-worker"). A
// worker is reaped by init, not by this process, so it is found by its command line; a person's worker is "worker".
func workerPIDs() []int {
	var out []int
	procs, _ := os.ReadDir("/proc")
	for _, e := range procs {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"); len(args) == 3 && args[1] == contracts.HelperCommand && args[2] == "idle-worker" {
			out = append(out, pid)
		}
	}
	return out
}

// assertGovernedWorkersLowPriority holds the mechanism itself, which no host load changes: the workers of the governed
// requests that are running now have nice 19 on every thread, and the idle policy where this kernel gives it to an
// unprivileged thread (internal/contracts holds the same for one worker started directly). At least one thread must be
// seen; the loops start workers without pause.
func assertGovernedWorkersLowPriority(t *testing.T) {
	t.Helper()
	probe := make(chan bool)
	go func() {
		runtime.LockOSThread() // never unlocked: the lowered thread is retired with this goroutine
		idle, err := proc.LowerPriority()
		probe <- idle && err == nil
	}()
	idle := <-probe
	seen := 0
	for deadline := time.Now().Add(10 * time.Second); seen == 0 && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for _, pid := range workerPIDs() {
			tasks, _ := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
			for _, task := range tasks {
				b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/task/" + task.Name() + "/stat")
				if err != nil {
					continue // the thread, or the whole worker, ended meanwhile
				}
				str := string(b)
				f := strings.Fields(str[strings.LastIndexByte(str, ')')+1:])
				if len(f) < 39 {
					continue
				}
				nice, _ := strconv.Atoi(f[16])
				policy, _ := strconv.Atoi(f[38])
				seen++
				if nice != 19 || idle && policy != unix.SCHED_IDLE {
					t.Errorf("a governed worker (pid %d, thread %s) runs at nice %d policy %d, want nice 19 and policy %d (idle available: %v)",
						pid, task.Name(), nice, policy, unix.SCHED_IDLE, idle)
				}
			}
		}
	}
	if seen == 0 {
		t.Error("no governed worker thread was seen while the governed load ran")
	}
}

// governedLoad keeps governed Previews of target running without pause, as many as a governed program may have
// helpers at once, on the one CPU the whole process tree shares (pinToOneCPU): a loaded machine, by construction,
// whatever the machine. It returns once every loop has started and has had a second to put its helper and its
// compiler to work, and stops the loops when the test ends or stop is called. A request is a governed program's
// when its query says as=governed; any other is the person's.
func governedLoad(t *testing.T, f *changeFix, target string) (stop func()) {
	t.Helper()
	pinToOneCPU(t)
	f.s.governed = func(r *http.Request) error {
		if r.URL.Query().Get("as") == "governed" {
			return &governedError{Run: rulesRunB}
		}
		return nil
	}
	sep := "&"
	if !strings.Contains(target, "?") {
		sep = "?"
	}
	target += sep + "as=governed"
	var (
		quit    atomic.Bool
		started atomic.Int32
		wg      sync.WaitGroup
	)
	const loops = 24 // under the 28 slots a governed program may hold (contracts.helperLimit less its reserve)
	for range loops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Add(1)
			for !quit.Load() {
				do(f.s, "GET", target, "127.0.0.1:8484", f.c)
			}
		}()
	}
	var once sync.Once
	stop = func() { once.Do(func() { quit.Store(true); wg.Wait() }) }
	t.Cleanup(stop)
	for started.Load() < loops {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(time.Second)
	return stop
}
