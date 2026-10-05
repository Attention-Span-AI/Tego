// SPDX-License-Identifier: Apache-2.0

// Command perfsuite is the tier-3 guest perf suite (docs/p0/enforce-plane.md §10): it drives `tego run` as root
// in a KVM guest (test/vm/perf.sh boots one) and measures, in this order,
//
//	cold   the first run with no pinned build, per mode, after `tego gc --builds` (ADR 0022's up to 2.3 s), each
//	       sample attributed per program, map, D7 hook and plane-probe mode (attribution.go; enforce-plane §10.1)
//	start  the warm start latency per mode with the per-phase breakdown Prepare prints under
//	       TEGO_TEST_PHASE_TIMING (probe, select, load, Landlock compose, fill, arm), against landlock's
//	fill   Prepare's fill phase at 1, 1000 and one row under the cap
//	open   a raw open+close loop (cmd/openbench: 200k opens, one pinned CPU) per mode, modes alternated
//	socket a raw socket+close loop (openbench -socket) at landlock and on tier cgroup's fanotify fallback,
//	       alternated: cgroup/sock_create's cost on an admitted socket (ADR 0018 PR 2), and a setsockopt loop
//	       (-setsockopt): cgroup/setsockopt's cost on an option it passes (ADR 0018 (7))
//	exec   a fork+exec+wait loop of a minimal static image (cmd/execbench: 10,000 execs, one pinned CPU) per mode,
//	       without command rules and under a rule that reads and pins the whole vector, at 512 bytes and 128 KiB of
//	       argv, alternated; the pin check's own kernel time per exec of a run without rules (bpf_stats); and doctor's
//	       exec pin cell (ADR 0048 P2's K7, exec.go)
//	conc   2, 8 and 32 concurrent runs, with landlock alone as the control so the plane's share is separable
//
// It prints one "PERF {json}" line per measurement and one BUDGET line per budget of test/perf, then
// "PERF-RESULT PASS" or "PERF-RESULT FAIL" and exits 1 on FAIL. A budget over its limit fails; a figure over its
// target and within its limit is a TARGET-MISS the spec owner decides. -budget name=value moves a limit, which is
// how the failure path is checked (a limit set under a measurement must fail).
//
// It needs root, SUDO_UID and SUDO_GID (the agent drops to that user), and a tego built with
// -tags tegobpf,tegotesthooks: TEGO_TEST_PLANE pins the plane mode, TEGO_TEST_PHASE_TIMING prints the phases.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/test/perf"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

var (
	tegoBin  = flag.String("tego", "/usr/local/bin/tego", "the tego binary (-tags tegobpf,tegotesthooks)")
	benchBin = flag.String("bench", "/usr/local/bin/openbench", "the openbench binary")
	execBin  = flag.String("execbench", "/usr/local/bin/execbench", "the execbench binary")
	base     = flag.String("base", "/tmp/perf", "scratch directory (a tmpfs in the guest)")
	// name (ADR 0043 C10) is not in the default list: its first guest run (2026-10-20) found its set-over-clear
	// figures below the run-to-run noise, so it runs when asked (-checks name) until its design resolves them.
	checks   = flag.String("checks", "cold,start,fill,open,socket,exec,conc", "checks to run, in this order (name: only when asked)")
	opens    = flag.Int("opens", 200000, "opens per round in the open check (at least 200000 for a stated result)")
	cpu      = flag.Int("cpu", 3, "CPU the open check's loop is pinned to")
	startN   = flag.Int("start-runs", 8, "warm starts per mode")
	coldN    = flag.Int("cold-runs", 3, "cold starts per mode")
	rounds   = flag.Int("rounds", 9, "rounds of the open check; each round runs every mode once, the order rotated")
	concList = flag.String("conc", "2,8,32", "concurrent run counts")
	coldAttr = flag.Bool("cold-attribution", true, "print a cold-attribution record a cold sample and follow each "+
		"budgeted sample with one launched with TEGO_TEST_LOAD_STATS (per program, map, D7 hook and plane-probe mode); "+
		"the budgeted samples launch unattributed either way")
	coldSettle = flag.Bool("cold-settle", false, "after the cold samples, as many again that wait after gc until the "+
		"removed builds' trampolines are untraced (cold-settled: diagnostic, never a budget)")
	overs listFlag
)

func main() {
	flag.Var(&overs, "budget", "name=value: replace a budget's limit (repeatable)")
	flag.Parse()
	counts, err := validateSampleCounts(*coldN, *startN, *rounds, *opens, *concList)
	if err == nil {
		err = validateSettle(*checks, *coldSettle)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "perfsuite:", err)
		os.Exit(2)
	}
	budgets, err := perf.Override(perf.Defaults(), overs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "perfsuite:", err)
		os.Exit(2)
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "perfsuite: SUDO_UID and SUDO_GID must name the user the agent drops to")
		os.Exit(2)
	}
	s := &suite{uid: uid, gid: gid, got: map[string]float64{}, counts: counts, attribution: *coldAttr, settle: *coldSettle}
	// A table of n rows holds about n descriptors in tier 1's compose (enforce-landlock E11); the guest's hard limit is
	// 4096, which a 4095-row table exhausts. A real host's is far higher, and a Go program raises its soft limit to
	// the hard one, so the suite raises the hard one for the launchers it starts.
	lim := unix.Rlimit{Cur: 1 << 20, Max: 1 << 20}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		fmt.Fprintln(os.Stderr, "perfsuite: raising RLIMIT_NOFILE:", err)
	}
	if err := s.setup(); err != nil {
		fmt.Fprintln(os.Stderr, "perfsuite:", err)
		os.Exit(2)
	}
	lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
	rel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	fmt.Printf("KERNEL %s lsm=%s\n", strings.TrimSpace(string(rel)), strings.TrimSpace(string(lsm)))
	s.modes = perf.ModesFor(strings.TrimSpace(string(lsm)))
	names := make([]string, len(s.modes))
	for i, m := range s.modes {
		names[i] = m.Name
	}
	fmt.Println("MODES " + strings.Join(names, " "))
	budgets = perf.ForModes(budgets, s.modes)
	s.bootFirst = strings.HasPrefix(*checks, "cold")
	for _, c := range strings.Split(*checks, ",") {
		switch c {
		case "cold":
			s.cold()
		case "start":
			s.start()
		case "fill":
			s.fill()
		case "open":
			s.open()
		case "name":
			s.nameCheck()
		case "socket":
			s.socket()
		case "exec":
			s.execCheck()
		case "conc":
			s.conc()
		default:
			fmt.Fprintf(os.Stderr, "perfsuite: unknown check %q\n", c)
			os.Exit(2)
		}
	}
	// A check that was not asked for is not judged: only budgets whose check ran are in the report.
	ran := map[string]bool{}
	for _, c := range strings.Split(*checks, ",") {
		ran[c] = true
	}
	var judged []perf.Budget
	for _, b := range budgets {
		if b.Name == "cold.bootfirst.ms" && !strings.HasPrefix(*checks, "cold") {
			continue // the boot's first run is the boot's first only when cold runs first
		}
		if ran[checkOf(b.Name)] {
			judged = append(judged, b)
		}
	}
	if s.report(judged) {
		os.Exit(1)
	}
}

// checkOf maps a budget name to the check that produces it.
func checkOf(name string) string {
	if nameBudget(name) {
		return "name"
	}
	switch strings.SplitN(name, ".", 2)[0] {
	case "cold":
		return "cold"
	case "start":
		return "start"
	case "fill":
		return "fill"
	case "open":
		return "open"
	case "socket", "setsockopt":
		return "socket"
	case "exec", "doctor":
		return "exec"
	}
	return "conc"
}

type suite struct {
	uid, gid    int
	got         map[string]float64
	bootFirst   bool
	modes       []perf.Mode
	proj        string
	nfiles      int
	seq         int
	mu          sync.Mutex
	failed      bool
	counts      []int
	output      io.Writer
	oneRun      func(spec) (*run, error)
	launchRun   func(spec) (*run, error)
	clearBuilds func() error
	// pinStats and doctorRun stand in for the kernel's bpf_stats and for `tego doctor` in tests (exec.go).
	pinStats  func() (runNS, runs uint64, err error)
	doctorRun func() ([]byte, error)
	// attribution and settle are -cold-attribution and -cold-settle (attribution.go); tracedFuncs, settleBound
	// and pressure stand in for the kernel in tests.
	attribution, settle bool
	tracedFuncs         func() (map[string]bool, error)
	traceBase           map[string]bool // what the kernel traced before the boot's first run (settle's baseline)
	traceBaseErr        error
	settleBound         time.Duration
	pressure            func() (int64, float64, bool)
}

func validateSampleCounts(cold, warm, rounds, opens int, list string) ([]int, error) {
	for _, request := range []struct {
		name  string
		value int
	}{{"cold-runs", cold}, {"start-runs", warm}, {"rounds", rounds}, {"opens", opens}} {
		if request.value <= 0 {
			return nil, fmt.Errorf("%s must be positive", request.name)
		}
	}
	var counts []int
	seen := map[int]bool{}
	for _, field := range strings.Split(list, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n <= 0 || seen[n] {
			return nil, fmt.Errorf("conc must contain distinct positive counts, got %q", field)
		}
		counts = append(counts, n)
		seen[n] = true
	}
	return counts, nil
}

func sampleError(r *run, err error, results ...string) error {
	if err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("run returned no sample")
	}
	if r.rc != 0 {
		return fmt.Errorf("run exited %d", r.rc)
	}
	if r.up <= 0 {
		return fmt.Errorf("run emitted no readiness result")
	}
	for _, key := range append([]string{"up"}, results...) {
		value, ok := r.res[key]
		if !ok || value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("missing or invalid benchmark result %s", key)
		}
	}
	return nil
}

func (s *suite) fail(kind string, details map[string]any) { s.failed = true; s.emit(kind, details) }

func (s *suite) writer() io.Writer {
	if s.output != nil {
		return s.output
	}
	return os.Stdout
}

func (s *suite) report(budgets []perf.Budget) bool {
	text, failed := perf.Report(perf.Evaluate(budgets, s.got))
	failed = failed || s.failed
	fmt.Fprint(s.writer(), text)
	if failed {
		fmt.Fprintln(s.writer(), "PERF-RESULT FAIL")
	} else {
		fmt.Fprintln(s.writer(), "PERF-RESULT PASS")
	}
	return failed
}

func (s *suite) emit(kind string, kv map[string]any) {
	kv["kind"] = kind
	b, _ := json.Marshal(kv)
	fmt.Fprintln(s.writer(), "PERF "+string(b))
}

func (s *suite) record(name string, v float64) { s.got[name] = v }

func (s *suite) setup() error {
	_ = os.RemoveAll(*base)
	s.proj = filepath.Join(*base, "proj")
	for _, d := range []string{"out/a/b/c/d/e", "data"} {
		if err := os.MkdirAll(filepath.Join(s.proj, d), 0o755); err != nil {
			return err
		}
	}
	if err := os.Chmod(*base, 0o711); err != nil {
		return err
	}
	for p, c := range map[string]string{"notes.txt": "n\n", "out/f": "x", "out/a/b/c/d/e/f": "x"} {
		if err := os.WriteFile(filepath.Join(s.proj, p), []byte(c), 0o644); err != nil {
			return err
		}
	}
	in, err := os.ReadFile(*benchBin)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.proj, "openbench"), in, 0o755); err != nil {
		return err
	}
	if err := s.setupExec(); err != nil {
		return err
	}
	return s.chownTree(s.proj)
}

func (s *suite) chownTree(root string) error {
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, s.uid, s.gid)
	})
}

// data makes ./data2 hold exactly g00000..g<n-1>, the user's. Exactly: Landlock cannot deny one file of a directory it
// grants, so tier 1 grants each sibling of a denied file separately, one descriptor each, and a table that denies
// one file of 4096 opens 4095 of them and hits the launcher's descriptor limit (found by this suite).
func (s *suite) data(n int) error {
	d := filepath.Join(s.proj, "data2")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return err
	}
	_ = os.Chown(d, s.uid, s.gid)
	for ; s.nfiles > n; s.nfiles-- {
		if err := os.Remove(filepath.Join(d, fmt.Sprintf("g%05d", s.nfiles-1))); err != nil {
			return err
		}
	}
	for ; s.nfiles < n; s.nfiles++ {
		p := filepath.Join(d, fmt.Sprintf("g%05d", s.nfiles))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			return err
		}
		if err := os.Chown(p, s.uid, s.gid); err != nil {
			return err
		}
	}
	return nil
}

// run is one `tego run`.
type run struct {
	cmd    *exec.Cmd
	t0     time.Time
	up     time.Duration // launch to the agent's first output line; 0 until then
	res    map[string]float64
	phases map[string]float64 // ms
	// stats and stacks are an attributed launch's counts ("tego-stat") and slow-load stacks ("tego-phase-stack"),
	// and maxrssKB the launcher's peak resident set (wait4's rusage).
	stats    map[string]int64
	stacks   []string
	maxrssKB int64
	lines    []string
	rc       int
	wall     time.Duration
	mu       sync.Mutex
	upCh     chan struct{}
	done     chan struct{}
	// pr is the output pipe's read end, and readerDone is closed when read has returned: wait joins it, so every
	// line is in res, phases and lines before a caller reads them without mu.
	pr         *os.File
	readerDone chan struct{}
	// cleanup removes the run's state directory (its ledger: a run that records every open writes hundreds of MB to
	// the guest's tmpfs) and its contract, once the run's output is read.
	cleanup func()
}

var resRE = regexp.MustCompile(`^RESULT (\S+) (\S+)`)
var phaseRE = regexp.MustCompile(`^tego-phase (\S+) (\d+)`)
var capacityRE = regexp.MustCompile(`decision plane keys (\d+) inodes.*at most 4096 a run`)

type spec struct {
	mode   perf.Mode
	rows   int
	record string // off | full
	args   []string
	tag    string
	env    []string // added to the launch's environment
	// command is the image the contract runs (default ./openbench), exec its exec: section's lines (default
	// `allow: ["./openbench"]`).
	command, exec string
	// noBuiltIn writes deny_read: [], which switches the built-in list off (the name check's flag-clear contract);
	// denyRead are deny_read entries written after the rows (the name check's declared globs).
	noBuiltIn bool
	denyRead  []string
}

func (s *suite) contract(sp spec) string {
	var sb strings.Builder
	command, execLines := sp.command, sp.exec
	if command == "" {
		command, execLines = "./openbench", "  allow: [\"./openbench\"]\n"
	}
	sb.WriteString("version: 0\nname: perf-" + sp.tag + "\ncommand: [" + strconv.Quote(command))
	for _, a := range sp.args {
		sb.WriteString(", " + strconv.Quote(a))
	}
	sb.WriteString("]\nfs:\n  write: [\"./out/\"]\n")
	switch {
	case sp.noBuiltIn:
		sb.WriteString("  deny_read: []\n")
	case sp.rows > 0 || len(sp.denyRead) > 0:
		sb.WriteString("  deny_read:\n")
		for i := 0; i < sp.rows; i++ {
			fmt.Fprintf(&sb, "    - \"./data2/g%05d\"\n", i)
		}
		for _, g := range sp.denyRead {
			sb.WriteString("    - " + strconv.Quote(g) + "\n")
		}
	}
	sb.WriteString("exec:\n" + execLines + "net:\n  allow: []\nenv:\n  pass: [\"PATH\", \"HOME\"]\n")
	sb.WriteString("record: " + sp.record + "\n")
	return sb.String()
}

func (s *suite) launch(sp spec) (*run, error) {
	if s.launchRun != nil {
		return s.launchRun(sp)
	}
	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("p%d", s.seq) // a contract name is at most 40 characters of [a-z0-9-]
	s.mu.Unlock()
	if sp.record == "" {
		sp.record = "full"
	}
	sp.tag = id
	st := filepath.Join(*base, "state-"+id)
	if err := os.MkdirAll(filepath.Join(st, "ledger"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(st, "home"), 0o755); err != nil {
		return nil, err
	}
	// The run's runtime directory: a launch not run as root makes <XDG_RUNTIME_DIR>/tego and sweeps the directories
	// the invoking user's crashed runs left there (identity-config.md R27 clause b4), so it is the suite's own, 0700.
	if err := os.MkdirAll(filepath.Join(st, "run"), 0o700); err != nil {
		return nil, err
	}
	cfg := s.config(st)
	cpath := filepath.Join(s.proj, "c-"+id+".yaml")
	if err := os.WriteFile(cpath, []byte(s.contract(sp)), 0o644); err != nil {
		return nil, err
	}
	_ = os.Chown(cpath, s.uid, s.gid)
	pin := sp.mode.Plane
	args := []string{"run"}
	if sp.mode.Tier != "" {
		args = append(args, "--tier", sp.mode.Tier)
	}
	args = append(args, cpath)
	cmd := exec.Command(*tegoBin, args...)
	cmd.Dir = s.proj
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "TEGO_TEST_PLANE="+pin, "TEGO_TEST_PHASE_TIMING=1",
		"TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(st, "chain.log"), "TEGO_TEST_OWN_LOG_HOME="+filepath.Join(st, "home"),
		"XDG_RUNTIME_DIR="+filepath.Join(st, "run"))
	cmd.Env = append(cmd.Env, sp.env...)
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	r := &run{cmd: cmd, res: map[string]float64{}, phases: map[string]float64{}, upCh: make(chan struct{}), done: make(chan struct{}),
		pr: pr, readerDone: make(chan struct{}), cleanup: func() { _ = os.RemoveAll(st); _ = os.Remove(cpath) }}
	r.t0 = time.Now()
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	_ = pw.Close()
	go r.read(pr)
	go func() {
		err := cmd.Wait()
		r.mu.Lock()
		r.wall = time.Since(r.t0)
		if cmd.ProcessState != nil {
			if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
				r.maxrssKB = ru.Maxrss
			}
		}
		r.rc = 0
		if err != nil {
			r.rc = -1
			if ee, ok := err.(*exec.ExitError); ok {
				r.rc = ee.ExitCode()
			}
		}
		r.mu.Unlock()
		close(r.done)
	}()
	return r, nil
}

func (s *suite) config(st string) string {
	cfg := filepath.Join(st, "config.yaml")
	body := fmt.Sprintf("version: 0\nledger_root: %s/ledger\nresolver: [\"127.0.0.2\"]\n", st)
	_ = os.WriteFile(cfg, []byte(body), 0o600)
	return cfg
}

func (r *run) read(pr *os.File) {
	defer close(r.readerDone)
	defer func() { _ = pr.Close() }()
	sc := bufio.NewScanner(io.Reader(pr))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var once sync.Once
	for sc.Scan() {
		line := sc.Text()
		r.mu.Lock()
		r.lines = append(r.lines, line)
		if m := phaseRE.FindStringSubmatch(line); m != nil {
			us, _ := strconv.ParseFloat(m[2], 64)
			r.phases[m[1]] = us / 1000
		} else if m := statRE.FindStringSubmatch(line); m != nil {
			if r.stats == nil {
				r.stats = map[string]int64{}
			}
			r.stats[m[1]], _ = strconv.ParseInt(m[2], 10, 64)
		} else if m := stackRE.FindStringSubmatch(line); m != nil {
			r.stacks = append(r.stacks, m[1])
		} else if m := resRE.FindStringSubmatch(line); m != nil {
			v, _ := strconv.ParseFloat(m[2], 64)
			r.res[m[1]] = v
			if m[1] == "up" {
				r.up = time.Since(r.t0)
				once.Do(func() { close(r.upCh) })
			}
		}
		r.mu.Unlock()
	}
	once.Do(func() { close(r.upCh) })
}

// readerGrace bounds how long wait waits, after the process has exited, for the rest of its output.
var readerGrace = 10 * time.Second

func (r *run) wait(timeout time.Duration) {
	select {
	case <-r.done:
	case <-time.After(timeout):
		_ = r.cmd.Process.Kill()
		<-r.done
		r.mu.Lock()
		r.rc = -999
		r.mu.Unlock()
	}
	// The reader ends at the pipe's end of file, which comes after the exit when a descendant still holds the
	// output. Joined, not slept on (it was 20 ms), so sampleError and fill never read res or phases while it writes
	// them; after readerGrace the read end is closed under it, so a descendant that never lets go cannot hold the
	// suite.
	if r.readerDone != nil {
		select {
		case <-r.readerDone:
		case <-time.After(readerGrace):
			_ = r.pr.Close()
			<-r.readerDone
		}
	}
	if r.cleanup != nil {
		r.cleanup()
	}
}

func (r *run) tail() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) > 4 {
		return r.lines[len(r.lines)-4:]
	}
	return append([]string(nil), r.lines...)
}

func (s *suite) one(sp spec) (*run, error) {
	if s.oneRun != nil {
		return s.oneRun(sp)
	}
	r, err := s.launch(sp)
	if err != nil {
		return nil, err
	}
	r.wait(240 * time.Second)
	return r, nil
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// gcBuilds removes every idle build and pauses a second, the cold sample's fixed settle (perf-cold: unchanged).
func (s *suite) gcBuilds() error {
	err := s.gcOnly()
	if err == nil {
		s.pauseAfterGC()
	}
	return err
}

// gcOnly runs `tego gc --builds`.
func (s *suite) gcOnly() error {
	if s.clearBuilds != nil {
		return s.clearBuilds()
	}
	st := filepath.Join(*base, "state-gc")
	_ = os.MkdirAll(st, 0o700)
	cmd := exec.Command(*tegoBin, "gc", "--builds")
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+s.config(st))
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("perfsuite: gc --builds: %v: %s\n", err, strings.TrimSpace(string(out)))
	}
	return err
}

// pauseAfterGC is the second every cold sample waits after gc; a test's stand-in gc pauses for nothing.
func (s *suite) pauseAfterGC() {
	if s.clearBuilds == nil {
		time.Sleep(time.Second)
	}
}

func phaseNames(rs []*run) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		for n := range r.phases {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// medianPhases is the median of each coarse phase over rs; the fine-grained ones are the cold-attribution records'.
func medianPhases(rs []*run) map[string]any {
	out := map[string]any{}
	for _, n := range phaseNames(rs) {
		if fineGrained(n) {
			continue
		}
		var xs []float64
		for _, r := range rs {
			if v, ok := r.phases[n]; ok {
				xs = append(xs, v)
			}
		}
		out[n] = round1(perf.Median(xs))
	}
	return out
}

// round1 rounds v to a tenth, half away from zero (a cold-attributed cost may be negative).
func round1(v float64) float64 { return math.Round(v*10) / 10 }

// cold: gc --builds removes every idle build, so the run after it loads, verifies and attaches.
func (s *suite) cold() {
	first := s.bootFirst
	s.bootFirst = false
	if s.settle && first {
		s.baseTraced()
	}
	for i, m := range s.modes[1:] {
		var ups, attrUps []float64
		var rs []*run
		for k := 0; k < *coldN; k++ {
			bootFirst := first && i == 0 && k == 0
			if !bootFirst {
				if err := s.gcBuilds(); err != nil {
					s.fail("cold-fail", map[string]any{"mode": m.Name, "err": err.Error(), "operation": "gc --builds"})
					continue
				}
			}
			// The budget's sample launches as it did before the attribution existed (A-PERF-5).
			r, err := s.coldSample(m, k, bootFirst, false, false, nil)
			if err = sampleError(r, err, "open_0"); err != nil {
				s.fail("cold-fail", map[string]any{"mode": m.Name, "err": fmt.Sprint(err), "tail": tailOf(r)})
			} else {
				ups = append(ups, ms(r.up))
				rs = append(rs, r)
				if bootFirst {
					s.record("cold.bootfirst.ms", ms(r.up))
					s.emit("cold-boot-first", map[string]any{"mode": m.Name, "up_ms": round1(ms(r.up)),
						"phases_ms": medianPhases([]*run{r})})
				}
			}
			if s.attribution {
				if up, ok := s.attributedSample(m, k); ok {
					attrUps = append(attrUps, up)
				}
			}
		}
		if len(ups) != *coldN {
			s.fail("cold-fail", map[string]any{"mode": m.Name, "samples": len(ups), "required": *coldN})
		}
		if len(ups) > 0 {
			s.record("cold."+m.Name+".ms", perf.Min(ups))
			s.emit("cold", map[string]any{"mode": m.Name, "up_ms": roundAll(ups), "min_ms": round1(perf.Min(ups)), "median_ms": round1(perf.Median(ups)), "phases_ms": medianPhases(rs)})
		}
		s.attributedSummary(m, attrUps, ups)
		if s.settle {
			s.settled(m)
		}
	}
}

func tailOf(r *run) []string {
	if r == nil {
		return nil
	}
	return r.tail()
}

func roundAll(xs []float64) []float64 {
	o := make([]float64, len(xs))
	for i, x := range xs {
		o[i] = round1(x)
	}
	return o
}

// start: one priming run per mode (which adopts or loads the build), then -start-runs measured warm starts.
func (s *suite) start() {
	med := map[string]float64{}
	for _, m := range s.modes {
		args := []string{"-n", "1", "-reps", "1", "-up", "notes.txt"}
		r, err := s.one(spec{mode: m, tag: "prime-" + m.Name, args: args})
		if err = sampleError(r, err, "open_0"); err != nil {
			s.fail("start-fail", map[string]any{"mode": m.Name, "err": fmt.Sprint(err), "tail": tailOf(r)})
			continue
		}
		var ups, walls []float64
		var rs []*run
		for i := 0; i < *startN; i++ {
			r, err := s.one(spec{mode: m, tag: "start-" + m.Name, args: args})
			if err = sampleError(r, err, "open_0"); err != nil {
				s.fail("start-fail", map[string]any{"mode": m.Name, "err": fmt.Sprint(err), "tail": tailOf(r)})
				continue
			}
			ups = append(ups, ms(r.up))
			walls = append(walls, ms(r.wall))
			rs = append(rs, r)
		}
		if len(ups) != *startN {
			s.fail("start-fail", map[string]any{"mode": m.Name, "samples": len(ups), "required": *startN})
		}
		if len(ups) == 0 {
			continue
		}
		med[m.Name] = perf.Min(ups)
		s.record("start.warm."+m.Name+".min_ms", med[m.Name])
		s.emit("start", map[string]any{"mode": m.Name, "up_ms": roundAll(ups), "min_ms": round1(med[m.Name]), "p50_ms": round1(perf.Median(ups)),
			"p90_ms": round1(perf.Percentile(ups, 90)), "wall_p50_ms": round1(perf.Median(walls)), "phases_ms": medianPhases(rs)})
	}
	if a, ok := med["bpflsm"]; ok {
		if b, ok := med["landlock"]; ok {
			s.record("start.warm.bpflsm.excess_ms", a-b)
		}
	}
}

// fill: Prepare's fill phase at 1, 1000 and one row under the cap, tier bpflsm.
func (s *suite) fill() {
	m := s.modes[len(s.modes)-1] // bpflsm where bpf is an active LSM, else cgroup with the fmod_ret plane
	const capRows = 4096
	measure := func(n int, capacityProbe bool) (fillMs, prepMs, upMs float64, rs []*run, ok bool) {
		if err := s.data(n); err != nil {
			s.fail("fill-fail", map[string]any{"rows": n, "err": err.Error()})
			return 0, 0, 0, nil, false
		}
		var fills, preps, ups []float64
		for i := 0; i < 3; i++ {
			r, err := s.one(spec{mode: m, rows: n, tag: fmt.Sprintf("fill-%d", n), args: []string{"-n", "1", "-reps", "1", "-up", "notes.txt"}})
			// Only the initial near-cap probe may legitimately be rejected. A later failed
			// sample of an already fitting table is a required measurement failure.
			fallback := r != nil && err == nil && r.rc == 0 && sampleError(r, nil, "open_0") == nil
			if fallback {
				_, plane := r.phases["load.plane"]
				fallback = !plane
			}
			capacity := false
			if r != nil && err == nil && r.rc == identity.ExitLauncher {
				tail := strings.Join(tailOf(r), " ")
				match := capacityRE.FindStringSubmatch(tail)
				if len(match) == 2 {
					rows, _ := strconv.Atoi(match[1])
					capacity = rows > 4096
				}
			}
			if capacityProbe && i == 0 && (fallback || capacity) {
				if fallback {
					err = fmt.Errorf("the run fell back to the fanotify listener: the plane took no rows")
				}
				s.emit("fill-refused", map[string]any{"rows": n, "err": fmt.Sprint(err), "tail": tailOf(r)})
				return 0, 0, 0, nil, false
			}
			err = sampleError(r, err, "open_0")
			if err == nil {
				for _, key := range []string{"load.plane", "prepare.fill", "prepare"} {
					v, ok := r.phases[key]
					if !ok || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
						err = fmt.Errorf("missing or invalid phase %s", key)
						break
					}
				}
			}
			if err != nil {
				s.fail("fill-fail", map[string]any{"rows": n, "err": err.Error(), "tail": tailOf(r)})
				return 0, 0, 0, nil, false
			}
			fills = append(fills, r.phases["prepare.fill"])
			preps = append(preps, r.phases["prepare"])
			ups = append(ups, ms(r.up))
			rs = append(rs, r)
		}
		return perf.Median(fills), perf.Median(preps), perf.Median(ups), rs, true
	}
	// Warm the build first: this check is Prepare's own cost, not a load.
	r, err := s.one(spec{mode: m, tag: "fill-prime", args: []string{"-n", "1", "-reps", "1", "-up", "notes.txt"}})
	if err = sampleError(r, err, "open_0"); err != nil {
		s.fail("fill-fail", map[string]any{"operation": "prime", "err": err.Error(), "tail": tailOf(r)})
	}
	for _, n := range []int{1, 1000} {
		f, p, u, rs, ok := measure(n, false)
		if !ok {
			continue
		}
		if n == 1000 {
			s.record("fill.rows1000.ms", f)
		}
		s.emit("fill", map[string]any{"rows": n, "samples": len(rs), "fill_ms": round1(f), "prepare_ms": round1(p), "up_ms": round1(u), "phases_ms": medianPhases(rs)})
	}
	// One row under the cap: the table also holds the write directory's and the working directory's rows, so
	// step down from cap-1 until Prepare accepts the table.
	for n := capRows - 1; n > capRows-40; n-- {
		f, p, u, rs, ok := measure(n, true)
		if !ok {
			continue
		}
		s.record("fill.rowscap.ms", f)
		s.emit("fill", map[string]any{"rows": n, "cap_minus": capRows - n, "samples": len(rs), "fill_ms": round1(f), "prepare_ms": round1(p), "up_ms": round1(u), "phases_ms": medianPhases(rs)})
		return
	}
	s.fail("fill-fail", map[string]any{"rows": "cap"})
}

// open: -rounds rounds; each runs every mode once in an order that rotates, so a drifting host does not favour one
// mode. Alternating whole runs rather than loops keeps every mode's build loaded for the whole check.
func (s *suite) open() {
	paths := []string{"notes.txt", "out/f", "out/a/b/c/d/e/f"}
	names := []string{"norow", "write", "deep"}
	args := append([]string{"-n", strconv.Itoa(*opens), "-reps", "3", "-cpu", strconv.Itoa(*cpu), "-up"}, paths...)
	// Every mode's build stays pinned for the check: prime each, then measure.
	for _, m := range s.modes {
		r, err := s.one(spec{mode: m, tag: "open-prime", args: []string{"-n", "1", "-reps", "1", "-up", "notes.txt"}})
		if err = sampleError(r, err, "open_0"); err != nil {
			s.fail("open-fail", map[string]any{"mode": m.Name, "operation": "prime", "err": err.Error(), "tail": tailOf(r)})
		}
	}
	for _, rec := range []string{"off", "summary"} {
		vals := map[string][]float64{} // mode/path -> per round
		for round := 0; round < *rounds; round++ {
			for k := range s.modes {
				m := s.modes[(k+round)%len(s.modes)]
				r, err := s.one(spec{mode: m, record: rec, tag: "open-" + m.Name, args: args})
				if err = sampleError(r, err, "open_0", "open_1", "open_2"); err != nil {
					s.fail("open-fail", map[string]any{"mode": m.Name, "rec": rec, "err": err.Error(), "tail": tailOf(r)})
					continue
				}
				for i, n := range names {
					vals[m.Name+"/"+n] = append(vals[m.Name+"/"+n], r.res["open_"+strconv.Itoa(i)])
				}
			}
		}
		// The estimate is each mode's best round: another tenant on the host only ever adds to a loop's time, so the
		// minimum of nine best-of-three loops is the stable figure, and the medians are printed beside it.
		best := map[string]float64{}
		samples := map[string]int{}
		out := map[string]any{"rec": rec, "opens": *opens, "rounds": *rounds, "cpu": *cpu, "samples": samples}
		for _, m := range s.modes {
			for _, n := range names {
				xs := vals[m.Name+"/"+n]
				samples[m.Name+"/"+n] = len(xs)
				if len(xs) != *rounds {
					s.fail("open-fail", map[string]any{"mode": m.Name, "rec": rec, "path": n, "samples": len(xs), "required": *rounds})
				}
				lo := 0.0
				for i, x := range xs {
					if i == 0 || x < lo {
						lo = x
					}
				}
				best[m.Name+"/"+n] = lo
				out[m.Name+"."+n+"_min_ns"] = lo
				out[m.Name+"."+n+"_med_ns"] = perf.Median(xs)
			}
		}
		if _, ok := best["cgroup-fmod_ret/norow"]; ok {
			if _, ok := best["cgroup-lsm/norow"]; ok {
				for _, n := range names {
					// ADR 0024's ordering claim: fmod_ret mode is cheaper than LSM mode; negative here means it is.
					out["fmod_ret_minus_lsm."+n+"_ns"] = best["cgroup-fmod_ret/"+n] - best["cgroup-lsm/"+n]
				}
			}
		}
		for _, m := range s.modes[1:] {
			worst := -1e18
			for _, n := range names {
				e := best[m.Name+"/"+n] - best["landlock/"+n]
				out["excess."+m.Name+"."+n+"_ns"] = e
				if e > worst {
					worst = e
				}
			}
			out["excess."+m.Name+".worst_ns"] = worst
			if rec == "summary" {
				s.record("open.excess."+m.Name+"_ns", worst)
			}
		}
		s.emit("open", out)
	}
}

// socket: -rounds rounds of a raw socket(AF_INET, SOCK_STREAM, 0)+close loop (openbench -socket), landlock and tier
// cgroup on the fanotify fallback alternated, both under a net: section, so the seccomp filter's socket arm admits the
// socket in registers at both. The fallback attaches nothing else that runs when a socket is made, so its best loop
// less landlock's is cgroup/sock_create's cost on an admitted socket (socket.excess.cgroup_ns, ADR 0018 PR 2). The
// same runs loop setsockopt(TCP_NODELAY) on one socket, which the filter admits at both and only cgroup/setsockopt
// sees at the fallback, so that difference is its cost on an option it passes, the kernel's copy of the value
// included (setsockopt.excess.cgroup_ns, ADR 0018 (7)). Each mode's best round is its figure, as in the open check.
func (s *suite) socket() {
	modes := perf.SocketModes
	args := []string{"-n", strconv.Itoa(*opens), "-reps", "3", "-cpu", strconv.Itoa(*cpu), "-up", "-socket", "-setsockopt"}
	samples := []string{"socket_0", "setsockopt_0"}
	for _, m := range modes {
		r, err := s.one(spec{mode: m, record: "summary", tag: "socket-prime", args: []string{"-n", "1", "-reps", "1", "-up",
			"-socket", "-setsockopt"}})
		if err = sampleError(r, err, samples...); err != nil {
			s.fail("socket-fail", map[string]any{"mode": m.Name, "operation": "prime", "err": err.Error(), "tail": tailOf(r)})
		}
	}
	vals := map[string][]float64{}
	for round := 0; round < *rounds; round++ {
		for k := range modes {
			m := modes[(k+round)%len(modes)]
			r, err := s.one(spec{mode: m, record: "summary", tag: "socket-" + m.Name, args: args})
			if err = sampleError(r, err, samples...); err != nil {
				s.fail("socket-fail", map[string]any{"mode": m.Name, "err": err.Error(), "tail": tailOf(r)})
				continue
			}
			for _, sample := range samples {
				vals[m.Name+"."+sample] = append(vals[m.Name+"."+sample], r.res[sample])
			}
		}
	}
	out := map[string]any{"sockets": *opens, "rounds": *rounds, "cpu": *cpu}
	complete := true
	for _, m := range modes {
		for _, sample := range samples {
			xs := vals[m.Name+"."+sample]
			out[m.Name+"."+sample+".samples"] = len(xs)
			if len(xs) != *rounds {
				complete = false
				s.fail("socket-fail", map[string]any{"mode": m.Name, "sample": sample, "samples": len(xs), "required": *rounds})
				continue
			}
			out[m.Name+"."+sample+".min_ns"] = perf.Min(xs)
			out[m.Name+"."+sample+".med_ns"] = perf.Median(xs)
		}
	}
	if complete {
		for i, budget := range []string{"socket.excess.cgroup_ns", "setsockopt.excess.cgroup_ns"} {
			sample := samples[i]
			excess := perf.Min(vals[modes[1].Name+"."+sample]) - perf.Min(vals[modes[0].Name+"."+sample])
			out[sample+".excess_ns"] = excess
			s.record(budget, excess)
		}
	}
	s.emit("socket", out)
}

// conc: n gated runs at once per mode, landlock as the control. The fanotify fallback is measured at small n only:
// it is not budgeted, doctor says it does not scale.
func (s *suite) conc() {
	counts := s.counts
	if counts == nil {
		var err error
		counts, err = validateSampleCounts(*coldN, *startN, *rounds, *opens, *concList)
		if err != nil {
			s.fail("conc-fail", map[string]any{"err": err.Error()})
			return
		}
	}
	modes := append(append([]perf.Mode(nil), s.modes...), perf.Mode{Name: "cgroup-fanotify", Tier: "cgroup", Plane: "fanotify"})
	control := map[int]float64{}
	for _, n := range counts {
		for _, m := range modes {
			if m.Name == "cgroup-fanotify" && n > 8 {
				continue
			}
			allUp, ok, ups, opensNS, rcs := s.concOnce(m, n)
			if ok != n || len(ups) != n || len(opensNS) != n || len(rcs) != 1 || rcs[0] != 0 {
				s.fail("conc-fail", map[string]any{"mode": m.Name, "n": n, "ok": ok, "ready_samples": len(ups), "benchmark_samples": len(opensNS), "rcs": rcs})
			}
			out := map[string]any{"mode": m.Name, "n": n, "ok": ok, "rcs": rcs, "ready_samples": len(ups), "benchmark_samples": len(opensNS), "all_up_s": round1(allUp), "open_ns_med": perf.Median(opensNS)}
			if len(opensNS) > 0 {
				out["open_ns_max"] = perf.Percentile(opensNS, 100)
			}
			if len(ups) > 0 {
				out["up_ms_med"] = round1(perf.Median(ups))
				out["up_ms_max"] = round1(perf.Percentile(ups, 100))
			}
			if m.Name == "landlock" {
				control[n] = perf.Median(opensNS)
			} else if c, ok := control[n]; ok && len(opensNS) > 0 {
				out["open_excess_ns"] = perf.Median(opensNS) - c
				out["open_ratio"] = perf.Median(opensNS) / c
			}
			if m.Name == "bpflsm" {
				if ok == n {
					s.record(fmt.Sprintf("conc.bpflsm.n%d.all_up_s", n), allUp)
				}
				if c, has := control[n]; has && len(opensNS) > 0 {
					s.record(fmt.Sprintf("conc.bpflsm.n%d.open_ratio", n), perf.Median(opensNS)/c)
				}
			}
			s.emit("conc", out)
		}
	}
}

func (s *suite) concOnce(m perf.Mode, n int) (allUp float64, ok int, ups, opensNS []float64, rcs []int) {
	gate := filepath.Join(s.proj, "out", "go")
	_ = os.Remove(gate)
	args := []string{"-n", "50000", "-reps", "1", "-up", "-gate", "out/go", "notes.txt"}
	// A build the earlier count left is adopted; the first launch of a mode primes it.
	r, err := s.one(spec{mode: m, record: "off", tag: "conc-prime", args: []string{"-n", "1", "-reps", "1", "-up", "notes.txt"}})
	if err = sampleError(r, err, "open_0"); err != nil {
		s.fail("conc-fail", map[string]any{"mode": m.Name, "operation": "prime", "err": err.Error(), "tail": tailOf(r)})
		return
	}
	t0 := time.Now()
	var rs []*run
	for i := 0; i < n; i++ {
		r, err := s.launch(spec{mode: m, record: "off", tag: fmt.Sprintf("conc-%s-%d", m.Name, n), args: args})
		if err != nil {
			s.fail("conc-fail", map[string]any{"mode": m.Name, "n": n, "err": err.Error()})
			break
		}
		rs = append(rs, r)
	}
	dl := time.NewTimer(150 * time.Second)
	defer dl.Stop()
	timedOut := false
	for _, r := range rs {
		if timedOut {
			continue
		}
		select {
		case <-r.upCh:
		case <-dl.C:
			timedOut = true
			s.fail("conc-fail", map[string]any{"mode": m.Name, "n": n, "err": "readiness deadline exceeded"})
		}
	}
	allUp = time.Since(t0).Seconds()
	f, err := os.Create(gate)
	if err != nil {
		s.fail("conc-fail", map[string]any{"mode": m.Name, "n": n, "operation": "release gate", "err": err.Error()})
	} else {
		if err := f.Close(); err != nil {
			s.fail("conc-fail", map[string]any{"operation": "close gate", "err": err.Error()})
		}
		if err := os.Chown(gate, s.uid, s.gid); err != nil {
			s.fail("conc-fail", map[string]any{"operation": "own gate", "err": err.Error()})
		}
	}
	seen := map[int]bool{}
	for _, r := range rs {
		r.wait(300 * time.Second)
		r.mu.Lock()
		if sampleError(r, nil, "open_0") == nil {
			ok++
			ups = append(ups, ms(r.up))
			opensNS = append(opensNS, r.res["open_0"])
		}
		if !seen[r.rc] {
			seen[r.rc] = true
			rcs = append(rcs, r.rc)
		}
		r.mu.Unlock()
	}
	_ = os.Remove(gate)
	return allUp, ok, ups, opensNS, rcs
}
