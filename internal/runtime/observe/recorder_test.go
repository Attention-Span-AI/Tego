// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// fakeRing replays a fixed slice of synthetic samples and then behaves like a live, empty ring:
// every further read blocks until the deadline or Close, which is exactly what *ringbuf.Reader does.
type fakeRing struct {
	mu       sync.Mutex
	samples  [][]byte
	closed   chan struct{}
	deadline time.Time
	readErr  error // returned instead of a sample once the queue drains
	once     sync.Once
}

func newFakeRing(samples ...[]byte) *fakeRing {
	return &fakeRing{samples: samples, closed: make(chan struct{})}
}

// ReadInto is RingReader's read; next is the record it copies.
func (f *fakeRing) ReadInto(rec *ringbuf.Record) error { return readInto(rec, f.next) }

// readInto hands out one record the way *ringbuf.Reader.ReadInto does: copied into rec's own array, which the
// next read overwrites. A drain that kept a record's bytes past its read would see them change here, as it
// would on a kernel ring, rather than keep a private copy the fake happened to give it.
func readInto(rec *ringbuf.Record, next func() (ringbuf.Record, error)) error {
	got, err := next()
	if err != nil {
		return err
	}
	rec.RawSample = append(rec.RawSample[:0], got.RawSample...)
	rec.Remaining = got.Remaining
	return nil
}

// next takes the next record off the fake's queue, or waits for the deadline or Close.
func (f *fakeRing) next() (ringbuf.Record, error) {
	f.mu.Lock()
	if len(f.samples) > 0 {
		s := f.samples[0]
		f.samples = f.samples[1:]
		remaining := 0
		if len(f.samples) > 0 {
			remaining = len(f.samples) * 8
		}
		f.mu.Unlock()
		return ringbuf.Record{RawSample: s, Remaining: remaining}, nil
	}
	err, deadline := f.readErr, f.deadline
	f.mu.Unlock()
	if err != nil {
		return ringbuf.Record{}, err
	}
	var timer <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timer = t.C
	}
	select {
	case <-f.closed:
		return ringbuf.Record{}, ringbuf.ErrClosed
	case <-timer:
		return ringbuf.Record{}, os.ErrDeadlineExceeded
	}
}

func (f *fakeRing) SetDeadline(t time.Time) {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
}

func (f *fakeRing) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// fakeSink collects events the way runtime.Queue would, without dropping any.
type fakeSink struct {
	mu     sync.Mutex
	events []*record.Event
}

func (s *fakeSink) Emit(ev *record.Event) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

func (s *fakeSink) all() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*record.Event(nil), s.events...)
}

func (s *fakeSink) byKind(k record.Kind) []*record.Event {
	var out []*record.Event
	for _, ev := range s.all() {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// payload shares the typed ledger decoder used by the other runtime fixtures.
func payload[T any](t *testing.T, ev *record.Event) T {
	t.Helper()
	return ledgertest.Decode[T](t, ev)
}

// fixture builds a rule table over a real temporary project plus the fake /proc the process cache
// reads, and returns both with the started recorder's sink.
type fixture struct {
	dir     string
	out     string
	secrets string
	watch   string
	git     string // exec.allow [git]: the fixture's own bin/git, never the host's (root-suites R1)
	procFS  *proc.FS
	rules   *agent.RuleTable
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	secrets := filepath.Join(dir, "secrets")
	watch := filepath.Join(dir, "config")
	for _, d := range []string{out, secrets, watch} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(secrets, "key.pem")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	procRoot := t.TempDir()
	writeProc(t, procRoot, 50, 1, "python3", "/usr/bin/python3.12", []string{"python3", "app.py"}, 900)
	compiled := contracttest.BuildAt(t, dir, `version: 0
name: retriever
command: [fixture]
tier: landlock
capture: off
record: summary
fs:
  write: [./out]
  watch: [./config]
  deny_read: [./secrets/key.pem]
net:
  allow: [api.example.com:443]
exec:
  allow: [git]
`, contracttest.Tree{"bin/git": "#!/bin/sh\nexit 0\n"},
		agent.WithResolver(contracttest.Resolver{"api.example.com": parseAddrs("93.184.216.34")}))
	return &fixture{
		dir: dir, out: out, secrets: secrets, watch: watch, git: compiled.Path("bin/git"),
		procFS: proc.NewAt(procRoot), rules: compiled.Rules,
	}

}

// addSyntheticParentIndex is a wire-fixture counterfactual, not compiler output.
// Samples carrying only the project's parent dev/inode/name need that directory
// in the attribution index. The ordinary compiled fixture has no such grant.
func addSyntheticParentIndex(f *fixture) {
	f.rules.FS = append(f.rules.FS, agent.FSRule{Path: f.dir, Kind: agent.FSImplicit})
}

// runRecorder starts a recorder over the given samples, waits for them to be consumed and stops it.
func runRecorder(t *testing.T, f *fixture, opts Options, samples ...[]byte) (*Recorder, *fakeSink) {
	t.Helper()
	return runRecorderAfter(t, f, opts, nil, samples...)
}

// runRecorderAfter is runRecorder with built called once New has built the recorder's index, before the samples are
// read: a test changes the tree there as the agent would after the run started.
func runRecorderAfter(t *testing.T, f *fixture, opts Options, built func(), samples ...[]byte) (*Recorder, *fakeSink) {
	t.Helper()
	ring := newFakeRing(samples...)
	opts.Rules = f.rules
	opts.Reader = ring
	opts.Proc = f.procFS
	if opts.FlushInterval == 0 {
		opts.FlushInterval = 20 * time.Millisecond
	}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if built != nil {
		built()
	}
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx, source.RunRef{ID: "r-host-1", Agent: "retriever"}, sink); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		ring.mu.Lock()
		defer ring.mu.Unlock()
		return len(ring.samples) == 0
	}, "samples were never drained")
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	return r, sink
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}

// TestRecorderEmitsEveryActionKind: every exec, open and connect
// of a run appears with its rule and verdict.
func TestRecorderEmitsEveryActionKind(t *testing.T) {
	f := newFixture(t)
	h := sample{MonoNS: 1000, CgroupID: 77, PID: 50, TID: 50, PPID: 1}
	openWrite := h
	openWrite.Kind, openWrite.MonoNS = KindOpen, 1100
	denyRead := h
	denyRead.Kind, denyRead.MonoNS = KindOpen, 1200
	conn := h
	conn.Kind, conn.MonoNS = KindConnect, 1300

	_, sink := runRecorder(t, f, Options{},
		execSample(h, 900*proc.NanosPerTick, "python3", f.git, []string{"git", "status"}, false),
		fsSample(openWrite, 0o1, 1, 2049, filepath.Join(f.out, "report.md"), ""),
		fsSample(denyRead, 0, 2, 2049, filepath.Join(f.secrets, "key.pem"), ""),
		netSample(conn, 2, 6, 443, addr4(93, 184, 216, 34)),
	)

	execs := sink.byKind(record.KindExec)
	if len(execs) != 1 {
		t.Fatalf("%d exec events", len(execs))
	}
	e := execs[0]
	if e.Rule != "exec[git]" || e.Verdict != record.VerdictAllow || e.Source != record.SourceKernel {
		t.Errorf("exec event %+v", e)
	}
	if e.Authority != record.AuthorityRule || !e.Attr.Valid() {
		t.Errorf("exec event attribution/authority %+v", e)
	}
	ep := payload[record.ExecPayload](t, e)
	if ep.Path != f.git || ep.ExecID == "" || !strings.HasPrefix(ep.ExecID, "r-host-1/50/") ||
		strings.Join(ep.Argv, " ") != "git status" {
		t.Errorf("exec payload %+v", ep)
	}
	if err := e.Validate(); err != nil {
		t.Errorf("exec event does not satisfy spec/record/v1: %v", err)
	}

	fs := sink.byKind(record.KindFS)
	var write, deny *record.Event
	for _, ev := range fs {
		p := payload[record.FSPayload](t, ev)
		switch {
		case strings.HasSuffix(p.Path, "report.md"):
			write = ev
		case strings.HasSuffix(p.Path, "key.pem"):
			deny = ev
		}
	}
	if write == nil || write.Rule != "fs.write[./out]" || write.Verdict != record.VerdictAllow {
		t.Errorf("write event %+v", write)
	}
	if deny == nil || deny.Rule != "fs.deny_read[./secrets/key.pem]" || deny.Verdict != record.VerdictRefused ||
		deny.Reason != record.ReasonReadDenied {
		t.Errorf("deny_read event %+v", deny)
	}

	nets := sink.byKind(record.KindNet)
	if len(nets) != 1 {
		t.Fatalf("%d net events", len(nets))
	}
	np := payload[record.NetPayload](t, nets[0])
	if nets[0].Rule != "net[api.example.com:443]" || np.Dst != "93.184.216.34:443" || np.Proto != "tcp" {
		t.Errorf("net event %+v %+v", nets[0], np)
	}
	if err := nets[0].Validate(); err != nil {
		t.Errorf("net event does not satisfy spec/record/v1: %v", err)
	}
}

// TestRecorderAggregatesStartupReads: ordinary reads become one fs event per (exec id, rule)
// with a count, and the flush happens when the process exits.
func TestRecorderAggregatesStartupReads(t *testing.T) {
	f := newFixture(t)
	var samples [][]byte
	base := sample{Kind: KindOpen, CgroupID: 77, PID: 50, TID: 50}
	for i := 0; i < 200; i++ {
		s := base
		s.MonoNS = uint64(1000 + i)
		samples = append(samples, fsSample(s, 0, uint32(i), 2049, "/usr/lib/python3.12/os.py", ""))
	}
	exit := sample{Kind: KindExit, PID: 50, MonoNS: 9000}
	samples = append(samples, exitSample(exit, 0, 0))

	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, samples...)

	fs := sink.byKind(record.KindFS)
	if len(fs) != 1 {
		t.Fatalf("%d fs events, want one aggregate: %+v", len(fs), fs)
	}
	p := payload[record.FSPayload](t, fs[0])
	if p.Count != 200 || p.Op != record.FSOpen {
		t.Errorf("aggregate payload %+v", p)
	}
	if fs[0].Rule != RuleUnmatched || fs[0].Verdict != record.VerdictAllow {
		t.Errorf("aggregate event %+v", fs[0])
	}
	if err := fs[0].Validate(); err != nil {
		t.Errorf("aggregate does not satisfy spec/record/v1: %v", err)
	}
}

// TestRecorderRecordFullDisablesAggregation is SEMANTICS §7's "record: full disables aggregation" at tier 2:
// each read is its own event, carrying the file it opened and the verdict its aggregate would have carried.
func TestRecorderRecordFullDisablesAggregation(t *testing.T) {
	f := newFixture(t)
	addSyntheticParentIndex(f)
	f.rules.Record = agent.RecordFull
	var samples [][]byte
	for i := range 3 {
		samples = append(samples, fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: uint64(10 + i)}, 0, uint32(i), 2049,
			"/usr/lib/python3.12/os.py", ""))
	}
	samples = append(samples, fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 20}, 0, 9, 2049,
		filepath.Join(f.dir, "app.py"), ""))
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, samples...)
	fs := sink.byKind(record.KindFS)
	if len(fs) != 4 {
		t.Fatalf("record: full gave %d fs events, want the 4 reads individually", len(fs))
	}
	for i, ev := range fs {
		p := payload[record.FSPayload](t, ev)
		want, rule := "/usr/lib/python3.12/os.py", RuleUnmatched
		if i == 3 {
			want, rule = filepath.Join(f.dir, "app.py"), "fs.implicit["+f.dir+"]"
		}
		if p.Count != 0 || p.Path != want || ev.Rule != rule || ev.Verdict != record.VerdictAllow {
			t.Errorf("read %d recorded %s %s path=%s count=%d, want %s allow path=%s", i, ev.Rule, ev.Verdict, p.Path,
				p.Count, rule, want)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("read %d does not satisfy spec/record/v1: %v", i, err)
		}
	}
}

// TestRecorderResolvesARelativeExec is an execve of a relative name: bprm->filename is what the process passed,
// and "./git" run beside the agent was recorded exec[/usr/bin/git] allow. The name is joined to the process's
// working directory while that is the one the kernel saw at the exec; otherwise it names no file and is
// recorded unmatched and observed.
func TestRecorderResolvesARelativeExec(t *testing.T) {
	f := newFixture(t)
	work := t.TempDir()
	if err := os.Symlink(work, filepath.Join(f.procFS.Root(), "50", "cwd")); err != nil {
		t.Fatal(err)
	}
	f.rules.Tier = backend.TierCgroup
	f.rules.Exec = []agent.ExecRule{
		{Raw: "/usr/bin/git", Path: "/usr/bin/git", Basename: "git", Verdict: agent.VerdictAllow},
		{Raw: "./tool", Path: filepath.Join(work, "tool"), Basename: "tool", Verdict: agent.VerdictAllow},
	}
	di, ok := statDevIno(work)
	if !ok {
		t.Fatal("stat the working directory")
	}
	here := sample{Kind: KindExec, PID: 50, PPID: 1, CwdDev: di.Dev, CwdIno: di.Ino}
	moved := here
	moved.CwdIno++ // the process has changed directory since its exec
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		execSample(here, 900*proc.NanosPerTick, "tool", "./tool", []string{"./tool"}, false),
		execSample(here, 900*proc.NanosPerTick, "git", "./git", []string{"./git"}, false),
		execSample(moved, 900*proc.NanosPerTick, "tool", "./tool", []string{"./tool"}, false))
	execs := sink.byKind(record.KindExec)
	if len(execs) != 3 {
		t.Fatalf("%d exec events", len(execs))
	}
	want := []struct {
		path, rule string
		verdict    record.Verdict
	}{
		{filepath.Join(work, "tool"), "exec[./tool]", record.VerdictAllow},
		{filepath.Join(work, "git"), RuleUnmatched, record.VerdictObserved},
		{"./tool", RuleUnmatched, record.VerdictObserved},
	}
	for i, ev := range execs {
		p := payload[record.ExecPayload](t, ev)
		if p.Path != want[i].path || ev.Rule != want[i].rule || ev.Verdict != want[i].verdict {
			t.Errorf("exec %d recorded path=%s %s %s, want path=%s %s %s", i, p.Path, ev.Rule, ev.Verdict, want[i].path,
				want[i].rule, want[i].verdict)
		}
	}
	if n := gapCount(r.Gaps())[GapExecUnresolved]; n != 1 {
		t.Errorf("exec-unresolved %d, want the one exec whose directory moved: %+v", n, r.Gaps())
	}
}

// TestRecorderAReusedPidIsNotTheOldProcess is E14 with an exit record lost: the process cache kept pid 50's
// first process, whose exit never arrived, and an open of the pid's next process (the one /proc now has) was
// counted as the first one's, whose exec id a child's exec then named as its parent. Every record carries its
// process's start time, and the cache answers for a pid only the process that time names.
//
// Also pins record-ledger.md E19: a reused pid gets its own exec_id.
func TestRecorderAReusedPidIsNotTheOldProcess(t *testing.T) {
	f := newFixture(t) // /proc has pid 50 started at tick 900: the pid's second process
	first, second := uint64(100*proc.NanosPerTick), uint64(900*proc.NanosPerTick)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		execSample(sample{Kind: KindExec, PID: 50, PPID: 1, MonoNS: 1}, first, "git", "/usr/bin/git", []string{"git"}, false),
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 2, Start: first}, 0, 1, 2049, "/usr/lib/a.so", ""),
		// The first process's exit was lost; the pid is the second process's now.
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 3, Start: second}, 0, 1, 2049, "/usr/lib/a.so", ""),
		execSample(sample{Kind: KindExec, PID: 60, PPID: 50, ParentStart: second, MonoNS: 4}, 950*proc.NanosPerTick, "git",
			"/usr/bin/git", []string{"git"}, false),
		exitSample(sample{Kind: KindExit, PID: 50, MonoNS: 5, Start: second}, 0, 0))

	var child record.ExecPayload
	for _, ev := range sink.byKind(record.KindExec) {
		if ev.PID == 60 {
			child = payload[record.ExecPayload](t, ev)
		}
	}
	if want := "r-host-1/50/" + strconv.FormatUint(second, 10); child.ParentExecID != want {
		t.Errorf("the child's parent is %q, want the pid's second process %q", child.ParentExecID, want)
	}
	fs := sink.byKind(record.KindFS)
	if len(fs) != 2 {
		t.Fatalf("%d read aggregates, want one for each of the two processes: %+v", len(fs), fs)
	}
	for _, ev := range fs {
		if p := payload[record.FSPayload](t, ev); p.Count != 1 {
			t.Errorf("an aggregate counted %d reads, want each process's one", p.Count)
		}
	}
}

// TestRecorderNeverAggregatesWatchedOrDeniedPaths is R13's exception list.
//
// Also pins record-ledger.md E1: reads under a watched or denied path are individual events.
func TestRecorderNeverAggregatesWatchedOrDeniedPaths(t *testing.T) {
	f := newFixture(t)
	var samples [][]byte
	for i := 0; i < 3; i++ {
		s := sample{Kind: KindOpen, PID: 50, MonoNS: uint64(100 + i)}
		samples = append(samples, fsSample(s, 0, 1, 2049, filepath.Join(f.watch, "app.yaml"), ""))
		s.MonoNS += 10
		samples = append(samples, fsSample(s, 0, 2, 2049, filepath.Join(f.secrets, "key.pem"), ""))
	}
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, samples...)

	fs := sink.byKind(record.KindFS)
	if len(fs) != 6 {
		t.Fatalf("%d fs events, want six individual ones: %+v", len(fs), fs)
	}
	for _, ev := range fs {
		if p := payload[record.FSPayload](t, ev); p.Count != 0 {
			t.Errorf("a watched or denied read was aggregated: %+v", p)
		}
	}
}

// TestRecorderResolvesFSOpsThroughTheDirectoryIndex is R9: unlink/rename/mkdir carry no resolved
// path, and a (dev, ino) hit yields the declared entry while a miss stays unattributed.
func TestRecorderResolvesFSOpsThroughTheDirectoryIndex(t *testing.T) {
	f := newFixture(t)
	di, ok := statDevIno(f.out)
	if !ok {
		t.Fatal("could not stat the write directory")
	}
	hit := sample{Kind: KindUnlink, PID: 50, MonoNS: 10}
	miss := sample{Kind: KindMkdir, PID: 50, MonoNS: 20}
	rename := sample{Kind: KindRename, PID: 50, MonoNS: 30}

	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		fsSample(hit, 0, uint32(di.Ino), di.Dev, "stale.txt", ""),
		fsSample(miss, 0, 0, 999999, "newdir", ""),
		fsSample(rename, 0, uint32(di.Ino), di.Dev, "a.txt", "b.txt"),
	)

	fs := sink.byKind(record.KindFS)
	if len(fs) != 3 {
		t.Fatalf("%d fs events", len(fs))
	}
	unlink := payload[record.FSPayload](t, fs[0])
	if unlink.Op != record.FSUnlink || unlink.Path != filepath.Join(f.out, "stale.txt") {
		t.Errorf("unlink payload %+v", unlink)
	}
	if fs[0].Rule != "fs.write[./out]" || fs[0].Verdict != record.VerdictAllow {
		t.Errorf("unlink event %+v", fs[0])
	}
	mkdir := payload[record.FSPayload](t, fs[1])
	if mkdir.Path != "999999:0/newdir" {
		t.Errorf("a directory-index miss must keep the raw identifier, got %+v", mkdir)
	}
	if fs[1].Rule != RuleUnmatched || fs[1].Verdict != record.VerdictObserved {
		t.Errorf("a miss must be observed and unmatched, never a guessed verdict: %+v", fs[1])
	}
	if fs[1].Attr.Confidence != record.ConfidenceUnattributed {
		t.Errorf("a miss must be unattributed, got %+v", fs[1].Attr)
	}
	// struct tego_ev_fsop carries the destination's own parent, here the same directory, so both sides
	// resolve through the index.
	ren := payload[record.FSPayload](t, fs[2])
	if ren.Path != filepath.Join(f.out, "a.txt") || ren.Path2 != filepath.Join(f.out, "b.txt") {
		t.Errorf("rename payload %+v", ren)
	}
	gaps := gapCount(r.Gaps())
	if gaps[GapDirUnresolved] != 1 {
		t.Errorf("gaps %+v", r.Gaps())
	}
}

// TestRecorderSaysWhichEntriesItCannotIndex is R9 where stat does not name a file by its super block's device:
// on btrfs and on an overlayfs of one filesystem every unlink, rename and mkdir missed the directory index
// while the spec said it resolved. The run records, once, how many entries the index had to leave out, and an
// operation beneath one stays unresolved rather than guessed.
func TestRecorderSaysWhichEntriesItCannotIndex(t *testing.T) {
	f := newFixture(t)
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, f.out, 0, unix.STATX_MNT_ID, &stx); err != nil || stx.Mask&unix.STATX_MNT_ID == 0 {
		t.Skipf("statx names no mount id here: %v", err)
	}
	di, ok := statDevIno(f.out)
	if !ok {
		t.Fatal("stat the write directory")
	}
	// The fixture's four entries share one mount, whose super block this table says is another device.
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(mountinfo, []byte(strconv.FormatUint(stx.Mnt_id, 10)+" 1 0:4242 / / rw - btrfs /dev/x rw\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, mountinfo: mountinfo},
		fsSample(sample{Kind: KindUnlink, PID: 50, MonoNS: 10}, 0, uint32(di.Ino), di.Dev, "stale.txt", ""))
	fs := sink.byKind(record.KindFS)
	if len(fs) != 1 || fs[0].Rule != RuleUnmatched || fs[0].Verdict != record.VerdictObserved {
		t.Fatalf("an unlink beneath an entry the index left out: %+v", fs)
	}
	g := gapCount(r.Gaps())
	if g[GapDirUnindexed] != 4 || g[GapDirUnresolved] != 1 {
		t.Errorf("gaps %+v, want dir-unindexed 4 and dir-unresolved 1", r.Gaps())
	}
}

// TestRecorderKernelVerdictWins is R5: an explicit kernel refusal is never re-derived, while the
// zero verdict every record-only producer leaves behind is inferred from the contract.
func TestRecorderKernelVerdictWins(t *testing.T) {
	f := newFixture(t)
	refused := sample{Kind: KindConnect, PID: 50, MonoNS: 1, Verdict: KernelRefused, Reason: ReasonNetNotAllowed}
	neutral := sample{Kind: KindOpen, PID: 50, MonoNS: 2, Verdict: KernelAllow}
	observed := sample{Kind: KindOpen, PID: 50, MonoNS: 3, Verdict: KernelObserved}
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		netSample(refused, 2, 6, 443, addr4(8, 8, 8, 8)),
		// A write outside every declared entry: the header's zero verdict must not overrule it.
		fsSample(neutral, 0o1, 1, 2049, "/etc/hosts", ""),
		fsSample(observed, 0o1, 1, 2049, "/etc/shadow", ""),
	)
	net := sink.byKind(record.KindNet)
	if len(net) != 1 || net[0].Verdict != record.VerdictRefused || net[0].Reason != record.ReasonNetNotAllowed {
		t.Fatalf("net event %+v", net)
	}
	if net[0].Rule != RuleUnmatched {
		t.Errorf("an undeclared destination carries rule %q", net[0].Rule)
	}
	fs := sink.byKind(record.KindFS)
	if len(fs) != 2 {
		t.Fatalf("%d fs events", len(fs))
	}
	for _, ev := range fs {
		if ev.Verdict != record.VerdictObserved || ev.Rule != RuleUnmatched {
			t.Errorf("an undeclared write must be observed and unmatched: %+v", ev)
		}
	}
}

// TestRecorderLostCounterBecomesAGap is §7's ring-buffer-full row. The first value is the counter as New
// found it, the run's baseline.
func TestRecorderLostCounterBecomesAGap(t *testing.T) {
	f := newFixture(t)
	lost := &stepLost{values: []uint64{3, 10, 10, 15}}
	r, _ := runRecorder(t, f, Options{FlushInterval: 5 * time.Millisecond, Lost: lost},
		exitSample(sample{Kind: KindExit, PID: 50}, 0, 0))
	if n := gapCount(r.Gaps())[GapRingbufFull]; n < 7 {
		t.Errorf("gap count %d, want at least the first increment of 7: %+v", n, r.Gaps())
	}
	for _, g := range r.Gaps() {
		if g.What != record.GapRecord {
			t.Errorf("gap %+v is not a record gap", g)
		}
	}
}

// TestRecorderLostCounterCountsFromTheRunsStart is the counter's baseline: tego_lost is the build's,
// cumulative since the build was loaded, and already holds the drops of the runs before this one (a run that
// read before it, a dead launcher's orphans). A run that lost nothing reports no ringbuf-full.
func TestRecorderLostCounterCountsFromTheRunsStart(t *testing.T) {
	f := newFixture(t)
	lost := &stepLost{values: []uint64{500}}
	r, _ := runRecorder(t, f, Options{FlushInterval: 5 * time.Millisecond, Lost: lost},
		exitSample(sample{Kind: KindExit, PID: 50}, 0, 0))
	if n := gapCount(r.Gaps())[GapRingbufFull]; n != 0 {
		t.Errorf("ringbuf-full %d for a run that lost nothing: the build's cumulative counter was taken as this run's", n)
	}
}

// TestRecorderMalformedSamplesAreGapsNotCrashes covers the decoder's half of I11.
func TestRecorderMalformedSamplesAreGapsNotCrashes(t *testing.T) {
	f := newFixture(t)
	junk := []byte{1, 2, 3}
	wrongKind := sample{Kind: Kind(99), Size: HeaderSize}.bytes(nil)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, junk, wrongKind,
		execSample(sample{Kind: KindExec, PID: 50}, 1, "a", "/usr/bin/git", []string{"git"}, false))
	if len(sink.byKind(record.KindExec)) != 1 {
		t.Error("a malformed sample stopped the drain")
	}
	if n := gapCount(r.Gaps())[GapMalformedRecord]; n != 2 {
		t.Errorf("malformed gap count %d, want 2: %+v", n, r.Gaps())
	}
}

// TestRecorderTruncationIsRecordedAndCounted is enforce-cgroup-observe.md §6 E4, E19 (a path longer than its 256-byte buffer
// truncates with path_ok clear) and E25 (argv-truncated).
func TestRecorderTruncationIsRecordedAndCounted(t *testing.T) {
	f := newFixture(t)
	long := strings.Repeat("a", PathMax)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		execSample(sample{Kind: KindExec, PID: 50}, 1, "a", long, []string{"a"}, true),
		fsSample(sample{Kind: KindOpen, PID: 50}, 0o1, 1, 2049, long, ""))
	ep := payload[record.ExecPayload](t, sink.byKind(record.KindExec)[0])
	if ep.Path != TruncatedPath {
		t.Errorf("exec path %q, want %q", ep.Path, TruncatedPath)
	}
	fp := payload[record.FSPayload](t, sink.byKind(record.KindFS)[0])
	if fp.Path != TruncatedPath {
		t.Errorf("fs path %q, want %q", fp.Path, TruncatedPath)
	}
	g := gapCount(r.Gaps())
	if g[GapPathTruncated] != 2 || g[GapArgvTruncated] != 1 {
		t.Errorf("gaps %+v", r.Gaps())
	}
}

// TestRecorderTruncatedReadIsNotAnAllowedAggregate is E4 at the aggregation: a read whose path bpf_d_path
// could not fit arrives with the buffer zeroed and path_ok clear, so the file it opened, which may be a
// deny_read file the kernel refused, is unknown. It must be its own event, unmatched and observed, never
// counted into an aggregate, which the ledger stamps allow.
func TestRecorderTruncatedReadIsNotAnAllowedAggregate(t *testing.T) {
	f := newFixture(t)
	long := f.secrets + "/" + strings.Repeat("k", PathMax)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, 2049, "", ""),
		// A buffer bpf_d_path filled whole, with no terminator: its first bytes name the deny_read directory, and
		// what they name is a prefix, not the file.
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 2}, 0, 2, 2049, long, ""))
	fs := sink.byKind(record.KindFS)
	if len(fs) != 2 {
		t.Fatalf("%d fs events, want the two truncated reads individually: %+v", len(fs), fs)
	}
	for _, ev := range fs {
		p := payload[record.FSPayload](t, ev)
		if p.Count != 0 || p.Path != TruncatedPath || ev.Rule != RuleUnmatched || ev.Verdict != record.VerdictObserved {
			t.Errorf("a read whose path the kernel truncated was recorded %s %s path=%q count=%d", ev.Rule, ev.Verdict,
				p.Path, p.Count)
		}
	}
	if n := gapCount(r.Gaps())[GapPathTruncated]; n != 2 {
		t.Errorf("path-truncated %d, want 2: %+v", n, r.Gaps())
	}
}

// TestRecorderTruncatedExecIsNotMatched is E4 for an exec: the 255 bytes the kernel kept are a prefix of the
// path the process exec'd, and Evaluate cleans a prefix of trailing slashes into the entry that pins
// /usr/bin/git. The exec is recorded unmatched and observed.
func TestRecorderTruncatedExecIsNotMatched(t *testing.T) {
	f := newFixture(t)
	long := "/usr/bin/git" + strings.Repeat("/", PathMax)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		execSample(sample{Kind: KindExec, PID: 50, MonoNS: 1}, 900*proc.NanosPerTick, "git", long, []string{"git"}, false))
	execs := sink.byKind(record.KindExec)
	if len(execs) != 1 {
		t.Fatalf("%d exec events", len(execs))
	}
	if ev := execs[0]; ev.Rule != RuleUnmatched || ev.Verdict != record.VerdictObserved {
		t.Errorf("an exec whose path the kernel truncated was stamped %s %s", ev.Rule, ev.Verdict)
	}
}

// TestRecorderUnreadableExecNameIsAGap: an exec whose bprm->filename the kernel could not read arrives with
// no path and reason PATH_UNRESOLVED on an observed record. The recorder matched it as the path "" and emitted
// no gap, so the ledger held an exec with an empty name and nothing said a name was lost. It is recorded as a
// truncated name is (E4): unmatched, observed, path <truncated>, and one gap why=path-truncated.
func TestRecorderUnreadableExecNameIsAGap(t *testing.T) {
	f := newFixture(t)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		execSample(sample{Kind: KindExec, PID: 50, MonoNS: 1, Reason: ReasonPathUnresolved}, 900*proc.NanosPerTick,
			"git", "", []string{"git"}, false))
	execs := sink.byKind(record.KindExec)
	if len(execs) != 1 {
		t.Fatalf("%d exec events", len(execs))
	}
	if ev := execs[0]; ev.Rule != RuleUnmatched || ev.Verdict != record.VerdictObserved {
		t.Errorf("an exec whose name the kernel could not read was stamped %s %s", ev.Rule, ev.Verdict)
	}
	if p := payload[record.ExecPayload](t, execs[0]); p.Path != TruncatedPath {
		t.Errorf("path %q, want %q", p.Path, TruncatedPath)
	}
	if n := gapCount(r.Gaps())[GapPathTruncated]; n != 1 {
		t.Errorf("path-truncated %d, want 1: %+v", n, r.Gaps())
	}
}

// TestRecorderPeriodicFlush is R13's five-second window, shrunk: counts reach the ledger while the
// process is still running.
func TestRecorderPeriodicFlush(t *testing.T) {
	f := newFixture(t)
	ring := newFakeRing(fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, 2049, "/usr/lib/libc.so", ""))
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Stop(); err != nil {
			t.Error(err)
		}
	}()
	waitFor(t, func() bool { return len(sink.byKind(record.KindFS)) == 1 }, "the aggregate was never flushed on the timer")
	p := payload[record.FSPayload](t, sink.byKind(record.KindFS)[0])
	if p.Count != 1 {
		t.Errorf("aggregate %+v", p)
	}
}

// busyRing hands out one sample of this run and then, forever, samples this run does not keep (stamped with
// another slot), each read reporting bytes still behind it: a ring whose producers never let it run dry.
type busyRing struct {
	mu     sync.Mutex
	first  []byte
	other  []byte
	closed chan struct{}
	once   sync.Once
}

func (b *busyRing) ReadInto(rec *ringbuf.Record) error {
	select {
	case <-b.closed:
		return ringbuf.ErrClosed
	default:
	}
	b.mu.Lock()
	s := b.other
	if b.first != nil {
		s, b.first = b.first, nil
	}
	b.mu.Unlock()
	time.Sleep(10 * time.Microsecond)
	rec.RawSample = append(rec.RawSample[:0], s...)
	rec.Remaining = 4096
	return nil
}
func (b *busyRing) SetDeadline(time.Time) {}
func (b *busyRing) Close() error          { b.once.Do(func() { close(b.closed) }); return nil }

// TestRecorderPeriodicFlushUnderANeverEmptyRing is R13's window and the lost poll on a ring that never runs
// dry: both ran only when a read found the ring empty, which another run's producers can keep from ever
// happening, so a live process's counts and the kernel's drops waited for its exit or for Stop.
func TestRecorderPeriodicFlushUnderANeverEmptyRing(t *testing.T) {
	f := newFixture(t)
	ring := &busyRing{
		first:  fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 5000, CgroupID: 41, RunIdx: 3}, 0, 1, 2049, "/usr/lib/libc.so", ""),
		other:  fsSample(sample{Kind: KindOpen, PID: 60, MonoNS: 1, CgroupID: 99, RunIdx: 9}, 0, 1, 2049, "/usr/lib/libc.so", ""),
		closed: make(chan struct{}),
	}
	lost := &stepLost{values: []uint64{0, 9}}
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: 20 * time.Millisecond,
		RunSet: &fakeRunSet{rows: map[uint64]uint32{41: 3}}, Lost: lost, namespaceCheck: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Stop() }()
	waitFor(t, func() bool { return len(sink.byKind(record.KindFS)) == 1 && gapCount(r.Gaps())[GapRingbufFull] == 9 },
		"no aggregate flushed and no lost poll within 100 flush intervals while the ring stayed busy")
}

// TestRecorderStopsOnContextCancel covers the goroutine's ownership: cancelling the run's context
// ends the drain without Stop being called first.
func TestRecorderStopsOnContextCancel(t *testing.T) {
	f := newFixture(t)
	ring := newFakeRing()
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx, source.RunRef{ID: "r-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- r.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the drain goroutine outlived its context")
	}
	if err := r.Stop(); err != nil {
		t.Errorf("Stop is not idempotent: %v", err)
	}
}

// TestRecorderReadErrorIsFatal: any error other than a clean close reaches the run.
func TestRecorderReadErrorIsFatal(t *testing.T) {
	f := newFixture(t)
	boom := errors.New("ring buffer went away")
	ring := newFakeRing()
	ring.readErr = boom
	var onErr error
	var once sync.Once
	done := make(chan struct{})
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour,
		OnError: func(e error) { onErr = e; once.Do(func() { close(done) }) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnError was never called")
	}
	if !errors.Is(onErr, boom) {
		t.Errorf("OnError got %v", onErr)
	}
	if err := r.Stop(); !errors.Is(err, boom) {
		t.Errorf("Stop = %v, want the fatal read error", err)
	}
	// Nothing the run did after the drain ended is recorded, which the run's ledger must say: the error alone
	// reached a log line at shutdown.
	if n := gapCount(r.Gaps())[GapReadFailed]; n != 1 {
		t.Errorf("gaps %+v, want %s once", r.Gaps(), GapReadFailed)
	}
}

func TestNewRequiresAReaderAndStartRequiresASink(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrNoReader) {
		t.Errorf("New with no reader = %v", err)
	}
	r, err := New(Options{Reader: newFakeRing()})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r"}, nil); err == nil {
		t.Error("Start with a nil sink must fail")
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r", Agent: "a"}, &fakeSink{}); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("a second Start = %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Error(err)
	}
	if r.Name() != Name {
		t.Errorf("Name = %q", r.Name())
	}
}

func TestStopBeforeStart(t *testing.T) {
	r, err := New(Options{Reader: newFakeRing()})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Errorf("Stop before Start = %v", err)
	}
	if len(r.Gaps()) != 0 {
		t.Errorf("gaps before a run: %+v", r.Gaps())
	}
}

func TestIsWriteMatchesTheSeccompMask(t *testing.T) {
	cases := []struct {
		flags uint32
		want  bool
	}{
		{0, false},                    // O_RDONLY
		{1, true},                     // O_WRONLY
		{2, true},                     // O_RDWR
		{0o100, true},                 // O_CREAT
		{0o1000, true},                // O_TRUNC
		{0o2000000 | 0o400000, false}, // O_CLOEXEC|O_DIRECTORY, still a read
	}
	for _, tc := range cases {
		if got := isWrite(tc.flags); got != tc.want {
			t.Errorf("isWrite(%#o) = %v, want %v", tc.flags, got, tc.want)
		}
	}
}

// stepLost returns a new value on each call, the last one forever.
type stepLost struct {
	mu     sync.Mutex
	values []uint64
}

func (s *stepLost) Lost() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.values[0]
	if len(s.values) > 1 {
		s.values = s.values[1:]
	}
	return v, nil
}

func gapCount(gaps []source.Gap) map[string]int64 {
	m := map[string]int64{}
	for _, g := range gaps {
		m[g.Why] = g.Count
	}
	return m
}

// addr4 renders an IPv4 address into the 16-byte wire field, which holds v4 in its first four bytes.
func addr4(a, b, c, d byte) [16]byte {
	var out [16]byte
	out[0], out[1], out[2], out[3] = a, b, c, d
	return out
}

// parseAddrs is netip.MustParseAddr over a list, for rule fixtures.
func parseAddrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// TestStopIsSafeConcurrently: two callers racing to stop a run must not both flush the aggregation
// table, and both must see the same answer.
func TestStopIsSafeConcurrently(t *testing.T) {
	f := newFixture(t)
	ring := newFakeRing(fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, 2049, "/usr/lib/libc.so", ""))
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		ring.mu.Lock()
		defer ring.mu.Unlock()
		return len(ring.samples) == 0
	}, "the sample was never drained")

	const callers = 8
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() { errs <- r.Stop() }()
	}
	for i := 0; i < callers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}
	if n := len(sink.byKind(record.KindFS)); n != 1 {
		t.Fatalf("%d fs events after %d concurrent Stops, want exactly one aggregate", n, callers)
	}
}

// TestStopRacingStartNeverSeesAHalfPublishedRun pins Stop's documented "safe to call twice,
// concurrently" contract at the one moment it is hardest to hold: while Start is still publishing
// the run's state. Stop reads started and done under r.mu and then blocks on `<-done`, so a started
// it can see without that channel is a permanent hang with no wake-up — the drain goroutine closes
// the channel Start assigned, not the nil one Stop captured — and the same half-published window
// would hand Stop's final R13 flush a nil aggregation table. The observer below reads those fields
// under the lock Stop reads them with, so it fails on the torn publish itself rather than waiting
// for a lucky hang. The rounds exist because catching a torn publish still needs the two goroutines
// to interleave inside it: 3000 of them caught the original defect on every attempt, and a -race
// build reports the unsynchronised write against Stop's locked read with no interleaving at all.
func TestStopRacingStartNeverSeesAHalfPublishedRun(t *testing.T) {
	f := newFixture(t)
	const rounds = 3000
	for i := 0; i < rounds; i++ {
		r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), Proc: f.procFS, FlushInterval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		var startReturned, torn atomic.Bool
		watching := make(chan struct{})
		go func() {
			defer close(watching)
			for !startReturned.Load() {
				r.mu.Lock()
				bad := r.started && (r.startDone == nil || r.done == nil || r.procs == nil || r.agg == nil)
				r.mu.Unlock()
				if bad {
					torn.Store(true)
					return
				}
			}
		}()
		stopped := make(chan error, 1)
		gate := make(chan struct{})
		go func() {
			<-gate
			stopped <- r.Stop()
		}()
		close(gate)
		startErr := r.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, &fakeSink{})
		startReturned.Store(true)
		<-watching
		// Stop may win the initial lock and release the reader before Start owns any state.
		// That ordering must refuse Start rather than restart on the closed reader.
		if startErr != nil && !errors.Is(startErr, ErrStopped) {
			t.Fatalf("round %d: Start: %v", i, startErr)
		}
		if torn.Load() {
			t.Fatalf("round %d: Stop's own view showed a started recorder whose run state was not published yet: a nil done blocks Stop forever, a nil agg panics its final flush", i)
		}
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatalf("round %d: Stop racing Start: %v", i, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("round %d: Stop racing Start never returned", i)
		}
		if err := r.Stop(); err != nil {
			t.Fatalf("round %d: second Stop: %v", i, err)
		}
	}
}

// nullSink discards events, so a benchmark measures the recorder and not the ledger.
type nullSink struct{ n int }

func (s *nullSink) Emit(*record.Event) { s.n++ }

// BenchmarkDrain measures the whole per-sample path — decode, process-cache lookup, rule stamping,
// aggregation and payload marshal — against the mix a real run produces: mostly reads, some execs
// and connects (docs/P0-DESIGN.md §9's ring-buffer drain budget).
func BenchmarkDrain(b *testing.B) {
	dir := b.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		b.Fatal(err)
	}
	procRoot := b.TempDir()
	writeProcForBench(b, procRoot, 50, 900)
	rules := &agent.RuleTable{FS: []agent.FSRule{
		{Path: dir, Kind: agent.FSImplicit},
		{Path: out, Kind: agent.FSWrite, Raw: "./out"},
	}}
	r, err := New(Options{Rules: rules, Reader: newFakeRing(), Proc: proc.NewAt(procRoot), FlushInterval: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	sink := &nullSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-bench", Agent: "a"}, sink); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = r.Stop() })

	h := sample{PID: 50, TID: 50, MonoNS: 1}
	mix := [][]byte{
		fsSample(func() sample { s := h; s.Kind = KindOpen; return s }(), 0, 1, 2049, "/usr/lib/python3.12/os.py", ""),
		fsSample(func() sample { s := h; s.Kind = KindOpen; return s }(), 0, 2, 2049, "/usr/lib/python3.12/io.py", ""),
		fsSample(func() sample { s := h; s.Kind = KindOpen; return s }(), 0o1, 3, 2049, filepath.Join(out, "report.md"), ""),
		netSample(func() sample { s := h; s.Kind = KindConnect; return s }(), 2, 6, 443, addr4(93, 184, 216, 34)),
		execSample(func() sample { s := h; s.Kind = KindExec; return s }(), 900*proc.NanosPerTick, "python3",
			"/usr/bin/python3.12", []string{"python3", "-m", "pytest"}, false),
	}
	// Each sample comes off a ring that copies it out the way *ringbuf.Reader does, so the read's own cost is
	// in the figure. ReadInto is what drain does: one Record for every read. Read is what it did before,
	// and what (*ringbuf.Reader).Read still does: a fresh Record, and so a fresh array, per sample.
	for _, mode := range []struct {
		name  string
		fresh bool
	}{{"ReadInto", false}, {"Read", true}} {
		b.Run(mode.name, func(b *testing.B) {
			var (
				rec    Record
				sample ringbuf.Record
			)
			i := 0
			next := func() (ringbuf.Record, error) {
				s := mix[i%len(mix)]
				i++
				return ringbuf.Record{RawSample: s}, nil
			}
			b.ReportAllocs()
			for b.Loop() {
				if mode.fresh {
					sample = ringbuf.Record{}
				}
				if err := readInto(&sample, next); err != nil {
					b.Fatal(err)
				}
				if err := DecodeInto(&rec, sample.RawSample); err != nil {
					b.Fatal(err)
				}
				r.handle(&rec)
			}
		})
	}
}

// writeProcForBench is writeProc for a *testing.B; the test helper takes a *testing.T.
func writeProcForBench(b *testing.B, root string, pid int, startTicks uint64) {
	b.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	tail := []string{"S", "1"}
	for len(tail) < 17 {
		tail = append(tail, "0")
	}
	tail = append(tail, "1", "0", strconv.FormatUint(startTicks, 10))
	line := strconv.Itoa(pid) + " (python3) " + strings.Join(tail, " ") + "\n"
	for name, body := range map[string]string{
		"stat": line, "cmdline": "python3\x00app.py\x00", "cgroup": "0::/tego/run\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			b.Fatal(err)
		}
	}
}

// TestRecordOffEmitsNothingButStillBoundsTheCache is E23: enforcement does not depend on recording,
// so the drain and the lost-counter mechanism stay wired while every handler becomes a near-no-op —
// but sched_process_exit must still evict, or a long run's cache would grow forever.
func TestRecordOffEmitsNothingButStillBoundsTheCache(t *testing.T) {
	f := newFixture(t)
	f.rules.Record = agent.RecordOff
	h := sample{PID: 50, TID: 50, MonoNS: 1}
	lost := &stepLost{values: []uint64{1, 5}} // the baseline New reads, then four drops of this run
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, Lost: lost},
		execSample(func() sample { s := h; s.Kind = KindExec; return s }(), 900*proc.NanosPerTick, "python3",
			"/usr/bin/git", []string{"git"}, false),
		fsSample(func() sample { s := h; s.Kind = KindOpen; return s }(), 0, 1, 2049, "/usr/lib/libc.so", ""),
		netSample(func() sample { s := h; s.Kind = KindConnect; return s }(), 2, 6, 443, addr4(93, 184, 216, 34)),
		exitSample(func() sample { s := h; s.Kind = KindExit; return s }(), 0, 0),
	)
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("record: off emitted %d events: %+v", len(got), got)
	}
	if r.procs.len() != 0 {
		t.Errorf("the exit sample did not evict the process: %d cached", r.procs.len())
	}
	if gapCount(r.Gaps())[GapRingbufFull] != 4 {
		t.Errorf("the lost counter is not accounted under record: off: %+v", r.Gaps())
	}
}

// TestRecordOffReportsActivity covers the kernel half: under record: off the recorder keeps no line for an
// allowed exec, open or connect, so the budget watcher saw a busy tier-2 agent as idle and killed it for
// stalling. Every sample of the run is reported as activity instead.
func TestRecordOffReportsActivity(t *testing.T) {
	f := newFixture(t)
	f.rules.Record = agent.RecordOff
	var mu sync.Mutex
	var seen []uint64
	activity := func(mono uint64) {
		mu.Lock()
		seen = append(seen, mono)
		mu.Unlock()
	}
	h := sample{PID: 50, TID: 50}
	at := func(kind Kind, mono uint64) sample { s := h; s.Kind, s.MonoNS = kind, mono; return s }
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, Activity: activity},
		fsSample(at(KindOpen, 10), 0, 1, 2049, "/usr/lib/libc.so", ""),
		netSample(at(KindConnect, 20), 2, 6, 443, addr4(93, 184, 216, 34)),
	)
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("record: off emitted %d events", len(got))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != 10 || seen[1] != 20 {
		t.Fatalf("activity %v, want the two samples' mono_ns", seen)
	}
}

// TestAggregationSurvivesASlowProducer is the cadence rule: with a producer slow enough that every
// read finds the ring already empty, the reads must still land in one aggregate. Flushing on the
// "ring ran dry" signal alone would give each read its own event and defeat R13.
func TestAggregationSurvivesASlowProducer(t *testing.T) {
	f := newFixture(t)
	var samples [][]byte
	for i := 0; i < 50; i++ {
		samples = append(samples, fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: uint64(i)}, 0, uint32(i), 2049,
			"/usr/lib/python3.12/os.py", ""))
	}
	// Every read reports an empty ring behind it, the shape a trickling producer gives.
	ring := &drySpacedRing{fakeRing: newFakeRing(samples...)}
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		ring.mu.Lock()
		defer ring.mu.Unlock()
		return len(ring.samples) == 0
	}, "the samples were never drained")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	fs := sink.byKind(record.KindFS)
	if len(fs) != 1 {
		t.Fatalf("%d fs events, want one aggregate of 50 reads", len(fs))
	}
	if p := payload[record.FSPayload](t, fs[0]); p.Count != 50 {
		t.Errorf("aggregate count %d", p.Count)
	}
}

// drySpacedRing is a fakeRing whose every read reports nothing left behind it.
type drySpacedRing struct{ *fakeRing }

func (d *drySpacedRing) ReadInto(rec *ringbuf.Record) error {
	return readInto(rec, func() (ringbuf.Record, error) {
		got, err := d.next()
		got.Remaining = 0
		return got, err
	})
}

// TestRecorderAggregateOverflowFlushesEarlyAndResets is R13's bound on the aggregation table: a run
// that touches more distinct (exec id, rule) buckets than AggregateLimit must flush everything open
// right away rather than let the table grow past its cap, and the flush must actually reset the
// table rather than merely mark it full. The proof is what happens to reads of the same rule that
// keep arriving afterward: if the table were reset, they start a fresh bucket (two separate counts
// reach the ledger); if the "full" signal were ever ignored, they would silently merge into the
// bucket that was already over the cap (one inflated count, and no gap accounted for what happened).
func TestRecorderAggregateOverflowFlushesEarlyAndResets(t *testing.T) {
	f := newFixture(t)
	addSyntheticParentIndex(f)
	implicitRule := (agent.FSRule{Path: f.dir, Kind: agent.FSImplicit}).RuleName()

	var samples [][]byte
	// Two distinct buckets against a table capped at 2: adding the second must report the table
	// full and force an immediate flush of both, well before any exit or periodic tick.
	samples = append(samples,
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, 2049, filepath.Join(f.out, "report.md"), ""),
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 2}, 0, 2, 2049, filepath.Join(f.dir, "readme.txt"), ""))
	// Three more reads of the first bucket's rule, arriving after the forced flush.
	for i := 0; i < 3; i++ {
		samples = append(samples, fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: uint64(10 + i)}, 0, uint32(10+i), 2049,
			filepath.Join(f.out, "report.md"), ""))
	}
	samples = append(samples, exitSample(sample{Kind: KindExit, PID: 50, MonoNS: 100}, 0, 0))

	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, AggregateLimit: 2}, samples...)

	fs := sink.byKind(record.KindFS)
	if len(fs) != 3 {
		t.Fatalf("%d fs events, want 3 (2 from the forced flush, 1 from exit): %+v", len(fs), fs)
	}
	writeCounts := map[int]bool{}
	implicitCount := -1
	nWrite := 0
	for _, ev := range fs {
		p := payload[record.FSPayload](t, ev)
		switch ev.Rule {
		case "fs.write[./out]":
			writeCounts[p.Count] = true
			nWrite++
		case implicitRule:
			implicitCount = p.Count
		default:
			t.Errorf("unexpected rule %q in %+v", ev.Rule, p)
		}
	}
	if implicitCount != 1 {
		t.Errorf("implicit-rule bucket count = %d, want 1 (flushed once, by itself)", implicitCount)
	}
	if nWrite != 2 || !writeCounts[1] || !writeCounts[3] {
		t.Errorf("fs.write[./out] bucket counts = %v (n=%d), want two buckets of {1, 3}: the overflow flush "+
			"must reset the table instead of letting later reads merge into the pre-overflow bucket", writeCounts, nWrite)
	}
	if n := gapCount(r.Gaps())[GapAggregateOverflow]; n != 1 {
		t.Errorf("GapAggregateOverflow = %d, want 1", n)
	}
}

// TestRecorderNeverAggregatesAKernelRefusedRead pins R13's third exception. Watched files and deny_read files
// are the two *named* exceptions R13 lists, but a read the kernel itself marked refused must never be folded
// into a bucket either, because emitAggregates always stamps a flushed bucket VerdictAllow. On an fs record the
// one kernel refusal on the header is the decision plane's, stamped by the fexit that read it (TIER3-PLAN T9):
// a path no declared entry names, which matchFS answers neither Watched nor DenyRead, is still its own refused
// line, named as the plane named it.
func TestRecorderNeverAggregatesAKernelRefusedRead(t *testing.T) {
	f := newFixture(t)
	refused := sample{Kind: KindOpen, PID: 50, MonoNS: 1, Verdict: KernelRefused, Reason: uint8(bpf.ReasonReadDenied),
		RuleIdx: bpf.PlaneRuleNone}
	// A path with no declared entry at all, so matchFS can answer neither Watched nor DenyRead: the
	// only thing that can be keeping this read out of the aggregate table is the kernel's own
	// explicit refusal on the header.
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		fsSample(refused, 0, 1, 2049, "/etc/shadow", ""))

	fs := sink.byKind(record.KindFS)
	if len(fs) != 1 {
		t.Fatalf("%d fs events, want the refused read recorded on its own: %+v", len(fs), fs)
	}
	if fs[0].Verdict != record.VerdictRefused || fs[0].Reason != record.ReasonReadDenied {
		t.Errorf("refused read event = verdict %s reason %s, want refused/%s", fs[0].Verdict, fs[0].Reason, record.ReasonReadDenied)
	}
	if p := payload[record.FSPayload](t, fs[0]); p.Count != 0 || p.Mechanism != record.MechanismPlane {
		t.Errorf("a refused read must never carry an aggregate Count, and is the plane's: got %+v", p)
	}
}

// TestRecorderAggregatePathIsTheDeclaredRulePath pins the aggregate payload's Path field (agg.go:
// "the matched rule's path, or the first path seen when nothing matched"). Two different files read
// under one write entry must still report the entry's own directory in the ledger, not whichever of
// the two files the recorder happened to see first — the count already tells the reader how many
// reads happened, and the path is what names the rule that covered them, not an arbitrary sample.
func TestRecorderAggregatePathIsTheDeclaredRulePath(t *testing.T) {
	f := newFixture(t)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 1}, 0, 1, 2049, filepath.Join(f.out, "first.txt"), ""),
		fsSample(sample{Kind: KindOpen, PID: 50, MonoNS: 2}, 0, 2, 2049, filepath.Join(f.out, "second.txt"), ""),
		exitSample(sample{Kind: KindExit, PID: 50, MonoNS: 3}, 0, 0))

	fs := sink.byKind(record.KindFS)
	if len(fs) != 1 {
		t.Fatalf("%d fs events, want one aggregate covering both files: %+v", len(fs), fs)
	}
	p := payload[record.FSPayload](t, fs[0])
	if p.Count != 2 {
		t.Fatalf("count %d, want 2", p.Count)
	}
	if p.Path != f.out {
		t.Errorf("aggregate path %q, want the declared entry's own path %q, not one of the files it covers", p.Path, f.out)
	}
}

// fentry/security_path_unlink fires before Landlock decides. At tier 2 the inherited ruleset refuses an
// unlink of a write entry itself (REMOVE_FILE on the parent), but the recorder infers from FSDecider, the
// tier-3 nearest-wins chooser, and records allow.
func TestRecorderUnlinkOfWriteEntryItself(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/work/out.txt", Raw: "/work/out.txt", Access: agent.AccessWriteSet},
	}}
	ri := newRuleIndexAt(rt, "/nonexistent")
	m := ri.matchFS("/work/out.txt")
	v, _ := ri.inferFS(record.FSUnlink, true, m)
	ev := rt.Evaluate(agent.Action{Kind: agent.ActionFSDelete, Path: "/work/out.txt"}, backend.TierCgroup)
	if string(v) != string(ev.Verdict) {
		t.Errorf("unlink /work/out.txt at tier 2: recorder infers %s, compile --test %+v", v, ev)
	}
}

// TestRecorderAnExecNameWithDotDotIsUnresolved: the kernel resolves "link/../tool" physically, following link
// first, and a lexical join or clean named another file. With link -> /usr/local/bin the exec ran
// /usr/local/tool and was recorded as <cwd>/tool under that path's entry. A name holding a ".." component,
// relative or absolute, names no file the recorder can vouch for: it is recorded as passed, unmatched and observed.
func TestRecorderAnExecNameWithDotDotIsUnresolved(t *testing.T) {
	f := newFixture(t)
	work := t.TempDir()
	if err := os.Symlink(work, filepath.Join(f.procFS.Root(), "50", "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	f.rules.Tier = backend.TierCgroup
	tool := filepath.Join(work, "tool")
	f.rules.Exec = []agent.ExecRule{{Raw: tool, Path: tool, Basename: "tool", Verdict: agent.VerdictAllow}}
	di, ok := statDevIno(work)
	if !ok {
		t.Fatal("stat the working directory")
	}
	here := sample{Kind: KindExec, PID: 50, PPID: 1, CwdDev: di.Dev, CwdIno: di.Ino}
	abs := filepath.Join(work, "link") + "/../tool"
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		execSample(here, 900*proc.NanosPerTick, "tool", "link/../tool", []string{"link/../tool"}, false),
		execSample(here, 900*proc.NanosPerTick, "tool", abs, []string{abs}, false))
	execs := sink.byKind(record.KindExec)
	if len(execs) != 2 {
		t.Fatalf("%d exec events", len(execs))
	}
	for i, want := range []string{"link/../tool", abs} {
		ev := execs[i]
		p := payload[record.ExecPayload](t, ev)
		if p.Path != want || ev.Rule != RuleUnmatched || ev.Verdict != record.VerdictObserved {
			t.Errorf("exec %d recorded path=%s %s %s, want path=%s unmatched observed", i, p.Path, ev.Rule, ev.Verdict, want)
		}
	}
	if n := gapCount(r.Gaps())[GapExecUnresolved]; n != 2 {
		t.Errorf("exec-unresolved %d, want 2: %+v", n, r.Gaps())
	}
}

// TestRecorderResolvesARelativeExecOfAnExitedProcess: a process that exec'd a relative name and exited before the
// recorder read its record (a quick tool: ADR 0017's exec cells, a multi-call link running `noop`) has no
// /proc/<pid>/cwd left. Its parent's working directory, when it is the very directory the kernel saw at the exec
// (the same dev and inode), names it; one that is not leaves the exec unresolved, as before.
func TestRecorderResolvesARelativeExecOfAnExitedProcess(t *testing.T) {
	f := newFixture(t)
	work, other := t.TempDir(), t.TempDir()
	if err := os.Symlink(work, filepath.Join(f.procFS.Root(), "50", "cwd")); err != nil {
		t.Fatal(err)
	}
	f.rules.Tier = backend.TierCgroup
	f.rules.Exec = []agent.ExecRule{{Raw: "./tool", Path: filepath.Join(work, "tool"), Basename: "tool", Verdict: agent.VerdictAllow}}
	di, ok := statDevIno(work)
	oi, ok2 := statDevIno(other)
	if !ok || !ok2 {
		t.Fatal("stat the working directories")
	}
	gone := sample{Kind: KindExec, PID: 51, PPID: 50, CwdDev: di.Dev, CwdIno: di.Ino}
	elsewhere := sample{Kind: KindExec, PID: 52, PPID: 50, CwdDev: oi.Dev, CwdIno: oi.Ino}
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		execSample(gone, 900*proc.NanosPerTick, "tool", "./tool", []string{"./tool"}, false),
		execSample(elsewhere, 900*proc.NanosPerTick, "tool", "./tool", []string{"./tool"}, false))
	execs := sink.byKind(record.KindExec)
	if len(execs) != 2 {
		t.Fatalf("%d exec events", len(execs))
	}
	if p := payload[record.ExecPayload](t, execs[0]); p.Path != filepath.Join(work, "tool") || execs[0].Rule != "exec[./tool]" {
		t.Errorf("an exited process's relative exec recorded path=%s %s, want %s under exec[./tool]", p.Path, execs[0].Rule,
			filepath.Join(work, "tool"))
	}
	if p := payload[record.ExecPayload](t, execs[1]); p.Path != "./tool" || execs[1].Rule != RuleUnmatched {
		t.Errorf("an exec in a directory the parent is not in recorded path=%s %s, want it unresolved", p.Path, execs[1].Rule)
	}
	if n := gapCount(r.Gaps())[GapExecUnresolved]; n != 1 {
		t.Errorf("exec-unresolved %d, want 1: %+v", n, r.Gaps())
	}
}
