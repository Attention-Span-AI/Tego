// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// followed is what one Follower pass delivered and how it ended.
type followed struct {
	lines   []string
	cursors []Cursor
	err     error
}

// followAll runs fl.Lines to its end under a deadline and returns what it delivered.
func followAll(t *testing.T, fl *Follower, d time.Duration) followed {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var out followed
	for en, err := range fl.Lines(ctx) {
		if err != nil {
			out.err = err
			break
		}
		out.lines = append(out.lines, string(en.Line))
		out.cursors = append(out.cursors, en.Cursor)
	}
	return out
}

// startFollow runs a Follower over dir from c on a goroutine; the result arrives on the channel.
func startFollow(t *testing.T, dir string, c Cursor, d time.Duration) (*Follower, <-chan followed) {
	t.Helper()
	fl, err := Follow(dir, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fl.Close() })
	ch := make(chan followed, 1)
	go func() { ch <- followAll(t, fl, d) }()
	return fl, ch
}

// storedLines is every complete line of dir's ledger, as Reader.Lines yields them.
func storedLines(t *testing.T, dir string) []string {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var out []string
	for l, err := range r.Lines() {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(l))
	}
	return out
}

// appendRaw appends b to dir's events.jsonl behind the Writer's back.
func appendRaw(t *testing.T, dir string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

// nextLine is the line w would append next for e, made without w: seq, prev and the run's fields set as Append
// sets them.
func nextLine(t *testing.T, w *Writer, e *record.Event) []byte {
	t.Helper()
	e.V, e.Run, e.Agent, e.Seq, e.Prev, e.TS = record.Version, w.ref.ID, w.ref.Agent, w.Seq(), w.Head(), fixedStart
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func equalLines(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("delivered %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d:\n got %s\nwant %s", i+1, got[i], want[i])
		}
	}
}

// TestFollowerYieldsEachLineOnceInOrder: over an ended run the Follower delivers every stored line once, in
// order, byte for byte, each with a cursor naming it, and ends cleanly.
func TestFollowerYieldsEachLineOnceInOrder(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 5)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 10*time.Second)
	if got.err != nil {
		t.Fatalf("follow of an ended run: %v", got.err)
	}
	equalLines(t, got.lines, storedLines(t, dir))
	off := int64(0)
	for i, c := range got.cursors {
		id, err := record.VerifyLine([]byte(got.lines[i]))
		if err != nil {
			t.Fatal(err)
		}
		if c != (Cursor{Offset: off, Seq: uint64(i), ID: id}) {
			t.Fatalf("cursor %d = %+v, want offset %d seq %d id %s", i, c, off, i, id)
		}
		off += int64(len(got.lines[i])) + 1
	}
}

// TestFollowerLiveWriter follows a run while its Writer appends from another goroutine, the race detector's
// case: every line arrives exactly once, in order, and the Follower ends at run_end once Close has released the
// lock.
func TestFollowerLiveWriter(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	_, ch := startFollow(t, dir, Cursor{}, 60*time.Second)
	const n = 2000
	for i := 0; i < n; i++ {
		if err := w.Append(gapEvent("live" + strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
		if i%250 == 0 {
			time.Sleep(2 * time.Millisecond) // let the follower catch up and wait, so it is woken mid-run
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("follow: %v", got.err)
	}
	equalLines(t, got.lines, storedLines(t, dir))
	if len(got.lines) != n+2 {
		t.Fatalf("delivered %d lines, want %d", len(got.lines), n+2)
	}
}

// TestFollowDetectsTamperedAppend: a line appended with a prev that names no line breaks the chain; the
// Follower delivers the lines before it, then ErrCorruptLedger naming the line, and nothing more.
func TestFollowDetectsTamperedAppend(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	defer func() { _ = w.Abandon() }()
	startRun(t, w, 2)
	e := gapEvent("forged")
	line := nextLine(t, w, e)
	forged := strings.Replace(string(line), `"prev":"`+w.Head()+`"`, `"prev":"`+strings.Repeat("ef", 32)+`"`, 1)
	if forged == string(line) {
		t.Fatal("the test could not forge prev")
	}
	appendRaw(t, dir, []byte(forged+"\n"))
	appendRaw(t, dir, append(nextLine(t, w, gapEvent("after")), '\n'))
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 10*time.Second)
	if !errors.Is(got.err, ErrCorruptLedger) || !strings.Contains(got.err.Error(), "corrupt line 4:") {
		t.Fatalf("follow over a forged prev: %v, want ErrCorruptLedger naming line 4", got.err)
	}
	if len(got.lines) != 3 {
		t.Fatalf("delivered %d lines before the break, want 3", len(got.lines))
	}
}

// TestFollowerHoldsUnterminatedLine: half a line under a held lock is not delivered; once the rest arrives the
// whole line is delivered once.
func TestFollowerHoldsUnterminatedLine(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	line := nextLine(t, w, gapEvent("split"))
	appendRaw(t, dir, line[:len(line)/2])
	got := make(chan string, 4)
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		for en, err := range fl.Lines(ctx) {
			if err != nil {
				done <- err
				return
			}
			got <- string(en.Line)
		}
		done <- nil
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("the two complete lines were not delivered")
		}
	}
	select {
	case l := <-got:
		t.Fatalf("half a line was delivered: %q", l)
	case <-time.After(300 * time.Millisecond):
	}
	appendRaw(t, dir, append(line[len(line)/2:], '\n'))
	select {
	case l := <-got:
		if l != string(line) {
			t.Fatalf("the completed line: %q, want %q", l, line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the completed line was not delivered")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	_ = w.Abandon()
}

// TestFollowerTornTailOfALostRun: a torn last line and a free lock is a run that will write no more: ErrRunLost,
// the torn bytes never delivered.
func TestFollowerTornTailOfALostRun(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	tearTail(t, w)
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 10*time.Second)
	if !errors.Is(got.err, ErrRunLost) || len(got.lines) != 2 {
		t.Fatalf("follow of a lost run with a torn tail: %d lines, %v; want 2 lines and ErrRunLost", len(got.lines),
			got.err)
	}
}

// TestFollowerWholeUnterminatedLastLine: a last line that lost only its "\n" (E8) is a line once the lock is
// free, as Reader.Lines reads it; a run_end so written ends the follow cleanly.
func TestFollowerWholeUnterminatedLastLine(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, EventsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, int64(len(b)-1)); err != nil {
		t.Fatal(err)
	}
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 10*time.Second)
	if got.err != nil || len(got.lines) != 3 {
		t.Fatalf("follow: %d lines, %v; want 3 lines and a clean end", len(got.lines), got.err)
	}
	equalLines(t, got.lines, storedLines(t, dir))
}

// TestFollowerEndsAfterRunEndOnceLockFree: after run_end the Follower waits while the lock is held (a launcher
// still inside Close, anchoring) and ends once it is released.
func TestFollowerEndsAfterRunEndOnceLockFree(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, LockFile), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	_, ch := startFollow(t, dir, Cursor{}, 20*time.Second)
	select {
	case got := <-ch:
		t.Fatalf("the follow ended while the lock was held: %d lines, %v", len(got.lines), got.err)
	case <-time.After(400 * time.Millisecond):
	}
	start := time.Now()
	_ = lock.Close() // releases the flock and raises IN_CLOSE_WRITE
	got := <-ch
	if got.err != nil || len(got.lines) != 3 {
		t.Fatalf("follow: %d lines, %v; want 3 and a clean end", len(got.lines), got.err)
	}
	if d := time.Since(start); d > 900*time.Millisecond && !raceEnabled {
		t.Errorf("the end took %v after the lock was released; inotify should wake it at once", d)
	}
}

// TestFollowerLineAfterRunEnd: a line after run_end is no Writer's; the follow ends with ErrCorruptLedger.
func TestFollowerLineAfterRunEnd(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	appendRaw(t, dir, []byte("garbage\n"))
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 10*time.Second)
	if !errors.Is(got.err, ErrCorruptLedger) || !strings.Contains(got.err.Error(), "follows run_end") {
		t.Fatalf("a line after run_end: %v", got.err)
	}
	// Torn bytes after run_end are not a record either.
	w2, dir2, _ := openTestWriter(t)
	startRun(t, w2, 1)
	if err := w2.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	appendRaw(t, dir2, []byte{0, 0, 0})
	fl2, err := Follow(dir2, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl2.Close() }()
	got = followAll(t, fl2, 10*time.Second)
	if !errors.Is(got.err, ErrCorruptLedger) || !strings.Contains(got.err.Error(), "after run_end") {
		t.Fatalf("NUL bytes after run_end: %v", got.err)
	}
}

// TestFollowerLineTooLong: a line past MaxLineBytes is ErrCorruptLedger, and the buffer never grew past the
// bound reading it.
func TestFollowerLineTooLong(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	defer func() { _ = w.Abandon() }()
	startRun(t, w, 1)
	appendRaw(t, dir, append([]byte(`{"v":1,"x":"`), make([]byte, MaxLineBytes+10)...))
	appendRaw(t, dir, []byte("\n"))
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 10*time.Second)
	if !errors.Is(got.err, ErrCorruptLedger) || !strings.Contains(got.err.Error(), "longer than") {
		t.Fatalf("a line past the bound: %v", got.err)
	}
	if fl.maxBuf > MaxLineBytes {
		t.Fatalf("the buffer grew to %d bytes, past MaxLineBytes %d", fl.maxBuf, MaxLineBytes)
	}
}

// TestFollowerWakesOnInotify: with the poll backstop pushed out to a minute, a new line still arrives at once:
// inotify woke the Follower.
func TestFollowerWakesOnInotify(t *testing.T) {
	defer func(d time.Duration) { pollInterval = d }(pollInterval)
	pollInterval = time.Minute
	w, dir, _ := openTestWriter(t)
	defer func() { _ = w.Abandon() }()
	startRun(t, w, 0)
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	if mode, why := fl.Wake(); mode != WakeInotify {
		t.Skipf("inotify is unavailable here (%v); the poll fallback has its own test", why)
	}
	got := make(chan time.Time, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// The follow ends before the deferred restore of pollInterval, which its wait reads.
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		for _, err := range fl.Lines(ctx) {
			if err != nil {
				return
			}
			got <- time.Now()
		}
	}()
	<-got // run_start
	time.Sleep(100 * time.Millisecond)
	sent := time.Now()
	if err := w.Append(gapEvent("wake")); err != nil {
		t.Fatal(err)
	}
	select {
	case at := <-got:
		if d := at.Sub(sent); d > 500*time.Millisecond {
			t.Errorf("the line arrived %v after it was written", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("inotify did not wake the follower")
	}
}

// TestFollowerPollFallback: without inotify (EMFILE: fs.inotify.max_user_instances spent) the Follower says it
// polls and still delivers every line, within the poll interval.
func TestFollowerPollFallback(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EMFILE, unix.ENOSPC} {
		t.Run(errno.Error(), func(t *testing.T) {
			defer func(f func() (*sys.FD, error)) { newInotify = f }(newInotify)
			newInotify = func() (*sys.FD, error) { return nil, errno }
			w, dir, _ := openTestWriter(t)
			startRun(t, w, 1)
			fl, ch := startFollow(t, dir, Cursor{}, 20*time.Second)
			if mode, why := fl.Wake(); mode != WakePoll || !errors.Is(why, errno) {
				t.Fatalf("Wake = %s, %v; want poll and %v", mode, why, errno)
			}
			time.Sleep(50 * time.Millisecond)
			if err := w.Append(gapEvent("polled")); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			got := <-ch
			if got.err != nil {
				t.Fatal(got.err)
			}
			equalLines(t, got.lines, storedLines(t, dir))
		})
	}
}

// TestFollowerWatchENOSPCDegradesToPoll: an instance whose watch cannot be added (ENOSPC,
// fs.inotify.max_user_watches spent) is dropped and the waker polls.
func TestFollowerWatchENOSPCDegradesToPoll(t *testing.T) {
	w := newWaker()
	defer func() { _ = w.close() }()
	if w.mode != WakeInotify {
		t.Skipf("inotify is unavailable here: %v", w.why)
	}
	// A watch on a path that is not there is reported and changes nothing; the poll backstop covers it.
	if err := w.watch(filepath.Join(t.TempDir(), "absent"), unix.IN_MODIFY); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("watch of an absent path: %v", err)
	}
	if w.mode != WakeInotify {
		t.Fatal("an absent path dropped inotify")
	}
	defer func() { watchRefused = nil }()
	watchRefused = unix.ENOSPC
	if err := w.watch(t.TempDir(), unix.IN_MODIFY); err != nil {
		t.Fatal(err)
	}
	if w.mode != WakePoll || !errors.Is(w.why, unix.ENOSPC) {
		t.Fatalf("a refused watch left the waker at %s (%v)", w.mode, w.why)
	}
	start := time.Now()
	defer func(d time.Duration) { pollInterval = d }(pollInterval)
	pollInterval = 20 * time.Millisecond
	if err := w.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the degraded waker did not poll")
	}
}

// TestFollowerCursorResume: a Follower started from the cursor of the k-th line delivers exactly the lines
// after it, across a live append.
func TestFollowerCursorResume(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 6)
	first, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	var cursors []Cursor
	ctx, cancel := context.WithCancel(context.Background())
	for en, err := range first.Lines(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		cursors = append(cursors, en.Cursor)
		if len(cursors) == 4 {
			break
		}
	}
	cancel()
	_ = first.Close()
	_, ch := startFollow(t, dir, cursors[3], 20*time.Second)
	if err := w.Append(gapEvent("after resume")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatal(got.err)
	}
	equalLines(t, got.lines, storedLines(t, dir)[4:])
}

// TestFollowerCursorMismatch: a cursor whose line is not there, or does not carry its seq and id, is refused
// [cursor-mismatch]; nothing is delivered.
func TestFollowerCursorMismatch(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 3)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	all := followAll(t, fl, 10*time.Second)
	_ = fl.Close()
	if all.err != nil {
		t.Fatal(all.err)
	}
	good := all.cursors[2]
	for name, c := range map[string]Cursor{
		"another id":       {Offset: good.Offset, Seq: good.Seq, ID: all.cursors[1].ID},
		"another seq":      {Offset: good.Offset, Seq: good.Seq + 1, ID: good.ID},
		"inside a line":    {Offset: good.Offset + 3, Seq: good.Seq, ID: good.ID},
		"past the end":     {Offset: 1 << 30, Seq: good.Seq, ID: good.ID},
		"negative offset":  {Offset: -1, Seq: good.Seq, ID: good.ID},
		"malformed id":     {Offset: good.Offset, Seq: good.Seq, ID: "x"},
		"another line's":   {Offset: all.cursors[1].Offset, Seq: good.Seq, ID: good.ID},
		"offset, no id":    {Offset: good.Offset, Seq: good.Seq},
		"an id at offset0": {Offset: 0, Seq: 0, ID: good.ID},
	} {
		fl, err := Follow(dir, c)
		if err != nil {
			t.Fatal(err)
		}
		got := followAll(t, fl, 10*time.Second)
		_ = fl.Close()
		if !errors.Is(got.err, ErrCursorMismatch) || !strings.Contains(got.err.Error(), "[cursor-mismatch]") ||
			len(got.lines) != 0 {
			t.Errorf("%s: %d lines, %v; want ErrCursorMismatch and nothing delivered", name, len(got.lines), got.err)
		}
	}
	// The cursor of run_end resumes to a clean end with nothing more.
	fl, err = Follow(dir, all.cursors[len(all.cursors)-1])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	if got := followAll(t, fl, 10*time.Second); got.err != nil || len(got.lines) != 0 {
		t.Fatalf("resume at run_end: %d lines, %v", len(got.lines), got.err)
	}
}

// writeSynthetic writes a whole run of n gap lines between run_start and run_end straight to dir's
// events.jsonl, with no lock file (a free lock, E27), for the tests that need more lines than a Writer writes
// quickly.
func writeSynthetic(t *testing.T, dir string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	prev := ""
	put := func(e *record.Event, seq uint64) {
		e.V, e.Run, e.Agent, e.Seq, e.Prev, e.TS = record.Version, testRef.ID, testRef.Agent, seq, prev, fixedStart
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		prev = e.ID
		_, _ = bw.Write(line)
		_ = bw.WriteByte('\n')
	}
	start := &record.Event{Kind: record.KindRunStart, Source: record.SourceSupervisor, PID: 1, TID: 1}
	if err := start.SetPayload(startPayload()); err != nil {
		t.Fatal(err)
	}
	put(start, 0)
	// The gap lines differ only in seq, prev and id, so each is the canonical line MarshalLine made for line 1
	// with those three spliced in and the id recomputed as VerifyLine computes it (R2): a fifteenth of
	// MarshalLine's cost, and a test that fails if the splice ever stops matching the chain.
	const holder = "abababababababababababababababababababababababababababababababab"
	tmpl := gapEvent("m")
	tmpl.V, tmpl.Run, tmpl.Agent, tmpl.Seq, tmpl.Prev, tmpl.TS = record.Version, testRef.ID, testRef.Agent, 1, holder,
		fixedStart
	line, err := tmpl.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	const head = `{"v":1,"seq":1,"id":"`
	p := strings.Index(string(line), `"prev":"`+holder+`"`) + len(`"prev":"`)
	if !strings.HasPrefix(string(line), head) || p < len(`"prev":"`) {
		t.Fatalf("the template line is not canonical: %s", line)
	}
	mid, tail := line[len(head)+record.IDLen:p], line[p+record.IDLen:]
	var buf []byte
	for i := 1; i <= n; i++ {
		buf = append(buf[:0], `{"v":1,"seq":`...)
		buf = strconv.AppendInt(buf, int64(i), 10)
		buf = append(buf, `,"id":"`...)
		idAt := len(buf)
		buf = append(buf, strings.Repeat("0", record.IDLen)...)
		buf = append(buf, mid...)
		buf = append(buf, prev...)
		buf = append(buf, tail...)
		sum := sha256.Sum256(buf)
		hex.Encode(buf[idAt:idAt+record.IDLen], sum[:])
		prev = string(buf[idAt : idAt+record.IDLen])
		_, _ = bw.Write(buf)
		_ = bw.WriteByte('\n')
	}
	end := &record.Event{Kind: record.KindRunEnd, Source: record.SourceSupervisor, PID: 1, TID: 1}
	if err := end.SetPayload(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	put(end, uint64(n+1))
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestFollowerMemoryFlat: following a run of a million lines holds the heap under a ceiling a follower that
// kept its lines would pass a hundred times over, and its one buffer never passes MaxLineBytes.
func TestFollowerMemoryFlat(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("a million lines: not in -short or -race")
	}
	const n = 1_000_000
	dir := filepath.Join(t.TempDir(), testRef.ID)
	writeSynthetic(t, dir, n)
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse
	const ceiling = 32 << 20 // the ledger is about 250 MB
	var peak uint64
	count := 0
	for _, err := range fl.Lines(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		if count++; count%50_000 == 0 {
			runtime.ReadMemStats(&ms)
			peak = max(peak, ms.HeapInuse)
		}
	}
	if count != n+2 {
		t.Fatalf("delivered %d lines, want %d", count, n+2)
	}
	if peak > base+ceiling {
		t.Fatalf("heap in use peaked at %d bytes, %d over the %d before the follow: past the %d ceiling", peak,
			peak-base, base, ceiling)
	}
	if fl.maxBuf > MaxLineBytes {
		t.Fatalf("the buffer grew to %d bytes, past MaxLineBytes", fl.maxBuf)
	}
	t.Logf("%d lines: heap in use peaked %d bytes over the base; buffer at most %d bytes", count, peak-base, fl.maxBuf)
}

// FuzzFollowerMatchesReader: whatever the lengths of a run's lines (each input byte is one line of that many
// KiB, so lines cross the 32 KiB buffer, grow it and let it shrink in every order) and whatever torn tail follows
// them, the Follower over the stopped run delivers exactly the lines Reader.Lines yields, then ErrRunLost.
func FuzzFollowerMatchesReader(f *testing.F) {
	f.Add([]byte{0, 40, 0, 0, 33, 1}, uint16(0))
	f.Add([]byte{31, 32, 33, 0, 64, 64, 0}, uint16(17))
	f.Add([]byte{100, 0, 1, 2, 3, 100, 0, 0, 0}, uint16(300))
	f.Fuzz(func(t *testing.T, sizes []byte, torn uint16) {
		if len(sizes) > 24 {
			sizes = sizes[:24]
		}
		w, dir, _ := openTestWriter(t)
		startRun(t, w, 0)
		for _, kib := range sizes {
			if err := w.Append(gapEvent(strings.Repeat("y", int(kib%128)<<10+int(kib)))); err != nil {
				t.Fatal(err)
			}
		}
		if torn > 0 {
			line := nextLine(t, w, gapEvent("torn"))
			appendRaw(t, dir, line[:int(torn)%(len(line)-1)+1])
		}
		if err := w.Abandon(); err != nil {
			t.Fatal(err)
		}
		fl, err := Follow(dir, Cursor{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fl.Close() }()
		got := followAll(t, fl, 30*time.Second)
		if !errors.Is(got.err, ErrRunLost) {
			t.Fatalf("follow of a stopped run: %v, want ErrRunLost", got.err)
		}
		equalLines(t, got.lines, storedLines(t, dir))
		if fl.maxBuf > MaxLineBytes {
			t.Fatalf("buffer %d past MaxLineBytes", fl.maxBuf)
		}
	})
}

// TestFollowerGrowsForALongLine: a line longer than the buffer grows it (to no more than the line needs, within
// MaxLineBytes), is delivered whole, and the lines around it arrive as Reader.Lines reads them.
func TestFollowerGrowsForALongLine(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	if err := w.Append(gapEvent(strings.Repeat("x", 100<<10))); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ { // enough short lines after it to need the buffer again
		if err := w.Append(gapEvent("after" + strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	var lines []string
	shrunk := -1 // the buffer's size once the lines after the long one are being delivered
	for en, err := range fl.Lines(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(en.Line))
		if len(lines) == 2+150 {
			shrunk = fl.bufLen
		}
	}
	equalLines(t, lines, storedLines(t, dir))
	if fl.maxBuf < 100<<10 || fl.maxBuf > 256<<10 {
		t.Fatalf("the buffer grew to %d bytes for a line of about 100 KiB", fl.maxBuf)
	}
	// The room is given back once the long line is delivered, not held while the follow catches up.
	if shrunk != followBuf || fl.bufLen != followBuf {
		t.Fatalf("the buffer is %d bytes 150 lines after the long one and %d at the end, want %d", shrunk,
			fl.bufLen, followBuf)
	}
}

// TestFollowerRereadsATornTailAResumeTruncates: a Writer that resumes a run (the reaper, gc's orphan ending)
// truncates the torn tail and appends after it, under the lock. A Follower that held the torn bytes while
// it waited must read the new lines, not its stale bytes joined to them: what it delivers is what the file
// holds, line for line as Reader.Lines reads it, and the end is the lost run's, never a false break.
func TestFollowerRereadsATornTailAResumeTruncates(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	tearTail(t, w)
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	// A holder of the lock that is not a Writer: its close raises no IN_CLOSE_WRITE, so the Follower does not
	// wake when it is released, only when the resume writes.
	lock, err := os.Open(filepath.Join(dir, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	idle := make(chan struct{}, 1)
	fl.OnIdle(func() error {
		select {
		case idle <- struct{}{}:
		default:
		}
		return nil
	})
	ch := make(chan followed, 1)
	go func() { ch <- followAll(t, fl, 20*time.Second) }()
	select {
	case <-idle: // the two lines delivered, the torn bytes held
	case <-time.After(10 * time.Second):
		t.Fatal("the follower never caught up")
	}
	// The resuming Writer takes the lock the instant the holder lets it go.
	prev := lockOpened
	lockOpened = func(string) { _ = lock.Close() }
	w2, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	lockOpened = prev
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w2.Append(gapEvent("resumed" + strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w2.Abandon(); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	want := storedLines(t, dir)
	if len(want) != 6 {
		t.Fatalf("the resumed ledger holds %d lines, want 6", len(want))
	}
	if !errors.Is(got.err, ErrRunLost) {
		t.Fatalf("follow across a resume: %d lines, %v; want the 6 stored lines and ErrRunLost", len(got.lines),
			got.err)
	}
	equalLines(t, got.lines, want)
}

// unterminatedEnd ends dir's ledger without its last "\n" (E8: a whole last line that lost only its
// terminator).
func unterminatedEnd(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, EventsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, int64(len(b)-1)); err != nil {
		t.Fatal(err)
	}
}

// TestFollowerResumesFromAnUnterminatedLastLine: the cursor a Follower issued for a whole unterminated last
// line (E8) names a line the ledger holds, so a Follower started from it resumes: to a clean end after a
// run_end, to ErrRunLost after any other line, with nothing delivered either way.
func TestFollowerResumesFromAnUnterminatedLastLine(t *testing.T) {
	for _, ended := range []bool{true, false} {
		w, dir, _ := openTestWriter(t)
		startRun(t, w, 1)
		var err error
		if ended {
			err = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
		} else {
			err = w.Abandon()
		}
		if err != nil {
			t.Fatal(err)
		}
		unterminatedEnd(t, dir)
		fl, err := Follow(dir, Cursor{})
		if err != nil {
			t.Fatal(err)
		}
		all := followAll(t, fl, 10*time.Second)
		_ = fl.Close()
		if want := map[bool]int{true: 3, false: 2}[ended]; len(all.lines) != want {
			t.Fatalf("ended=%v: the first follow delivered %d lines (%v), want %d", ended, len(all.lines), all.err,
				want)
		}
		fl, err = Follow(dir, all.cursors[len(all.cursors)-1])
		if err != nil {
			t.Fatal(err)
		}
		got := followAll(t, fl, 10*time.Second)
		_ = fl.Close()
		if len(got.lines) != 0 || (ended && got.err != nil) || (!ended && !errors.Is(got.err, ErrRunLost)) {
			t.Fatalf("ended=%v: resume from the unterminated last line: %d lines, %v", ended, len(got.lines), got.err)
		}
	}
}

// TestFollowerNewerVersionLine pins the Follower's newer-version rule (record-ledger.md §4 Follow): without
// SkipNewerVersions a newer record version's line ends the follow as ErrCorruptLedger naming
// ErrNewerVersion, the line and its offset, after the lines before it; with it the line is skipped, counted,
// and the lines after it delivered, and a resume from the cursor before it skips it again.
func TestFollowerNewerVersionLine(t *testing.T) {
	dir := newerRun(t, "2") // run_start, e0, a v2 line, e1, run_end
	stored := storedLines(t, dir)
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	got := followAll(t, fl, 10*time.Second)
	_ = fl.Close()
	if !errors.Is(got.err, ErrCorruptLedger) || !errors.Is(got.err, record.ErrNewerVersion) ||
		!strings.Contains(got.err.Error(), "line 3: at byte offset") || len(got.lines) != 2 {
		t.Fatalf("without skip: %d lines, %v; want 2 and ErrCorruptLedger naming ErrNewerVersion at line 3",
			len(got.lines), got.err)
	}
	fl, err = Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	fl.SkipNewerVersions()
	got = followAll(t, fl, 10*time.Second)
	_ = fl.Close()
	if got.err != nil || fl.SkippedNewer() != 1 {
		t.Fatalf("with skip: %v, skipped %d; want a clean end and 1 skipped", got.err, fl.SkippedNewer())
	}
	equalLines(t, got.lines, []string{stored[0], stored[1], stored[3], stored[4]})
	fl, err = Follow(dir, got.cursors[1])
	if err != nil {
		t.Fatal(err)
	}
	fl.SkipNewerVersions()
	resumed := followAll(t, fl, 10*time.Second)
	_ = fl.Close()
	if resumed.err != nil || fl.SkippedNewer() != 1 {
		t.Fatalf("resume before the newer line: %v, skipped %d", resumed.err, fl.SkippedNewer())
	}
	equalLines(t, resumed.lines, stored[3:])
}

// TestFollowerLockSeenFreeMeansTheReadWasFinal pins the order of Lines' end: the lock is probed before the
// read that finds the end of the file. A Writer that appends run_end and releases the lock after the read
// that found no more bytes and before the probe has its run_end delivered, and the follow ends cleanly, never
// as ErrRunLost.
func TestFollowerLockSeenFreeMeansTheReadWasFinal(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	closed := false
	prev := beforeLockProbe
	beforeLockProbe = func() {
		if closed {
			return
		}
		closed = true
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeLockProbe = prev })
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 10*time.Second)
	if !closed {
		t.Fatal("the probe hook never ran")
	}
	if got.err != nil {
		t.Fatalf("follow: %d lines, %v; want run_end delivered and a clean end", len(got.lines), got.err)
	}
	equalLines(t, got.lines, storedLines(t, dir))
}

// holdLock takes dir's lock the way a holder that is not a Writer does: it opened the lock file read-only, so
// its close raises no IN_CLOSE_WRITE and a waiting Follower learns of the release only from a write or the poll
// backstop. The hold ends when the returned file is closed.
func holdLock(t *testing.T, dir string) *os.File {
	t.Helper()
	lock, err := os.Open(filepath.Join(dir, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	return lock
}

// unterminatedCursor ends a lost run of one event without its last "\n" (E8) and returns its directory and
// what a Follower delivers from its start: the last cursor names the whole unterminated line.
func unterminatedCursor(t *testing.T) (string, followed) {
	t.Helper()
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	unterminatedEnd(t, dir)
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	all := followAll(t, fl, 10*time.Second)
	_ = fl.Close()
	if len(all.lines) != 2 || !errors.Is(all.err, ErrRunLost) {
		t.Fatalf("the first follow: %d lines, %v; want 2 and ErrRunLost", len(all.lines), all.err)
	}
	return dir, all
}

// resumeWriter opens a Writer on dir that takes the lock the instant hold lets it go, as a launcher resuming
// the run does; its resume terminates the unterminated last line. It appends a gap line and ends the run.
func resumeWriter(t *testing.T, dir string, hold *os.File) {
	t.Helper()
	prev := lockOpened
	lockOpened = func(string) { _ = hold.Close() }
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	lockOpened = prev
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(gapEvent("after")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestFollowerResumeWaitsWhileTheLockIsHeld pins resume's lock probe (record-ledger.md §4 Follow): a cursor
// naming the whole unterminated last line of a ledger whose lock is held is waited on, neither refused as
// [cursor-mismatch] nor ended as ErrRunLost, since the holder may yet terminate it; once a resuming Writer
// does and ends the run, the Follower delivers the lines after the cursor and ends cleanly.
func TestFollowerResumeWaitsWhileTheLockIsHeld(t *testing.T) {
	dir, all := unterminatedCursor(t)
	hold := holdLock(t, dir)
	_, ch := startFollow(t, dir, all.cursors[len(all.cursors)-1], 20*time.Second)
	select {
	case got := <-ch:
		t.Fatalf("the follow from the cursor ended while the lock was held: %d lines, %v", len(got.lines), got.err)
	case <-time.After(500 * time.Millisecond):
	}
	resumeWriter(t, dir, hold)
	got := <-ch
	if got.err != nil {
		t.Fatalf("resume once the Writer ended the run: %d lines, %v; want a clean end", len(got.lines), got.err)
	}
	equalLines(t, got.lines, storedLines(t, dir)[len(all.lines):])
}

// TestFollowerResumeLockSeenFreeMeansTheReadWasFinal pins the order of resume's probe, as
// TestFollowerLockSeenFreeMeansTheReadWasFinal pins Lines': a Writer that terminates the cursor's line, ends
// the run and releases the lock after the read that found the line unterminated and before the probe has its
// lines read after the probe and delivered, and the follow ends cleanly, never as ErrRunLost or
// [cursor-mismatch].
func TestFollowerResumeLockSeenFreeMeansTheReadWasFinal(t *testing.T) {
	dir, all := unterminatedCursor(t)
	hold := holdLock(t, dir)
	ran := false
	prev := beforeLockProbe
	beforeLockProbe = func() {
		if !ran {
			ran = true
			resumeWriter(t, dir, hold)
		}
	}
	t.Cleanup(func() { beforeLockProbe = prev })
	fl, err := Follow(dir, all.cursors[len(all.cursors)-1])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fl.Close() }()
	got := followAll(t, fl, 20*time.Second)
	if !ran {
		t.Fatal("the probe hook never ran")
	}
	if got.err != nil {
		t.Fatalf("resume: %d lines, %v; want the Writer's lines and a clean end", len(got.lines), got.err)
	}
	equalLines(t, got.lines, storedLines(t, dir)[len(all.lines):])
}

// TestFollowerResumeWaitsForAPartialCursorLine pins resume's wait for a partial line (record-ledger.md §4
// Follow): when the file ends inside the cursor's line while a writer holds the lock, the Follower waits,
// and once the rest of the line arrives it accepts the cursor and delivers the lines after it.
func TestFollowerResumeWaitsForAPartialCursorLine(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 3)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	stored := storedLines(t, dir)
	fl, err := Follow(dir, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	all := followAll(t, fl, 10*time.Second)
	_ = fl.Close()
	if all.err != nil || len(all.lines) != len(stored) {
		t.Fatalf("the first follow: %d lines, %v", len(all.lines), all.err)
	}
	const k = 2 // the cursor names the third line, e1
	c := all.cursors[k]
	path := filepath.Join(dir, EventsFile)
	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cut := c.Offset + 10
	if err := os.Truncate(path, cut); err != nil {
		t.Fatal(err)
	}
	hold := holdLock(t, dir)
	fl, ch := startFollow(t, dir, c, 20*time.Second)
	idle := make(chan struct{}, 1)
	fl.OnIdle(func() error {
		select {
		case idle <- struct{}{}:
		default:
		}
		return nil
	})
	select {
	case got := <-ch:
		t.Fatalf("the follow ended on a partial cursor line while the lock was held: %d lines, %v",
			len(got.lines), got.err)
	case <-idle:
		t.Fatal("the follow went idle before the cursor's line was whole")
	case <-time.After(500 * time.Millisecond):
	}
	appendRaw(t, dir, full[cut:])
	select {
	case got := <-ch:
		t.Fatalf("the follow ended while the lock was held: %d lines, %v", len(got.lines), got.err)
	case <-idle: // the rest delivered, the lock still held
	case <-time.After(10 * time.Second):
		t.Fatal("the follower never caught up")
	}
	_ = hold.Close()
	got := <-ch
	if got.err != nil {
		t.Fatalf("resume from a cursor whose line arrived late: %d lines, %v; want a clean end", len(got.lines),
			got.err)
	}
	equalLines(t, got.lines, stored[k+1:])
}
