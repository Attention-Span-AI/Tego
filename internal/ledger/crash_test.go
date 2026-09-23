// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// helperEnv selects the subprocess role. The test binary re-executes itself so the lock is held, and the
// crash happens, in a real second process: flock release on death and torn tails are kernel behaviour, not
// something a fake can show.
const helperEnv = "TEGO_LEDGER_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		// Leak-gated (testutil.LeakCheckMain): the ledger starts no goroutine a closed Writer or Reader
		// may leave behind.
		os.Exit(testutil.LeakCheckMain(m))
	case "hold":
		helperHold()
	case "concurrentcrash":
		helperConcurrentCrash()
	case "crash":
		helperCrash()
	}
}

// helperHold opens the run, prints "ready", and keeps the lock until stdin closes.
func helperHold() {
	dir := os.Getenv("TEGO_LEDGER_DIR")
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndStopped})
	os.Exit(0)
}

// helperCrash writes n events, then puts the first half of a line on disk with a direct write and kills
// itself with SIGKILL mid-line, exactly as a crash during write(2) would leave the file. With
// TEGO_LEDGER_LIVE set it lists the run in the live index first, as the launcher does before run_start.
func helperCrash() {
	dir := os.Getenv("TEGO_LEDGER_DIR")
	n, _ := strconv.Atoi(os.Getenv("TEGO_LEDGER_N"))
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	if os.Getenv("TEGO_LEDGER_LIVE") != "" {
		if err := MarkLive(filepath.Dir(dir), testRef.ID); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	for i := 0; i < n; i++ {
		if err := w.Append(fsEvent("/home/u/proj/out/"+strconv.Itoa(i), nil)); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
	}
	e := fsEvent("/home/u/proj/out/torn", nil)
	e.Run, e.Agent, e.Seq, e.Prev, e.TS, e.V = testRef.ID, testRef.Agent, uint64(n+1), w.Head(), time.Now(), 1
	line, _ := e.MarshalLine()
	_, _ = w.events.Write(line[:len(line)/2])
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

func helper(t *testing.T, role, dir string, extra ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+role, "TEGO_LEDGER_DIR="+dir)
	cmd.Env = append(cmd.Env, extra...)
	return cmd
}

func TestLockHeldAcrossProcesses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), testRef.ID)
	cmd := helper(t, "hold", dir)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("helper: %q %v", line, err)
	}
	if _, err := Open(dir, testRef); !errors.Is(err, ErrRunLocked) {
		t.Fatalf("Open while another process holds the lock: %v, want ErrRunLocked", err)
	}
	if s := stateOf(t, dir); s != StateRunning {
		t.Fatalf("state %s, want running", s)
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
	if s := stateOf(t, dir); s != StateEnded {
		t.Fatalf("state after a clean close %s, want ended", s)
	}
	w, err := Open(dir, testRef)
	if !errors.Is(err, ErrRunEnded) {
		t.Fatalf("Open after the holder ended the run: %v %v", w, err)
	}
}

// TestCrashMidWrite: kill -9 mid-write leaves a torn last line the reader
// ignores; the chain verifies; the run reads as lost, and gc's sweep ends it with an anchor line.
//
// Also pins record-ledger.md E8: only a torn in-flight write leaves a partial last line.
func TestCrashMidWrite(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, testRef.ID)
	const n = 5
	cmd := helper(t, "crash", dir, "TEGO_LEDGER_N="+strconv.Itoa(n))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("helper should die by SIGKILL: %v %s", err, out)
	}
	data, _ := os.ReadFile(filepath.Join(dir, EventsFile))
	if data[len(data)-1] == '\n' {
		t.Fatal("the file must end mid-line")
	}
	events := readAll(t, dir)
	if len(events) != n+1 {
		t.Fatalf("reader yielded %d lines, want %d complete ones", len(events), n+1)
	}
	rep := verify(t, dir, nil)
	if rep.Lines != n+1 || rep.TornBytes == 0 || rep.Ended {
		t.Fatalf("verify: %+v", rep)
	}
	if s := stateOf(t, dir); s != StateLost {
		t.Fatalf("state %s, want lost (lock free, no run_end)", s)
	}
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	gcRep, err := GC(context.Background(), root, 365*24*time.Hour, false, WithWriterOptions(WithAnchor(anchor)))
	if err != nil || len(gcRep.Errors) != 0 || len(gcRep.Swept) != 1 {
		t.Fatalf("gc: %+v %v", gcRep, err)
	}
	after := verify(t, dir, anchor)
	if after.Lines != n+4 || !after.Ended || !after.Anchored || after.TornBytes != 0 {
		t.Fatalf("after sweep: %+v", after)
	}
	events = readAll(t, dir)
	var gap record.GapPayload
	if events[n+1].Kind != record.KindGap || events[n+1].DecodePayload(&gap) != nil || gap.Why != "torn-tail" {
		t.Fatalf("gap line: %+v", events[n+1])
	}
	if events[n+2].Kind != record.KindGap || events[n+2].DecodePayload(&gap) != nil || gap.Why != record.GapLauncherLost {
		t.Fatalf("orphaned gap line: %+v", events[n+2])
	}
	if s := stateOf(t, dir); s != StateEnded {
		t.Fatalf("state %s", s)
	}
}

// TestResumeLineMissingOnlyItsTerminator covers the crash that takes exactly the last byte of a line. The
// write(2) of a line is not atomic against a power loss, so the newline is as likely a casualty as any other
// byte, and what is left on disk is a whole event that decodes and whose id verifies. resume must restore the
// line boundary rather than leave it: an Append onto an unterminated file puts two events on one physical
// line, and nothing downstream can separate them again (E8).
func TestResumeLineMissingOnlyItsTerminator(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	first := fsEvent("/tmp/before-the-crash", nil)
	if err := w.Append(first); err != nil {
		t.Fatal(err)
	}
	keptID := first.ID
	// Drop the writer's descriptors without Close, which would write run_end: the process died instead.
	_ = w.events.Close()
	_ = w.lock.Close()

	events := filepath.Join(dir, EventsFile)
	st, err := os.Stat(events)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(events, st.Size()-1); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if w2.Head() != keptID {
		t.Errorf("head %q after resume, want the surviving line's id %q", w2.Head(), keptID)
	}
	if err := w2.Append(fsEvent("/tmp/after-the-crash", nil)); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(record.RunEndPayload{Reason: record.RunEndStopped}); err != nil {
		t.Fatal(err)
	}

	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var kinds []record.Kind
	var ids []string
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatalf("line %d: %v", len(kinds), err)
		}
		kinds = append(kinds, e.Kind)
		ids = append(ids, e.ID)
	}
	want := []record.Kind{record.KindRunStart, record.KindFS, record.KindFS, record.KindRunEnd}
	if len(kinds) != len(want) {
		t.Fatalf("kinds %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("line %d is %s, want %s", i, kinds[i], want[i])
		}
	}
	// Terminating the line must not have changed what it says: the id is over the bytes the reader takes,
	// and the reader has never taken the newline.
	if ids[1] != keptID {
		t.Errorf("surviving line's id is now %q, want %q", ids[1], keptID)
	}
	rep, err := r.Verify(context.Background(), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Lines != uint64(len(want)) || !rep.Started || !rep.Ended || rep.TornBytes != 0 {
		t.Errorf("verify report %+v, want %d verified lines, started, ended and no torn bytes", rep, len(want))
	}
}
