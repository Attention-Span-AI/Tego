// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stressEnv lengthens the stress tests to their full tens of seconds, e.g.
// TEGO_STRESS=1 go test -run CrashConcurrentWriters ./internal/ledger/; the plain run runs them briefly.
const stressEnv = "TEGO_STRESS"

// helperConcurrentCrash appends from 8 goroutines, lines of mixed size, until it is killed.
func helperConcurrentCrash() {
	dir := os.Getenv("TEGO_LEDGER_DIR")
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	if !w.started {
		if err := w.WriteRunStart(startPayload()); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
	}
	fmt.Println("ready")
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := 0; ; i++ {
				p := "/p/" + strconv.Itoa(g) + "/" + strconv.Itoa(i)
				if i%7 == 0 {
					p += strings.Repeat("x", 3000)
				}
				if i%11 == 0 {
					if err := w.Append(refusedEvent(p)); err != nil {
						fmt.Println("error:", err)
						os.Exit(1)
					}
					continue
				}
				if err := w.Append(fsEvent(p, nil)); err != nil {
					fmt.Println("error:", err)
					os.Exit(1)
				}
			}
		})
	}
	wg.Wait()
}

// TestCrashConcurrentWriters SIGKILLs a process appending from 8 goroutines at varying moments, resumes the
// run in a new process each round, and verifies the chain after every round (R4, E6): a kill mid-line leaves
// at most a torn tail the next Open cuts. One second of rounds in the plain run, 40 s under TEGO_STRESS.
func TestCrashConcurrentWriters(t *testing.T) {
	dur := time.Second
	if os.Getenv(stressEnv) != "" {
		dur = 40 * time.Second
	}
	dir := filepath.Join(t.TempDir(), testRef.ID)
	deadline := time.Now().Add(dur)
	rounds, torn := 0, 0
	for time.Now().Before(deadline) {
		cmd := helper(t, "concurrentcrash", dir)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 6)
		if n, _ := out.Read(b); string(b[:n]) != "ready\n" {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("round %d: helper said %q", rounds, b[:n])
		}
		time.Sleep(time.Duration(5+rounds%40) * time.Millisecond)
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = cmd.Wait()
		rep, err := VerifyRunDir(context.Background(), dir, nil)
		if err != nil {
			t.Fatalf("round %d verify: %v %+v", rounds, err, rep)
		}
		if rep.TornBytes > 0 {
			torn++
		}
		rounds++
	}
	rep, _ := VerifyRunDir(context.Background(), dir, nil)
	t.Logf("%d kill/resume rounds, %d left a torn tail, final %d lines", rounds, torn, rep.Lines)
}

// BenchmarkAppendParallel is Append from 8 concurrent appenders, and what Close costs after them.
func BenchmarkAppendParallel(b *testing.B) {
	dir := filepath.Join(b.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		b.Fatal(err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		b.Fatal(err)
	}
	b.SetParallelism(8)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := w.Append(fsEvent("/home/u/proj/out/report.md", nil)); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	t0 := time.Now()
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	b.ReportMetric(float64(time.Since(t0).Microseconds()), "close-us")
}

func openFDs(t *testing.T) int {
	t.Helper()
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(e)
}

// TestWriterLeaksNoDescriptor cycles Open/Close with a mirror, a blob and a refusal, the refused Opens (locked,
// ended), a Reader, and Open/Abandon, and counts /proc/self/fd before and after.
func TestWriterLeaksNoDescriptor(t *testing.T) {
	root := t.TempDir()
	cycle := func(i int) {
		dir := filepath.Join(root, fmt.Sprintf("x%d", i), testRef.ID)
		w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.MirrorLastRefusal(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteRunStart(startPayload()); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, testRef, WithAnchor(&memAnchor{})); err == nil {
			t.Fatal("a second Open of a locked run succeeded")
		}
		if _, err := w.Blob([]byte(strings.Repeat("b", 9000) + strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(refusedEvent("/t/" + strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, testRef, WithAnchor(&memAnchor{})); err == nil {
			t.Fatal("Open of an ended run succeeded")
		}
		r, err := OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		for range r.Iter() {
		}
		_, _ = r.Verify(context.Background(), nil)
		_ = r.Close()
		w2, err := Open(filepath.Join(root, fmt.Sprintf("y%d", i), testRef.ID), testRef, WithAnchor(&memAnchor{}))
		if err != nil {
			t.Fatal(err)
		}
		_ = w2.Abandon()
	}
	cycle(-1)
	f0 := openFDs(t)
	for i := range 200 {
		cycle(i)
	}
	if f1 := openFDs(t); f1 != f0 {
		t.Errorf("open descriptors %d -> %d over 200 cycles", f0, f1)
	}
}
