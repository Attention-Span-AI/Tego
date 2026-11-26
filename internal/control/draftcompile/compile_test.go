// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == Argument {
		b, _ := io.ReadAll(os.Stdin)
		var r Request
		if json.Unmarshal(b, &r) == nil {
			if composeStalledHelperForTest(r) {
				os.Exit(125)
			}
			switch string(r.Text) {
			case "stall": // a compile that never ends: the child has said it is running
				_, _ = os.Stdout.Write([]byte{readyMark})
				time.Sleep(time.Hour)
				os.Exit(125)
			case "stall-before-ready": // a child that never gets to read its request
				time.Sleep(time.Hour)
				os.Exit(125)
			case "slow-start": // a child on a busy machine, slow to start
				time.Sleep(900 * time.Millisecond)
			case "slow-finish": // a child that compiles, slowly, and answers
				_, _ = os.Stdout.Write([]byte{readyMark})
				time.Sleep(900 * time.Millisecond)
				_, _ = os.Stdout.Write([]byte("{}"))
				os.Exit(0)
			case "dies": // a child that is killed (the machine ran out of memory) while it compiles
				_, _ = os.Stdout.Write([]byte{readyMark})
				os.Exit(3)
			case "report-dumpable": // the real Helper over a request that says, at its first read, whether the process is dumpable
				_, code := Helper(os.Args, &dumpReport{}, io.Discard)
				os.Exit(code)
			case "garbage": // a child whose answer is no result
				_, _ = os.Stdout.Write([]byte{readyMark, 'x'})
				os.Exit(0)
			}
		}
		_, code := Helper(os.Args, bytes.NewReader(b), os.Stdout)
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestCompilerCancellationAndAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	// Whatever way the test ends, the stalled compilations are cancelled and have returned before the next test starts:
	// a failure here once left them holding both slots (every later test then answered busy) and reading the helper
	// command a later test sets (a data race).
	var running sync.WaitGroup
	// The join is bounded: if a cancelled compile never returns (the regression this test exists for), the test says so
	// and the package still ends, instead of waiting for its own timeout.
	t.Cleanup(func() {
		cancel()
		if !joinedWithin(&running, joinBound) {
			t.Errorf("a cancelled compilation did not return within %v of the cancel: its slot is still held", joinBound)
		}
	})
	for i := 0; i < cap(slots); i++ {
		running.Add(1)
		go func() { defer running.Done(); _, err := Check(ctx, Request{Text: []byte("stall")}); done <- err }()
	}
	waitSlots(t, cap(slots))
	start := time.Now()
	_, err := Check(WithGoverned(context.Background()), Request{Text: []byte("stall")}) // a governed request is refused at the admission wait
	if err == nil || !strings.Contains(err.Error(), "busy, try again") {
		t.Fatalf("capacity exceeded: %v", err)
	}
	// The refusal comes when the admission wait ends, which a race build scales (raceScale: 1 s there), so the bound is
	// that wait and a second, not a second.
	if time.Since(start) > AdmissionWait+time.Second {
		t.Fatal("admission wait unbounded")
	}
	cancel()
	for i := 0; i < cap(slots); i++ {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("HTTP worker held by child")
		}
	}
	waitSlots(t, 0)
	// The killed workers were reaped and capacity is reusable.
	_, err = Check(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "no machine config") {
		t.Fatalf("capacity did not recover: %v", err)
	}
}

// joinBound is how long a test waits for cancelled compilations to return: far more than a killed child needs, far
// less than the package's timeout.
const joinBound = 5 * time.Second

// joinedWithin reports whether every goroutine of wg returned within d. The goroutines that did not stay behind.
func joinedWithin(wg *sync.WaitGroup, d time.Duration) bool {
	over := make(chan struct{})
	go func() { wg.Wait(); close(over) }()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-over:
		return true
	case <-timer.C:
		return false
	}
}

func TestJoinedWithinGivesUpOnAGoroutineThatNeverReturns(t *testing.T) {
	var stuck, fine sync.WaitGroup
	stuck.Add(1)
	defer stuck.Done() // lets the waiter below end with the test
	if joinedWithin(&stuck, 50*time.Millisecond) {
		t.Fatal("a goroutine that has not returned was reported as joined")
	}
	if !joinedWithin(&fine, time.Second) {
		t.Fatal("an empty group was reported as not joined")
	}
}

func waitSlots(t *testing.T, n int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for len(slots) != n {
		select {
		case <-deadline.C:
			t.Fatalf("slots %d want %d", len(slots), n)
		case <-tick.C:
		}
	}
}
func TestCompilerTotalDeadline(t *testing.T) {
	start := time.Now()
	_, err := Check(context.Background(), Request{Text: []byte("stall")})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if time.Since(start) > Budget+time.Second {
		t.Fatal("deadline did not release caller")
	}
	waitSlots(t, 0)
}
func TestCompilerAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Check(ctx, Request{})
	if !errors.Is(err, context.Canceled) || len(slots) != 0 {
		t.Fatalf("canceled request took worker: %v", err)
	}
}

func TestCompilerDoesNoDNS(t *testing.T) {
	previous := net.DefaultResolver
	var calls atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("test resolver refuses lookup")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	m := config.Builtin()
	m.Home = t.TempDir()
	r := compile(Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(m.Home, "agent.yaml"), Cwd: m.Home, PATH: "/usr/bin:/bin", Home: m.Home}, Text: []byte("version: 0\nname: offline\ncommand: [sh]\nnet:\n  allow: ['slow-one.example:443','slow-two.example:443']\n")})
	if r.Error != "" {
		t.Fatal(r.Error)
	}
	if calls.Load() != 0 {
		t.Fatalf("untrusted compile sent %d DNS lookups", calls.Load())
	}
}

// A person's own check is not refused as busy after the admission wait: both slots held by governed compilations cost
// it a wait, bounded by its own request, and it is admitted when one is free; a governed request is refused at the
// admission wait as before. A person whose request ends while it waits is told the check did not finish.
func TestAPersonsCheckWaitsForASlotAndIsNeverRefusedAsBusy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	var running sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		if !joinedWithin(&running, joinBound) {
			t.Errorf("a cancelled compilation did not return within %v of the cancel: its slot is still held", joinBound)
		}
	})
	for i := 0; i < cap(slots); i++ {
		running.Add(1)
		go func() {
			defer running.Done()
			_, err := Check(WithGoverned(ctx), Request{Text: []byte("stall")})
			done <- err
		}()
	}
	waitSlots(t, cap(slots))

	// Past the admission wait, with the slots still held, the person is still waiting; its request's end is the end of
	// the wait, said as a check that did not finish and never as busy.
	person, endPerson := context.WithTimeout(context.Background(), 4*AdmissionWait+200*time.Millisecond)
	defer endPerson()
	begin := time.Now()
	_, err := Check(person, Request{Text: []byte("stall")})
	if !contracts.IsCompileUnfinished(err) || strings.Contains(err.Error(), contracts.CompileBusy) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a person's check that waited out its request: %v", err)
	}
	if waited := time.Since(begin); waited < 3*AdmissionWait {
		t.Fatalf("a person's check gave up after %v, inside the admission wait of a governed one (%v)", waited, AdmissionWait)
	}

	// A slot freed during the wait admits the person: it is not refused for having waited.
	admitted := make(chan error, 1)
	go func() { _, err := Check(context.Background(), Request{Text: []byte("quick")}); admitted <- err }()
	time.Sleep(3 * AdmissionWait)
	select {
	case err := <-admitted:
		t.Fatalf("a person's check was answered while both slots were held: %v", err)
	default:
	}
	cancel() // the governed compilations end; the person takes a freed slot
	select {
	case err := <-admitted:
		if strings.Contains(fmt.Sprint(err), contracts.CompileBusy) {
			t.Fatalf("a person's check was refused as busy after a slot freed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a person's check was not admitted after the slots were freed")
	}
}
