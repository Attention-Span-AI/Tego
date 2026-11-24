// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	for i := 0; i < cap(slots); i++ {
		go func() { _, err := Check(ctx, Request{Text: []byte("stall")}); done <- err }()
	}
	waitSlots(t, cap(slots))
	start := time.Now()
	_, err := Check(context.Background(), Request{Text: []byte("stall")})
	if err == nil || !strings.Contains(err.Error(), "busy, try again") {
		t.Fatalf("capacity exceeded: %v", err)
	}
	if time.Since(start) > time.Second {
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
