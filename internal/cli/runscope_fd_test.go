// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

const scopeFDHelperEnv = "TEGO_SCOPE_FD_HELPER"

// scopeFDHelper runs before the testing framework or TestMain makes any descriptor owner. Its inherited FIFO
// could be owned until executeUserScope creates its pipes; accepting it afterwards would mint a second owner.
func scopeFDHelper() {
	if _, err := sys.Inherited(-1, sys.KindFIFO, "seal-precondition"); !errors.Is(err, sys.ErrKind) {
		fmt.Fprintf(os.Stderr, "inherited seal was already closed before scope pipes: %v\n", err)
		os.Exit(3)
	}
	scopeCommandFor = func(string, ...string) *proc.Cmd {
		fd, err := sys.Inherited(3, sys.KindFIFO, "ownership-probe")
		if !errors.Is(err, sys.ErrSealed) {
			if fd != nil {
				_ = fd.Close()
			}
			fmt.Fprintf(os.Stderr, "scope pipes did not seal inherited descriptors: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
		return nil
	}
	_, _ = executeUserScope(context.Background(), scopePlan{}, io.Discard)
	os.Exit(2)
}

// TestScopeHandshakePipesAreOwnedBeforeStart pins ADR 0023's birth rule on the actual allocation path, before
// any command is started. An os.Pipe handoff leaves sys's seal open and fails this subprocess check.
func TestScopeHandshakePipesAreOwnedBeforeStart(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), scopeFDHelperEnv+"=1")
	cmd.ExtraFiles = []*os.File{rd}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ownership before start: %v\n%s", err, out)
	}
}

// The timeout and cancellation paths close a pipe while its handshake goroutine is waiting on I/O. Release
// uses os.NewFile, which only registers already nonblocking descriptors with Go's poller, unlike os.Pipe.
func TestScopeHandshakePipesKeepCancelableIO(t *testing.T) {
	rd, wr, err := scopePipe("cancelable")
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	deadline := time.Now().Add(time.Second)
	if err := rd.SetReadDeadline(deadline); err != nil {
		t.Fatalf("request read cannot be interrupted: %v", err)
	}
	if err := wr.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("request write cannot be interrupted: %v", err)
	}
}
