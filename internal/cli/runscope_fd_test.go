// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
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

const (
	scopeCloexecHelperEnv = "TEGO_SCOPE_CLOEXEC_HELPER"
	scopeCloexecChildEnv  = "TEGO_SCOPE_CLOEXEC_CHILD"
)

// scopeCloexecHelper is the launcher's start: it adopts descriptors 3, 4 and 5 as scopedMain does, then starts a child
// of its own, as the launcher starts its ask notice, helpers and MCP relay, and passes on what the child reports.
func scopeCloexecHelper() {
	request, response, signals, err := scopeAdoptInherited()
	if err != nil || signals == nil {
		fmt.Fprintf(os.Stderr, "adoption failed: %v (channel %v)\n", err, signals != nil)
		os.Exit(3)
	}
	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), scopeCloexecChildEnv+"=1", scopeCloexecHelperEnv+"=")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "child: %v\n", err)
		os.Exit(4)
	}
	_, _, _ = request, response, signals // owned until here
	os.Exit(0)
}

// scopeCloexecChild prints the descriptors 3, 4 and 5 it holds.
func scopeCloexecChild() {
	for _, n := range []int{3, 4, 5} {
		if _, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0); err == nil {
			fmt.Printf("holds %d\n", n)
		}
	}
	os.Exit(0)
}

// The launcher's three inherited descriptors (the request and readiness FIFOs, and the interrupt channel's socket) are
// marked close-on-exec as they are adopted: a process the launcher starts afterwards holds none of them, so none can
// write the channel or the handshake.
func TestScopeLauncherDescriptorsAreCloseOnExec(t *testing.T) {
	r1, w1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()
	defer w1.Close()
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	defer w2.Close()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(pair[0]), "mine"), os.NewFile(uintptr(pair[1]), "theirs")
	defer mine.Close()
	defer theirs.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), scopeCloexecHelperEnv+"=1")
	cmd.ExtraFiles = []*os.File{r1, r2, theirs}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("a process the launcher started holds inherited descriptors:\n%s", out)
	}
}
