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
	scopeCloexecIDsEnv    = "TEGO_SCOPE_CLOEXEC_IDS"
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

// scopeCloexecChild prints every descriptor it holds that is one of the three the test passed to the launcher, by
// identity (device and inode, from scopeCloexecIDsEnv) and at whatever number it has. It never judges a number: a Go
// process lays out descriptors of its own at the lowest free numbers, and once the launcher has marked 3, 4 and 5
// those are free, so the child's epoll instance and eventfd (made when its runtime first needs the poller, a timer
// of the garbage collector's scavenger among the causes, at a moment no test controls) sit at exactly 3 and 4. The
// child makes such descriptors itself below, as its runtime does, so a check by number cannot pass.
func scopeCloexecChild() {
	names := [...]string{"request FIFO", "readiness FIFO", "signal socket"}
	want := map[[2]uint64]string{}
	for i, id := range strings.Split(os.Getenv(scopeCloexecIDsEnv), ",") {
		var dev, ino uint64
		if _, err := fmt.Sscanf(id, "%d:%d", &dev, &ino); err != nil || i >= len(names) {
			fmt.Fprintf(os.Stderr, "identity %d of %q: %v\n", i, os.Getenv(scopeCloexecIDsEnv), err)
			os.Exit(5)
		}
		want[[2]uint64{dev, ino}] = names[i]
	}
	if len(want) != len(names) {
		fmt.Fprintf(os.Stderr, "want %d distinct identities, have %d\n", len(names), len(want))
		os.Exit(5)
	}
	// Descriptors of the child's own at the numbers the launcher's had: the poller's epoll instance and eventfd, and
	// a pipe it watches.
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "child pipe: %v\n", err)
		os.Exit(5)
	}
	defer r.Close()
	defer w.Close()
	for n := 3; n < 256; n++ {
		var st unix.Stat_t
		if unix.Fstat(n, &st) != nil {
			continue
		}
		if name, ok := want[[2]uint64{uint64(st.Dev), uint64(st.Ino)}]; ok {
			fmt.Printf("holds %d: the launcher's %s\n", n, name)
		}
	}
	os.Exit(0)
}

// scopeCloexecIDs is the "device:inode" of each file, joined by commas, for scopeCloexecChild.
func scopeCloexecIDs(files ...*os.File) (string, error) {
	var ids []string
	for _, f := range files {
		var st unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &st); err != nil {
			return "", err
		}
		ids = append(ids, fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)))
	}
	return strings.Join(ids, ","), nil
}

// The launcher's three inherited descriptors (the request and readiness FIFOs, and the interrupt channel's socket) are
// marked close-on-exec as they are adopted: a process the launcher starts afterwards holds none of them, so none can
// write the channel or the handshake. The test names them by what they are (the files it made and passed), not by the
// numbers 3, 4 and 5, which the child's own descriptors take once they are free.
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
	ids, err := scopeCloexecIDs(r1, r2, theirs)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), scopeCloexecHelperEnv+"=1", scopeCloexecIDsEnv+"="+ids)
	cmd.ExtraFiles = []*os.File{r1, r2, theirs}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("a process the launcher started holds inherited descriptors:\n%s", out)
	}
}
