// SPDX-License-Identifier: Apache-2.0

//go:build integration

package launch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestTheChildStageRefusesAWrongKindDescriptor is ADR 0023 C6's child stage: it owns the control pipe at 3 and the
// report pipe at 4 as FIFOs, and the deputy end its spec names as a socket, through sys.Inherited, and a number of
// the wrong kind there (a socket, /dev/null, a regular file, a pipe where the socket should be) ends it with exit
// 125 and one line naming the number before it reads from or writes to that number: a good report pipe carries
// the spec step's failure frame, a good control pipe keeps every byte of the spec when the report pipe is the one
// refused, and the stage never reports success.
func TestTheChildStageRefusesAWrongKindDescriptor(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	regular, err := os.Create(filepath.Join(t.TempDir(), "stray"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regular.Close() }()
	sock := closedPeerSocket(t)
	defer func() { _ = sock.Close() }()
	strayR, strayW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = strayR.Close(); _ = strayW.Close() }()

	const (
		goodPipe = iota // the position holds the test's own pipe of the right direction
		other           // the position holds the case's wrong-kind file
	)
	for _, tc := range []struct {
		name            string
		control, report int      // goodPipe or other
		wrong           *os.File // what other is
		deputy          *os.File // the spec's deputy at 5, nil for none
		want            string
		frame, specKept bool // a failure frame on the report pipe; the spec still unread in the control pipe
	}{
		{name: "a socket for the control pipe", control: other, report: goodPipe, wrong: sock,
			want: "inherited control at 3", frame: true},
		{name: "/dev/null for the control pipe", control: other, report: goodPipe, wrong: devNull,
			want: "inherited control at 3", frame: true},
		{name: "a file for the control pipe", control: other, report: goodPipe, wrong: regular,
			want: "inherited control at 3", frame: true},
		{name: "/dev/null for the report pipe", control: goodPipe, report: other, wrong: devNull,
			want: "inherited report at 4", specKept: true},
		{name: "a socket for the report pipe", control: goodPipe, report: other, wrong: sock,
			want: "inherited report at 4", specKept: true},
		{name: "a file for the deputy end", control: goodPipe, report: goodPipe, deputy: regular,
			want: "inherited deputy control at 5", frame: true},
		{name: "a pipe for the deputy end", control: goodPipe, report: goodPipe, deputy: strayR,
			want: "inherited deputy control at 5", frame: true},
		{name: "/dev/null for the deputy end", control: goodPipe, report: goodPipe, deputy: devNull,
			want: "inherited deputy control at 5", frame: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controlR, controlW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = controlR.Close(); _ = controlW.Close() }()
			reportR, reportW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reportR.Close(); _ = reportW.Close() }()
			w := wireSpec{Command: []string{"/bin/true"}, Dir: "/", UID: -1, GID: -1,
				ParentPID: os.Getpid(), RulesetFD: -1}
			if tc.deputy != nil {
				w.DeputyFD = childRulesetFD
			}
			var frame bytes.Buffer
			if err := writeSpec(&frame, w); err != nil {
				t.Fatal(err)
			}
			if _, err := controlW.Write(frame.Bytes()); err != nil {
				t.Fatal(err)
			}
			// No ack follows: a stage that went past a refusal it should have stopped at ends at the ack's EOF, saying
			// so, rather than wait for one.
			_ = controlW.Close()
			files := []*os.File{controlR, reportW}
			if tc.control == other {
				files[0] = tc.wrong
			}
			if tc.report == other {
				files[1] = tc.wrong
			}
			if tc.deputy != nil {
				files = append(files, tc.deputy)
			}
			// Bounded: a stage that read a refused number could block on it (the socket's peer is closed, so it
			// should not).
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], ChildCommand, "--run", "wrong-kind")
			cmd.WaitDelay = time.Second
			cmd.ExtraFiles = files
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err = cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != identity.ExitLauncher {
				t.Fatalf("child stage ended %v, stderr %q: want exit %d", err, stderr.String(), identity.ExitLauncher)
			}
			lines := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
			if len(lines) != 1 || !strings.HasPrefix(lines[0], "tego "+ChildCommand+" run=wrong-kind: ") ||
				!strings.Contains(lines[0], tc.want) || !strings.Contains(lines[0], sys.ErrKind.Error()) {
				t.Fatalf("child stage said %q, want one line naming %q as %v", stderr.String(), tc.want, sys.ErrKind)
			}

			_ = reportW.Close()
			got, err := io.ReadAll(reportR)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.frame:
				m, err := decodeControl(got)
				if err != nil || len(got) != controlSize || m.Kind != MessageError || m.Step != StepSpec ||
					m.Errno != syscall.EIO {
					t.Fatalf("report pipe held %x (%+v, %v), want one spec-step failure frame", got, m, err)
				}
			case len(got) != 0:
				t.Fatalf("report pipe held %x, want nothing: the stage was given no report pipe", got)
			}

			// The write end is closed and the stage has exited: the read ends at what is left.
			left, err := io.ReadAll(controlR)
			if err != nil {
				t.Fatal(err)
			}
			if (tc.specKept || tc.control == other) && !bytes.Equal(left, frame.Bytes()) {
				t.Fatalf("control pipe kept %d of the spec's %d bytes, want all: the stage read a pipe it refused "+
					"or was not given", len(left), frame.Len())
			}
		})
	}
}

// closedPeerSocket is one end of a connected Unix stream socket pair whose other end is closed: a socket that
// is not a pipe, and that reads EOF rather than block.
func closedPeerSocket(t *testing.T) *os.File {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fds[1])
	return os.NewFile(uintptr(fds[0]), "socket")
}
