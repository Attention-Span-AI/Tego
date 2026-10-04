// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestStartIdentityFailureReleasesCommandPipes(t *testing.T) {
	cmd := Command("sleep", "30")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	if _, err := startWithIdentity(cmd, NewAt(t.TempDir()).Identity); !errors.Is(err, ErrIdentity) {
		t.Fatalf("start without a readable proc filesystem: %v", err)
	}
	for name, pipe := range map[string]*os.File{"stdin": in.(*os.File), "stdout": out.(*os.File), "stderr": stderr.(*os.File)} {
		if _, err := pipe.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("%s pipe still open after failed start: %v", name, err)
		}
	}
	if cmd.ProcessState == nil {
		t.Error("the command did not complete its Wait cleanup")
	}
}

// exec's stdin copier may be inside a caller's Read when the child is killed. The failed
// start must reap the child promptly without trying to close that caller-owned reader.
func TestStartIdentityFailureDoesNotWaitForCallerInput(t *testing.T) {
	r := &blockedInput{entered: make(chan struct{}), release: make(chan struct{})}
	cmd := Command("sleep", "30")
	cmd.Stdin = r
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	var release sync.Once
	unblock := func() { release.Do(func() { close(r.release) }) }
	t.Cleanup(unblock)
	result := make(chan error, 1)
	fs := NewAt(t.TempDir())
	go func() {
		_, err := startWithIdentity(cmd, fs.Identity)
		result <- err
	}()
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("command did not start its input copier")
	}
	var startErr error
	select {
	case startErr = <-result:
	case <-time.After(250 * time.Millisecond):
		t.Error("identity failure waited for the caller's blocked input")
		unblock()
		select {
		case startErr = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("failed start did not finish after input was released")
		}
	}
	if !errors.Is(startErr, ErrIdentity) {
		t.Fatalf("start without a readable proc filesystem: %v", startErr)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("failed start returned before the child was reaped: %v", err)
	}
	unblock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := out.(*os.File).Stat()
		if errors.Is(err, os.ErrClosed) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("command pipe was not closed after caller input finished: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

type blockedInput struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockedInput) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return 0, io.EOF
}

func TestStartIdentityFailureDoesNotWaitForCallerOutput(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			w := &blockedOutput{entered: make(chan struct{}), release: make(chan struct{})}
			script := "printf ready; exec sleep 30"
			if stream == "stderr" {
				script = "printf ready >&2; exec sleep 30"
			}
			cmd := Command("/bin/sh", "-c", script)
			if stream == "stdout" {
				cmd.Stdout = w
			} else {
				cmd.Stderr = w
			}
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			var release sync.Once
			unblock := func() { release.Do(func() { close(w.release) }) }
			t.Cleanup(unblock)
			result := make(chan error, 1)
			go func() {
				_, err := startWithIdentity(cmd, func(int) (Identity, error) {
					select {
					case <-w.entered:
						return Identity{}, os.ErrNotExist
					case <-time.After(5 * time.Second):
						return Identity{}, errors.New("child did not reach its output writer")
					}
				})
				result <- err
			}()
			select {
			case <-w.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("child did not reach its output writer")
			}
			var startErr error
			select {
			case startErr = <-result:
			case <-time.After(250 * time.Millisecond):
				t.Error("identity failure waited for the caller's blocked output")
				unblock()
				select {
				case startErr = <-result:
				case <-time.After(5 * time.Second):
					t.Fatal("failed start did not finish after output was released")
				}
			}
			if !errors.Is(startErr, ErrIdentity) {
				t.Fatalf("identity refusal: %v", startErr)
			}
			if err := cmd.Process.Signal(syscall.Signal(0)); !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("failed start returned before the child was reaped: %v", err)
			}
			unblock()
			deadline := time.Now().Add(5 * time.Second)
			for {
				_, err := in.(*os.File).Stat()
				if errors.Is(err, os.ErrClosed) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("command pipe was not closed after caller output finished: %v", err)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

type blockedOutput struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedOutput) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}
