// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestParseChildArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"none", nil, "", false},
		{"run tag", []string{"--run", "r-1"}, "r-1", false},
		{"run needs a value", []string{"--run"}, "", true},
		{"unknown flag", []string{"--bogus"}, "", true},
		{"unknown after run", []string{"--run", "x", "extra"}, "", true},
	}
	for _, c := range cases {
		got, err := parseChildArgs(c.args)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: parseChildArgs(%q) = %q, %v; want %q, err=%v", c.name, c.args, got, err, c.want, c.wantErr)
		}
	}
}

func TestFailKeepsTheErrnoAndDefaultsToEIO(t *testing.T) {
	e := fail(StepDumpable, syscall.EPERM)
	se := e.(*stepError)
	if se.errno != syscall.EPERM || !errors.Is(e, syscall.EPERM) {
		t.Fatalf("errno not carried: %+v", se)
	}
	if got := fail(StepDumpable, errors.New("odd")).(*stepError).errno; got != syscall.EIO {
		t.Fatalf("non-errno failure errno = %v, want EIO", got)
	}
}

// A control pipe whose write end is fed by the test stands in for the child.
func childWithControl(t *testing.T) (*Child, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return &Child{ControlR: r}, w
}

func TestExecVerdict(t *testing.T) {
	cases := []struct {
		name string
		feed []byte
		want syscall.Errno
	}{
		{"exec failure is reported", encodeError(StepExec, syscall.ENOENT), syscall.ENOENT},
		{"other step is not an exec verdict", encodeError(StepDumpable, syscall.EPERM), 0},
		{"fd message is not a verdict", encodeFD(7), 0},
		{"short read", []byte{1}, 0},
		{"garbage", []byte{0xff, 0xff, 0xff, 0xff}, 0},
	}
	for _, c := range cases {
		ch, w := childWithControl(t)
		w.Write(c.feed)
		w.Close()
		if got := ch.execVerdict(); got != c.want {
			t.Errorf("%s: verdict = %v, want %v", c.name, got, c.want)
		}
	}
	if got := (&Child{}).execVerdict(); got != 0 {
		t.Errorf("no pipe: verdict = %v", got)
	}
}

func TestReadControlOutcomes(t *testing.T) {
	ch, w := childWithControl(t)
	w.Write(encodeFD(5))
	m, err := ch.readControl(context.Background())
	if err != nil || m.Kind != MessageFD || m.FD != 5 {
		t.Fatalf("got %+v, %v", m, err)
	}
	w.Close()
	if _, err := ch.readControl(context.Background()); !errors.Is(err, ErrChildDied) {
		t.Fatalf("EOF err = %v, want ErrChildDied", err)
	}

	ch, w = childWithControl(t)
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := ch.readControl(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked read err = %v, want the context's", err)
	}
}

func TestAck(t *testing.T) {
	r, w, _ := os.Pipe()
	ch := &Child{controlW: w}
	if err := ch.Ack(); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, _ := r.Read(b[:]); n != 1 || b[0] != ackByte {
		t.Fatalf("ack byte not delivered: %v", b)
	}
	if err := ch.Ack(); err == nil {
		t.Fatal("second Ack must fail")
	}
	r.Close()

	r, w, _ = os.Pipe()
	r.Close()
	ch = &Child{controlW: w}
	if err := ch.Ack(); !errors.Is(err, ErrChildDied) {
		t.Fatalf("Ack to a dead child = %v, want ErrChildDied", err)
	}
}

func TestProcZombie(t *testing.T) {
	if procZombie(os.Getpid()) {
		t.Fatal("the running test process is not a zombie")
	}
	if procZombie(1 << 30) {
		t.Fatal("a missing pid is not a zombie")
	}
}
