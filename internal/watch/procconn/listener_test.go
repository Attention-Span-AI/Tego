// SPDX-License-Identifier: Apache-2.0

package procconn

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// datagram frames one proc event the way the kernel does: a netlink header, a cn_msg header, the event.
func datagram(what Kind, union []byte) []byte {
	cn := make([]byte, cnMsgHeaderLen)
	native.PutUint32(cn[0:4], cnIdxProc)
	native.PutUint32(cn[4:8], cnValProc)
	body := append(cn, procEvent(what, union)...)
	msg := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body))
	msg = append(msg, body...)
	native.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

func TestEventsInWalksADatagram(t *testing.T) {
	pad := func(b []byte) []byte { // NLMSG_ALIGN
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	buf := pad(datagram(Fork, u32(100, 100, 555, 550)))
	buf = append(buf, pad(datagram(Exec, u32(555, 555)))...)
	buf = append(buf, datagram(Exit, u32(555, 555, 0x100, 17))...)
	evs := eventsIn(buf)
	if len(evs) != 3 || evs[0].Kind != Fork || evs[1].Kind != Exec || evs[2].Kind != Exit || evs[2].ExitCode != 0x100 {
		t.Fatalf("eventsIn = %+v", evs)
	}
	// A truncated trailing message is dropped, the whole ones before it kept.
	if got := eventsIn(buf[:len(buf)-3]); len(got) != 2 {
		t.Fatalf("truncated datagram gave %d events, want 2", len(got))
	}
}

// pair is a Listener over one end of a datagram socket pair: the same poll, read and close path as the real
// socket, with no privilege.
func pair(t *testing.T) (*Listener, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	l, err := newListener(fds[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close(); _ = unix.Close(fds[1]) })
	return l, fds[1]
}

func TestRecvDeliversEvents(t *testing.T) {
	l, peer := pair(t)
	if err := unix.Send(peer, datagram(Exec, u32(42, 42)), 0); err != nil {
		t.Fatal(err)
	}
	evs, err := l.Recv()
	if err != nil || len(evs) != 1 || evs[0].Kind != Exec || evs[0].TGID != 42 {
		t.Fatalf("Recv = %+v, %v", evs, err)
	}
}

// Close from another goroutine ends a Recv that is blocked, which a plain blocking recvfrom does not do.
func TestCloseWakesABlockedRecv(t *testing.T) {
	l, _ := pair(t)
	done := make(chan error, 1)
	go func() { _, err := l.Recv(); done <- err }()
	time.Sleep(50 * time.Millisecond) // let it block in poll
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Recv = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not wake the blocked Recv")
	}
	if _, err := l.Recv(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Recv after Close = %v, want ErrClosed", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestIsOverrun(t *testing.T) {
	if !IsOverrun(unix.ENOBUFS) || !IsOverrun(errors.Join(errors.New("procconn: recvfrom"), unix.ENOBUFS)) {
		t.Fatal("ENOBUFS is not an overrun")
	}
	if IsOverrun(unix.EAGAIN) || IsOverrun(nil) || IsOverrun(ErrClosed) {
		t.Fatal("another error counted as an overrun")
	}
}

func TestDrainReturnsWhatIsQueuedAndNeverBlocks(t *testing.T) {
	l, peer := pair(t)
	if evs, err := l.Drain(); err != nil || len(evs) != 0 {
		t.Fatalf("Drain of an empty queue = %v, %v", evs, err)
	}
	for _, pid := range []uint32{1, 2, 3} {
		if err := unix.Send(peer, datagram(Exec, u32(pid, pid)), 0); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := l.Drain()
	if err != nil || len(evs) != 3 || evs[0].TGID != 1 || evs[2].TGID != 3 {
		t.Fatalf("Drain = %+v, %v", evs, err)
	}
	if evs, _ := l.Drain(); len(evs) != 0 {
		t.Fatalf("a second Drain returned %d events", len(evs))
	}
	_ = l.Close()
	if _, err := l.Drain(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Drain after Close = %v", err)
	}
}
