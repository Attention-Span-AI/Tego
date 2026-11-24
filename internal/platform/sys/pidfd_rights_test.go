// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestFDProcInfo(t *testing.T) {
	var empty *FD
	if _, err := empty.ProcInfo(); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil descriptor: %v", err)
	}
	h, err := PidfdOpenProcessFD(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	data, err := h.ProcInfo()
	if err != nil || !strings.Contains(string(data), "Pid:\t"+strconv.Itoa(os.Getpid())+"\n") {
		t.Fatalf("wrong process information: %s %v", data, err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ProcInfo(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed descriptor: %v", err)
	}
}

func TestReceivePidfdsOwnsAndCleansHandles(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     int
		malformed bool
		separate  bool
		partial   bool
	}{
		{name: "valid", count: 1},
		{name: "malformed tail", count: 1, malformed: true},
		{name: "two handles in one payload", count: 2, malformed: true},
		{name: "partial payload after whole handles", count: 2, malformed: true, partial: true},
		{name: "duplicate messages stay separately owned", count: 2, separate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var numbers []int
			for range tc.count {
				n, err := unix.PidfdOpen(os.Getpid(), 0)
				if err != nil {
					for _, prior := range numbers {
						_ = unix.Close(prior)
					}
					t.Fatal(err)
				}
				numbers = append(numbers, n)
			}
			// Model an already-installed SCM_PIDFD delivered by recvmsg. This
			// fresh number has no other owner, exactly the receiver contract.
			message := func(numbers ...int) []byte {
				oob := unix.UnixRights(numbers...)
				(*unix.Cmsghdr)(unsafe.Pointer(&oob[0])).Type = unix.SCM_PIDFD
				return oob
			}
			oob := message(numbers...)
			if tc.separate {
				oob = append(message(numbers[0]), message(numbers[1])...)
			} else if tc.partial {
				padded := make([]byte, unix.CmsgSpace(4*len(numbers)+1))
				copy(padded, oob)
				(*unix.Cmsghdr)(unsafe.Pointer(&padded[0])).SetLen(unix.CmsgLen(4*len(numbers) + 1))
				oob = padded
			} else if tc.malformed && tc.count == 1 {
				oob = append(oob, 1)
			}
			assertClosed := func() {
				t.Helper()
				for _, n := range numbers {
					if _, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
						t.Errorf("receive/close leaked pidfd %d: %v", n, err)
						_ = unix.Close(n)
					}
				}
			}
			owned, err := ReceivePidfds(oob)
			if tc.malformed {
				if err == nil || len(owned) != 0 {
					for _, h := range owned {
						_ = h.Close()
					}
					t.Errorf("malformed message retained handles: %v %v", owned, err)
				}
				assertClosed()
				return
			}
			if err != nil || len(owned) != tc.count {
				for _, h := range owned {
					_ = h.Close()
				}
				t.Fatalf("handle not owned: %v %v", owned, err)
			}
			for _, h := range owned {
				if exited, err := PollPidfdFD(h, 0); exited || err != nil {
					t.Errorf("wrong sender handle: exited=%v err=%v", exited, err)
				}
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			}
			assertClosed()
		})
	}
}
