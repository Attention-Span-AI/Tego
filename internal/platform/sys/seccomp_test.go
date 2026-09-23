// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func TestCheckSeccompNotifLayout(t *testing.T) {
	if err := CheckSeccompNotifLayout(); err != nil {
		t.Fatal(err)
	}
}

func TestSeccompSetFilterRejectsBadPrograms(t *testing.T) {
	tests := []struct {
		name string
		prog []bpf.RawInstruction
	}{
		{"empty", nil},
		{"too long", make([]bpf.RawInstruction, unix.BPF_MAXINSNS+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SeccompSetFilterNewListener(tc.prog)
			if !errors.Is(err, unix.EINVAL) {
				t.Fatalf("got %v, want EINVAL", err)
			}
		})
	}
}

func TestLandlockABI(t *testing.T) {
	abi, err := LandlockABI()
	if err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	if abi < 1 {
		t.Fatalf("ABI %d", abi)
	}
}

// TestSeccompSetFilterRefusesMismatchedLayout proves the layout check is wired into the one call that
// creates a listener. seccomp_unotify(2) tells the supervisor to take its struct sizes from
// SECCOMP_GET_NOTIF_SIZES; a kernel that disagrees with this build encodes a different size into the
// SECCOMP_IOCTL_NOTIF_RECV ioctl number, so the listener is unreadable and the first RECV returns EINVAL
// long after the agent has started. Refusing to create the listener turns that into a startup error.
func TestSeccompSetFilterRefusesMismatchedLayout(t *testing.T) {
	real := getNotifSizes
	t.Cleanup(func() { getNotifSizes = real })
	sizes, err := real()
	if err != nil {
		t.Fatal(err)
	}
	sizes.Notif += 8 // a kernel that grew struct seccomp_notif, the case GET_NOTIF_SIZES exists for
	getNotifSizes = func() (SeccompNotifSizes, error) { return sizes, nil }

	if err := CheckSeccompNotifLayout(); !errors.Is(err, ErrSeccompNotifLayout) {
		t.Fatalf("CheckSeccompNotifLayout = %v, want ErrSeccompNotifLayout", err)
	}
	// nil program: the layout gate runs before the argument checks, so nothing here can install a filter
	// on this thread. Without the gate this returns the empty-program EINVAL instead.
	if _, err := SeccompSetFilterNewListener(nil); !errors.Is(err, ErrSeccompNotifLayout) {
		t.Fatalf("SeccompSetFilterNewListener under a mismatched layout = %v, want ErrSeccompNotifLayout", err)
	}
}

// TestSeccompNotifSetFlagsRejectsNonListener checks the ioctl number and the error wrapping without a
// listener: every fd that is not a seccomp notification fd answers SECCOMP_IOCTL_NOTIF_SET_FLAGS with
// ENOTTY, so a wrong ioctl number or a dropped errno shows up here. The real listener case is in
// TestSeccompNotifSetFlagsSyncWakeUp, behind the integration tag.
func TestSeccompNotifSetFlagsRejectsNonListener(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := SeccompNotifSetFlags(int(f.Fd()), SeccompUserNotifFdSyncWakeUp); !errors.Is(err, unix.ENOTTY) {
		t.Fatalf("SET_FLAGS on %s = %v, want ENOTTY", os.DevNull, err)
	}
}

// TestSeccompSetFilterAsksForWaitKillableRecv pins the flag choice without installing anything: the
// listener is asked for with WAIT_KILLABLE_RECV, which closes docs/p0/supervisor.md E35's double side
// effect, and a kernel that does not know the flag (EINVAL, below 5.19) still gets a listener with
// NEW_LISTENER alone. Any other refusal is returned as it is, with no second attempt.
func TestSeccompSetFilterAsksForWaitKillableRecv(t *testing.T) {
	real := seccompSetFilter
	t.Cleanup(func() { seccompSetFilter = real })
	prog, err := bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}})
	if err != nil {
		t.Fatal(err)
	}
	const both = unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	for _, tc := range []struct {
		name    string
		answers []unix.Errno
		want    []uintptr
		wantErr error
	}{
		{"a 5.19+ kernel", []unix.Errno{0}, []uintptr{both}, nil},
		{"a kernel without the flag", []unix.Errno{unix.EINVAL, 0}, []uintptr{both, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER}, nil},
		{"a chain that already has a listener", []unix.Errno{unix.EBUSY}, []uintptr{both}, unix.EBUSY},
		{"a malformed program", []unix.Errno{unix.EINVAL, unix.EINVAL}, []uintptr{both, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER}, unix.EINVAL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []uintptr
			seccompSetFilter = func(flags uintptr, _ *unix.SockFprog) (int, unix.Errno) {
				e := tc.answers[len(got)]
				got = append(got, flags)
				if e != 0 {
					return -1, e
				}
				return 42, 0
			}
			fd, err := SeccompSetFilterNewListener(prog)
			if len(got) != len(tc.want) {
				t.Fatalf("calls = %#x, want %#x", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("call %d flags = %#x, want %#x", i, got[i], tc.want[i])
				}
			}
			if tc.wantErr == nil && (err != nil || fd != 42) {
				t.Errorf("fd, err = %d, %v; want the listener", fd, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
