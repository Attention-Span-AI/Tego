// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// memfdRaw is memfd_create(2) as a raw syscall, the form runFiltered's fn must use; the descriptor it
// returns is closed at once.
func memfdRaw(name *byte, flags int) error {
	fd, _, e := unix.Syscall(unix.SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(name)), uintptr(flags), 0)
	if e != 0 {
		return e
	}
	unix.Syscall(unix.SYS_CLOSE, fd, 0, 0)
	return nil
}

// TestFilterMemfdArmsOnKernel is the memfd arm's two closing forms against the real kernel.
//
// The refusing arm, which a restricted-exec run gets on a kernel below 6.3, answers every memfd_create
// ENOSYS whatever its flags: there no flag makes a memfd non-executable. It is a syscall-number arm, so it
// installs and is exercised on any kernel, this one included.
//
// The sealing arm allows a memfd created with MFD_NOEXEC_SEAL and refuses one without it, and refuses a
// hugetlb memfd even with the flag: the control below shows why, on a kernel that creates one, since an
// fchmod then gives the sealed hugetlb memfd its execute bits back where a sealed shmem one refuses it.
func TestFilterMemfdArmsOnKernel(t *testing.T) {
	name, err := unix.BytePtrFromString("tego-arm")
	if err != nil {
		t.Fatal(err)
	}

	if MemfdNoexecSealSupported() {
		// The control, outside every filter: what the sealing arm has to refuse and why.
		if fd, err := unix.MemfdCreate("tego-hugetlb", mfdHugetlb|mfdNoexecSeal|unix.MFD_CLOEXEC); err == nil {
			if cerr := unix.Fchmod(fd, 0o755); cerr == nil {
				t.Log("a sealed hugetlb memfd took fchmod 0755: F_SEAL_EXEC is not enforced on hugetlbfs")
			} else {
				t.Logf("a sealed hugetlb memfd refused fchmod (%v) on this kernel", cerr)
			}
			_ = unix.Close(fd)
		} else {
			t.Logf("no hugetlb memfd on this kernel (%v); the arm's refusal is still exercised", err)
		}

		sealed, err := assembleFilter(NativeArch(), filterOpts{abi: minTruncateABI, memfd: MemfdSealed})
		if err != nil {
			t.Fatal(err)
		}
		errs, ok := runFiltered(sealed, func() []error {
			return []error{
				memfdRaw(name, 0),
				memfdRaw(name, mfdNoexecSeal|unix.MFD_CLOEXEC),
				memfdRaw(name, mfdHugetlb|mfdNoexecSeal|unix.MFD_CLOEXEC),
			}
		})
		if !ok {
			t.Skip("could not install a seccomp filter on this thread")
		}
		if !errors.Is(errs[0], unix.EACCES) {
			t.Errorf("sealing arm: a flagless memfd_create returned %v, want EACCES", errs[0])
		}
		if errs[1] != nil {
			t.Errorf("sealing arm: a sealed data memfd was refused (%v); ordinary shared memory must work", errs[1])
		}
		if !errors.Is(errs[2], unix.EACCES) {
			t.Errorf("sealing arm: a sealed hugetlb memfd returned %v, want EACCES: hugetlbfs ignores F_SEAL_EXEC", errs[2])
		}
	} else {
		t.Log("kernel does not honour MFD_NOEXEC_SEAL; only the refusing arm applies here")
	}

	refused, err := assembleFilter(NativeArch(), filterOpts{abi: minTruncateABI, memfd: MemfdRefused})
	if err != nil {
		t.Fatal(err)
	}
	errs, ok := runFiltered(refused, func() []error {
		return []error{
			memfdRaw(name, 0),
			memfdRaw(name, unix.MFD_CLOEXEC),
			memfdRaw(name, mfdNoexecSeal|unix.MFD_CLOEXEC),
		}
	})
	if !ok {
		t.Skip("could not install a seccomp filter on this thread")
	}
	for i, e := range errs {
		if !errors.Is(e, unix.ENOSYS) {
			t.Errorf("refusing arm, call %d: memfd_create returned %v, want ENOSYS", i, e)
		}
	}
}
