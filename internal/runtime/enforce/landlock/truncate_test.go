// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// runFilterABI is runFilter for a chosen Landlock ABI: the truncation arms are the only part of the
// program that depends on it (R2's ABI-3 row).
func runFilterABI(t *testing.T, arch Arch, full bool, abi int, data []byte) uint32 {
	t.Helper()
	insts, err := buildFilter(arch, filterOpts{full: full, abi: abi})
	if err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	ret, err := vm.Run(data)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return uint32(ret)
}

// TestFilterTruncateBelowABI3 is R2's ABI-3 degrade row and E31.
//
// LANDLOCK_ACCESS_FS_TRUNCATE arrived with ABI 3 (kernel 6.2); before it the kernel has no
// path_truncate hook, and the Landlock documentation states it outright: "File truncation could not be
// denied before the third Landlock ABI, so it is always allowed when using a kernel that only supports
// the first or second ABI." ARCHITECTURE §14's tested floor is 6.1 and names Amazon Linux 2023 (ABI 2),
// so this is a supported configuration, not a corner. truncate(2) takes a path and needs no fd, so
// neither the write-flag test nor any notify arm sees it: without these arms an agent on a 6.1 kernel
// truncates any DAC-writable file to zero while SEMANTICS §1 promises `fs: {}` refuses truncate.
//
// The O_RDONLY|O_TRUNC shape (and O_ACCMODE|O_TRUNC, access mode 3) is the same hole through open(2): Landlock's file_open access derives
// WRITE_FILE from FMODE_WRITE, which O_RDONLY does not set, while the VFS truncates anyway. It is
// notified (WriteFlagMask covers O_TRUNC) but the supervisor's open handler is record-only and answers
// CONTINUE, so the notification would record the truncation rather than prevent it.
//
// Spec: docs/p0/enforce-landlock.md E31.
func TestFilterTruncateBelowABI3(t *testing.T) {
	const (
		x86Truncate  = 76
		x86FTruncate = 77
		x86Open      = 2
		x86OpenAt    = 257
		armTruncate  = 45
		armFTruncate = 46
		armOpenAt    = 56
	)
	rdonlyTrunc := uint64(unix.O_RDONLY | unix.O_TRUNC)
	accmodeTrunc := uint64(unix.O_ACCMODE | unix.O_TRUNC)
	cases := []struct {
		name string
		arch Arch
		full bool
		abi  int
		data []byte
		want uint32
	}{
		{"abi2 truncate -> EPERM", ArchX86_64, false, 2, seccompData(ArchX86_64, x86Truncate, 0, 0), retEPERM},
		{"abi1 truncate -> EPERM", ArchX86_64, false, 1, seccompData(ArchX86_64, x86Truncate, 0, 0), retEPERM},
		{"abi2 arm64 truncate -> EPERM", ArchARM64, false, 2, seccompData(ArchARM64, armTruncate, 0, 0), retEPERM},
		// ABI 3+ has the right and decides per path, so the blunt arm disappears; the call is notified so the
		// supervisor records it (R11).
		{"abi3 truncate -> notify", ArchX86_64, false, 3, seccompData(ArchX86_64, x86Truncate, 0, 0), retNotify},
		{"abi7 truncate -> notify", ArchX86_64, false, 7, seccompData(ArchX86_64, x86Truncate, 0, 0), retNotify},
		{"abi7 arm64 truncate -> notify", ArchARM64, false, 7, seccompData(ArchARM64, armTruncate, 0, 0), retNotify},
		// ftruncate needs a fd opened for writing, and WRITE_FILE is handled from ABI 1: the open
		// already decided it, so refusing it here would be over-restriction with no gap behind it.
		{"abi2 ftruncate -> allow", ArchX86_64, false, 2, seccompData(ArchX86_64, x86FTruncate, 3, 0), retAllow},
		{"abi2 arm64 ftruncate -> allow", ArchARM64, false, 2, seccompData(ArchARM64, armFTruncate, 3, 0), retAllow},
		// open(2) with O_TRUNC: only the O_RDONLY shape is unreachable for Landlock below ABI 3.
		{"abi2 openat O_RDONLY|O_TRUNC -> EPERM", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, rdonlyTrunc), retEPERM},
		{"abi2 open O_RDONLY|O_TRUNC -> EPERM", ArchX86_64, false, 2, seccompData(ArchX86_64, x86Open, 0, rdonlyTrunc), retEPERM},
		{"abi2 arm64 openat O_RDONLY|O_TRUNC -> EPERM", ArchARM64, false, 2, seccompData(ArchARM64, armOpenAt, 0, 0, rdonlyTrunc), retEPERM},
		// record: full notifies every open; the refusal must still come first, because a notified open
		// is answered CONTINUE by the record-only handler and would truncate.
		{"abi2 full openat O_RDONLY|O_TRUNC -> EPERM", ArchX86_64, true, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, rdonlyTrunc), retEPERM},
		// Access mode 3 (O_ACCMODE) is a legal open that gives an fd with neither FMODE_READ nor FMODE_WRITE,
		// so Landlock below ABI 3 checks nothing, yet the VFS still truncates: refused like O_RDONLY.
		{"abi2 openat O_ACCMODE|O_TRUNC -> EPERM", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, accmodeTrunc), retEPERM},
		{"abi2 open O_ACCMODE|O_TRUNC -> EPERM", ArchX86_64, false, 2, seccompData(ArchX86_64, x86Open, 0, accmodeTrunc), retEPERM},
		{"abi2 arm64 openat O_ACCMODE|O_TRUNC -> EPERM", ArchARM64, false, 2, seccompData(ArchARM64, armOpenAt, 0, 0, accmodeTrunc), retEPERM},
		{"abi2 full openat O_ACCMODE|O_TRUNC -> EPERM", ArchX86_64, true, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, accmodeTrunc), retEPERM},
		// Mode 3 without O_TRUNC is untouched by the arm.
		{"abi2 openat O_ACCMODE -> notify", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_ACCMODE), retNotify},
		{"abi2 full openat O_WRONLY|O_TRUNC -> notify", ArchX86_64, true, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_WRONLY|unix.O_TRUNC), retNotify},
		// A write-mode O_TRUNC asks Landlock for WRITE_FILE, handled since ABI 1: notify, do not refuse.
		{"abi2 openat O_WRONLY|O_TRUNC -> notify", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_WRONLY|unix.O_TRUNC), retNotify},
		{"abi2 openat O_RDWR|O_TRUNC -> notify", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_RDWR|unix.O_TRUNC), retNotify},
		// No O_TRUNC, and ABI 3+ with O_TRUNC, keep exactly the behaviour they had.
		{"abi2 openat O_RDONLY -> allow", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_RDONLY|unix.O_CLOEXEC), retAllow},
		{"abi3 openat O_RDONLY|O_TRUNC -> notify", ArchX86_64, false, 3, seccompData(ArchX86_64, x86OpenAt, 0, 0, rdonlyTrunc), retNotify},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runFilterABI(t, tc.arch, tc.full, tc.abi, tc.data); got != tc.want {
				t.Errorf("filter = %#x, want %#x", got, tc.want)
			}
		})
	}
}

// TestPrepareThreadsABIIntoFilter is the wiring the fix depends on: build() must assemble the filter
// with the *probed* ABI, not a constant. A Prepare that always used the ABI-3 form would pass every
// case above and still ship a 6.1-class run with truncation unrestricted — the same shape of gap
// TestPrepareRecordFull guards for record: full.
func TestPrepareThreadsABIIntoFilter(t *testing.T) {
	const x86Truncate, armTruncate = 76, 45
	nr := uint32(x86Truncate)
	if NativeArch() == ArchARM64 {
		nr = armTruncate
	}
	for _, tc := range []struct {
		abi  int
		want uint32
	}{{2, retEPERM}, {7, retNotify}} {
		h, _ := prepare(t, tc.abi, &agent.RuleTable{})
		raw, ok := h.SeccompFilter()
		if !ok {
			t.Fatalf("ABI %d: no filter on the handle", tc.abi)
		}
		insts, all := bpf.Disassemble(raw)
		if !all {
			t.Fatalf("ABI %d: not every instruction disassembled", tc.abi)
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatalf("ABI %d: NewVM: %v", tc.abi, err)
		}
		got, err := vm.Run(seccompData(NativeArch(), nr, 0, 0))
		if err != nil {
			t.Fatalf("ABI %d: Run: %v", tc.abi, err)
		}
		if uint32(got) != tc.want {
			t.Errorf("ABI %d: truncate = %#x, want %#x (Prepare did not thread the probed ABI into the filter)", tc.abi, got, tc.want)
		}
	}
}
