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
// WRITE_FILE from FMODE_WRITE, which O_RDONLY does not set, while the VFS truncates anyway. An open the filter
// merely notifies (WriteFlagMask covers O_TRUNC) is recorded and continued by the supervisor, which would truncate, so
// the arm notifies it ahead of the open family's own arms and the supervisor refuses it with EPERM and a line
// (supervisor.TestNoTruncateRightRefusesWithALine). The filter returns the notification, not the errno: the same calls
// are refused, TestTruncationArmsRefuseWhatTheyAlwaysDid pins that, and the answer is the supervisor's.
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
		{"abi2 truncate -> notify (the supervisor refuses it)", ArchX86_64, false, 2, seccompData(ArchX86_64, x86Truncate, 0, 0), retNotify},
		{"abi1 truncate -> notify (the supervisor refuses it)", ArchX86_64, false, 1, seccompData(ArchX86_64, x86Truncate, 0, 0), retNotify},
		{"abi2 arm64 truncate -> notify (the supervisor refuses it)", ArchARM64, false, 2, seccompData(ArchARM64, armTruncate, 0, 0), retNotify},
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
		{"abi2 openat O_RDONLY|O_TRUNC -> notify (the supervisor refuses it)", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, rdonlyTrunc), retNotify},
		{"abi2 open O_RDONLY|O_TRUNC -> notify (the supervisor refuses it)", ArchX86_64, false, 2, seccompData(ArchX86_64, x86Open, 0, rdonlyTrunc), retNotify},
		{"abi2 arm64 openat O_RDONLY|O_TRUNC -> notify (the supervisor refuses it)", ArchARM64, false, 2, seccompData(ArchARM64, armOpenAt, 0, 0, rdonlyTrunc), retNotify},
		// record: full notifies every open; the refusal must still come first, because a notified open
		// is answered CONTINUE by the record-only handler and would truncate.
		{"abi2 full openat O_RDONLY|O_TRUNC -> notify (the supervisor refuses it)", ArchX86_64, true, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, rdonlyTrunc), retNotify},
		// Access mode 3 (O_ACCMODE) is a legal open that gives an fd with neither FMODE_READ nor FMODE_WRITE,
		// so Landlock below ABI 3 checks nothing, yet the VFS still truncates: refused like O_RDONLY.
		{"abi2 openat O_ACCMODE|O_TRUNC -> notify (the supervisor refuses it)", ArchX86_64, false, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, accmodeTrunc), retNotify},
		{"abi2 open O_ACCMODE|O_TRUNC -> notify (the supervisor refuses it)", ArchX86_64, false, 2, seccompData(ArchX86_64, x86Open, 0, accmodeTrunc), retNotify},
		{"abi2 arm64 openat O_ACCMODE|O_TRUNC -> notify (the supervisor refuses it)", ArchARM64, false, 2, seccompData(ArchARM64, armOpenAt, 0, 0, accmodeTrunc), retNotify},
		{"abi2 full openat O_ACCMODE|O_TRUNC -> notify (the supervisor refuses it)", ArchX86_64, true, 2, seccompData(ArchX86_64, x86OpenAt, 0, 0, accmodeTrunc), retNotify},
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
// with the *probed* ABI, not a constant, and the handle must give the supervisor the same ABI's answer. A Prepare that
// always used the ABI-3 form would pass every case above and still ship a 6.1-class run with truncation
// unrestricted — the same shape of gap TestPrepareRecordFull guards for record: full. truncate(2) is notified at
// every ABI now (below 3 for the supervisor to refuse it, from 3 to record and continue it), so the filter's verdict
// no longer tells the two apart: the handle's own word (LandlockDecidesTruncate, which the supervisor's
// Options.LandlockTruncate is set from) and the opts the filter was built from do.
func TestPrepareThreadsABIIntoFilter(t *testing.T) {
	const x86Truncate, armTruncate = 76, 45
	nr := uint32(x86Truncate)
	if NativeArch() == ArchARM64 {
		nr = armTruncate
	}
	for _, tc := range []struct {
		abi         int
		decidesTrnc bool
	}{{1, false}, {2, false}, {3, true}, {7, true}} {
		h, _ := prepare(t, tc.abi, &agent.RuleTable{})
		if h.filterOpts.abi != tc.abi || h.abi != tc.abi {
			t.Errorf("ABI %d: the filter was built for ABI %d and the handle says %d (Prepare did not thread the probed ABI)", tc.abi, h.filterOpts.abi, h.abi)
		}
		if got := h.LandlockDecidesTruncate(); got != tc.decidesTrnc {
			t.Errorf("ABI %d: LandlockDecidesTruncate = %v, want %v", tc.abi, got, tc.decidesTrnc)
		}
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
		if uint32(got) != retNotify {
			t.Errorf("ABI %d: truncate = %#x, want a notification (retNotify %#x): the supervisor answers it", tc.abi, got, retNotify)
		}
	}
}

// TestTruncationArmsRefuseWhatTheyAlwaysDid pins that moving the truncation arms from an errno to a notification
// changed no decision. The reference is the old arms written as a plain function of the call: below ABI 3 every
// truncate(2) is refused, and so is every open or openat whose flags carry O_TRUNC with an access mode that is neither
// O_WRONLY nor O_RDWR, with every other call left to the filter's other arms. For a grid of flags on both
// architectures, with and without record: full and the plane's skips, a refused call must be the notification and any other
// call must get exactly the verdict the ABI-3 filter gives it (so the ABI-2 filter adds nothing and drops nothing but
// truncate(2)'s own notification, which it now makes unconditional: the plane never skips it below ABI 3).
func TestTruncationArmsRefuseWhatTheyAlwaysDid(t *testing.T) {
	type call struct {
		name string
		nr   uint32
		arg  int // the flags' argument index; -1 for a call with none
	}
	tables := map[Arch][]call{
		ArchX86_64: {{"truncate", 76, -1}, {"ftruncate", 77, -1}, {"open", 2, 1}, {"openat", 257, 2}, {"creat", 85, -1}, {"unlink", 87, -1}},
		ArchARM64:  {{"truncate", 45, -1}, {"ftruncate", 46, -1}, {"openat", 56, 2}},
	}
	flagBits := []uint64{unix.O_CREAT, unix.O_TRUNC, unix.O_PATH, unix.O_APPEND, unix.O_DIRECTORY, unix.O_NOFOLLOW, unix.O_CLOEXEC}
	var flagsGrid []uint64
	for acc := uint64(0); acc <= 3; acc++ {
		for mask := 0; mask < 1<<len(flagBits); mask++ {
			f := acc
			for i, b := range flagBits {
				if mask&(1<<i) != 0 {
					f |= b
				}
			}
			flagsGrid = append(flagsGrid, f)
		}
	}
	// Bits above the low 32 are not the kernel's flags: it reads an int. The arm must not be steered by them.
	flagsGrid = append(flagsGrid, 1<<32|unix.O_RDONLY|unix.O_TRUNC, 1<<32|unix.O_WRONLY|unix.O_TRUNC, 1<<40)
	refusedBelow3 := func(c call, flags uint64) bool {
		if c.name == "truncate" {
			return true
		}
		if c.arg < 0 || (c.name != "open" && c.name != "openat") {
			return false
		}
		f := uint32(flags)
		acc := f & unix.O_ACCMODE
		return f&unix.O_TRUNC != 0 && acc != unix.O_WRONLY && acc != unix.O_RDWR
	}
	verdict := func(arch Arch, o filterOpts, c call, flags uint64) uint32 {
		args := make([]uint64, 6)
		if c.arg >= 0 {
			args[c.arg] = flags
		}
		insts, err := buildFilter(arch, o)
		if err != nil {
			t.Fatal(err)
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatal(err)
		}
		got, err := vm.Run(seccompData(arch, c.nr, args...))
		if err != nil {
			t.Fatal(err)
		}
		return uint32(got)
	}
	all := planeSkips(hookSet(append(append([]string(nil), stepAHooks...), stepBHooks...)...), false, false)
	for arch, calls := range tables {
		for _, full := range []bool{false, true} {
			for _, withPlane := range []bool{false, true} {
				below, at := filterOpts{full: full, abi: 2}, filterOpts{full: full, abi: 3}
				if withPlane {
					below.plane, at.plane = all, all
				}
				for _, c := range calls {
					grid := flagsGrid
					if c.arg < 0 {
						grid = flagsGrid[:1] // no flags to vary
					}
					for _, flags := range grid {
						got, want := verdict(arch, below, c, flags), verdict(arch, at, c, flags)
						refused := refusedBelow3(c, flags)
						switch {
						case refused && got != retNotify:
							t.Fatalf("%s %s full=%v plane=%v flags %#x: got %#x, want a notification (the call was refused below ABI 3)", arch, c.name, full, withPlane, flags, got)
						case !refused && got != want:
							t.Fatalf("%s %s full=%v plane=%v flags %#x: the ABI-2 filter gives %#x, the ABI-3 filter %#x: the arm now decides a call it never did", arch, c.name, full, withPlane, flags, got, want)
						case !refused && got == retEPERM:
							t.Fatalf("%s %s flags %#x: EPERM from a call the arm never refused", arch, c.name, flags)
						}
					}
				}
			}
		}
	}
}
