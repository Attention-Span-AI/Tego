// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var update = flag.Bool("update", false, "rewrite the golden filter dumps under testdata/")

// seccompData encodes a struct seccomp_data for the x/net/bpf VM, which loads big-endian words:
// every 32-bit half sits at the offset the kernel's little-endian layout gives it.
func seccompData(arch Arch, nr uint32, args ...uint64) []byte {
	b := make([]byte, 64)
	be := binary.BigEndian
	be.PutUint32(b[offNR:], nr)
	be.PutUint32(b[offArch:], uint32(arch))
	for i, a := range args {
		be.PutUint32(b[offArg(i):], uint32(a))
		be.PutUint32(b[offArg(i)+4:], uint32(a>>32))
	}
	return b
}

func runFilter(t *testing.T, arch Arch, full bool, data []byte) uint32 {
	t.Helper()
	insts, err := BuildFilter(arch, full, false)
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

// TestFilterDecisions asserts docs/p0/enforce-landlock.md R11.
func TestFilterDecisions(t *testing.T) {
	const (
		x86Read   = 0
		x86Open   = 2
		x86OpenAt = 257
		armOpenAt = 56
		armRead   = 63
	)
	rdonly := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY)
	cases := []struct {
		name string
		arch Arch
		full bool
		data []byte
		want uint32
	}{
		{"x86 arch mismatch -> ENOSYS", ArchX86_64, false, seccompData(ArchARM64, x86Read), retENOSYS},
		{"arm64 arch mismatch -> ENOSYS", ArchARM64, false, seccompData(ArchX86_64, armRead), retENOSYS},
		{"x86 x32 bit -> ENOSYS", ArchX86_64, false, seccompData(ArchX86_64, x32Bit|x86Read), retENOSYS},
		{"x86 read -> allow", ArchX86_64, false, seccompData(ArchX86_64, x86Read), retAllow},
		{"arm64 read -> allow", ArchARM64, false, seccompData(ArchARM64, armRead), retAllow},
		{"io_uring_setup -> ENOSYS", ArchX86_64, false, seccompData(ArchX86_64, 425), retENOSYS},
		{"io_uring_enter -> ENOSYS", ArchARM64, false, seccompData(ArchARM64, 426), retENOSYS},
		{"io_uring_register -> ENOSYS", ArchX86_64, false, seccompData(ArchX86_64, 427), retENOSYS},
		{"openat2 -> ENOSYS", ArchARM64, false, seccompData(ArchARM64, 437), retENOSYS},
		// open_by_handle_at opens from a handle, not a path: no line could name what it opened (R10).
		{"x86 open_by_handle_at -> ENOSYS", ArchX86_64, false, seccompData(ArchX86_64, 304, 3, 0, unix.O_WRONLY), retENOSYS},
		{"arm64 open_by_handle_at -> ENOSYS", ArchARM64, false, seccompData(ArchARM64, 265, 3, 0, unix.O_RDONLY), retENOSYS},
		{"full: x86 open_by_handle_at -> ENOSYS", ArchX86_64, true, seccompData(ArchX86_64, 304, 3, 0, unix.O_RDONLY), retENOSYS},
		{"x86 name_to_handle_at -> allow", ArchX86_64, false, seccompData(ArchX86_64, 303), retAllow},
		{"arm64 name_to_handle_at -> allow", ArchARM64, false, seccompData(ArchARM64, 264), retAllow},
		{"connect -> notify", ArchX86_64, false, seccompData(ArchX86_64, 42), retNotify},
		{"arm64 connect -> notify", ArchARM64, false, seccompData(ArchARM64, 203), retNotify},
		{"sendmsg -> notify", ArchX86_64, false, seccompData(ArchX86_64, 46), retNotify},
		{"sendmmsg -> notify", ArchARM64, false, seccompData(ArchARM64, 269), retNotify},
		{"execve -> notify", ArchX86_64, false, seccompData(ArchX86_64, 59), retNotify},
		{"execveat -> notify", ArchARM64, false, seccompData(ArchARM64, 281), retNotify},
		{"creat -> notify, no flag test", ArchX86_64, false, seccompData(ArchX86_64, 85, 0, 0), retNotify},
		{"unlink -> notify", ArchX86_64, false, seccompData(ArchX86_64, 87), retNotify},
		{"rmdir -> notify", ArchX86_64, false, seccompData(ArchX86_64, 84), retNotify},
		{"unlinkat -> notify", ArchARM64, false, seccompData(ArchARM64, 35), retNotify},
		{"renameat2 -> notify", ArchX86_64, false, seccompData(ArchX86_64, 316), retNotify},
		{"mkdirat -> notify", ArchARM64, false, seccompData(ArchARM64, 34), retNotify},
		{"symlink -> notify", ArchX86_64, false, seccompData(ArchX86_64, 88), retNotify},
		{"sendto NULL addr -> allow", ArchX86_64, false, seccompData(ArchX86_64, 44, 3, 0, 0, 0, 0, 0), retAllow},
		{"sendto low-word addr -> notify", ArchX86_64, false, seccompData(ArchX86_64, 44, 3, 0, 0, 0, 0x1234, 0), retNotify},
		{"sendto high-word-only addr -> notify", ArchX86_64, false, seccompData(ArchX86_64, 44, 3, 0, 0, 0, 0x7f0000000000, 0), retNotify},
		{"arm64 sendto addr -> notify", ArchARM64, false, seccompData(ArchARM64, 206, 3, 0, 0, 0, 0x7ffd00001000, 16), retNotify},
		{"arm64 sendto NULL -> allow", ArchARM64, false, seccompData(ArchARM64, 206, 3, 0, 0, 0, 0, 0), retAllow},
		{"openat O_RDONLY -> allow", ArchX86_64, false, seccompData(ArchX86_64, x86OpenAt, ^uint64(0), 0, rdonly), retAllow},
		{"openat O_WRONLY -> notify", ArchX86_64, false, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_WRONLY), retNotify},
		{"openat O_RDWR -> notify", ArchX86_64, false, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_RDWR|unix.O_CLOEXEC), retNotify},
		{"openat O_CREAT -> notify", ArchX86_64, false, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_CREAT), retNotify},
		{"openat O_TRUNC -> notify", ArchX86_64, false, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_TRUNC), retNotify},
		{"openat O_TMPFILE|O_RDWR -> notify", ArchX86_64, false, seccompData(ArchX86_64, x86OpenAt, 0, 0, unix.O_TMPFILE|unix.O_RDWR), retNotify},
		{"open O_RDONLY -> allow", ArchX86_64, false, seccompData(ArchX86_64, x86Open, 0, rdonly), retAllow},
		{"open O_WRONLY -> notify", ArchX86_64, false, seccompData(ArchX86_64, x86Open, 0, unix.O_WRONLY|unix.O_CREAT), retNotify},
		{"arm64 openat O_RDONLY -> allow", ArchARM64, false, seccompData(ArchARM64, armOpenAt, 0, 0, rdonly), retAllow},
		{"arm64 openat O_WRONLY -> notify", ArchARM64, false, seccompData(ArchARM64, armOpenAt, 0, 0, unix.O_WRONLY), retNotify},
		{"full: openat O_RDONLY -> notify", ArchX86_64, true, seccompData(ArchX86_64, x86OpenAt, 0, 0, rdonly), retNotify},
		{"full: open O_RDONLY -> notify", ArchX86_64, true, seccompData(ArchX86_64, x86Open, 0, rdonly), retNotify},
		{"full: arm64 openat O_RDONLY -> notify", ArchARM64, true, seccompData(ArchARM64, armOpenAt, 0, 0, rdonly), retNotify},
		{"full: read still allowed", ArchX86_64, true, seccompData(ArchX86_64, x86Read), retAllow},
		{"x86 open number is not special on arm64", ArchARM64, false, seccompData(ArchARM64, x86Open), retAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runFilter(t, tc.arch, tc.full, tc.data); got != tc.want {
				t.Errorf("filter = %#x, want %#x", got, tc.want)
			}
		})
	}
}

// FuzzWriteFlag is R12 over the whole flag space: notify iff flags & 0x243 != 0.
func FuzzWriteFlag(f *testing.F) {
	f.Add(uint32(0))
	f.Add(uint32(unix.O_WRONLY))
	f.Add(uint32(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW))
	f.Add(uint32(unix.O_TMPFILE | unix.O_RDWR))
	f.Add(^uint32(0))
	x86, _ := BuildFilter(ArchX86_64, false, false)
	arm, _ := BuildFilter(ArchARM64, false, false)
	x86VM, _ := bpf.NewVM(x86)
	armVM, _ := bpf.NewVM(arm)
	f.Fuzz(func(t *testing.T, flags uint32) {
		want := uint32(retAllow)
		if flags&WriteFlagMask != 0 {
			want = retNotify
		}
		checks := []struct {
			vm   *bpf.VM
			data []byte
		}{
			{x86VM, seccompData(ArchX86_64, 257, 0, 0, uint64(flags))},
			{x86VM, seccompData(ArchX86_64, 2, 0, uint64(flags))},
			{armVM, seccompData(ArchARM64, 56, 0, 0, uint64(flags))},
		}
		for i, c := range checks {
			got, err := c.vm.Run(c.data)
			if err != nil {
				t.Fatal(err)
			}
			if uint32(got) != want {
				t.Fatalf("check %d flags %#x: got %#x want %#x", i, flags, got, want)
			}
		}
	})
}

// TestFilterGuardOrder is I6: the arch guard is the first thing evaluated and the x32 check follows
// it on x86_64 before any syscall-number comparison; arm64 has no x32 check at all.
//
// Spec: docs/p0/enforce-landlock.md R9.
func TestFilterGuardOrder(t *testing.T) {
	x86, err := BuildFilter(ArchX86_64, false, false)
	if err != nil {
		t.Fatal(err)
	}
	wantHead := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 4, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(ArchX86_64), SkipTrue: 1},
		bpf.RetConstant{Val: retENOSYS},
		bpf.LoadAbsolute{Off: 0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: x32Bit, SkipFalse: 1},
		bpf.RetConstant{Val: retENOSYS},
	}
	if !reflect.DeepEqual(x86[:len(wantHead)], wantHead) {
		t.Errorf("x86_64 head = %+v, want %+v", x86[:len(wantHead)], wantHead)
	}
	arm, err := BuildFilter(ArchARM64, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(arm[:4], wantHead[:4]) && !reflect.DeepEqual(arm[1], bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(ArchARM64), SkipTrue: 1}) {
		t.Errorf("arm64 head = %+v", arm[:4])
	}
	for i, ins := range arm {
		if j, ok := ins.(bpf.JumpIf); ok && j.Cond == bpf.JumpBitsSet && j.Val == x32Bit {
			t.Errorf("arm64 filter has an x32 check at %d", i)
		}
	}
	if last := x86[len(x86)-1]; last != (bpf.RetConstant{Val: retAllow}) {
		t.Errorf("last instruction = %+v, want ALLOW", last)
	}
	// No always-notified syscall carries a flag test: every notify of the table is a plain
	// compare-then-return pair.
	tbl, _ := tableFor(ArchX86_64)
	for _, s := range tbl.Notify {
		for i, ins := range x86 {
			if j, ok := ins.(bpf.JumpIf); ok && j.Cond == bpf.JumpEqual && j.Val == s.NR {
				if x86[i+1] != (bpf.RetConstant{Val: retNotify}) || j.SkipFalse != 1 {
					t.Errorf("%s: compare at %d is not followed by a plain notify", s.Name, i)
				}
			}
		}
	}
}

func TestFilterAssembleRoundTrip(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		for _, full := range []bool{false, true} {
			insts, err := BuildFilter(arch, full, false)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := assembleFilter(arch, filterOpts{full: full, abi: minTruncateABI, unixBinds: true})
			if err != nil {
				t.Fatal(err)
			}
			back, all := bpf.Disassemble(raw)
			if !all {
				t.Errorf("%s full=%v: not every instruction disassembled", arch, full)
			}
			// The disassembler normalizes a jump with only a false branch to its inverse condition,
			// so the round trip is checked on the assembled form.
			again, err := bpf.Assemble(back)
			if err != nil || !reflect.DeepEqual(again, raw) || len(back) != len(insts) {
				t.Errorf("%s full=%v: disassembly does not re-assemble to the same program (%v)", arch, full, err)
			}
			if len(raw) > 4096 {
				t.Errorf("%s: %d instructions exceeds BPF_MAXINSNS", arch, len(raw))
			}
		}
	}
	if _, err := BuildFilter(Arch(0x12345678), false, false); err == nil {
		t.Error("unknown arch built a filter")
	}
}

// TestFilterGolden keeps a human-readable dump per arch and record mode under testdata/ (§10).
//
// Spec: docs/p0/enforce-landlock.md R9, R11, R16.
func TestFilterGolden(t *testing.T) {
	cases := []struct {
		file string
		arch Arch
		full bool
	}{
		{"filter_x86_64.txt", ArchX86_64, false},
		{"filter_x86_64_full.txt", ArchX86_64, true},
		{"filter_arm64.txt", ArchARM64, false},
		{"filter_arm64_full.txt", ArchARM64, true},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			insts, err := BuildFilter(tc.arch, tc.full, false)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			for i, ins := range insts {
				fmt.Fprintf(&buf, "%3d %-16T %v\n", i, ins, ins)
			}
			path := filepath.Join("testdata", tc.file)
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if !bytes.Equal(want, buf.Bytes()) {
				t.Errorf("filter differs from %s:\n%s", path, buf.String())
			}
		})
	}
}

// TestNativeArch asserts docs/p0/enforce-landlock.md R9.
func TestNativeArch(t *testing.T) {
	a := NativeArch()
	if a != ArchX86_64 && a != ArchARM64 {
		t.Errorf("NativeArch = %s", a)
	}
	if ArchX86_64.String() != "x86_64" || ArchARM64.String() != "arm64" || Arch(7).String() != "arch(0x7)" {
		t.Error("Arch.String")
	}
}

func BenchmarkBuildFilter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := assembleFilter(ArchX86_64, filterOpts{full: false, abi: minTruncateABI}); err != nil {
			b.Fatal(err)
		}
	}
}
