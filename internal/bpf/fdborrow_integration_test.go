// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestBorrowsKeepTheObjectReachable: the object is reachable from nothing but the borrow, and the collector
// runs inside fn, which is when cilium's cleanup would close the number; the number still names the object
// when fn reads it, for a map and for a program (ADR 0023 A4, T3.3).
func TestBorrowsKeepTheObjectReachable(t *testing.T) {
	requireBPF(t)
	check := func(want string) func(fd int) error {
		return func(fd int) error {
			for range 3 {
				runtime.GC()
				time.Sleep(10 * time.Millisecond) // cleanups run on their own goroutine
			}
			link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			if err != nil {
				return fmt.Errorf("fd %d under the borrow: %w", fd, err)
			}
			if link != want {
				return fmt.Errorf("fd %d under the borrow names %q, want %q", fd, link, want)
			}
			return nil
		}
	}
	if err := borrowDroppedMap(check("anon_inode:bpf-map")); err != nil {
		t.Fatal(err)
	}
	if err := borrowDroppedProgram(check("anon_inode:bpf-prog")); err != nil {
		t.Fatal(err)
	}
}

// borrowDroppedMap makes a map whose one reference is MapFD's argument.
//
//go:noinline
func borrowDroppedMap(fn func(int) error) error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		return err
	}
	return MapFD(m, fn)
}

// borrowDroppedProgram makes a program whose one reference is ProgramFD's argument.
//
//go:noinline
func borrowDroppedProgram(fn func(int) error) error {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		return errors.Join(errors.New("load a socket filter"), err)
	}
	return ProgramFD(p, fn)
}
