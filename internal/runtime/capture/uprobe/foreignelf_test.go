// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"debug/elf"
	bin "encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// foreignMachine is an ELF machine this build is not.
func foreignMachine() elf.Machine {
	if nativeMachine() == elf.EM_386 {
		return elf.EM_X86_64
	}
	return elf.EM_386
}

// elf32Header is a bare ELFCLASS32 shared object of the given machine: a header, no sections.
func elf32Header(machine elf.Machine) []byte {
	h := make([]byte, 52)
	copy(h[0:4], "\x7fELF")
	h[4], h[5], h[6] = 1, 1, 1 // ELFCLASS32, ELFDATA2LSB, EV_CURRENT
	le := bin.LittleEndian
	le.PutUint16(h[16:], uint16(elf.ET_DYN))
	le.PutUint16(h[18:], uint16(machine))
	le.PutUint32(h[20:], 1)
	le.PutUint16(h[40:], 52) // e_ehsize
	le.PutUint16(h[42:], 32) // e_phentsize
	le.PutUint16(h[46:], 40) // e_shentsize
	return h
}

// TestOpenedForeignLibsslIsNotAttached: a libssl a process opens by name, or maps at its exec, is attached only
// when it is a 64-bit ELF for this build's machine, as pre-attach already required (nativeELF). The probes read
// their arguments by this machine's 64-bit calling convention, so on a 32-bit or foreign library they would read
// garbage for the buffer and the length. A foreign one that exports R1-R3 is refused before any probe goes on,
// and a 32-bit one is ErrNotELF, the binary's one attempt, rather than a symbol-table parse.
func TestOpenedForeignLibsslIsNotAttached(t *testing.T) {
	tree := newProcTree(t)
	syms := map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180}
	b, err := os.ReadFile(writeELF(t, elfOptions{Dynamic: syms, Machine: foreignMachine()}))
	if err != nil {
		t.Fatal(err)
	}
	lib := tree.inRoot(t, 83, "usr/lib/i386-linux-gnu/libssl.so.3", b)
	lib32 := tree.inRoot(t, 83, "usr/lib32/libssl.so.3", elf32Header(nativeMachine()))
	tree.process(t, 83, "/usr/bin/python3", nil)
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(83, 41, "")
	u.OnOpen(83, 41, lib)
	if att.count() != 0 {
		t.Errorf("attached %d probes to a libssl of machine %s on %s", att.count(), foreignMachine(), nativeMachine())
	}
	ok, err := u.attachCandidate(83, candidate{Path: u.disc.rootPath(83, lib32), Name: lib32})
	if ok || !errors.Is(err, ErrNotELF) {
		t.Errorf("a 32-bit libssl: attached %v, error %v, want ErrNotELF", ok, err)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if att.count() != 0 {
		t.Errorf("attached %d probes", att.count())
	}
}
