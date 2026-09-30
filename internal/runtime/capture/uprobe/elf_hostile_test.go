// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"debug/elf"
	bo "encoding/binary"
	"errors"
	"os"
	"runtime"
	"testing"
)

// hostileELF is a writeELF file opened for in-place patching of its headers.
type hostileELF struct {
	t     *testing.T
	f     *os.File
	shoff int64
	ef    *elf.File
}

func openHostile(t *testing.T, opts elfOptions) *hostileELF {
	t.Helper()
	f, err := os.OpenFile(writeELF(t, opts), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	ef, err := elf.NewFile(f)
	if err != nil {
		t.Fatal(err)
	}
	var eh [64]byte
	if _, err := f.ReadAt(eh[:], 0); err != nil {
		t.Fatal(err)
	}
	return &hostileELF{t: t, f: f, ef: ef, shoff: int64(bo.LittleEndian.Uint64(eh[0x28:]))}
}

func (h *hostileELF) index(typ elf.SectionType) int {
	for i, s := range h.ef.Sections {
		if s.Type == typ {
			return i
		}
	}
	h.t.Fatalf("no section of type %v", typ)
	return -1
}

func (h *hostileELF) put(off int64, v uint64, width int) {
	h.t.Helper()
	b := make([]byte, 8)
	bo.LittleEndian.PutUint64(b, v)
	if _, err := h.f.WriteAt(b[:width], off); err != nil {
		h.t.Fatal(err)
	}
}

// point makes section i hold data, appended to the file.
func (h *hostileELF) point(i int, data []byte) {
	h.t.Helper()
	st, err := h.f.Stat()
	if err != nil {
		h.t.Fatal(err)
	}
	off := (st.Size() + 7) &^ 7
	if _, err := h.f.WriteAt(data, off); err != nil {
		h.t.Fatal(err)
	}
	h.put(h.shoff+int64(i)*64+24, uint64(off), 8)
	h.put(h.shoff+int64(i)*64+32, uint64(len(data)), 8)
}

// allocated runs fn and returns the bytes the process allocated meanwhile.
func allocated(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// TestSymbolNamesAreNotMultiplied: many symbol entries naming one long string must cost the sum of the two
// tables, not their product. debug/elf copied the name once per entry (20k entries x 8 KiB = 160 MiB here,
// hundreds of GiB for the 349k entries and 1 MiB string a 9 MB file can hold), and the launcher parses the
// file from OnOpen for any libssl-named open.
func TestSymbolNamesAreNotMultiplied(t *testing.T) {
	h := openHostile(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1010}})
	long := make([]byte, 8<<10)
	for i := range long {
		long[i] = 'A'
	}
	strs := append([]byte{0}, "SSL_write\x00"...)
	longOff := uint32(len(strs))
	strs = append(append(strs, long...), 0)
	const n = 20000
	table := make([]byte, 24, 24*(n+2))
	entry := func(name uint32, value uint64) []byte {
		e := make([]byte, 24)
		bo.LittleEndian.PutUint32(e[0:], name)
		e[4] = byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC))
		bo.LittleEndian.PutUint16(e[6:], 1)
		bo.LittleEndian.PutUint64(e[8:], value)
		return e
	}
	table = append(table, entry(1, 0x1010)...)
	for range n {
		table = append(table, entry(longOff, 0x1020)...)
	}
	di := h.index(elf.SHT_DYNSYM)
	h.point(di, table)
	h.point(int(h.ef.Sections[di].Link), strs)
	var bin *binary
	var err error
	got := allocated(func() { bin, err = readBinary(h.f.Name()) })
	if err != nil || !bin.Has(SymWrite) {
		t.Fatalf("readBinary = %v, %v; want SSL_write found", bin, err)
	}
	if got > 32<<20 {
		t.Fatalf("readBinary allocated %d MiB for a %d KiB symbol table and %d KiB string table", got>>20, len(table)>>10, len(strs)>>10)
	}
}

// TestNameOutsideStringTableIsRefused: a symbol name offset past its string table is a malformed file.
func TestNameOutsideStringTableIsRefused(t *testing.T) {
	h := openHostile(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1010}})
	di := h.index(elf.SHT_DYNSYM)
	h.put(int64(h.ef.Sections[di].Offset)+24, 1<<20, 4)
	if _, err := readBinary(h.f.Name()); !errors.Is(err, ErrNotELF) {
		t.Fatalf("readBinary = %v, want ErrNotELF", err)
	}
}

const sparseBudget = 64 << 20

// TestSparseShstrtabClaimIsBounded: a .shstrtab that claims far more than the file's headers can need reads
// back as zeros from a sparse file at no cost to its writer, and debug/elf allocated all of it.
func TestSparseShstrtabClaimIsBounded(t *testing.T) {
	h := openHostile(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1010}})
	var eh [64]byte
	if _, err := h.f.ReadAt(eh[:], 0); err != nil {
		t.Fatal(err)
	}
	idx := int(bo.LittleEndian.Uint16(eh[0x3e:]))
	off := int64(h.ef.Sections[idx].Offset)
	const claim = 128 << 20
	h.put(h.shoff+int64(idx)*64+32, claim, 8)
	if err := h.f.Truncate(off + claim); err != nil {
		t.Fatal(err)
	}
	var err error
	if got := allocated(func() { _, err = candidateIdentity(h.f.Name()) }); got > sparseBudget {
		t.Fatalf("candidateIdentity allocated %d MiB for a %d MiB .shstrtab claim", got>>20, claim>>20)
	}
	if !errors.Is(err, ErrSymbolTableTooLarge) {
		t.Fatalf("candidateIdentity = %v, want ErrSymbolTableTooLarge", err)
	}
	if got := allocated(func() { _, err = readBinary(h.f.Name()) }); got > sparseBudget || !errors.Is(err, ErrSymbolTableTooLarge) {
		t.Fatalf("readBinary = %v after allocating %d MiB, want ErrSymbolTableTooLarge and little", err, got>>20)
	}
}

// TestSparseSectionCountClaimIsBounded: e_shnum 0 makes debug/elf read section 0's sh_size headers.
func TestSparseSectionCountClaimIsBounded(t *testing.T) {
	h := openHostile(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1010}})
	const count = 512 << 10
	h.put(0x3c, 0, 2)
	h.put(h.shoff+32, count, 8)
	if err := h.f.Truncate(h.shoff + count*64); err != nil {
		t.Fatal(err)
	}
	var err error
	if got := allocated(func() { _, err = candidateIdentity(h.f.Name()) }); got > sparseBudget {
		t.Fatalf("candidateIdentity allocated %d MiB for %d claimed section headers", got>>20, count)
	}
	if !errors.Is(err, ErrSymbolTableTooLarge) {
		t.Fatalf("candidateIdentity = %v, want ErrSymbolTableTooLarge", err)
	}
}
