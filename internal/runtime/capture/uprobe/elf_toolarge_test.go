// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"debug/elf"
	bo "encoding/binary"
	"errors"
	"os"
	"testing"
)

// claimSymtab rewrites the .symtab section header of the ELF at path to claim size bytes, in a sparse tail.
func claimSymtab(t *testing.T, path string, claimed uint64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ef, err := elf.NewFile(f)
	if err != nil {
		t.Fatal(err)
	}
	idx := -1
	for i, s := range ef.Sections {
		if s.Type == elf.SHT_SYMTAB {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("fixture has no .symtab")
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	off := uint64(st.Size()+4095) &^ 4095
	var eh [64]byte
	if _, err := f.ReadAt(eh[:], 0); err != nil {
		t.Fatal(err)
	}
	at := int64(bo.LittleEndian.Uint64(eh[0x28:])) + int64(idx)*64
	var b [16]byte
	bo.LittleEndian.PutUint64(b[0:], off)
	bo.LittleEndian.PutUint64(b[8:], claimed)
	if _, err := f.WriteAt(b[:], at+24); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(off) + int64(claimed)); err != nil {
		t.Fatal(err)
	}
}

// TestOversizeSymtabDoesNotHideDynsym: a large unstripped .symtab (the official Node tarball) must not stop
// the SSL symbols in a small .dynsym from being found.
func TestOversizeSymtabDoesNotHideDynsym(t *testing.T) {
	path := writeELF(t, elfOptions{
		Dynamic: map[string]uint64{SymWrite: 0x1010, SymRead: 0x1020},
		Static:  map[string]uint64{SymWrite: 0x1010},
	})
	claimSymtab(t, path, 96<<20)
	bin, err := readBinary(path)
	if err != nil {
		t.Fatalf("readBinary = %v, want the .dynsym symbols found", err)
	}
	if !bin.Has(SymWrite) {
		t.Fatalf("offsets %v lack %s", bin.Offsets, SymWrite)
	}
}

// TestOversizeSymtabIsNotANoSymbolsVerdict: when the only place the symbols could be is a table too large to
// read, the error says so, is not soft (no static-tls-no-symbols) and is not one the attach cache keeps.
func TestOversizeSymtabIsNotANoSymbolsVerdict(t *testing.T) {
	path := writeELF(t, elfOptions{Static: map[string]uint64{SymWrite: 0x1010}})
	claimSymtab(t, path, 96<<20)
	_, err := readBinary(path)
	if !errors.Is(err, ErrSymbolTableTooLarge) {
		t.Fatalf("readBinary = %v, want ErrSymbolTableTooLarge", err)
	}
	if softErr(err) || errors.Is(err, ErrNotELF) || errors.Is(err, ErrNoSymbols) {
		t.Fatalf("%v is filed as nothing-to-attach; want a real failure", err)
	}
}
