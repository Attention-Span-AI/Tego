// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"bytes"
	"debug/elf"
	bin "encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// FuzzReadBinary feeds readBinary an arbitrary file. It runs inside the root capture path over every ELF a
// traced process maps, and an agent can map a file it wrote itself, so the bytes are the agent's
// (ARCHITECTURE §16: every reader of another process's memory, or of a file it chose, has a fuzz target).
// The file goes through a real path rather than a reader, so openELF's classification is fuzzed as well.
//
// The properties: no input panics; a failure is ErrNotELF, ErrNoSymbols or one of readBinary's own
// "uprobe: " errors, and ErrSymbolOutsideFile only for a file with a symbol of Symbols at an address an
// executable segment maps with no byte of the file behind it, so that no well-formed binary is refused whole;
// and a binary that is returned names only symbols of Symbols, is Usable, carries a hex build id or none, and
// gives every symbol a file offset inside the bytes the file holds for an executable PT_LOAD segment (below
// its Filesz, and before the file's end, which debug/elf does not check a segment against), which is the only
// place a uprobe can sensibly be attached.
//
// That last property is how this target found fileOffset taking a symbol anywhere up to a segment's
// Vaddr+Memsz when the file holds only its first Filesz bytes. testdata/fuzz/FuzzReadBinary/f7f78dde318e6af4
// is the fuzzer's input for it: a Memsz of 0x40000000001000, and SSL_read_ex at 0xf31080, past the segment's
// 0x1000 file bytes and past the end of the 0x22d0-byte file as well, so the file-end bound refuses it too and
// it fails only with both bounds taken out. testdata/fuzz/FuzzReadBinary/88db291db363c0fb is the input the
// fuzzer failed on with the Filesz bound alone taken out, a mutation of the tail seed below: SSL_read_ex at
// 0x1800, past the segment's 0x400 file bytes but inside the 0x22c8-byte file, which only the Filesz bound
// refuses. The seed and TestReadBinaryAttachesOnlyWhereTheFileHoldsTheSymbol name the case.
func FuzzReadBinary(f *testing.F) {
	const text = 0x1000 // writeELF's executable segment: vaddr and file offset 0x1000, 0x1000 bytes
	for _, opts := range []elfOptions{
		{Dynamic: map[string]uint64{SymWrite: text + 0x10, SymRead: text + 0x40}, BuildID: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Static: map[string]uint64{SymWriteEx: text + 0x20, SymReadEx: text + 0x80}},
		{Dynamic: map[string]uint64{SymWrite: 0, SymRead: 0}},
		{Dynamic: map[string]uint64{SymWriteEx2: text + 0xff0}, NotFunc: true},
		{Dynamic: map[string]uint64{SymRead: text + 0x40}, Type: elf.ET_EXEC},
	} {
		b, err := os.ReadFile(writeELF(f, opts))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	// A symbol in the zero-filled tail of the executable segment, past its file bytes, beside one inside them.
	f.Add(writeELFWithText(f, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x10, SymReadEx: text + 0x800}}, 0x400, 0x1000))
	// A segment claiming 1 MiB of file bytes in a file of a few KiB, with a symbol past the file's end.
	f.Add(writeELFWithText(f, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x10, SymRead: text + 0x80000}}, 0x100000, 0x100000))
	f.Add([]byte("\x7fELF"))
	f.Add([]byte("not an elf"))
	// One file per fuzzing process, rewritten by each input: a t.TempDir per input made and removed a
	// directory every time and slowed the fuzzer to a few inputs a minute.
	path := filepath.Join(f.TempDir(), "libssl.so.3")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		bin, err := readBinary(path)
		if err != nil {
			if !errors.Is(err, ErrNotELF) && !errors.Is(err, ErrNoSymbols) && !strings.HasPrefix(err.Error(), "uprobe: ") {
				t.Fatalf("readBinary failed with %v, none of its own errors", err)
			}
			if errors.Is(err, ErrSymbolOutsideFile) && !hasUnbackedSymbol(data) {
				t.Fatalf("readBinary refused the file whole (%v), and no symbol of Symbols lies where an executable "+
					"segment maps it without the file's bytes", err)
			}
			return
		}
		if !bin.Usable() {
			t.Fatal("readBinary returned a binary with nothing to attach to and no ErrNoSymbols")
		}
		if bin.BuildID != "" {
			if _, err := hex.DecodeString(bin.BuildID); err != nil {
				t.Fatalf("build id %q is not hex", bin.BuildID)
			}
		}
		ef, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("readBinary accepted bytes debug/elf rejects: %v", err)
		}
		for sym, off := range bin.Offsets {
			if !slices.Contains(Symbols, sym) {
				t.Fatalf("offset for %q, which is not one of Symbols", sym)
			}
			inside := slices.ContainsFunc(ef.Progs, func(p *elf.Prog) bool {
				return p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && off >= p.Off && off-p.Off < p.Filesz
			})
			if !inside {
				t.Fatalf("%s at file offset %#x, outside every executable PT_LOAD's file bytes", sym, off)
			}
			if off >= uint64(len(data)) {
				t.Fatalf("%s at file offset %#x of a %#x-byte file", sym, off, len(data))
			}
		}
	})
}

// hasUnbackedSymbol checks R37 independently of fileOffset. Read complete entries even if a table ends in a
// partial entry: debug/elf's Symbols rejects that whole table, whereas readBinary still sees its functions.
// Names ending at the string table's end are seen too, as by collectOffsets. Neither malformed spelling
// makes a symbol in a segment's zero-filled tail safe to probe or to silently omit from capture (I4).
func hasUnbackedSymbol(data []byte) bool {
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return false
	}
	size := uint64(len(data))
	for _, typ := range []elf.SectionType{elf.SHT_DYNSYM, elf.SHT_SYMTAB} {
		sec := ef.SectionByType(typ)
		if sec == nil || int(sec.Link) >= len(ef.Sections) || ef.Sections[sec.Link].Type != elf.SHT_STRTAB {
			continue
		}
		table, err := sec.Data()
		if err != nil {
			continue
		}
		strs, err := ef.Sections[sec.Link].Data()
		if err != nil {
			continue
		}
		entrySize := elf.Sym64Size
		if ef.Class == elf.ELFCLASS32 {
			entrySize = elf.Sym32Size
		}
		for pos := entrySize; pos+entrySize <= len(table); pos += entrySize {
			var s elf.Sym64
			if ef.Class == elf.ELFCLASS32 {
				var s32 elf.Sym32
				if _, err := bin.Decode(table[pos:], ef.ByteOrder, &s32); err != nil {
					continue
				}
				s = elf.Sym64{Name: s32.Name, Info: s32.Info, Shndx: s32.Shndx, Value: uint64(s32.Value)}
			} else if _, err := bin.Decode(table[pos:], ef.ByteOrder, &s); err != nil {
				continue
			}
			if uint64(s.Name) >= uint64(len(strs)) || elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 ||
				elf.SectionIndex(s.Shndx) == elf.SHN_UNDEF || elf.SectionIndex(s.Shndx) >= elf.SHN_LORESERVE {
				continue
			}
			name, _, _ := bytes.Cut(strs[s.Name:], []byte{0})
			if !slices.Contains(Symbols, string(name)) {
				continue
			}
			for _, p := range ef.Progs {
				if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 || s.Value < p.Vaddr || s.Value-p.Vaddr >= p.Memsz {
					continue
				}
				if d := s.Value - p.Vaddr; d >= p.Filesz || p.Off >= size || d >= size-p.Off {
					return true
				}
			}
		}
	}
	return false
}

func TestUnbackedSymbolCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   elfOptions
		shrink elf.SectionType
		want   bool
	}{
		{"file bytes", elfOptions{Dynamic: map[string]uint64{SymReadEx: 0x1010}}, elf.SHT_NULL, false},
		{"zero-filled tail", elfOptions{Dynamic: map[string]uint64{SymReadEx: 0x1800}}, elf.SHT_NULL, true},
		{"partial dynsym", elfOptions{Dynamic: map[string]uint64{SymReadEx: 0x1800, SymWrite: 0x1010}}, elf.SHT_DYNSYM, true},
		{"partial symtab", elfOptions{Static: map[string]uint64{SymReadEx: 0x1800, SymWrite: 0x1010}}, elf.SHT_SYMTAB, true},
		{"unterminated name", elfOptions{Dynamic: map[string]uint64{SymReadEx: 0x1800}}, elf.SHT_STRTAB, true},
		{"undefined", elfOptions{Dynamic: map[string]uint64{SymReadEx: 0x1800}, Undefined: true}, elf.SHT_NULL, false},
		{"not a function", elfOptions{Dynamic: map[string]uint64{SymReadEx: 0x1800}, NotFunc: true}, elf.SHT_NULL, false},
		{"unmapped", elfOptions{Dynamic: map[string]uint64{SymReadEx: 0x2800}}, elf.SHT_NULL, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := writeELFWithText(t, tc.opts, 0x400, 0x1000)
			if tc.shrink != elf.SHT_NULL {
				ef, err := elf.NewFile(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				// writeELF writes ELF64 little-endian headers. Trim the first matching section by a byte,
				// leaving its last symbol or its final name incomplete, as in the nightly crash input.
				shoff := bin.LittleEndian.Uint64(data[40:48])
				for i, sec := range ef.Sections {
					if sec.Type == tc.shrink {
						bin.LittleEndian.PutUint64(data[shoff+uint64(i)*64+32:], sec.Size-1)
						break
					}
				}
			}
			if got := hasUnbackedSymbol(data); got != tc.want {
				t.Errorf("hasUnbackedSymbol = %v, want %v", got, tc.want)
			}
		})
	}
}
