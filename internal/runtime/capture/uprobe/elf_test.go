// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"debug/elf"
	bin "encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// TestWriteSymbolChoice is capture-derive.md R1, R2 and E7 (an unhooked _ex call still reaches the hooked
// SSL_write_ex2 by tail-call) as a table across the OpenSSL releases this component meets:
// SSL_write is hooked whenever it exists, exactly one _ex variant joins it, and SSL_write_ex2 wins where
// both exist because SSL_write_ex tail-calls it and hooking both double-counts every write.
func TestWriteSymbolChoice(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		exports []string
		write   []string
		read    []string
		usable  bool
	}{
		{
			name:    "openssl 1.1.1",
			exports: []string{SymWrite, SymWriteEx, SymRead, SymReadEx},
			write:   []string{SymWrite, SymWriteEx},
			read:    []string{SymRead, SymReadEx},
			usable:  true,
		},
		{
			name:    "openssl 3.0",
			exports: []string{SymWrite, SymWriteEx, SymRead, SymReadEx},
			write:   []string{SymWrite, SymWriteEx},
			read:    []string{SymRead, SymReadEx},
			usable:  true,
		},
		{
			name:    "openssl 3.3",
			exports: []string{SymWrite, SymWriteEx, SymWriteEx2, SymRead, SymReadEx},
			write:   []string{SymWrite, SymWriteEx2},
			read:    []string{SymRead, SymReadEx},
			usable:  true,
		},
		{
			name:    "openssl 3.5",
			exports: []string{SymWrite, SymWriteEx, SymWriteEx2, SymRead, SymReadEx},
			write:   []string{SymWrite, SymWriteEx2},
			read:    []string{SymRead, SymReadEx},
			usable:  true,
		},
		{
			name:    "openssl 0.9.8 era: no _ex at all",
			exports: []string{SymWrite, SymRead},
			write:   []string{SymWrite},
			read:    []string{SymRead},
			usable:  true,
		},
		{
			name:    "only the _ex variants",
			exports: []string{SymWriteEx, SymReadEx},
			write:   []string{SymWriteEx},
			read:    []string{SymReadEx},
			usable:  true,
		},
		{
			name:    "boringssl or rustls: nothing",
			exports: nil,
			usable:  false,
		},
		{
			name:    "writes only",
			exports: []string{SymWrite},
			write:   []string{SymWrite},
			usable:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &binary{Offsets: map[string]uint64{}}
			for i, s := range tc.exports {
				b.Offsets[s] = uint64(0x1000 + i*16)
			}
			if got := b.WriteSymbols(); !slices.Equal(got, tc.write) {
				t.Errorf("WriteSymbols = %v, want %v", got, tc.write)
			}
			if got := b.ReadSymbols(); !slices.Equal(got, tc.read) {
				t.Errorf("ReadSymbols = %v, want %v", got, tc.read)
			}
			if b.Usable() != tc.usable {
				t.Errorf("Usable = %t, want %t", b.Usable(), tc.usable)
			}
			// R2 restated as a property: the two _ex variants are never hooked together.
			w := b.WriteSymbols()
			if slices.Contains(w, SymWriteEx) && slices.Contains(w, SymWriteEx2) {
				t.Errorf("both _ex variants hooked: %v", w)
			}
		})
	}
}

// TestProbesFor covers R3's entry+return pairing: every read symbol gets two probes and every write one,
// each pointed at the program that knows its calling convention.
func TestProbesFor(t *testing.T) {
	t.Parallel()
	b := &binary{Offsets: map[string]uint64{
		SymWrite: 0x100, SymWriteEx2: 0x200, SymWriteEx: 0x300, SymRead: 0x400, SymReadEx: 0x500, SymFree: 0x600,
	}}
	probes := probesFor(b)
	var entries, returns int
	seen := map[string]int{}
	for _, p := range probes {
		seen[p.Symbol]++
		if p.Return {
			returns++
			continue
		}
		entries++
		if p.Offset != b.Offsets[p.Symbol] {
			t.Errorf("%s: offset %#x, want %#x", p.Symbol, p.Offset, b.Offsets[p.Symbol])
		}
	}
	if seen[SymRead] != 2 || seen[SymReadEx] != 2 {
		t.Errorf("reads need an entry and a return each: %v", seen)
	}
	if seen[SymWrite] != 1 || seen[SymWriteEx2] != 1 {
		t.Errorf("writes need one probe each: %v", seen)
	}
	if seen[SymWriteEx] != 0 {
		t.Errorf("SSL_write_ex hooked alongside SSL_write_ex2 (R2)")
	}
	if entries != 5 || returns != 2 {
		t.Errorf("%d entry probes and %d return probes", entries, returns)
	}
	// SSL_free first of all, so a connection whose I/O is captured has its end captured too.
	if probes[0].Symbol != SymFree || probes[0].Program != bpf.ProgSSLFree || seen[SymFree] != 1 {
		t.Errorf("first probe %s, SSL_free hooked %d times; want SSL_free's probe first, once", probes[0], seen[SymFree])
	}
	// Every read probe, entry and return, before any write probe: a late attach must never capture a
	// request and miss the read of its response (see probesFor).
	for i, p := range probes {
		isRead := p.Symbol == SymRead || p.Symbol == SymReadEx
		if !isRead {
			continue
		}
		for _, w := range probes[:i] {
			if w.Symbol == SymWrite || w.Symbol == SymWriteEx2 || w.Symbol == SymWriteEx {
				t.Fatalf("read probe %s comes after write probe %s: %v", p, w, probes)
			}
		}
	}
	if got := probes[0].String(); got == "" {
		t.Error("Probe.String is empty")
	}
}

// elfOptions describe the synthetic ELF an fixture test builds.
type elfOptions struct {
	// Dynamic and Static are the symbol names to put in .dynsym and .symtab; a static-only binary is
	// the uv Python / official Node case ARCHITECTURE §12 names.
	Dynamic map[string]uint64
	Static  map[string]uint64
	// BuildID is the .note.gnu.build-id descriptor, empty for a binary that carries none.
	BuildID []byte
	// NotFunc puts every symbol's type at STT_OBJECT instead of STT_FUNC.
	NotFunc bool
	// Undefined puts every symbol at SHN_UNDEF, as a reference to another object with a PLT-stub value.
	Undefined bool
	// Type overrides the ELF type; zero means ET_DYN, a shared library.
	Type elf.Type
	// Machine overrides the ELF machine; zero means this build's own (nativeMachine).
	Machine elf.Machine
}

// writeELF builds a minimal but real ELF64 shared object with the requested symbol tables and returns its
// path. debug/elf reads it exactly as it reads a system libssl, so readBinary's whole path — segment
// lookup, symbol type filtering, build id — is exercised against bytes rather than against a mock.
func writeELF(t testing.TB, opts elfOptions) string {
	t.Helper()
	const (
		textVaddr = 0x1000
		textOff   = 0x1000
		textSize  = 0x1000
	)
	typ := opts.Type
	if typ == 0 {
		typ = elf.ET_DYN
	}
	var buf []byte
	grow := func(to int) {
		for len(buf) < to {
			buf = append(buf, 0)
		}
	}
	// Section name table and symbol string tables are built first so their offsets are known.
	shstr := []byte{0}
	addName := func(s string) uint32 {
		off := uint32(len(shstr))
		shstr = append(shstr, s...)
		shstr = append(shstr, 0)
		return off
	}
	names := map[string]uint32{}
	for _, n := range []string{".text", ".dynsym", ".dynstr", ".symtab", ".strtab", ".note.gnu.build-id", ".shstrtab"} {
		names[n] = addName(n)
	}

	symTable := func(syms map[string]uint64) (table, strs []byte) {
		strs = []byte{0}
		table = make([]byte, 24) // index 0 is the reserved null symbol
		keys := make([]string, 0, len(syms))
		for k := range syms {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, name := range keys {
			nameOff := uint32(len(strs))
			strs = append(strs, name...)
			strs = append(strs, 0)
			e := make([]byte, 24)
			bin.LittleEndian.PutUint32(e[0:4], nameOff)
			info := byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC))
			if opts.NotFunc {
				info = byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT))
			}
			e[4] = info
			shndx := uint16(1) // .text
			if opts.Undefined {
				shndx = uint16(elf.SHN_UNDEF)
			}
			bin.LittleEndian.PutUint16(e[6:8], shndx)
			bin.LittleEndian.PutUint64(e[8:16], syms[name])
			bin.LittleEndian.PutUint64(e[16:24], 32)
			table = append(table, e...)
		}
		return table, strs
	}
	dynTable, dynStr := symTable(opts.Dynamic)
	stTable, stStr := symTable(opts.Static)

	var note []byte
	if len(opts.BuildID) > 0 {
		note = make([]byte, 12)
		bin.LittleEndian.PutUint32(note[0:4], 4) // "GNU\0"
		bin.LittleEndian.PutUint32(note[4:8], uint32(len(opts.BuildID)))
		bin.LittleEndian.PutUint32(note[8:12], 3) // NT_GNU_BUILD_ID
		note = append(note, "GNU\x00"...)
		note = append(note, opts.BuildID...)
		for len(note)%4 != 0 {
			note = append(note, 0)
		}
	}

	grow(textOff + textSize)
	place := func(b []byte) (off, size uint64) {
		if len(b) == 0 {
			return 0, 0
		}
		for len(buf)%8 != 0 {
			buf = append(buf, 0)
		}
		off = uint64(len(buf))
		buf = append(buf, b...)
		return off, uint64(len(b))
	}
	dynOff, dynSize := place(dynTable)
	dynStrOff, dynStrSize := place(dynStr)
	stOff, stSize := place(stTable)
	stStrOff, stStrSize := place(stStr)
	noteOff, noteSize := place(note)
	shstrOff, shstrSize := place(shstr)

	type section struct {
		name        uint32
		typ         elf.SectionType
		flags       elf.SectionFlag
		addr        uint64
		off, size   uint64
		link, info  uint32
		align, entS uint64
	}
	sections := []section{
		{},
		{name: names[".text"], typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR,
			addr: textVaddr, off: textOff, size: textSize, align: 16},
		{name: names[".dynsym"], typ: elf.SHT_DYNSYM, off: dynOff, size: dynSize, link: 3, info: 1, align: 8, entS: 24},
		{name: names[".dynstr"], typ: elf.SHT_STRTAB, off: dynStrOff, size: dynStrSize, align: 1},
		{name: names[".symtab"], typ: elf.SHT_SYMTAB, off: stOff, size: stSize, link: 5, info: 1, align: 8, entS: 24},
		{name: names[".strtab"], typ: elf.SHT_STRTAB, off: stStrOff, size: stStrSize, align: 1},
		{name: names[".note.gnu.build-id"], typ: elf.SHT_NOTE, flags: elf.SHF_ALLOC, off: noteOff, size: noteSize, align: 4},
		{name: names[".shstrtab"], typ: elf.SHT_STRTAB, off: shstrOff, size: shstrSize, align: 1},
	}
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	shoff := uint64(len(buf))
	for _, s := range sections {
		e := make([]byte, 64)
		bin.LittleEndian.PutUint32(e[0:4], s.name)
		bin.LittleEndian.PutUint32(e[4:8], uint32(s.typ))
		bin.LittleEndian.PutUint64(e[8:16], uint64(s.flags))
		bin.LittleEndian.PutUint64(e[16:24], s.addr)
		bin.LittleEndian.PutUint64(e[24:32], s.off)
		bin.LittleEndian.PutUint64(e[32:40], s.size)
		bin.LittleEndian.PutUint32(e[40:44], s.link)
		bin.LittleEndian.PutUint32(e[44:48], s.info)
		bin.LittleEndian.PutUint64(e[48:56], s.align)
		bin.LittleEndian.PutUint64(e[56:64], s.entS)
		buf = append(buf, e...)
	}

	hdr := make([]byte, 64)
	copy(hdr[0:4], "\x7fELF")
	hdr[4], hdr[5], hdr[6] = 2, 1, 1 // ELFCLASS64, ELFDATA2LSB, EV_CURRENT
	bin.LittleEndian.PutUint16(hdr[16:18], uint16(typ))
	machine := opts.Machine
	if machine == 0 {
		machine = nativeMachine()
	}
	bin.LittleEndian.PutUint16(hdr[18:20], uint16(machine))
	bin.LittleEndian.PutUint32(hdr[20:24], 1)
	bin.LittleEndian.PutUint64(hdr[32:40], 64) // e_phoff
	bin.LittleEndian.PutUint64(hdr[40:48], shoff)
	bin.LittleEndian.PutUint16(hdr[52:54], 64)                    // e_ehsize
	bin.LittleEndian.PutUint16(hdr[54:56], 56)                    // e_phentsize
	bin.LittleEndian.PutUint16(hdr[56:58], 1)                     // e_phnum
	bin.LittleEndian.PutUint16(hdr[58:60], 64)                    // e_shentsize
	bin.LittleEndian.PutUint16(hdr[60:62], uint16(len(sections))) // e_shnum
	bin.LittleEndian.PutUint16(hdr[62:64], uint16(len(sections)-1))
	copy(buf, hdr)

	phdr := make([]byte, 56)
	bin.LittleEndian.PutUint32(phdr[0:4], uint32(elf.PT_LOAD))
	bin.LittleEndian.PutUint32(phdr[4:8], uint32(elf.PF_R|elf.PF_X))
	bin.LittleEndian.PutUint64(phdr[8:16], textOff)
	bin.LittleEndian.PutUint64(phdr[16:24], textVaddr)
	bin.LittleEndian.PutUint64(phdr[24:32], textVaddr)
	bin.LittleEndian.PutUint64(phdr[32:40], textSize)
	bin.LittleEndian.PutUint64(phdr[40:48], textSize)
	bin.LittleEndian.PutUint64(phdr[48:56], 0x1000)
	copy(buf[64:], phdr)

	path := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write elf: %v", err)
	}
	return path
}

// TestReadBinary covers capture-derive.md E6 (both .dynsym and .symtab are read, so musl and glibc binaries
// attach alike) and the ELF reader against real bytes: exported and local symbol tables, the file
// offset a uprobe attaches at, the build id, and every shape that is not something to attach to.
func TestReadBinary(t *testing.T) {
	t.Parallel()
	id := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}

	t.Run("shared library", func(t *testing.T) {
		path := writeELF(t, elfOptions{
			Dynamic: map[string]uint64{SymWrite: 0x1100, SymWriteEx2: 0x1140, SymRead: 0x1180, SymReadEx: 0x11c0},
			BuildID: id,
		})
		b, err := readBinary(path)
		if err != nil {
			t.Fatalf("readBinary: %v", err)
		}
		// vaddr 0x1000 maps to file offset 0x1000, so a symbol at 0x1100 attaches at 0x100 past it.
		if got := b.Offsets[SymWrite]; got != 0x1100 {
			t.Errorf("SSL_write offset = %#x, want %#x", got, 0x1100)
		}
		if b.BuildID != hex.EncodeToString(id) {
			t.Errorf("build id = %q, want %q", b.BuildID, hex.EncodeToString(id))
		}
		if !slices.Equal(b.WriteSymbols(), []string{SymWrite, SymWriteEx2}) {
			t.Errorf("write symbols = %v", b.WriteSymbols())
		}
	})

	t.Run("static binary keeps symbols in symtab only", func(t *testing.T) {
		path := writeELF(t, elfOptions{
			Static: map[string]uint64{SymWrite: 0x1200, SymRead: 0x1240},
			Type:   elf.ET_EXEC,
		})
		b, err := readBinary(path)
		if err != nil {
			t.Fatalf("readBinary: %v", err)
		}
		if !b.Has(SymWrite) || !b.Has(SymRead) {
			t.Errorf("local symbols missed: %v", b.Offsets)
		}
		if b.BuildID != "" {
			t.Errorf("build id = %q, want empty", b.BuildID)
		}
	})

	t.Run("no openssl symbols", func(t *testing.T) {
		path := writeELF(t, elfOptions{Dynamic: map[string]uint64{"malloc": 0x1100}})
		_, err := readBinary(path)
		if !errors.Is(err, ErrNoSymbols) {
			t.Fatalf("error = %v, want ErrNoSymbols", err)
		}
	})

	t.Run("symbols that are not functions", func(t *testing.T) {
		path := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0x1100}, NotFunc: true})
		if _, err := readBinary(path); !errors.Is(err, ErrNoSymbols) {
			t.Fatalf("error = %v, want ErrNoSymbols", err)
		}
	})

	t.Run("undefined symbol has nothing to attach to", func(t *testing.T) {
		path := writeELF(t, elfOptions{Dynamic: map[string]uint64{SymWrite: 0}})
		if _, err := readBinary(path); !errors.Is(err, ErrNoSymbols) {
			t.Fatalf("error = %v, want ErrNoSymbols", err)
		}
	})

	t.Run("not an ELF", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "script.sh")
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := readBinary(path); err == nil {
			t.Fatal("want an error for a shell script")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := readBinary(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("want an error")
		}
	})
}

// TestParseBuildIDNote covers the note reader on its own, including every truncated shape a stripped or
// corrupt section can present. None of them may panic.
func TestParseBuildIDNote(t *testing.T) {
	t.Parallel()
	u32 := bin.LittleEndian.Uint32
	note := func(namesz, descsz, typ uint32, name string, desc []byte) []byte {
		b := make([]byte, 12)
		bin.LittleEndian.PutUint32(b[0:4], namesz)
		bin.LittleEndian.PutUint32(b[4:8], descsz)
		bin.LittleEndian.PutUint32(b[8:12], typ)
		b = append(b, name...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return append(b, desc...)
	}
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"good", note(4, 2, 3, "GNU\x00", []byte{0xab, 0xcd}), "abcd"},
		{"wrong type", note(4, 2, 1, "GNU\x00", []byte{0xab, 0xcd}), ""},
		{"wrong name", note(4, 2, 3, "ABI\x00", []byte{0xab, 0xcd}), ""},
		{"empty", nil, ""},
		{"header only", make([]byte, 12), ""},
		{"truncated header", make([]byte, 7), ""},
		{"descsz past the end", note(4, 64, 3, "GNU\x00", []byte{0xab}), ""},
		{"huge namesz", note(1<<30, 2, 3, "GNU\x00", []byte{0xab, 0xcd}), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseBuildIDNote(tc.in, u32); got != tc.want {
				t.Errorf("parseBuildIDNote = %q, want %q", got, tc.want)
			}
		})
	}
}

// FuzzParseBuildIDNote is the fuzz target for the one place this package reads a length out of a file it
// did not write.
func FuzzParseBuildIDNote(f *testing.F) {
	f.Add([]byte{4, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 'G', 'N', 'U', 0, 0xab, 0xcd})
	f.Add(make([]byte, 12))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		if got := parseBuildIDNote(b, bin.LittleEndian.Uint32); len(got) > 2*len(b) {
			t.Fatalf("build id longer than the note: %d from %d bytes", len(got), len(b))
		}
	})
}

// TestStatIdentity covers the (device, inode) key, including capture-derive.md E4 (edge case #4): two names for one file are one
// cache entry.
func TestStatIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	real := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "libssl.so")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	a, err := statIdentity(real)
	if err != nil {
		t.Fatalf("statIdentity: %v", err)
	}
	b, err := statIdentity(link)
	if err != nil {
		t.Fatalf("statIdentity through a symlink: %v", err)
	}
	if a != b {
		t.Errorf("symlink and target have different identities: %+v and %+v", a, b)
	}
	if _, err := statIdentity(filepath.Join(dir, "missing")); err == nil {
		t.Error("want an error for a missing path")
	}
}
