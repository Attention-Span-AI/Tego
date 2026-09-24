// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"debug/elf"
	bin "encoding/binary"
	"errors"
	"math"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// writeELFWithText is writeELF's shared object with its one executable segment's sizes rewritten: filesz and
// memsz replace the 0x1000 bytes writeELF gives both. The section headers are left as writeELF made them, so
// debug/elf still reads the symbol tables; only the segment readBinary maps addresses through changes.
func writeELFWithText(t testing.TB, opts elfOptions, filesz, memsz uint64) []byte {
	t.Helper()
	b, err := os.ReadFile(writeELF(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	const phdr = 64 // e_phoff: the one program header follows the ELF header
	bin.LittleEndian.PutUint64(b[phdr+32:], filesz)
	bin.LittleEndian.PutUint64(b[phdr+40:], memsz)
	return b
}

// TestReadBinaryAttachesOnlyWhereTheFileHoldsTheSymbol is the defect FuzzReadBinary found, as named cases: a
// symbol whose address lies in the zero-filled tail of an executable segment (past Filesz, inside Memsz) has no
// byte of the file behind it, so the file offset readBinary gave it named bytes that are not the function's,
// and one past the file's end is an offset the kernel refuses to probe. Either refuses the whole candidate
// with ErrSymbolOutsideFile, which is not soft: attaching the rest would have left a binary with SSL_write and
// no read capturing requests and never their responses, with no gap (I4). A symbol in the file's bytes of the
// same segment, up to its last byte, keeps its offset.
func TestReadBinaryAttachesOnlyWhereTheFileHoldsTheSymbol(t *testing.T) {
	t.Parallel()
	const text = 0x1000 // writeELF's executable segment: vaddr and file offset 0x1000
	write := func(t *testing.T, b []byte) string {
		t.Helper()
		path := t.TempDir() + "/libssl.so.3"
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	refused := func(t *testing.T, b []byte, why string) {
		t.Helper()
		got, err := readBinary(write(t, b))
		if !errors.Is(err, ErrSymbolOutsideFile) || errors.Is(err, ErrNoSymbols) || softErr(err) {
			t.Fatalf("%s: readBinary = %v, soft=%v; want ErrSymbolOutsideFile, which is not soft", why, err, softErr(err))
		}
		if got != nil {
			t.Errorf("%s: readBinary refused the binary and still returned offsets %v", why, got.Offsets)
		}
	}
	attached := func(t *testing.T, b []byte, sym string, want uint64) {
		t.Helper()
		got, err := readBinary(write(t, b))
		if err != nil {
			t.Fatalf("readBinary: %v", err)
		}
		if off, ok := got.Offsets[sym]; !ok || off != want {
			t.Errorf("%s: offset %#x, %v; want %#x", sym, off, ok, want)
		}
	}

	t.Run("a symbol in the zero-filled tail refuses the binary", func(t *testing.T) {
		refused(t, writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x10, SymRead: text + 0x800}},
			0x400, 0x1000), "SSL_read past the segment's 0x400 file bytes beside SSL_write inside them")
	})

	t.Run("a binary whose only symbols are in the tail is refused the same way", func(t *testing.T) {
		refused(t, writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x800}}, 0x400, 0x1000),
			"SSL_write past the segment's file bytes")
	})

	t.Run("the last byte before Filesz is in and the first past it is out", func(t *testing.T) {
		attached(t, writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x3ff, SymRead: text + 0x10}},
			0x400, 0x1000), SymWrite, text+0x3ff)
		refused(t, writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x10, SymRead: text + 0x400}},
			0x400, 0x1000), "SSL_read at the first byte past Filesz")
	})

	// debug/elf never checks Off+Filesz against the file's length, so a segment may claim 1 MiB of file bytes
	// in a file of a few KiB. An offset past the end is one the kernel refuses to probe (EINVAL).
	t.Run("a symbol past the file's end refuses the binary", func(t *testing.T) {
		b := writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x10, SymRead: text + 0x80000}},
			0x100000, 0x100000)
		if uint64(len(b)) >= text+0x80000 {
			t.Fatalf("the file is %#x bytes, so SSL_read's offset is inside it and the case tests nothing", len(b))
		}
		refused(t, b, "SSL_read past the file's end")
	})

	t.Run("the file's last byte is in and its end is out", func(t *testing.T) {
		// The same two symbols first, to learn the file's length: a symbol's value does not change it.
		b := writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text, SymRead: text}}, 0x100000, 0x100000)
		last := uint64(len(b)) - 1
		for _, syms := range []map[string]uint64{{SymWrite: last, SymRead: text}, {SymWrite: text, SymRead: last + 1}} {
			if b := writeELFWithText(t, elfOptions{Dynamic: syms}, 0x100000, 0x100000); uint64(len(b)) != last+1 {
				t.Fatalf("the file changed length from %#x to %#x with its symbols' values", last+1, len(b))
			}
		}
		attached(t, writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: last, SymRead: text}},
			0x100000, 0x100000), SymWrite, last)
		refused(t, writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text, SymRead: last + 1}},
			0x100000, 0x100000), "SSL_read at the file's end")
	})
}

// TestASymbolOutsideTheFileIsANoOpenSSLGap follows ErrSymbolOutsideFile to the record: a libssl that exports
// SSL_write in its file bytes and SSL_read in the zero-filled tail attaches nothing, and the process is a gap,
// no-openssl like a candidate the host refused to probe (R37), never static-tls-no-symbols, since the binary
// does export R1-R3, and never the silent write-only capture that attaching SSL_write alone would be (I4).
func TestASymbolOutsideTheFileIsANoOpenSSLGap(t *testing.T) {
	const text = 0x1000
	tree := newProcTree(t)
	b := writeELFWithText(t, elfOptions{Dynamic: map[string]uint64{SymWrite: text + 0x10, SymRead: text + 0x800}}, 0x400, 0x1000)
	lib := tree.inRoot(t, 81, "usr/lib/x86_64-linux-gnu/libssl.so.3", b)
	tree.process(t, 81, "/usr/bin/python3", []string{lib})
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: att})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a"}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	u.OnExec(81, 41, "")
	u.OnOpen(81, 41, lib)
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if att.count() != 0 {
		t.Errorf("attached %d probes to a libssl whose SSL_read has no byte of the file behind it", att.count())
	}
	gaps := u.Gaps()
	if !hasGap(gaps, GapNoOpenSSL) || hasGap(gaps, GapStaticTLSNoSymbols) {
		t.Errorf("gaps = %+v, want no-openssl and not static-tls-no-symbols", gaps)
	}
}

// TestFileOffsetRefusesWhatWraps holds fileOffset to its own arithmetic rather than to what debug/elf happens to
// reject today: the program header's words are the file's, and an offset whose sum wraps past 2^64 would come
// back as a small offset into the file's first page. debug/elf refuses an Off or Filesz with the top bit set
// when it parses, so these segments are built in memory, each in a file of the largest length a file can have
// unless the case is about the length. The first case's sum wraps to 0x7f, which a check made after the sum
// would find inside the file. The Memsz and file-length halves of the bound are here too, and which of
// fileOffset's two refusals each case is: an address a segment maps with no file byte behind it refuses the
// binary (ErrSymbolOutsideFile), and one no segment maps is passed over (errUnmapped).
func TestFileOffsetRefusesWhatWraps(t *testing.T) {
	t.Parallel()
	seg := func(off, vaddr, filesz, memsz uint64) *elf.File {
		return &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: off, Vaddr: vaddr, Filesz: filesz, Memsz: memsz,
		}}}}
	}
	for _, tc := range []struct {
		name  string
		f     *elf.File
		size  int64
		value uint64
		want  error
	}{
		{"Off plus the distance wraps", seg(0x100, 0, math.MaxUint64, math.MaxUint64), math.MaxInt64, math.MaxUint64 - 0x80, ErrSymbolOutsideFile},
		{"Off past any file's end", seg(math.MaxUint64-0xf, 0x1000, 0x100, 0x100), math.MaxInt64, 0x1020, ErrSymbolOutsideFile},
		{"Off at the largest file's end", seg(math.MaxInt64, 0x1000, 0x100, 0x100), math.MaxInt64, 0x1000, ErrSymbolOutsideFile},
		// A malformed segment whose Filesz exceeds its Memsz maps only Memsz bytes.
		{"Filesz past Memsz", seg(0x1000, 0x1000, 0x1000, 0x10), math.MaxInt64, 0x1020, errUnmapped},
		{"past Filesz, inside Memsz", seg(0x1000, 0x1000, 0x10, 0x100), math.MaxInt64, 0x1020, ErrSymbolOutsideFile},
		{"the offset is the file's length", seg(0x2000, 0x1000, 0x100, 0x100), 0x2020, 0x1020, ErrSymbolOutsideFile},
		{"the segment starts at the file's end", seg(0x2000, 0x1000, 0x100, 0x100), 0x2000, 0x1000, ErrSymbolOutsideFile},
		{"an empty file", seg(0, 0x1000, 0x100, 0x100), 0, 0x1000, ErrSymbolOutsideFile},
		{"below the segment", seg(0x2000, 0x1000, 0x100, 0x100), math.MaxInt64, 0xfff, errUnmapped},
		{"value 0", seg(0, 0, 0x100, 0x100), math.MaxInt64, 0, errUnmapped},
	} {
		if off, err := fileOffset(tc.f, tc.size, tc.value); !errors.Is(err, tc.want) {
			t.Errorf("%s: fileOffset(%#x) = %#x, %v; want %v", tc.name, tc.value, off, err, tc.want)
		}
	}
	if off, err := fileOffset(seg(0x2000, 0x1000, 0x100, 0x100), 0x2021, 0x1020); err != nil || off != 0x2020 {
		t.Errorf("an ordinary segment whose symbol is the file's last byte: fileOffset = %#x, %v; want 0x2020", off, err)
	}
	// A tail in one segment does not refuse an address another executable segment holds in its file bytes.
	two := seg(0x1000, 0x1000, 0x10, 0x100)
	two.Progs = append(two.Progs, &elf.Prog{ProgHeader: elf.ProgHeader{
		Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0x3000, Vaddr: 0x1000, Filesz: 0x100, Memsz: 0x100,
	}})
	if off, err := fileOffset(two, math.MaxInt64, 0x1020); err != nil || off != 0x3020 {
		t.Errorf("an address in one segment's tail and another's file bytes: fileOffset = %#x, %v; want 0x3020", off, err)
	}
}
