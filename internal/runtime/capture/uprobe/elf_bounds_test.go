// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"debug/elf"
	bo "encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestCandidateIdentityRefusesNonRegularFile holds the first read of an attach candidate to a regular file.
// The candidate's path is one a traced process chose (an open the kernel record saw, a mapping), and the read
// runs as root on the recorder's drain goroutine (source.ProcessHook), which must return promptly: an open
// of a FIFO with no writer never returns, and the kernel record, and the run's Stop, wait behind it.
func TestCandidateIdentityRefusesNonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := candidateIdentity(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !softErr(err) {
			t.Fatalf("candidateIdentity(fifo) = %v, want a soft error (not an ELF)", err)
		}
	case <-time.After(2 * time.Second):
		// Release the blocked open so the goroutine ends and the leak check stays meaningful.
		if w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		<-done
		t.Fatal("candidateIdentity blocked opening a FIFO named like a libssl")
	}
}

// TestCandidateOpenRunsNoOpenHandler: a candidate is opened O_PATH and read only once that descriptor shows a regular
// file. The O_NONBLOCK read-open it replaced returned at once for a FIFO, but it was still an open: a writer blocked
// opening the FIFO was released by it, and a device node's own open handler ran (a tape rewinds on open). The writer
// stays blocked now.
func TestCandidateOpenRunsNoOpenHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	opened := make(chan struct{})
	go func() {
		// Blocks until a reader opens the FIFO.
		if w, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			_ = w.Close()
		}
		close(opened)
	}()
	time.Sleep(20 * time.Millisecond) // the writer is waiting in open
	if _, err := candidateIdentity(path); err == nil || !softErr(err) {
		t.Fatalf("candidateIdentity(fifo) = %v, want a soft error", err)
	}
	select {
	case <-opened:
		t.Fatal("reading the candidate opened the FIFO: a blocked writer was released")
	case <-time.After(100 * time.Millisecond):
	}
	// Release the writer so the goroutine ends.
	if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
		<-opened
		_ = r.Close()
	}
}

// TestReadBinaryBoundsSymbolTable holds readBinary's memory to a bound that does not scale with a symbol
// table's claimed size. debug/elf reads a section whole and decodes one Symbol (~80 bytes) per 24-byte entry,
// bounded only by the file, and a sparse file makes a large section free to write, so a candidate a traced
// process wrote could cost the root launcher several times its size in allocations.
func TestReadBinaryBoundsSymbolTable(t *testing.T) {
	path := writeELF(t, elfOptions{Static: map[string]uint64{SymWrite: 0x1010}})
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ef, err := elf.NewFile(f)
	if err != nil {
		t.Fatal(err)
	}
	var idx = -1
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
	const claimed = 96 << 20 // a multiple of 24
	off := uint64(st.Size()+4095) &^ 4095
	// Elf64_Shdr: name 4, type 4, flags 8, addr 8, offset 8 (at 24), size 8 (at 32).
	var shoff uint64
	{
		var eh [64]byte
		if _, err := f.ReadAt(eh[:], 0); err != nil {
			t.Fatal(err)
		}
		shoff = bo.LittleEndian.Uint64(eh[0x28:])
	}
	at := int64(shoff) + int64(idx)*64
	var b [16]byte
	bo.LittleEndian.PutUint64(b[0:], off)
	bo.LittleEndian.PutUint64(b[8:], claimed)
	if _, err := f.WriteAt(b[:], at+24); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(off) + claimed); err != nil { // sparse: no disk behind the zeros
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, rerr := readBinary(path)
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 32<<20 {
		t.Fatalf("readBinary allocated %d MiB for a %d MiB claimed .symtab (err %v), want under 32 MiB",
			got>>20, claimed>>20, rerr)
	}
	if rerr == nil {
		t.Fatalf("readBinary accepted a .symtab claiming %d MiB", claimed>>20)
	}
}

// A candidate named like a libssl that the agent wrote and opened: a 4 KiB ELF on disk whose .symtab section header
// claims symtabBytes, backed by a sparse hole (no disk used). readBinary reads and decodes the whole section into the
// launcher's heap before looking at a single symbol, with no bound and no budget check.
func TestSparseSymtabELFIsBounded(t *testing.T) {
	const symtabBytes = 24 * 11_000_000
	path := filepath.Join(t.TempDir(), "libssl.so.3")
	writeSparseSymtabELF(t, path, symtabBytes)
	st, _ := os.Stat(path)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, err := readBinary(path)
	el := time.Since(start)
	runtime.ReadMemStats(&after)
	t.Logf("apparent size %d MiB; readBinary took %v, allocated %d MiB, err=%v",
		st.Size()>>20, el, (after.TotalAlloc-before.TotalAlloc)>>20, err)
	if a := after.TotalAlloc - before.TotalAlloc; a > 64<<20 {
		t.Errorf("parsing one hostile candidate allocated %d MiB in the launcher", a>>20)
	}
}

func writeSparseSymtabELF(t *testing.T, path string, symtabBytes int64) {
	t.Helper()
	le := bo.LittleEndian
	const ehsize, shentsize = 64, 64
	shstr := []byte("\x00.symtab\x00.strtab\x00.shstrtab\x00")
	strtab := []byte("\x00")
	// layout: ehdr | shstr | strtab | shdrs(4) | ... hole ... | symtab at 1 MiB
	shstrOff := int64(ehsize)
	strOff := shstrOff + int64(len(shstr))
	shOff := (strOff + int64(len(strtab)) + 7) &^ 7
	symOff := int64(1 << 20)
	buf := make([]byte, shOff+4*shentsize)
	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(buf[16:], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], uint64(shOff))
	le.PutUint16(buf[52:], ehsize)
	le.PutUint16(buf[58:], shentsize)
	le.PutUint16(buf[60:], 4)
	le.PutUint16(buf[62:], 3) // shstrndx
	copy(buf[shstrOff:], shstr)
	copy(buf[strOff:], strtab)
	sh := func(i int, name uint32, typ elf.SectionType, off, size int64, link uint32, entsize uint64) {
		b := buf[shOff+int64(i)*shentsize:]
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], uint32(typ))
		le.PutUint64(b[24:], uint64(off))
		le.PutUint64(b[32:], uint64(size))
		le.PutUint32(b[40:], link)
		le.PutUint64(b[48:], 1)
		le.PutUint64(b[56:], entsize)
	}
	sh(1, 1, elf.SHT_SYMTAB, symOff, symtabBytes, 2, 24)
	sh(2, 9, elf.SHT_STRTAB, strOff, int64(len(strtab)), 0, 0)
	sh(3, 17, elf.SHT_STRTAB, shstrOff, int64(len(shstr)), 0, 0)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, symOff+symtabBytes); err != nil {
		t.Fatal(err)
	}
}

// The note variant: candidateIdentity, which every open of a libssl-named file runs before any cache is
// consulted (so it is repeated for each open, even after the binary's failure is cached), reads the whole
// .note.gnu.build-id section.
func TestSparseBuildIDNoteIsBounded(t *testing.T) {
	const noteBytes = 512 << 20
	path := filepath.Join(t.TempDir(), "libssl.so.3")
	writeSparseSymtabELF(t, path, 24) // tiny symtab
	// Rewrite section 1 as the build-id note, sized noteBytes.
	b, _ := os.ReadFile(path)
	le := bo.LittleEndian
	shOff := int64(le.Uint64(b[40:]))
	shstr := []byte("\x00.note.gnu.build-id\x00.strtab\x00.shstrtab\x00")
	// put a new shstrtab at the end of the header area
	b = append(b, shstr...)
	newShstrOff := int64(len(b) - len(shstr))
	s1 := b[shOff+64:]
	le.PutUint32(s1[0:], 1)
	le.PutUint32(s1[4:], uint32(elf.SHT_NOTE))
	le.PutUint64(s1[32:], noteBytes)
	s3 := b[shOff+3*64:]
	le.PutUint64(s3[24:], uint64(newShstrOff))
	le.PutUint64(s3[32:], uint64(len(shstr)))
	s2 := b[shOff+2*64:]
	le.PutUint32(s2[0:], 20)
	le.PutUint32(s3[0:], 28)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, (1<<20)+noteBytes); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	id, err := candidateIdentity(path)
	el := time.Since(start)
	runtime.ReadMemStats(&after)
	a := after.TotalAlloc - before.TotalAlloc
	t.Logf("candidateIdentity took %v, allocated %d KiB, id=%+v err=%v", el, a>>10, id, err)
	// The note is read only when it is a note's size and inside the file, so one hostile candidate costs the launcher
	// kilobytes, not the 512 MiB its section header claims.
	if a > 1<<20 {
		t.Errorf("reading a sparse candidate's build id allocated %d KiB", a>>10)
	}
	if id.BuildID != "" {
		t.Errorf("an oversized note yielded build id %q", id.BuildID)
	}
}
