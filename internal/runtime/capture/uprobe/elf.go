// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxSymbolSection bounds one symbol table, and the string table it names, that readBinary will read. debug/elf
// reads a section whole, and the file is one a traced process may have written (sparse, so a large section
// costs it nothing). collectOffsets holds the section as bytes and compares names in place, so the table costs
// its own size and no per-entry copy of a name. A real libssl's .dynsym is well under 1 MiB and a statically linked interpreter's .symtab a few MiB.
const maxSymbolSection = 8 << 20

// maxStringSection bounds the string table a symbol table names. It is held as bytes, not decoded into
// Symbols, so it may be larger: the official unstripped Node has a 10 MiB .strtab and an 8 MiB .dynstr.
const maxStringSection = 32 << 20

// The OpenSSL entry points this package may hook (docs/p0/capture-derive.md §5 R1-R3).
const (
	// SymWrite is the universal write entry point Node, libcurl and CPython 3.9 call.
	SymWrite = "SSL_write"
	// SymWriteEx2 is OpenSSL 3.3+'s write; SSL_write_ex tail-calls it where both exist.
	SymWriteEx2 = "SSL_write_ex2"
	// SymWriteEx is the 1.1.1+ write CPython 3.10+ calls.
	SymWriteEx = "SSL_write_ex"
	// SymRead is the read whose length is its return value.
	SymRead = "SSL_read"
	// SymReadEx is the read whose length is *readbytes when the return is 1.
	SymReadEx = "SSL_read_ex"
	// SymFree ends a connection: its probe tells the reader that an SSL* at the same address is a new one
	// (R3a). It is hooked beside the reads and writes, never on its own (Usable).
	SymFree = "SSL_free"
)

// Symbols lists every symbol this package looks for, in the order R1/R2 prefer them.
var Symbols = []string{SymWrite, SymWriteEx2, SymWriteEx, SymRead, SymReadEx, SymFree}

// SymSendfile is OpenSSL 3.0+'s other way out of a connection and a deliberate non-hook, named here so its
// absence from Symbols is a recorded decision rather than an oversight (docs/p0/capture-derive.md R1).
//
// SSL_write(3ssl) declares `ossl_ssize_t SSL_sendfile(SSL *s, int fd, off_t offset, size_t size, int
// flags)` beside SSL_write and SSL_write_ex, "available only when Kernel TLS is enabled"; it hands a file
// descriptor's contents to the kernel with zero-copy semantics, so the plaintext never passes through a
// userspace buffer at all. There is nothing at that call site for an entry probe to read: the bytes are in
// a file, and the arguments are an fd and an offset rather than SSL_write's (buf, num), so pointing any of
// R1-R3's programs at it would read a file descriptor as a buffer pointer. Capturing it needs a program of
// its own and a way to read the file, both on the bpf side of the boundary and neither present.
//
// Hooking it is therefore worse than not hooking it, and the cost of not hooking it is a connection
// captured in one direction with no gap to say so — a silent absence I4 otherwise forbids. It is recorded
// as a known limitation in R1 instead. The exposure is small: SSL_sendfile is a server-side kTLS
// optimisation, and no mainstream client library an agent would use calls it.
const SymSendfile = "SSL_sendfile"

// ErrNoSymbols is a candidate binary that exports none of Symbols: Bun's BoringSSL, a rustls binary, a
// stripped copy of an interpreter. It is the static-tls-no-symbols gap of R37, never a run failure.
var ErrNoSymbols = errors.New("uprobe: no OpenSSL symbols")

// ErrNotELF is a candidate path that is not an ELF executable or shared object at all.
var ErrNotELF = errors.New("uprobe: not an ELF executable or shared object")

// ErrSymbolTableTooLarge is a candidate whose symbol table, or string table, is over the bound readBinary
// reads, and whose other table exports none of Symbols. It is not soft: the file was not read, so it is
// no-openssl with the size in its detail, never the static-tls-no-symbols verdict, and it is not cached.
var ErrSymbolTableTooLarge = errors.New("uprobe: symbol table too large to read")

// ErrSymbolOutsideFile is a candidate that exports one of Symbols at an address an executable segment maps
// but the file holds no byte for (fileOffset). A function a linker places has bytes in the file, so the file is
// malformed or written to mislead, and the candidate is refused whole rather than attached without that symbol:
// its other symbols would be attached, and a candidate left with SSL_write and no read would capture requests
// and never a response with no gap to say so (I4). It is not soft (softErr), so unless another of the process's
// candidates attaches, the process is a no-openssl gap whose detail names the symbol, as for a candidate the
// host refused to probe (capture-derive R37).
var ErrSymbolOutsideFile = errors.New("uprobe: an OpenSSL symbol has no byte of the file behind it")

// errUnmapped is fileOffset's answer for an address no executable segment maps: a symbol with nothing in
// this file to attach to, which readBinary passes over as it always has.
var errUnmapped = errors.New("uprobe: no executable segment maps the address")

// binary is one ELF this package can attach to: where it is, what identifies it across hosts and runs, and
// the file offset of every symbol it exports.
//
// Offsets are computed once here and cached by the binary's identity, so a second process mapping the same
// libssl costs a map lookup rather than a second ELF parse (R7, §3 "attach cache").
type binary struct {
	// Path is where this ELF was read from, already resolved through /proc/<pid>/root for a
	// containerized process (R39). It records one process's spelling of the file and is not an
	// attach target: the entry is cached by (dev,ino) and outlives that process, whose /proc entry
	// the kernel removes when it exits. An attach uses the live candidate's path instead.
	Path string
	// BuildID is the hex of .note.gnu.build-id when the binary carries one: the identity that holds
	// across hosts and runs, where (dev, ino) only holds on one filesystem (R7).
	BuildID string
	// Offsets maps each symbol of Symbols the binary exports to its file offset, which is what a
	// uprobe attaches at.
	Offsets map[string]uint64
}

// Has reports whether the binary exports a symbol.
func (b *binary) Has(sym string) bool {
	_, ok := b.Offsets[sym]
	return ok
}

// WriteSymbols applies R1 and R2: SSL_write is hooked whenever it exists, and exactly one _ex variant is
// hooked beside it — SSL_write_ex2 where OpenSSL 3.3+ provides it, else SSL_write_ex, never both, because
// SSL_write_ex tail-calls SSL_write_ex2 and hooking both double-counts every write.
//
// A binary that exports only an _ex variant still gets that one hook: R1 is "when present", not "or
// nothing" (edge case #7's dead-code-eliminated caller is the same shape seen from the other side).
func (b *binary) WriteSymbols() []string {
	var out []string
	if b.Has(SymWrite) {
		out = append(out, SymWrite)
	}
	switch {
	case b.Has(SymWriteEx2):
		out = append(out, SymWriteEx2)
	case b.Has(SymWriteEx):
		out = append(out, SymWriteEx)
	}
	return out
}

// ReadSymbols applies R3: every read this binary exports, each of which needs an entry and a return probe
// because its length exists only once the call has returned.
func (b *binary) ReadSymbols() []string {
	var out []string
	for _, sym := range []string{SymRead, SymReadEx} {
		if b.Has(sym) {
			out = append(out, sym)
		}
	}
	return out
}

// Usable reports whether the binary exports anything worth attaching to.
func (b *binary) Usable() bool { return len(b.WriteSymbols())+len(b.ReadSymbols()) > 0 }

// Complete reports whether the binary has both a write and a read hook, the only shape that captures a
// connection in both directions (I4). readBinary keeps reading tables until it holds.
func (b *binary) Complete() bool { return len(b.WriteSymbols()) > 0 && len(b.ReadSymbols()) > 0 }

// readBinary parses one ELF and returns what attaching needs: the build id and the file offset of every
// symbol of Symbols it exports.
//
// Both .dynsym and .symtab are read (.symtab only if .dynsym lacks a write or a read symbol), which is the whole of the static-linking story: an exported symbol of
// a shared libssl is in .dynsym, and a statically linked uv/python-build-standalone Python keeps the same
// names as local symbols in .symtab (ARCHITECTURE §12). musl and glibc binaries read identically (edge
// case #6). A binary that exports none of them is ErrNoSymbols, not an error worth logging as a failure.
func readBinary(path string) (*binary, error) {
	f, err := openELF(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return nil, fmt.Errorf("%w: %s is %s", ErrNotELF, path, f.Type)
	}
	out := &binary{Path: path, Offsets: map[string]uint64{}}
	// .dynsym first, so an exported definition wins over a local alias of the same name. .symtab is read
	// only when .dynsym did not hold both a write and a read symbol, so a huge unstripped .symtab costs nothing where .dynsym already
	// has the symbols (the official Node tarball: a 3 MB .symtab with a 10 MB .strtab, and SSL_write in .dynsym).
	var oversize error
	for _, typ := range []elf.SectionType{elf.SHT_DYNSYM, elf.SHT_SYMTAB} {
		if out.Complete() {
			break
		}
		if err := checkSymbolSection(f, typ, path); err != nil {
			oversize = err
			continue
		}
		if err := collectOffsets(f, typ, out, path); err != nil {
			return nil, err
		}
	}
	if !out.Usable() {
		if oversize != nil {
			// A table this package refused to read says nothing about what it holds: not the Bun/rustls
			// "exports none" verdict, and not cached as one.
			return nil, oversize
		}
		return out, fmt.Errorf("%w: %s", ErrNoSymbols, path)
	}
	out.BuildID = buildID(f)
	return out, nil
}

// checkSymbolSection refuses a symbol table of the given type, or its string table, over the bounds.
func checkSymbolSection(f *elfFile, typ elf.SectionType, path string) error {
	for _, sec := range f.Sections {
		if sec.Type != typ {
			continue
		}
		strSize := uint64(0)
		if int(sec.Link) < len(f.Sections) {
			strSize = f.Sections[sec.Link].Size
		}
		if sec.Size > maxSymbolSection || strSize > maxStringSection {
			return fmt.Errorf("%w: %s: %s of %d bytes (string table %d) is over %d (%d)", ErrSymbolTableTooLarge, path,
				sec.Name, sec.Size, strSize, maxSymbolSection, maxStringSection)
		}
	}
	return nil
}

// maxSymbolName is how far into the string table collectOffsets looks for a name's NUL. The longest name of
// Symbols is 13 bytes, so a name not terminated within this many bytes is not one of them and is passed over
// unread.
const maxSymbolName = 64

// collectOffsets records the file offset of each entry of Symbols that the first symbol table of type typ
// defines as a function, skipping names out already has.
//
// It walks the table's raw entries and compares each name in place against Symbols, never building an
// []elf.Symbol: debug/elf copies a symbol's name out of the string table per entry, so entries that all name
// one long string multiply the two bounds (349k entries of an 8 MiB table times a 1 MiB name is hundreds of
// GiB) instead of adding them. The string table is read once, bounded by checkSymbolSection.
func collectOffsets(f *elfFile, typ elf.SectionType, out *binary, path string) error {
	var sec *elf.Section
	for _, s := range f.Sections {
		if s.Type == typ {
			sec = s
			break
		}
	}
	if sec == nil || int(sec.Link) >= len(f.Sections) {
		return nil
	}
	strSec := f.Sections[sec.Link]
	if strSec.Type != elf.SHT_STRTAB {
		return nil
	}
	table, err := sec.Data()
	if err != nil {
		return fmt.Errorf("uprobe: symbols of %s: %w", path, err)
	}
	strs, err := strSec.Data()
	if err != nil {
		return fmt.Errorf("uprobe: symbols of %s: %w", path, err)
	}
	ent := 24
	if f.Class == elf.ELFCLASS32 {
		ent = 16
	}
	bo := f.ByteOrder
	for i := ent; i+ent <= len(table); i += ent { // entry 0 is the reserved null symbol
		e := table[i : i+ent]
		var info byte
		var shndx uint16
		var value uint64
		if ent == 24 {
			info, shndx, value = e[4], bo.Uint16(e[6:8]), bo.Uint64(e[8:16])
		} else {
			info, shndx, value = e[12], bo.Uint16(e[14:16]), uint64(bo.Uint32(e[4:8]))
		}
		nameOff := uint64(bo.Uint32(e[0:4]))
		if nameOff >= uint64(len(strs)) {
			return fmt.Errorf("%w: %s: symbol name at %d is outside its %d-byte string table", ErrNotELF, path, nameOff, len(strs))
		}
		window := strs[nameOff:min(nameOff+maxSymbolName, uint64(len(strs)))]
		n := bytes.IndexByte(window, 0)
		if n < 0 {
			if uint64(len(window)) == uint64(len(strs))-nameOff {
				n = len(window) // the table's last name, unterminated: what debug/elf reads as the name
			} else {
				continue
			}
		}
		name := window[:n]
		want := ""
		for _, w := range Symbols {
			if string(name) == w { // compared in place; the conversion does not allocate
				want = w
				break
			}
		}
		if want == "" || elf.ST_TYPE(info) != elf.STT_FUNC {
			continue
		}
		if elf.SectionIndex(shndx) == elf.SHN_UNDEF || elf.SectionIndex(shndx) >= elf.SHN_LORESERVE {
			// An undefined symbol is a reference into another object: a non-PIE executable that takes
			// SSL_write's address carries one whose value is its PLT stub, which is not the function.
			// Absolute and common symbols are not code this file defines either.
			continue
		}
		if _, seen := out.Offsets[want]; seen {
			continue
		}
		off, err := fileOffset(f.File, f.size, value)
		if errors.Is(err, errUnmapped) {
			// Value 0 from SHN_UNDEF is a call into another object, relocated at load time, and any other
			// address no executable segment maps is not code this file runs: either way there is nothing in
			// this file to attach to.
			continue
		}
		if err != nil {
			return fmt.Errorf("%w (%s at %#x in %s)", err, want, value, path)
		}
		out.Offsets[want] = off
	}
	return nil
}

// fileOffset turns a symbol's virtual address into the file offset a uprobe attaches at, by finding the
// executable PT_LOAD segment whose bytes in the file hold it: offset = value - segment vaddr + segment file
// offset. size is the length of the file the program headers were read from. An address no executable
// segment maps is errUnmapped; one a segment maps with no byte of the file behind it is ErrSymbolOutsideFile.
//
// The bound is the segment's Filesz and Memsz and the file's own end. A segment's memory image is its first
// Filesz bytes read from the file and then zeros up to Memsz, so an address in that zero-filled tail has no
// byte of this file behind it, and the offset computed for it names whatever follows the segment in the file:
// another segment's code, where a probe would fire on instructions that are not the function's, or bytes
// nothing executes, where it would never fire. Either is a capture that is wrong with nothing in the record to
// say so (I4). FuzzReadBinary found the tail case.
//
// debug/elf checks only that Off and Filesz are not negative, never that Off+Filesz fits in the file, so a
// segment can claim file bytes past the end. An offset there is not a place the file holds anything, and
// the kernel refuses a uprobe past the file's size with EINVAL.
//
// Vaddr, Filesz, Memsz and Off are the file's own words, which the agent may have written (the file is one
// it chose to map), so no sum of them is trusted not to wrap: the address is compared by its distance from
// Vaddr, and the offset by its distance from the file's end.
func fileOffset(f *elf.File, size int64, value uint64) (uint64, error) {
	if value == 0 {
		return 0, errUnmapped
	}
	end := uint64(max(size, 0))
	tail := false
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if value < prog.Vaddr {
			continue
		}
		delta := value - prog.Vaddr
		if delta >= prog.Memsz {
			continue
		}
		if delta >= prog.Filesz {
			// Another segment may still hold the address in its file bytes; only if none does is the
			// symbol one the file cannot back.
			tail = true
			continue
		}
		if prog.Off >= end || delta >= end-prog.Off {
			return 0, fmt.Errorf("%w: file offset past the file's %d bytes", ErrSymbolOutsideFile, size)
		}
		return prog.Off + delta, nil
	}
	if tail {
		return 0, fmt.Errorf("%w: in the zero-filled tail of an executable segment, past its file bytes", ErrSymbolOutsideFile)
	}
	return 0, errUnmapped
}

// maxBuildIDNote bounds what buildID reads of .note.gnu.build-id. A GNU build id is a 20-byte SHA-1 (or a
// 16-byte MD5, or a UUID) behind a 16-byte note header, so a real note is under a hundred bytes; the section
// header's size is the file's claim, and a sparse file a few KiB on disk that claims gigabytes made sec.Data()
// allocate and read all of it, on every open of a libssl-named file, before any cache was consulted
// (R7: 2.6 GiB for one hostile candidate).
const maxBuildIDNote = 1 << 10

// buildID returns the hex of .note.gnu.build-id, or "" when the binary carries none. A missing build id is
// not an error: (dev, ino) still identifies the file on this host, which is all the attach cache needs
// within one boot (R7). A note larger than maxBuildIDNote, or one that claims bytes past the end of the file
// the headers were read from, is read as no build id at all rather than allocated.
func buildID(f *elfFile) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil || sec.Type == elf.SHT_NOBITS {
		return ""
	}
	size := uint64(max(f.size, 0))
	if sec.Size > maxBuildIDNote || sec.Offset > size || sec.FileSize > size-sec.Offset {
		return ""
	}
	data := make([]byte, sec.Size)
	if _, err := sec.ReadAt(data, 0); err != nil {
		return ""
	}
	return parseBuildIDNote(data, f.ByteOrder.Uint32)
}

// readBuildID opens one candidate and returns only its build id, which is all the cache key needs before
// the decision to parse a whole symbol table is taken (R7).
//
// Its errors mirror readBinary's exactly, so a candidate that is not an ELF is classified the same way
// whichever of the two reaches it first and softErr keeps its meaning.
func readBuildID(path string) (string, error) {
	f, err := openELF(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return "", fmt.Errorf("%w: %s is %s", ErrNotELF, path, f.Type)
	}
	return buildID(f), nil
}

// elfFile is a candidate parsed as an ELF, with the length of the file its words were read from.
type elfFile struct {
	*elf.File
	// size is fstat's length of the descriptor debug/elf reads through, not of the path, which the agent
	// may have pointed at another file since: fileOffset holds offsets to the file the headers came from.
	size int64
	fd   *os.File
}

// Close closes the descriptor; debug/elf closes only a file it opened itself, which this one is not.
func (f *elfFile) Close() error { return f.fd.Close() }

// openELF opens a candidate as an ELF file. A file that is not one is ErrNotELF, the ordinary "nothing to
// attach to here" of softErr: every dynamically linked process maps /etc/ld.so.cache, and many map a locale
// archive or fonts, none of which is an ELF. Reported as the open failure it is not, the first such mapping
// became the process's no-openssl gap and hid whatever the real candidates said.
func openELF(path string) (*elfFile, error) {
	// The path is one the traced process named, and the launcher opens it as root: it is first opened
	// O_PATH, which runs no open handler, and read only once that descriptor shows a regular file, reopened
	// through it so the file checked is the file read. An O_NONBLOCK open of a FIFO returned at once, but a
	// device node's own open ran (a tape rewinds on open), and anything but a regular file is refused now
	// before it is opened at all. O_NONBLOCK stays on the read open for a file swapped
	// between the two opens, which the reopen through the descriptor rules out anyway.
	pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("uprobe: open %s: %w", path, &os.PathError{Op: "open", Path: path, Err: err})
	}
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		_ = unix.Close(pfd)
		return nil, fmt.Errorf("uprobe: stat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(pfd)
		return nil, fmt.Errorf("%w: %s is not a regular file (mode %#o)", ErrNotELF, path, st.Mode&unix.S_IFMT)
	}
	fd, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(pfd), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	_ = unix.Close(pfd)
	if err != nil {
		return nil, fmt.Errorf("uprobe: open %s: %w", path, err)
	}
	budget := &budgetReaderAt{r: fd, left: maxHeaderRead}
	f, err := elf.NewFile(budget)
	budget.unlimited = true // the section reads that follow are bounded by their own checks
	if err != nil {
		_ = fd.Close()
		if errors.Is(err, errHeaderBudget) {
			return nil, fmt.Errorf("%w: %s: %v", ErrSymbolTableTooLarge, path, err)
		}
		var format *elf.FormatError
		if errors.As(err, &format) {
			return nil, fmt.Errorf("%w: %s: %v", ErrNotELF, path, err)
		}
		return nil, fmt.Errorf("uprobe: open %s: %w", path, err)
	}
	return &elfFile{File: f, size: st.Size, fd: fd}, nil
}

// maxHeaderRead bounds what elf.NewFile may read of a candidate: the file header, the program and section
// headers and the section-name table. debug/elf sizes those reads from the file's own claims (a .shstrtab of
// 1 GiB, or e_shnum 0 with section 0's sh_size naming millions of headers), and in a sparse file the
// claimed bytes read back as zeros at no cost to the agent that wrote it, so the claim is bounded by what is
// read rather than by what the file says. A real libssl or interpreter needs well under 1 MiB.
const maxHeaderRead = 16 << 20

var errHeaderBudget = errors.New("ELF headers claim more than the bytes this package reads of them")

// budgetReaderAt is an io.ReaderAt that fails once more than left bytes were read through it, until unlimited.
type budgetReaderAt struct {
	r         io.ReaderAt
	left      int64
	unlimited bool
}

func (b *budgetReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if !b.unlimited && int64(len(p)) > b.left {
		return 0, errHeaderBudget
	}
	n, err := b.r.ReadAt(p, off)
	if !b.unlimited {
		b.left -= int64(n)
	}
	return n, err
}

// pinnedFile is a candidate held by an O_PATH descriptor from its identity through its attach, and the
// descriptor's magic link, /proc/self/fd/<n>, which every later step opens, stats and attaches through.
//
// The candidate's path is one the traced process named (an open of any libssl-named file, a mapping) and
// is resolved under /proc/<pid>/root, where the process may rename a symlink over it at any moment. Each
// separate resolution of that path could land on a different file: the stat that keys the cache, the parse
// that reads the offsets, and the perf_event_open the kernel resolves once per probe. An agent could then
// have a crafted libssl parsed and the probes placed at its offsets in a host library such as libc, which
// the launcher, as root, would write int3 into for every process on the host. The magic link resolves to the
// inode the descriptor holds, whatever the path names by then, so every step sees the one file (R7).
type pinnedFile struct {
	fd   int
	path string
}

// pinCandidate opens a candidate O_PATH, which runs no open handler, and refuses anything but a regular
// file before any step reads it (openELF's rule). Its errors match openELF's: a missing path is
// os.ErrNotExist, a non-regular file ErrNotELF.
func pinCandidate(path string) (*pinnedFile, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("uprobe: open %s: %w", path, &os.PathError{Op: "open", Path: path, Err: err})
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("uprobe: stat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s is not a regular file (mode %#o)", ErrNotELF, path, st.Mode&unix.S_IFMT)
	}
	return &pinnedFile{fd: fd, path: "/proc/self/fd/" + strconv.Itoa(fd)}, nil
}

// Close gives the descriptor back. The probes placed through it hold the inode themselves.
func (p *pinnedFile) Close() error { return unix.Close(p.fd) }

// named is an error from a step that read the pinned file, spelled with the candidate's own path rather
// than the descriptor's link, which names nothing to whoever reads the gap's detail.
type named struct {
	err        error
	link, path string
}

func (e *named) Error() string { return strings.ReplaceAll(e.err.Error(), e.link, e.path) }
func (e *named) Unwrap() error { return e.err }

// rename returns err spelled with the candidate's path, nil for nil.
func (p *pinnedFile) rename(err error, path string) error {
	if err == nil {
		return nil
	}
	return &named{err: err, link: p.path, path: path}
}

// parseBuildIDNote reads the first NT_GNU_BUILD_ID note out of a note section. The layout is namesz,
// descsz, type, the NUL-padded name and the NUL-padded descriptor, each padded to four bytes.
func parseBuildIDNote(data []byte, u32 func([]byte) uint32) string {
	const noteGNUBuildID = 3
	for len(data) >= 12 {
		namesz := int(u32(data[0:4]))
		descsz := int(u32(data[4:8]))
		typ := u32(data[8:12])
		nameEnd := 12 + align4(namesz)
		// The descriptor itself need not be padded when it is the last note in the section, so its
		// end is checked unpadded and only the step to the next note is aligned.
		descEnd := nameEnd + descsz
		next := nameEnd + align4(descsz)
		if namesz < 0 || descsz < 0 || nameEnd < 12 || descEnd < nameEnd || descEnd > len(data) {
			return ""
		}
		name := string(data[12 : 12+max(namesz-1, 0)])
		if typ == noteGNUBuildID && name == "GNU" && descsz > 0 {
			return hex.EncodeToString(data[nameEnd:descEnd])
		}
		if next <= 12 || next > len(data) {
			return ""
		}
		data = data[next:]
	}
	return ""
}

// align4 rounds a note field's length up to its four-byte alignment.
func align4(n int) int { return (n + 3) &^ 3 }

// identity is what the attach cache keys on: the (device, inode) pair as R7's fast path, and the ELF build
// id as the correctness key R7 names beside it.
//
// The build id is part of the key rather than a check applied after a hit because a stat() pair is not a
// file identity, and R39 puts every candidate on the one filesystem where that is most obviously true. The
// kernel's own overlayfs documentation says of a non-directory with layers not all on one filesystem and
// xino off that st_ino is not persistent and that "both [st_dev and st_ino] can change over the lifetime of
// a non-directory object" (Documentation/filesystems/overlayfs.rst, "Inode properties"); ADR 0010 banned
// the pair outright for enforcement after the same finding on btrfs subvolumes. Two different files can
// therefore reach the same pair — an inode number reused after a delete, a recycled btrfs anonymous device,
// an overlay copy-up — and this cache is host-wide and outlives runs (ARCHITECTURE §9 "resource
// lifetimes"), so there is no bound on how long a stale entry waits. Keyed on the pair alone, the second
// file would be handed the first binary's symbol offsets, or be refused by a failure the first binary
// recorded, in both cases with no probe of its own and no gap to show for it (I4).
//
// A binary carrying no build id keys on the pair alone, which is the residual limitation recorded in
// docs/p0/capture-derive.md R7: nothing in the file distinguishes it from another file that reaches the
// same pair.
type identity struct {
	Dev     uint64
	Ino     uint64
	BuildID string
}

// statIdentity reads a path's (device, inode). It follows symlinks, which is what makes edge case #4's two
// names for one libssl a single cache entry.
func statIdentity(path string) (identity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return identity{}, fmt.Errorf("uprobe: stat %s: %w", path, err)
	}
	dev, ino, ok := sysIdentity(fi)
	if !ok {
		return identity{}, fmt.Errorf("uprobe: stat %s: no inode identity", path)
	}
	return identity{Dev: dev, Ino: ino}, nil
}

// candidateIdentity reads a candidate's whole cache identity: the (device, inode) fast key and the build id
// that makes a hit on it correct (R7).
//
// It is called before any cache is consulted, which is the price of the correctness key: a stale entry can
// only be told from a live one by something read out of the file. The read is deliberately the cheap half
// of readBinary -- debug/elf parses the file header and the section headers, not the symbol tables that
// make a statically linked interpreter large -- so what R7 calls the fast path stays one.
//
// On an ELF that will not read it returns the partial identity with the error, so a caller that wants to
// record the failure has the key it belongs under.
func candidateIdentity(path string) (identity, error) {
	id, err := statIdentity(path)
	if err != nil {
		return identity{}, err
	}
	build, err := readBuildID(path)
	if err != nil {
		return id, err
	}
	id.BuildID = build
	return id, nil
}
