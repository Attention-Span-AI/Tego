// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/sys/unix"
)

// ELF constants used by the PT_INTERP reader (elf(5)).
const (
	elfMagic      = "\x7fELF"
	elfClass32    = 1
	elfClass64    = 2
	elfDataLE     = 1
	elfPTInterp   = 3
	elfHeader32   = 52
	elfHeader64   = 64
	maxProgHdrs   = 512     // more than any real binary; bounds the read (I7)
	maxInterpLen  = pathMax // a loader's path is opened by name
	shebangMaxLen = 256     // BINPRM_BUF_SIZE
	// maxELFRead is what ReadInterp reads of a file at most: the identification bytes, the file header, each
	// program header's fields (maxProgHdrs of them) and the interpreter string, with room to spare.
	maxELFRead = 16 + elfHeader64 + maxProgHdrs*56 + maxInterpLen + 1024
)

// ELF reader outcomes.
var (
	// ErrNotELF marks a file without the ELF magic: a script, a text file.
	ErrNotELF = errors.New("not an ELF file")
	// ErrMalformedELF marks a header too short or inconsistent to read
	// PT_INTERP from, or a class/endianness outside the P0 floor (E14, E34).
	ErrMalformedELF = errors.New("malformed ELF header")
)

// ReadInterp returns the PT_INTERP loader path of an ELF file, "" for a
// statically linked one (E16). The file is one the agent may control (an
// entry in the worktree, R8), and the Landlock tier's Prepare reads it again,
// so it is opened through openData: a FIFO, a device, a file on procfs or any
// other file system not known to store data, or one under a lease is refused
// with an error, never waited on. It reads at most maxELFRead bytes, with
// pread(2), and closes the file before returning.
func ReadInterp(path string) (string, error) {
	fd, _, err := openData(path, true)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	return readInterp(&boundedReaderAt{fd: fd, left: maxELFRead})
}

// readInterp is ReadInterp over any ReaderAt; the fuzz target feeds it bytes.
// A short read is a verdict on the content (ErrNotELF, ErrMalformedELF); any
// other read error is returned as it is, since a file that could not be read
// is neither.
func readInterp(r io.ReaderAt) (string, error) {
	var ident [16]byte
	if n, err := r.ReadAt(ident[:], 0); err != nil && n < len(ident) {
		if !errors.Is(err, io.EOF) {
			return "", err
		}
		if n >= 4 && string(ident[:4]) == elfMagic {
			return "", ErrMalformedELF
		}
		return "", ErrNotELF
	}
	if string(ident[:4]) != elfMagic {
		return "", ErrNotELF
	}
	if ident[5] != elfDataLE { // E34: big-endian fails closed as malformed
		return "", ErrMalformedELF
	}
	le := binary.LittleEndian
	var phoff uint64
	var phentsize, phnum uint16
	switch ident[4] {
	case elfClass64:
		var hdr [elfHeader64]byte
		if err := readFull(r, hdr[:], 0); err != nil {
			return "", err
		}
		phoff = le.Uint64(hdr[32:40])
		phentsize = le.Uint16(hdr[54:56])
		phnum = le.Uint16(hdr[56:58])
	case elfClass32:
		var hdr [elfHeader32]byte
		if err := readFull(r, hdr[:], 0); err != nil {
			return "", err
		}
		phoff = uint64(le.Uint32(hdr[28:32]))
		phentsize = le.Uint16(hdr[42:44])
		phnum = le.Uint16(hdr[44:46])
	default:
		return "", ErrMalformedELF
	}
	want := uint16(56)
	if ident[4] == elfClass32 {
		want = 32
	}
	// An executable always has program headers; none at all is not "static".
	if phentsize < want || phnum == 0 || phnum > maxProgHdrs || phoff == 0 {
		return "", ErrMalformedELF
	}
	// Only the fields read below are read of each header: an e_phentsize past them is the next header's
	// offset, not more to read, so maxProgHdrs headers cost maxProgHdrs*want bytes whatever it says.
	ph := make([]byte, want)
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*uint64(phentsize)
		if off > 1<<40 {
			return "", ErrMalformedELF
		}
		if err := readFull(r, ph, int64(off)); err != nil {
			return "", err
		}
		if le.Uint32(ph[0:4]) != elfPTInterp {
			continue
		}
		var poff, psize uint64
		if ident[4] == elfClass64 {
			poff, psize = le.Uint64(ph[8:16]), le.Uint64(ph[32:40])
		} else {
			poff, psize = uint64(le.Uint32(ph[4:8])), uint64(le.Uint32(ph[16:20]))
		}
		if psize == 0 || psize > maxInterpLen || poff > 1<<40 {
			return "", ErrMalformedELF
		}
		buf := make([]byte, psize)
		if err := readFull(r, buf, int64(poff)); err != nil {
			return "", err
		}
		s := string(buf)
		if i := indexNUL(s); i >= 0 {
			s = s[:i]
		}
		if s == "" || s[0] != '/' {
			return "", ErrMalformedELF
		}
		return s, nil
	}
	return "", nil // no PT_INTERP: static (E16)
}

// readFull is ReadAt for readInterp: a read the file ends before is ErrMalformedELF, and any other error
// is returned as it is.
func readFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	switch {
	case n == len(p):
		return nil
	case err == nil, errors.Is(err, io.EOF):
		return ErrMalformedELF
	}
	return err
}

func indexNUL(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return i
		}
	}
	return -1
}

// ReadShebang returns the interpreter path and its optional first argument
// from a "#!" script, or ok=false when the file is not a script. Only the
// first BINPRM_BUF_SIZE bytes are read, mirroring binfmt_script, and the file
// is opened through openData, as ReadInterp opens it.
func ReadShebang(path string) (interp, arg string, ok bool, err error) {
	fd, _, err := openData(path, true)
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = unix.Close(fd) }()
	buf := make([]byte, shebangMaxLen)
	n, err := preadFull(fd, buf, 0)
	if err != nil {
		return "", "", false, err
	}
	return parseShebang(buf[:n])
}

// ReadShebangLine is ReadShebang with the interpreter's name as the line writes it (ShebangLine): it may be relative,
// which the kernel opens from the task's cwd, or empty. compile --exec reads a script's #! line with it, as the
// supervisor reads every image's in a run with command rules (ADR 0048 (3), (4)).
func ReadShebangLine(path string) (interp, arg string, ok bool, err error) {
	fd, _, err := openData(path, true)
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = unix.Close(fd) }()
	buf := make([]byte, shebangMaxLen)
	n, err := preadFull(fd, buf, 0)
	if err != nil {
		return "", "", false, err
	}
	interp, arg, ok = ShebangLine(buf[:n])
	return interp, arg, ok, nil
}

// parseShebang reads a #! line as fs/binfmt_script.c load_script does (ShebangLine). A name that is not
// absolute is reported as no script (P0 models absolute #! paths only).
func parseShebang(b []byte) (interp, arg string, ok bool, err error) {
	interp, arg, ok = ShebangLine(b)
	if !ok || interp == "" || interp[0] != '/' {
		return "", "", false, nil
	}
	return interp, arg, true, nil
}

// ShebangLine reads a #! line exactly as fs/binfmt_script.c load_script does. b is the file's first
// BINPRM_BUF_SIZE bytes (more are ignored), zero-padded as the kernel's buffer is. The line ends at the
// first '\n' before any NUL (the kernel's strnchr stops at a NUL); with none, the interpreter name must
// end (space, tab or NUL) at or before the buffer's last byte or the file is no script (ENOEXEC), and the
// line runs up to that last byte, which is cut. Trailing spaces and tabs are trimmed, and nothing else: the '\r' of a CRLF line
// stays part of the name or the argument, so `#!/bin/sh\r` names the file "/bin/sh\r", and execve opens
// that path. The name runs up to a space, tab or NUL; a NUL there leaves no argument. Otherwise the
// argument is the whole remainder after the spaces and tabs that follow the name, up to a NUL, which the
// kernel passes to the interpreter as one string ("python3 -u", never "python3"). The name is returned
// as written: it may be relative (the kernel opens it from the task's cwd) or, after a NUL, empty.
func ShebangLine(b []byte) (interp, arg string, ok bool) {
	interp, arg, _, ok = ShebangArgv(b)
	return interp, arg, ok
}

// ShebangArgv is ShebangLine with what arg alone cannot say. emptyArg is a line whose argument is there and empty
// (`#!/opt/tool \0`): the kernel's i_arg points at the NUL, so binfmt_script gives the interpreter an empty element,
// where a line with no argument gives none.
func ShebangArgv(b []byte) (interp, arg string, emptyArg, ok bool) {
	if len(b) < 2 || b[0] != '#' || b[1] != '!' {
		return "", "", false, false
	}
	buf := make([]byte, shebangMaxLen)
	copy(buf, b)
	spaceTab := func(c byte) bool { return c == ' ' || c == '\t' }
	nextNonSpaceTab := func(i, end int) int {
		for ; i < end; i++ {
			if !spaceTab(buf[i]) {
				return i
			}
		}
		return -1
	}
	nextTerm := func(i, end int) int {
		for ; i < end; i++ {
			if spaceTab(buf[i]) || buf[i] == 0 {
				return i
			}
		}
		return -1
	}
	end := -1 // strnchr(buf, BINPRM_BUF_SIZE, '\n'), which stops at a NUL
	for i, c := range buf {
		if c == 0 {
			break
		}
		if c == '\n' {
			end = i
			break
		}
	}
	if end < 0 {
		// The kernel's next_non_spacetab and next_terminator scan up to and including buf_end, the last byte, so
		// a name whose only terminator is that byte (a 255-byte file's zero padding, or a space or tab there)
		// is a script. The line still ends at that byte, which load_script overwrites with a NUL.
		last := len(buf) - 1
		i := nextNonSpaceTab(2, last+1)
		if i < 0 || nextTerm(i, last+1) < 0 {
			return "", "", false, false // the interpreter name may be truncated: ENOEXEC
		}
		end = last
	}
	for spaceTab(buf[end-1]) {
		end--
	}
	name := nextNonSpaceTab(2, end)
	if name < 0 {
		return "", "", false, false // no interpreter name: ENOEXEC
	}
	sep := nextTerm(name, end)
	if sep < 0 {
		sep = end
	}
	interp = string(buf[name:sep])
	if sep < end && buf[sep] != 0 {
		if a := nextNonSpaceTab(sep, end); a >= 0 {
			rest := buf[a:end]
			if i := indexByte(rest, 0); i >= 0 {
				rest = rest[:i]
			}
			arg = string(rest)
			emptyArg = arg == ""
		}
	}
	return interp, arg, emptyArg, true
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
