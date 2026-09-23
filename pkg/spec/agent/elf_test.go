// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// elf64 builds a minimal little-endian ELF64 image; interp "" makes it static.
func elf64(interp string, phnum int) []byte {
	le := binary.LittleEndian
	hdr := make([]byte, 64)
	copy(hdr, "\x7fELF")
	hdr[4], hdr[5], hdr[6] = 2, 1, 1
	le.PutUint16(hdr[16:], 2)
	le.PutUint16(hdr[18:], 0x3e)
	le.PutUint32(hdr[20:], 1)
	le.PutUint64(hdr[32:], 64)
	le.PutUint16(hdr[52:], 64)
	le.PutUint16(hdr[54:], 56)
	le.PutUint16(hdr[56:], uint16(phnum))
	body := append([]byte{}, hdr...)
	dataOff := 64 + 56*phnum
	for i := 0; i < phnum; i++ {
		ph := make([]byte, 56)
		if interp != "" && i == phnum-1 {
			le.PutUint32(ph[0:], elfPTInterp)
			le.PutUint64(ph[8:], uint64(dataOff))
			le.PutUint64(ph[32:], uint64(len(interp)+1))
		} else {
			le.PutUint32(ph[0:], 1) // PT_LOAD
		}
		body = append(body, ph...)
	}
	return append(append(body, interp...), 0)
}

// elf32 builds a minimal little-endian ELF32 image with one PT_INTERP.
func elf32(interp string) []byte {
	le := binary.LittleEndian
	hdr := make([]byte, 52)
	copy(hdr, "\x7fELF")
	hdr[4], hdr[5], hdr[6] = 1, 1, 1
	le.PutUint32(hdr[28:], 52)
	le.PutUint16(hdr[40:], 52)
	le.PutUint16(hdr[42:], 32)
	le.PutUint16(hdr[44:], 1)
	ph := make([]byte, 32)
	le.PutUint32(ph[0:], elfPTInterp)
	le.PutUint32(ph[4:], 84)
	le.PutUint32(ph[16:], uint32(len(interp)+1))
	return append(append(append(hdr, ph...), interp...), 0)
}

// agent-contract.md E16 (static64: no PT_INTERP is "" and no error) against E14 (truncated: malformed) and E34 (big-endian, bad class: malformed).
func TestReadInterp(t *testing.T) {
	be := elf64("/lib64/ld.so", 1)
	be[5] = 2
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr error
	}{
		{"dynamic64", elf64("/lib64/ld-linux-x86-64.so.2", 3), "/lib64/ld-linux-x86-64.so.2", nil},
		{"dynamic32", elf32("/lib/ld-linux.so.2"), "/lib/ld-linux.so.2", nil},
		{"static64", elf64("", 2), "", nil},
		{"script", []byte("#!/bin/sh\necho hi\n"), "", ErrNotELF},
		{"empty", nil, "", ErrNotELF},
		{"short-magic", []byte("\x7fEL"), "", ErrNotELF},
		{"truncated-header", elf64("/x", 1)[:40], "", ErrMalformedELF},
		{"truncated-phdrs", elf64("/x", 3)[:100], "", ErrMalformedELF},
		{"big-endian", be, "", ErrMalformedELF},
		{"bad-class", func() []byte { b := elf64("/x", 1); b[4] = 3; return b }(), "", ErrMalformedELF},
		{"interp-not-absolute", func() []byte { b := elf64("x/ld", 1); return b }(), "", ErrMalformedELF},
		{"interp-truncated", func() []byte { b := elf64("/lib/ld.so", 1); return b[:len(b)-4] }(), "", ErrMalformedELF},
		{"no-phdrs", elf64("", 0), "", ErrMalformedELF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readInterp(bytes.NewReader(tc.data))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("interp=%q want %q", got, tc.want)
			}
		})
	}
}

// TestReadInterpRealBinary reads the loader of /bin/sh on this box.
func TestReadInterpRealBinary(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	got, err := ReadInterp("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Skip("/bin/sh is static here")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("interp %q", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("loader %s: %v", got, err)
	}
}

func TestParseShebang(t *testing.T) {
	tests := []struct {
		in     string
		interp string
		arg    string
		ok     bool
	}{
		{"#!/bin/sh\n", "/bin/sh", "", true},
		{"#!/usr/bin/env python3\nprint()", "/usr/bin/env", "python3", true},
		// binfmt_script: the '\r' of a CRLF line is not whitespace, and the argument is the whole
		// remainder, one string.
		{"#! /usr/bin/env\tpython3 -u\r\n", "/usr/bin/env", "python3 -u\r", true},
		{"#!/bin/sh\r\necho\r\n", "/bin/sh\r", "", true},
		{"#!/usr/bin/env python3 -u \t\n", "/usr/bin/env", "python3 -u", true},
		{"#!/usr/bin/env  a  b\n", "/usr/bin/env", "a  b", true},
		{"#!/bin/sh\x00-e\n", "/bin/sh", "", true},
		{"#!/bin/sh -e\x00x\n", "/bin/sh", "-e", true},
		{"#!/bin/sh", "/bin/sh", "", true},
		{"#!/bin/sh \t", "/bin/sh", "", true},
		{"#! \t\n", "", "", false},
		// No newline in the 256 bytes: the name must end before the last byte, or ENOEXEC.
		{"#!/" + strings.Repeat("a", 300), "", "", false},
		{"#!/b " + strings.Repeat("a", 300), "/b", strings.Repeat("a", 250), true},
		{"#!/usr/bin/python3 -u", "/usr/bin/python3", "-u", true},
		{"#!python\n", "", "", false},
		{"#!\n", "", "", false},
		{"echo\n", "", "", false},
		{"#", "", "", false},
	}
	for _, tc := range tests {
		interp, arg, ok, err := parseShebang([]byte(tc.in))
		if err != nil || ok != tc.ok || interp != tc.interp || arg != tc.arg {
			t.Errorf("parseShebang(%q)=(%q,%q,%v,%v)", tc.in, interp, arg, ok, err)
		}
	}
}

func FuzzPTInterp(f *testing.F) {
	f.Add(elf64("/lib64/ld-linux-x86-64.so.2", 3))
	f.Add(elf32("/lib/ld-linux.so.2"))
	f.Add(elf64("", 2))
	be := elf64("/lib64/ld.so", 1)
	be[5] = 2
	f.Add(be)
	f.Add([]byte("#!/bin/sh\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := readInterp(bytes.NewReader(data))
		if err == nil && got != "" && got[0] != '/' {
			t.Fatalf("relative interp %q accepted", got)
		}
		if err == nil && len(got) > maxInterpLen {
			t.Fatalf("interp longer than PATH_MAX")
		}
	})
}

// TestShebangArgvEmptyArgument: `#!/opt/tool \0` has an argument, empty, and the kernel gives the interpreter an empty
// element for it (probed: a #!/bin/echo line prints a leading space); a NUL right after the name, and a line that ends
// in spaces, have none.
func TestShebangArgvEmptyArgument(t *testing.T) {
	for _, tc := range []struct {
		in       string
		emptyArg bool
	}{
		{"#!/opt/tool \x00\n", true},
		{"#!/opt/tool\t \x00rest\n", true},
		{"#!/opt/tool\x00\n", false},
		{"#!/opt/tool \n", false},
		{"#!/opt/tool\n", false},
		{"#!/opt/tool x\n", false},
	} {
		interp, _, emptyArg, ok := ShebangArgv([]byte(tc.in))
		if !ok || interp != "/opt/tool" || emptyArg != tc.emptyArg {
			t.Errorf("ShebangArgv(%q) = %q, emptyArg %v, ok %v; want emptyArg %v", tc.in, interp, emptyArg, ok, tc.emptyArg)
		}
	}
}
