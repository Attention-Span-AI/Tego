// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.LeakCheckMain(m))
}

const loader = "/lib64/ld-linux-x86-64.so.2"

// fixture is an ELF64 little-endian x86-64 file of type typ with one PT_LOAD and one PT_INTERP segment for each
// entry of interps, holding those bytes: the headers execve and debug/elf read, and nothing else.
func fixture(t *testing.T, typ elf.Type, interps ...[]byte) []byte {
	t.Helper()
	const ehsize, phsize = 64, 56
	nph := 1 + len(interps)
	data := ehsize + nph*phsize
	var b bytes.Buffer
	w := func(v any) {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	w(elf.Header64{
		Ident:     [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(typ),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     ehsize,
		Ehsize:    ehsize,
		Phentsize: phsize,
		Phnum:     uint16(nph),
	})
	size := data
	for _, in := range interps {
		size += len(in)
	}
	w(elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Filesz: uint64(size), Memsz: uint64(size), Align: 0x1000})
	off := data
	for _, in := range interps {
		w(elf.Prog64{Type: uint32(elf.PT_INTERP), Flags: uint32(elf.PF_R), Off: uint64(off), Filesz: uint64(len(in)), Memsz: uint64(len(in)), Align: 1})
		off += len(in)
	}
	for _, in := range interps {
		b.Write(in)
	}
	return b.Bytes()
}

func nul(s string) []byte { return append([]byte(s), 0) }

// TestInspect: the four ways an executable can be linked are told apart by PT_INTERP and the ELF type; what execve
// would refuse is refused.
func TestInspect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		want    string // the line, "" for an error
		dynamic bool
		pie     bool
	}{
		{"go -buildmode=pie", fixture(t, elf.ET_DYN, nul(loader)), "dynamic " + loader + " type=DYN", true, true},
		{"dynamic, not PIE", fixture(t, elf.ET_EXEC, nul(loader)), "dynamic " + loader + " type=EXEC", true, false},
		{"static, Go's default", fixture(t, elf.ET_EXEC), "static type=EXEC", false, false},
		{"static-pie", fixture(t, elf.ET_DYN), "static type=DYN", false, false},
		{"two interpreters", fixture(t, elf.ET_DYN, nul(loader), nul(loader)), "", false, false},
		{"no NUL", fixture(t, elf.ET_DYN, []byte(loader)), "", false, false},
		{"a NUL inside", fixture(t, elf.ET_DYN, nul("/lib\x00/ld.so")), "", false, false},
		{"empty", fixture(t, elf.ET_DYN, nul("")), "", false, false},
		{"relocatable object", fixture(t, elf.ET_REL), "", false, false},
		{"not ELF", []byte("#!/bin/sh\nexit 0\n"), "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := inspect(bytes.NewReader(tc.data))
			if tc.want == "" {
				if err == nil {
					t.Fatalf("inspect = %v, want an error", l)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := l.String(); got != tc.want {
				t.Errorf("line %q, want %q", got, tc.want)
			}
			if l.is("dynamic") != tc.dynamic || l.is("pie") != tc.pie || l.is("static") == tc.dynamic {
				t.Errorf("is(dynamic, pie, static) = %v, %v, %v; want %v, %v, %v",
					l.is("dynamic"), l.is("pie"), l.is("static"), tc.dynamic, tc.pie, !tc.dynamic)
			}
		})
	}
}

// TestRunExitCodes: -want answers 0 or 1, the line is printed either way, and a usage error or an unreadable file
// is 2, so pairs.sh can tell "the build is static" from "the check could not run".
func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pie := write("tego-pie", fixture(t, elf.ET_DYN, nul(loader)))
	static := write("tego", fixture(t, elf.ET_EXEC))
	script := write("script", []byte("#!/bin/sh\n"))
	for _, tc := range []struct {
		args []string
		code int
		out  string
		err  string
	}{
		{[]string{pie}, 0, "dynamic " + loader + " type=DYN\n", ""},
		{[]string{"-want", "pie", pie}, 0, "dynamic " + loader + " type=DYN\n", ""},
		{[]string{"-want", "dynamic", pie}, 0, "dynamic", ""},
		{[]string{"-want", "static", pie}, exitNo, "dynamic", "is dynamic " + loader + " type=DYN, not static"},
		{[]string{"-want", "static", static}, 0, "static type=EXEC\n", ""},
		{[]string{"-want", "pie", static}, exitNo, "static type=EXEC\n", "not pie"},
		{[]string{"-want", "dynamic", static}, exitNo, "static", "not dynamic"},
		{[]string{"-want", "pie", script}, exitUsage, "", "script"},
		{[]string{"-want", "pie", filepath.Join(dir, "missing")}, exitUsage, "", "missing"},
		{[]string{"-want", "shared", pie}, exitUsage, "", "-want must be"},
		{[]string{}, exitUsage, "", "usage"},
		{[]string{pie, static}, exitUsage, "", "usage"},
		{[]string{"-bogus", pie}, exitUsage, "", "bogus"},
	} {
		var out, errb bytes.Buffer
		code := run(tc.args, &out, &errb)
		if code != tc.code || !strings.HasPrefix(out.String(), tc.out) || !strings.Contains(errb.String(), tc.err) {
			t.Errorf("run(%q) = %d, stdout %q, stderr %q; want %d, stdout starting %q, stderr containing %q",
				tc.args, code, out.String(), errb.String(), tc.code, tc.out, tc.err)
		}
	}
}
