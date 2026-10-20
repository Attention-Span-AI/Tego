// SPDX-License-Identifier: Apache-2.0

// Command elfinterp says how an ELF executable is linked, from its program headers: whether it names a program
// interpreter (PT_INTERP, the dynamic loader the kernel maps at execve) and which. test/vm/pairs.sh runs it on the
// host before it boots a guest, so ADR 0021's "a dynamically linked PIE tegobpf build runs tier cgroup" is never
// recorded for a build that came out static: -buildmode=pie with CGO_ENABLED=0 links against the loader on
// linux/amd64 and arm64 today, and a toolchain that one day linked it static-pie would silently turn that run into
// a second static one. It is a test tool: nothing in the engine imports it.
//
//	elfinterp [-want dynamic|static|pie] FILE
//
// It prints one line, "dynamic <interpreter> type=<EXEC|DYN>" or "static type=<EXEC|DYN>". With -want it exits 0
// when the file is what was asked for and 1 when it is not: dynamic names any file with an interpreter, pie one
// that is also position-independent (ET_DYN), static one without an interpreter. Exit 2 is a usage error or a
// file that is not a readable ELF executable.
package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Exit codes.
const (
	exitNo    = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// linking is what an executable's program headers say about how it is linked.
type linking struct {
	interp string // PT_INTERP's path, "" for none
	typ    elf.Type
}

func (l linking) String() string {
	t := "EXEC"
	if l.typ == elf.ET_DYN {
		t = "DYN"
	}
	if l.interp == "" {
		return "static type=" + t
	}
	return "dynamic " + l.interp + " type=" + t
}

// is reports whether l is what want names.
func (l linking) is(want string) bool {
	switch want {
	case "dynamic":
		return l.interp != ""
	case "pie":
		return l.interp != "" && l.typ == elf.ET_DYN
	case "static":
		return l.interp == ""
	}
	return false
}

// maxInterp bounds the interpreter path read: PATH_MAX, which the kernel's own read of PT_INTERP also enforces.
const maxInterp = 4096

// inspect reads r's ELF header and program headers. An executable has type ET_EXEC or ET_DYN; a PT_INTERP segment
// holds a NUL-terminated path, and more than one, like an empty one, is refused, as execve refuses it.
func inspect(r io.ReaderAt) (linking, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return linking{}, err
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return linking{}, fmt.Errorf("not an executable: ELF type %v", f.Type)
	}
	l := linking{typ: f.Type}
	seen := false
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		if seen {
			return linking{}, errors.New("more than one PT_INTERP")
		}
		seen = true
		if p.Filesz < 2 || p.Filesz > maxInterp {
			return linking{}, fmt.Errorf("PT_INTERP of %d bytes", p.Filesz)
		}
		b := make([]byte, p.Filesz)
		if _, err := p.ReadAt(b, 0); err != nil {
			return linking{}, fmt.Errorf("PT_INTERP: %w", err)
		}
		if b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 {
			return linking{}, errors.New("PT_INTERP is not one NUL-terminated path")
		}
		l.interp = string(b[:len(b)-1])
	}
	return l, nil
}

// run is the command: it returns the exit status.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("elfinterp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	want := fs.String("want", "", "dynamic, pie or static: exit 1 unless the file is that")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	switch *want {
	case "", "dynamic", "pie", "static":
	default:
		fmt.Fprintf(stderr, "elfinterp: -want must be dynamic, pie or static, not %q\n", *want)
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: elfinterp [-want dynamic|pie|static] FILE")
		return exitUsage
	}
	name := fs.Arg(0)
	f, err := os.Open(name)
	if err != nil {
		fmt.Fprintf(stderr, "elfinterp: %v\n", err)
		return exitUsage
	}
	l, err := inspect(f)
	_ = f.Close() // opened for reading: nothing to flush
	if err != nil {
		fmt.Fprintf(stderr, "elfinterp: %s: %v\n", name, err)
		return exitUsage
	}
	fmt.Fprintln(stdout, l)
	if *want != "" && !l.is(*want) {
		fmt.Fprintf(stderr, "elfinterp: %s is %s, not %s\n", name, l, *want)
		return exitNo
	}
	return 0
}
