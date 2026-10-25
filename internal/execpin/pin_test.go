// SPDX-License-Identifier: Apache-2.0

package execpin

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

var testKey = Key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// alloc_bprm's spelling of bprm->filename: what the pin's path MAC covers.
func TestFilenameOfIsAllocBprmsSpelling(t *testing.T) {
	for _, c := range []struct {
		dirfd int32
		raw   string
		want  string
	}{
		{atFDCWD, "/usr/bin/git", "/usr/bin/git"},
		{atFDCWD, "bin/git", "bin/git"},
		{atFDCWD, "./git", "./git"},
		{3, "/usr/bin/git", "/usr/bin/git"},
		{3, "git", "/dev/fd/3/git"},
		{3, "a/../git", "/dev/fd/3/a/../git"},
		{7, "", "/dev/fd/7"},
	} {
		if got := FilenameOf(c.dirfd, c.raw); got != c.want {
			t.Errorf("FilenameOf(%d, %q) = %q, want %q", c.dirfd, c.raw, got, c.want)
		}
	}
}

// A direct pin covers the first k strings, NUL-terminated and back to back, and says the vector's length only when
// the decision read it whole.
func TestBuildDirectCoversTheDecidedPrefix(t *testing.T) {
	e := Exec{Form: FormDirect, Guard: true, Image: Ident{Dev: KernelDev(8, 1), Ino: 42}, Name: "git", Filename: "/usr/bin/git",
		Argv: []string{"git", "status", "--short"}, Complete: true, K: 2}
	p, err := Build(testKey, e)
	if err != nil {
		t.Fatal(err)
	}
	cov := []byte("git\x00status\x00")
	if p.K != 2 || p.Argc != 3 || p.LenCov != uint32(len(cov)) || p.MACCov != MAC(testKey, DomainCovered, cov) {
		t.Fatalf("pin %+v: want k 2, argc 3, the MAC over %q", p, cov)
	}
	if p.Flags != FlagGuard || p.Form != FormDirect || p.LenTail != 0 || p.MACTail != 0 || p.NChain != 0 {
		t.Fatalf("pin %+v: want only the guard flag and no tail or chain", p)
	}
	if p.MACName != MAC(testKey, DomainName, []byte("git")) || p.LenPath != 12 || p.MACPath != MAC(testKey, DomainPath, []byte("/usr/bin/git")) {
		t.Fatalf("pin %+v: the name and path MACs are not over the name and the filename", p)
	}
	if p.Image != (Ident{Dev: 8<<20 | 1, Ino: 42}) {
		t.Fatalf("image %+v: want the kernel's encoding of 8:1", p.Image)
	}
	// k is at least argv[0], and a prefix read says no argc the plane could compare.
	e.K, e.Complete, e.Argv = 0, false, e.Argv[:1]
	if p, err = Build(testKey, e); err != nil || p.K != 1 || p.Argc != ArgcUnknown || p.MACCov != MAC(testKey, DomainCovered, []byte("git\x00")) {
		t.Fatalf("an unguarded prefix: pin %+v, %v", p, err)
	}
	// An empty vector is mapped as [""].
	e.Argv, e.Complete = nil, true
	if p, err = Build(testKey, e); err != nil || p.K != 1 || p.Argc != 1 || p.LenCov != 1 || p.MACCov != MAC(testKey, DomainCovered, []byte{0}) {
		t.Fatalf("an empty vector: pin %+v, %v", p, err)
	}
}

// A #! line's empty argument is an element of the vector binfmt_script maps, and no argument is none.
func TestScriptVectorKeepsAnEmptyArgument(t *testing.T) {
	got := ScriptVector("./s", []Stage{{Path: "/opt/tool", EmptyArg: true}}, []string{"a"})
	if want := []string{"/opt/tool", "", "./s", "a"}; !slices.Equal(got, want) {
		t.Fatalf("ScriptVector = %q, want %q", got, want)
	}
}

// A script pin covers binfmt_script's whole vector: each stage's interpreter and argument in front of the name the
// stage was run by, argv[0] dropped, and names each stage's file in order.
func TestBuildScriptCoversBinfmtScriptsVector(t *testing.T) {
	chain := []Stage{{Path: "/w/inner", Arg: "-x  y", ID: Ident{Dev: 1, Ino: 2}}, {Path: "/usr/bin/python3", ID: Ident{Dev: 3, Ino: 4}}}
	got := ScriptVector("/dev/fd/3/run.sh", chain, []string{"a", ""})
	want := []string{"/usr/bin/python3", "/w/inner", "-x  y", "/dev/fd/3/run.sh", "a", ""}
	if !slices.Equal(got, want) {
		t.Fatalf("ScriptVector = %q, want %q", got, want)
	}
	e := Exec{Form: FormScript, Image: Ident{Dev: 5, Ino: 6}, Name: "run.sh", Filename: "/dev/fd/3/run.sh",
		Argv: []string{"ignored", "a", ""}, Complete: true, K: 1, Chain: chain}
	p, err := Build(testKey, e)
	if err != nil {
		t.Fatal(err)
	}
	area := []byte(strings.Join(want, "\x00") + "\x00")
	if p.K != 6 || p.Argc != 6 || p.LenCov != uint32(len(area)) || p.MACCov != MAC(testKey, DomainScript, area) {
		t.Fatalf("pin %+v: want the whole vector %q under the script domain", p, area)
	}
	if p.NChain != 2 || p.Chain[0] != chain[0].ID || p.Chain[1] != chain[1].ID || p.Chain[2] != (Ident{}) {
		t.Fatalf("chain %d %+v: want the two stages in order", p.NChain, p.Chain)
	}
}

// An unknown-form pin also covers the tail an interpreter keeps, the filename binfmt puts in front of argv[1:] and
// argv[1:] itself, carries interp_ok when asked, and says whether the decided argv[0] is the filename.
func TestBuildUnknownCoversTheTail(t *testing.T) {
	e := Exec{Form: FormUnknown, InterpOK: true, Guard: true, Image: Ident{Dev: 1, Ino: 1}, Name: "x", Filename: "./x",
		Argv: []string{"x", "-c", "y"}, Complete: true, K: 3}
	p, err := Build(testKey, e)
	if err != nil {
		t.Fatal(err)
	}
	if p.Flags != FlagGuard|FlagInterpOK || p.LenTail != 9 || p.MACTail != MAC(testKey, DomainTail, []byte("./x\x00-c\x00y\x00")) ||
		p.MACCov != MAC(testKey, DomainCovered, []byte("x\x00-c\x00y\x00")) || p.Argc != 3 {
		t.Fatalf("pin %+v", p)
	}
	e.Argv[0] = "./x"
	if p, err = Build(testKey, e); err != nil || p.Flags != FlagGuard|FlagInterpOK|FlagArgv0Filename {
		t.Fatalf("argv[0] the filename: pin %+v, %v", p, err)
	}
}

// unknownInterpretedHolds models, byte for byte, what bpf/decide_execpin.h checks of an unknown-form exec that binfmt
// interpreted: tego_pin_later's first later stage (a binfmt_misc stage with the P flag, preserveArgv0, is refused
// unless the decided argv[0] is the filename) and tego_pin_area's unknown-and-interpreted branch (the vector's length
// as the first stage counted it, argc0, is the pin's, and the last len_tail bytes of the area, after a NUL, are the
// MACed tail).
func unknownInterpretedHolds(k Key, p Pin, area []byte, argc0 uint32, preserveArgv0 bool) bool {
	if p.Flags&FlagInterpOK == 0 || preserveArgv0 && p.Flags&FlagArgv0Filename == 0 {
		return false
	}
	n := int(p.LenTail)
	if argc0 != p.Argc || n >= len(area) || area[len(area)-n-1] != 0 {
		return false
	}
	return MAC(k, DomainTail, area[len(area)-n:]) == p.MACTail
}

// binfmtShapes are the vectors the kernel maps for an exec of filename with argv, by the first binfmt handler that
// takes it, and whether the interpreter sees argv[0] (only binfmt_misc's P flag keeps it).
var binfmtShapes = []struct {
	name     string
	area     func(filename string, argv []string) []string
	keeps0   bool
	misc0Pre bool
}{
	{"#!", func(f string, a []string) []string { return append([]string{"/bin/sh", f}, a[1:]...) }, false, false},
	{"#! with an argument", func(f string, a []string) []string { return append([]string{"/bin/sh", "-e", f}, a[1:]...) }, false, false},
	{"two #! stages", func(f string, a []string) []string { return append([]string{"/bin/sh", "./stage", f}, a[1:]...) }, false, false},
	{"binfmt_misc", func(f string, a []string) []string { return append([]string{"/usr/bin/qemu", f}, a[1:]...) }, false, false},
	{"binfmt_misc P", func(f string, a []string) []string { return append([]string{"/usr/bin/qemu", f}, a...) }, true, true},
}

// In a run with an exec gate alone every exec is pinned in the unknown form, and an interpreted one is
// held by its tail. A tail check alone let a racing thread put arguments in front of the decided argv[1:] (decided
// [./deploy.sh staging], mapped [/bin/sh ./deploy.sh --prod --force staging]: the last bytes are still "staging\0").
// Over every vector of up to four elements from a small alphabet, under each binfmt shape, the check holds exactly
// when the vector the interpreter sees is the decided one, except that it may refuse (fail closed) the one case it
// cannot tell apart: a P-flag binfmt_misc stage whose decided argv[0] is not the filename.
func TestUnknownTailHoldsOnlyTheDecidedVector(t *testing.T) {
	const filename = "./deploy.sh"
	words := []string{"", "staging", "--prod", filename}
	var vectors [][]string
	var grow func(v []string)
	grow = func(v []string) {
		vectors = append(vectors, slices.Clone(v))
		if len(v) < 4 {
			for _, w := range words {
				grow(append(v, w))
			}
		}
	}
	for _, w := range words {
		grow([]string{w})
	}
	decided := [][]string{{filename}, {filename, "staging"}, {"deploy.sh", "staging"}, {filename, "--prod", "staging"},
		{"deploy.sh", filename, ""}}
	for _, d := range decided {
		p, err := Build(testKey, Exec{Form: FormUnknown, InterpOK: true, Guard: true, Image: Ident{Dev: 1, Ino: 1},
			Name: "deploy.sh", Filename: filename, Argv: d, Complete: true, K: len(d)})
		if err != nil {
			t.Fatal(err)
		}
		for _, sh := range binfmtShapes {
			for _, v := range vectors {
				area, _ := pack(sh.area(filename, v))
				got := unknownInterpretedHolds(testKey, p, area, uint32(len(v)), sh.misc0Pre)
				same := slices.Equal(v[1:], d[1:]) && (!sh.keeps0 || v[0] == d[0])
				mayRefuse := sh.misc0Pre && d[0] != filename
				if got && !same || !got && same && !mayRefuse {
					t.Errorf("decided %q, %s maps %q: holds %v, want %v", d, sh.name, sh.area(filename, v), got, same)
				}
			}
		}
	}
	// The finding's own vector, by name.
	p, _ := Build(testKey, Exec{Form: FormUnknown, InterpOK: true, Guard: true, Image: Ident{Dev: 1, Ino: 1},
		Name: "deploy.sh", Filename: filename, Argv: []string{filename, "staging"}, Complete: true, K: 2})
	raced, _ := pack([]string{"/bin/sh", filename, "--prod", "--force", "staging"})
	if unknownInterpretedHolds(testKey, p, raced, 4, false) {
		t.Error("arguments a racer put in front of the decided argv[1:] held")
	}
}

// What no pin can carry is ErrUnpinnable, never a pin that would hold the kernel to less than was decided.
func TestBuildRefusesWhatAPinCannotCarry(t *testing.T) {
	base := Exec{Form: FormDirect, Image: Ident{Dev: 1, Ino: 1}, Name: "x", Filename: "/x", Argv: []string{"x", "y"}, Complete: true, K: 1}
	big := strings.Repeat("a", MaxArea)
	for name, mut := range map[string]func(*Exec){
		"long name":         func(e *Exec) { e.Name = strings.Repeat("n", NameMax+1) },
		"no name":           func(e *Exec) { e.Name = "" },
		"long filename":     func(e *Exec) { e.Filename = "/" + strings.Repeat("p", PathMax) },
		"k past the read":   func(e *Exec) { e.K = 3 },
		"big prefix":        func(e *Exec) { e.Argv, e.K = []string{big}, 1 },
		"unknown, a prefix": func(e *Exec) { e.Form, e.Complete = FormUnknown, false },
		"big tail":          func(e *Exec) { e.Form, e.Argv = FormUnknown, []string{"x", big} },
		"script, a prefix": func(e *Exec) {
			e.Form, e.Complete, e.Chain = FormScript, false, []Stage{{Path: "/bin/sh"}}
		},
		"script, no chain": func(e *Exec) { e.Form = FormScript },
		"script, deep":     func(e *Exec) { e.Form, e.Chain = FormScript, make([]Stage, ChainMax+1) },
		"big script":       func(e *Exec) { e.Form, e.Argv, e.Chain = FormScript, []string{"x", big}, []Stage{{Path: "/bin/sh"}} },
		"no form":          func(e *Exec) { e.Form = 0 },
	} {
		e := base
		mut(&e)
		if _, err := Build(testKey, e); !errors.Is(err, ErrUnpinnable) {
			t.Errorf("%s: Build = %v, want ErrUnpinnable", name, err)
		}
	}
	// The bounds themselves pin.
	e := base
	e.Argv, e.K = []string{big[:MaxArea-1]}, 1
	if _, err := Build(testKey, e); err != nil {
		t.Errorf("a prefix of exactly %d bytes: %v", MaxArea, err)
	}
	e = base
	e.Name, e.Filename = strings.Repeat("n", NameMax), "/"+strings.Repeat("p", PathMax-1)
	if _, err := Build(testKey, e); err != nil {
		t.Errorf("a name of %d bytes and a filename of %d: %v", NameMax, PathMax, err)
	}
}

// Encode lays the pin out as struct tego_exec_pin (internal/bpf's parity test checks it against bpf.ExecPin), and
// SetGenSeq writes the first two words.
func TestEncodeLayout(t *testing.T) {
	p := Pin{Form: 2, Flags: 3, NChain: 4, K: 5, Argc: 6, LenCov: 7, LenTail: 8, LenPath: 9, Image: Ident{10, 11},
		MACCov: 12, MACTail: 13, MACName: 14, MACPath: 15}
	for i := range p.Chain {
		p.Chain[i] = Ident{uint64(20 + 2*i), uint64(21 + 2*i)}
	}
	b := p.Encode()
	SetGenSeq(b, 0xaabb, 0xccdd)
	le := binary.LittleEndian
	if len(b) != Size || le.Uint32(b) != 0xaabb || le.Uint32(b[4:]) != 0xccdd || b[8] != 2 || b[9] != 3 || b[10] != 4 || b[11] != 0 ||
		le.Uint32(b[12:]) != 5 || le.Uint32(b[28:]) != 9 || le.Uint64(b[32:]) != 10 || le.Uint64(b[72:]) != 15 ||
		le.Uint64(b[80:]) != 20 || le.Uint64(b[152:]) != 29 {
		t.Fatalf("encoding % x", b)
	}
	k0, k1 := testKey.Halves()
	if k0 != 0x0807060504030201 || k1 != 0x100f0e0d0c0b0a09 {
		t.Fatalf("halves %#x %#x", k0, k1)
	}
}
