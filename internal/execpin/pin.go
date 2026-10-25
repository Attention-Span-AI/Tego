// SPDX-License-Identifier: Apache-2.0

package execpin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The pin's forms and flags (struct tego_exec_pin's form and flags; bpf/include/events.h enum tego_pin_form and
// enum tego_pin_flag, internal/bpf PinForm* and PinFlag*).
const (
	FormDirect  uint8 = 1 // not a script: no later binfmt stage may run; the covered prefix is the program's argv
	FormScript  uint8 = 2 // a #! script: each later stage is the pinned chain's; the MAC covers binfmt_script's vector
	FormUnknown uint8 = 3 // the image's head was not read (an exec gate alone) or could not be (an execute-only file)

	FlagGuard    uint8 = 0x01 // a traced exec is refused, and the task is argv-guarded once the exec passes
	FlagInterpOK uint8 = 0x02 // unknown form: a later stage may run (no command rule is reachable through one)
	// FlagArgv0Filename (unknown form): the decided argv[0] is the filename. Without it, a first binfmt_misc stage
	// with the P flag, which keeps argv[0] in front of argv[1:], is refused (0x04 is TEGO_PIN_TRACE_GATE's).
	FlagArgv0Filename uint8 = 0x08
)

// The pin's bounds, as the plane checks them (bpf/include/exec_pin.h, bpf/decide_execpin.h).
const (
	// Size is sizeof(struct tego_exec_pin), the bytes Encode writes.
	Size = 160
	// ChainMax is TEGO_PIN_CHAIN_MAX: the later binfmt stages a script pin names (exec_binprm refuses depth > 5).
	ChainMax = 5
	// MaxArea is TEGO_PIN_MAX_LEN: the most bytes of the argument area one MAC covers.
	MaxArea = 128 * 1024
	// PathMax is TEGO_PIN_PATH_MAX: bprm->filename's bytes before its NUL.
	PathMax = 4095
	// NameMax is a dentry name's longest (NAME_MAX).
	NameMax = 255
	// ArgcUnknown is a pin's argc when the decision did not read the whole vector: never equal to k, so the plane
	// checks the covered prefix alone.
	ArgcUnknown = ^uint32(0)
)

// atFDCWD is AT_FDCWD, execve's implicit dirfd.
const atFDCWD = -100

// ErrUnpinnable is an exec whose decided facts no pin can carry: a vector or a name past the plane's bounds, or a
// decision that read less than the pin must cover. The supervisor refuses such an exec (rule exec.pin,
// pin_unavailable), since the kernel would refuse or kill it.
var ErrUnpinnable = errors.New("execpin: the exec's facts exceed what a pin carries")

// Ident is a file's identity as the plane holds it (struct tego_pin_ident): its inode's super block s_dev in the
// kernel's encoding (KernelDev), and its i_ino.
type Ident struct{ Dev, Ino uint64 }

// KernelDev is a device number in the kernel's internal encoding (MKDEV: major << 20 | minor), which the plane
// compares with an inode's i_sb->s_dev. stat's st_dev is the other encoding, and differs from it once minor > 255.
func KernelDev(major, minor uint32) uint64 { return uint64(major)<<20 | uint64(minor&0xfffff) }

// Stage is one #! stage as binfmt_script reads it: the interpreter's path and optional argument from the line, and
// the interpreter file's identity.
type Stage struct {
	Path, Arg string
	// EmptyArg says the line has an argument and it is empty, which binfmt_script maps as an empty element.
	EmptyArg bool
	ID       Ident
}

// Exec is what one exec's decision read: the facts its pin holds the kernel to.
type Exec struct {
	// Form is FormDirect, FormScript or FormUnknown.
	Form uint8
	// Guard and InterpOK are the pin's flags.
	Guard, InterpOK bool
	// Image is the first stage's file; Name its final name as its dentry holds it.
	Image Ident
	Name  string
	// Filename is bprm->filename (FilenameOf).
	Filename string
	// Argv is the vector as the decision read it, a prefix of whole elements unless Complete.
	Argv     []string
	Complete bool
	// K is the elements the decision read, at least argv[0] (direct and unknown forms).
	K int
	// Chain is the script form's #! stages, the script's own interpreter first.
	Chain []Stage
}

// Pin is one exec's pin without its gen and seq, which the plane's adapter writes (SetGenSeq).
type Pin struct {
	Form, Flags, NChain               uint8
	K, Argc, LenCov, LenTail, LenPath uint32
	Image                             Ident
	MACCov, MACTail, MACName, MACPath uint64
	Chain                             [ChainMax]Ident
}

// FilenameOf is bprm->filename for an exec of raw relative to atDir, the dirfd argument the task passed (a number in
// the task's descriptor table, spelled into the name, never one of this process): alloc_bprm keeps an absolute path,
// and any path of an execve or an execveat at AT_FDCWD, as passed; it spells a path relative to another descriptor
// "/dev/fd/<atDir>/<raw>", and an empty one (AT_EMPTY_PATH) "/dev/fd/<atDir>".
func FilenameOf(atDir int32, raw string) string {
	if atDir == atFDCWD || strings.HasPrefix(raw, "/") {
		return raw
	}
	dir := "/dev/fd/" + strconv.Itoa(int(atDir))
	if raw == "" {
		return dir
	}
	return dir + "/" + raw
}

// Build is e's pin under k (ADR 0048 (3) "Pin value", "MACs"), or ErrUnpinnable.
func Build(k Key, e Exec) (Pin, error) {
	p := Pin{Form: e.Form, Image: e.Image}
	if e.Guard {
		p.Flags |= FlagGuard
	}
	if e.Name == "" || len(e.Name) > NameMax || e.Filename == "" || len(e.Filename) > PathMax {
		return Pin{}, fmt.Errorf("%w: a name of %d bytes or a filename of %d", ErrUnpinnable, len(e.Name), len(e.Filename))
	}
	p.MACName = MAC(k, DomainName, []byte(e.Name))
	p.LenPath = uint32(len(e.Filename))
	p.MACPath = MAC(k, DomainPath, []byte(e.Filename))
	argv := e.Argv
	if e.Complete && len(argv) == 0 {
		argv = []string{""} // the kernel maps an empty vector as [""] (fs/exec.c, since 5.18)
	}
	switch e.Form {
	case FormScript:
		if !e.Complete || len(e.Chain) == 0 || len(e.Chain) > ChainMax {
			return Pin{}, fmt.Errorf("%w: a script vector read whole %v, %d stages", ErrUnpinnable, e.Complete, len(e.Chain))
		}
		area := ScriptVector(e.Filename, e.Chain, argv[1:])
		cov, n := pack(area)
		if len(cov) > MaxArea {
			return Pin{}, fmt.Errorf("%w: a script vector of %d bytes", ErrUnpinnable, len(cov))
		}
		p.K, p.Argc, p.LenCov, p.MACCov = uint32(n), uint32(n), uint32(len(cov)), MAC(k, DomainScript, cov)
		p.NChain = uint8(len(e.Chain))
		for i, st := range e.Chain {
			p.Chain[i] = st.ID
		}
		return p, nil
	case FormDirect, FormUnknown:
	default:
		return Pin{}, fmt.Errorf("%w: form %d", ErrUnpinnable, e.Form)
	}
	kk := max(e.K, 1)
	if kk > len(argv) {
		return Pin{}, fmt.Errorf("%w: the decision read %d of the %d elements it needs", ErrUnpinnable, len(argv), kk)
	}
	cov, _ := pack(argv[:kk])
	if len(cov) > MaxArea {
		return Pin{}, fmt.Errorf("%w: a covered prefix of %d bytes", ErrUnpinnable, len(cov))
	}
	p.K, p.Argc, p.LenCov, p.MACCov = uint32(kk), ArgcUnknown, uint32(len(cov)), MAC(k, DomainCovered, cov)
	if e.Complete {
		p.Argc = uint32(len(argv))
	}
	if e.Form == FormUnknown {
		// An interpreted unknown-form exec is checked on the area's tail: the filename, which binfmt_script and
		// binfmt_misc put in front of argv[1:], then argv[1:]. With the vector's length that the first stage counted,
		// which the plane holds to argc, that tail is exactly the decided argv[1:], and it needs the
		// whole vector.
		if !e.Complete {
			return Pin{}, fmt.Errorf("%w: an unknown-form vector not read whole", ErrUnpinnable)
		}
		tail, _ := pack(append([]string{e.Filename}, argv[1:]...))
		if len(tail) > MaxArea {
			return Pin{}, fmt.Errorf("%w: a tail of %d bytes", ErrUnpinnable, len(tail))
		}
		p.LenTail, p.MACTail = uint32(len(tail)), MAC(k, DomainTail, tail)
		if e.InterpOK {
			p.Flags |= FlagInterpOK
		}
		if argv[0] == e.Filename {
			p.Flags |= FlagArgv0Filename
		}
	}
	return p, nil
}

// ScriptVector is the vector binfmt_script maps for a script spelled filename whose #! chain is chain (the script's
// own interpreter first) and whose argv[1:] is rest: each stage drops argv[0], then puts the name it was run by, its
// line's argument (when there is one) and its interpreter in front, so the last stage's interpreter comes first:
// [interp_n, arg_n?, ..., interp_1, arg_1?, filename, rest...].
func ScriptVector(filename string, chain []Stage, rest []string) []string {
	head := []string{filename}
	for _, st := range chain {
		next := []string{st.Path}
		if st.Arg != "" || st.EmptyArg {
			next = append(next, st.Arg)
		}
		head = append(next, head...)
	}
	return append(head, rest...)
}

// pack lays strings out as the kernel's argument area does: each NUL-terminated, back to back.
func pack(v []string) ([]byte, int) {
	n := 0
	for _, s := range v {
		n += len(s) + 1
	}
	b := make([]byte, 0, n)
	for _, s := range v {
		b = append(append(b, s...), 0)
	}
	return b, len(v)
}

// Encode is p as struct tego_exec_pin's bytes, with gen and seq zero (SetGenSeq writes them).
func (p *Pin) Encode() []byte {
	b := make([]byte, Size)
	le := binary.LittleEndian
	b[8], b[9], b[10] = p.Form, p.Flags, p.NChain
	le.PutUint32(b[12:], p.K)
	le.PutUint32(b[16:], p.Argc)
	le.PutUint32(b[20:], p.LenCov)
	le.PutUint32(b[24:], p.LenTail)
	le.PutUint32(b[28:], p.LenPath)
	le.PutUint64(b[32:], p.Image.Dev)
	le.PutUint64(b[40:], p.Image.Ino)
	le.PutUint64(b[48:], p.MACCov)
	le.PutUint64(b[56:], p.MACTail)
	le.PutUint64(b[64:], p.MACName)
	le.PutUint64(b[72:], p.MACPath)
	for i, c := range p.Chain {
		le.PutUint64(b[80+16*i:], c.Dev)
		le.PutUint64(b[88+16*i:], c.Ino)
	}
	return b
}

// SetGenSeq writes a pin's gen (the run's) and seq (per run, from 1) into its encoding.
func SetGenSeq(b []byte, gen, seq uint32) {
	binary.LittleEndian.PutUint32(b[0:], gen)
	binary.LittleEndian.PutUint32(b[4:], seq)
}

// Halves is k as struct tego_pin_keyval's k0 and k1: two little-endian words.
func (k Key) Halves() (k0, k1 uint64) {
	return binary.LittleEndian.Uint64(k[:8]), binary.LittleEndian.Uint64(k[8:])
}
