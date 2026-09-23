// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// sample builds one synthetic ring-buffer record: the header of struct tego_hdr in front of one of
// internal/bpf's record structs, serialized exactly as the kernel lays it out. Every unit test in this
// package feeds the recorder through this, so no kernel is needed to exercise decode, enrichment and
// aggregation — and because the bytes come from the checked structs rather than from offsets written
// here, a test can no longer agree with a decoder the kernel disagrees with.
type sample struct {
	Kind     Kind
	Size     int
	MonoNS   uint64
	CgroupID uint64
	PID      uint32
	TID      uint32
	PPID     uint32
	RunIdx   uint32
	Verdict  KernelVerdict
	Reason   uint8
	RuleIdx  uint16
	Gen      uint32 // the run-set row's generation the program stamped
	Version  uint16 // 0 means the current Version
	// Start is the process start time a record carries beside its header: an exit's exec_start_ns, an open's,
	// file operation's or connect's start_ns. ParentStart is an exec's parent_start_ns.
	Start       uint64
	ParentStart uint64
	// CwdDev (stat(2)-encoded) and CwdIno are an exec's working directory.
	CwdDev uint64
	CwdIno uint64
	// Ret, RetOK and Created are an fs record's chain return, whether it carries one, and an open's
	// FMODE_CREATED (ADR 0016 (3)).
	Ret     int32
	RetOK   bool
	Created bool
}

// header renders the sample's header for a record of the given width, unless the sample names its own.
func (s sample) header(size int) bpf.Header {
	if s.Size != 0 {
		size = s.Size
	}
	v := s.Version
	if v == 0 {
		v = Version
	}
	return bpf.Header{Version: v, Kind: uint16(s.Kind), Size: uint32(size), TSMonoNS: s.MonoNS,
		CgroupID: s.CgroupID, PID: s.PID, TID: s.TID, PPID: s.PPID, RunIdx: s.RunIdx,
		Verdict: uint8(s.Verdict), Reason: s.Reason, RuleIdx: s.RuleIdx, Gen: s.Gen}
}

// bytes renders a header-only record (and whatever tail follows it), for the malformed cases.
func (s sample) bytes(tail []byte) []byte {
	h := s.header(HeaderSize + len(tail))
	return append(wire(&h), tail...)
}

// wire is a record's bytes as the kernel writes them: the struct's own memory.
func wire[T any](v *T) []byte {
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(v)), unsafe.Sizeof(*v))...)
}

// fixed copies s into an n-byte NUL-padded buffer, the way the kernel fills a char[n] field; a
// string of exactly n bytes has no terminator, which is how the wire says "truncated".
func fixed(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}

// kernelDev is the kernel's internal dev_t for a stat(2)-encoded device, which is what a record's dev
// field carries: major above MINORBITS=20, minor below.
func kernelDev(dev uint64) uint64 {
	return uint64(unix.Major(dev))<<20 | uint64(unix.Minor(dev))
}

// execSample builds a struct tego_ev_exec record.
func execSample(h sample, startNS uint64, comm, path string, argv []string, argvTruncated bool) []byte {
	h.Kind = KindExec
	blob := []byte(strings.Join(argv, "\x00"))
	if len(argv) > 0 {
		blob = append(blob, 0)
	}
	e := bpf.ExecEvent{Hdr: h.header(ExecSize), ExecStartNS: startNS, ParentStartNS: h.ParentStart,
		CwdDev: kernelDev(h.CwdDev), CwdIno: h.CwdIno,
		ArgvLen: uint32(len(blob))}
	copy(e.Comm[:], fixed(comm, CommLen))
	copy(e.Path[:], fixed(path, PathMax))
	copy(e.Argv[:], fixed(string(blob), ArgvMax))
	if argvTruncated {
		e.ArgvTruncated = 1
	}
	return wire(&e)
}

// fsSample builds an open (struct tego_ev_fs) for KindOpen, and an unlink, rename or mkdir (struct
// tego_ev_fsop) for the other three kinds: path is then the final component and ino the parent
// directory's, path2 the rename destination's final component. dev is stat(2)-encoded, as the directory
// index sees it; the record carries the kernel's encoding of it. A buffer the string exactly fills has no
// terminator, and its ok flag is 0, as the kernel sets it.
func fsSample(h sample, flags uint32, ino uint32, dev uint64, path, path2 string) []byte {
	if h.Kind == KindOpen || h.Kind == 0 {
		h.Kind = KindOpen
		e := bpf.FSEvent{Hdr: h.header(FSSize), StartNS: h.Start, Dev: kernelDev(dev), Flags: flags, Ino: ino,
			Ret: h.Ret, RetOk: b2u(h.RetOK), Created: b2u(h.Created)}
		copy(e.Path[:], fixed(path, PathMax))
		if len(path) > 0 && len(path) < PathMax {
			e.PathOk = 1
		}
		if path2 != "" {
			panic("an open record has no second path")
		}
		return wire(&e)
	}
	e := bpf.FSOpEvent{Hdr: h.header(FSOpSize), StartNS: h.Start, Dev: kernelDev(dev), DirIno: uint64(ino),
		Op: fsOpCode(h.Kind), Ret: h.Ret, RetOk: b2u(h.RetOK)}
	copy(e.Name[:], fixed(path, NameMax))
	if len(path) > 0 && len(path) < NameMax {
		e.NameOk = 1
	}
	if h.Kind == KindRename || h.Kind == KindLink || h.Kind == KindSymlink {
		if h.Kind != KindSymlink {
			e.Dev2, e.DirIno2 = kernelDev(dev), uint64(ino)
		}
		copy(e.Name2[:], fixed(path2, NameMax))
		if len(path2) > 0 && len(path2) < NameMax {
			e.Name2Ok = 1
		}
	}
	return wire(&e)
}

// b2u is a C boolean byte.
func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// fsOpCode is the enum tego_fsop value the kernel writes for a file-operation kind.
func fsOpCode(k Kind) uint8 {
	switch k {
	case KindRename:
		return uint8(bpf.FSOpRename)
	case KindMkdir:
		return uint8(bpf.FSOpMkdir)
	case KindMknod:
		return uint8(bpf.FSOpMknod)
	case KindRmdir:
		return uint8(bpf.FSOpRmdir)
	case KindLink:
		return uint8(bpf.FSOpLink)
	case KindSymlink:
		return uint8(bpf.FSOpSymlink)
	case KindTruncate:
		return uint8(bpf.FSOpTruncate)
	default:
		return uint8(bpf.FSOpUnlink)
	}
}

// netSample builds a struct tego_ev_net record.
func netSample(h sample, family, proto uint8, port uint16, addr [16]byte) []byte {
	e := bpf.NetEvent{Hdr: h.header(NetSize), StartNS: h.Start, Family: family, Proto: proto, Port: port, Addr: addr}
	return wire(&e)
}

// exitSample builds a struct tego_ev_exit record. The kernel always writes the whole struct, so there is
// no header-only shape to build.
func exitSample(h sample, code int32, signal uint32) []byte {
	h.Kind = KindExit
	e := bpf.ExitEvent{Hdr: h.header(ExitSize), ExecStartNS: h.Start, Code: code, Signal: signal}
	return wire(&e)
}

// cgroupSample builds a struct tego_ev_cgroup record.
func cgroupSample(h sample, parent, child uint64) []byte {
	e := bpf.CgroupEvent{Hdr: h.header(CgroupSize), ParentCgroupID: parent, ChildCgroupID: child}
	return wire(&e)
}

// sslSample builds a struct tego_ev_ssl record plus its plaintext.
func sslSample(h sample, ptr uint64, direction uint8, data []byte) []byte {
	h.Kind = KindSSLChunk
	tail := make([]byte, SSLSize-HeaderSize+len(data))
	e := binary.NativeEndian
	e.PutUint64(tail[0:8], ptr)
	e.PutUint32(tail[8:12], uint32(len(data)))
	tail[12] = direction
	copy(tail[SSLSize-HeaderSize:], data)
	return h.bytes(tail)
}

// TestLayoutMatchesEventsHeader keeps the Go constants and bpf/include/events.h in step: the header
// is the single source of truth for the wire (§9), so a change there must fail here rather than
// silently misdecode every sample.
func TestLayoutMatchesEventsHeader(t *testing.T) {
	b, err := os.ReadFile("../../../bpf/include/events.h")
	if err != nil {
		t.Fatalf("read events.h: %v", err)
	}
	src := string(b)
	for _, tc := range []struct {
		define string
		want   int
	}{
		{"TEGO_EVENTS_VERSION", Version},
		{"TEGO_PATH_MAX", PathMax},
		{"TEGO_ARGV_MAX", ArgvMax},
		{"TEGO_COMM_LEN", CommLen},
		{"TEGO_NAME_MAX", NameMax},
	} {
		re := regexp.MustCompile(`(?m)^#define\s+` + tc.define + `\s+(\d+)`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("%s is not defined in bpf/include/events.h", tc.define)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil || got != tc.want {
			t.Errorf("%s = %s in events.h, %d in Go", tc.define, m[1], tc.want)
		}
	}
	// Every struct's size must be a multiple of its 8-byte alignment, or the C compiler would add
	// tail padding the Go offsets do not account for.
	for name, size := range map[string]int{
		"tego_hdr": HeaderSize, "tego_ev_exec": ExecSize, "tego_ev_exit": ExitSize, "tego_ev_fs": FSSize,
		"tego_ev_fsop": FSOpSize, "tego_ev_net": NetSize, "tego_ev_cgroup": CgroupSize, "tego_ev_ssl": SSLSize,
	} {
		if size%8 != 0 {
			t.Errorf("sizeof(struct %s) = %d is not 8-byte aligned", name, size)
		}
		if !strings.Contains(src, "struct "+name+" {") {
			t.Errorf("struct %s is not declared in bpf/include/events.h", name)
		}
	}
}

func TestDecodeEveryKind(t *testing.T) {
	head := sample{MonoNS: 77, CgroupID: 9, PID: 11, TID: 12, PPID: 1, RunIdx: 3, Verdict: KernelRefused, Reason: ReasonNetNotAllowed, RuleIdx: 4}
	var v4 [16]byte
	copy(v4[:], []byte{93, 184, 216, 34})

	t.Run("exec", func(t *testing.T) {
		r, err := Decode(execSample(head, 555, "python3", "/usr/bin/python3.12", []string{"python3", "-m", "pytest"}, false))
		if err != nil {
			t.Fatal(err)
		}
		if r.Kind != KindExec || r.MonoNS != 77 || r.PID != 11 || r.PPID != 1 || r.RunIdx != 3 {
			t.Fatalf("header %+v", r.Header)
		}
		if r.Exec.StartBootNS != 555 || r.Exec.Comm != "python3" || r.Exec.Path != "/usr/bin/python3.12" {
			t.Fatalf("exec %+v", r.Exec)
		}
		if !reflect.DeepEqual(r.Exec.Argv, []string{"python3", "-m", "pytest"}) {
			t.Fatalf("argv %q", r.Exec.Argv)
		}
		if r.Exec.ArgvTruncated || r.Exec.PathTruncated {
			t.Fatal("nothing should be truncated")
		}
	})

	t.Run("exit header only is not an exit", func(t *testing.T) {
		// struct tego_ev_exit is always written whole; a header-only exit is a producer this build does
		// not understand, and reading a code out of bytes that are not there would invent one.
		h := head
		h.Kind = KindExit
		if _, err := Decode(h.bytes(nil)); !errors.Is(err, ErrShortRecord) {
			t.Fatalf("Decode(header-only exit) = %v, want ErrShortRecord", err)
		}
	})

	t.Run("exit with start time, code and signal", func(t *testing.T) {
		h := head
		h.Kind = KindExit
		e := bpf.ExitEvent{Hdr: h.header(ExitSize), ExecStartNS: 1 << 40, Code: -1, Signal: 9}
		r, err := Decode(wire(&e))
		if err != nil {
			t.Fatal(err)
		}
		if r.Exit.ExecStartNS != 1<<40 || r.Exit.Code != -1 || r.Exit.Signal != 9 {
			t.Fatalf("exit %+v", r.Exit)
		}
	})

	t.Run("open", func(t *testing.T) {
		h := head
		h.Kind = KindOpen
		r, err := Decode(fsSample(h, 0o100, 42, unix.Mkdev(8, 1), "/work/out/report.md", ""))
		if err != nil {
			t.Fatal(err)
		}
		if r.FS.Flags != 0o100 || r.FS.Ino != 42 || r.FS.Dev != unix.Mkdev(8, 1) || r.FS.Path != "/work/out/report.md" ||
			r.FS.PathTruncated {
			t.Fatalf("open %+v", r.FS)
		}
	})

	t.Run("rename", func(t *testing.T) {
		h := head
		h.Kind = KindRename
		r, err := Decode(fsSample(h, 0, 42, unix.Mkdev(259, 3), "old", "new"))
		if err != nil {
			t.Fatal(err)
		}
		if r.FS.Ino != 42 || r.FS.Dev != unix.Mkdev(259, 3) || r.FS.Path != "old" || r.FS.Path2 != "new" ||
			r.FS.Ino2 != 42 || r.FS.Dev2 != unix.Mkdev(259, 3) || r.FS.PathTruncated || r.FS.Path2Truncated {
			t.Fatalf("rename %+v", r.FS)
		}
	})

	t.Run("unlink carries no destination", func(t *testing.T) {
		h := head
		h.Kind = KindUnlink
		r, err := Decode(fsSample(h, 0, 7, unix.Mkdev(0, 42), "gone.txt", ""))
		if err != nil {
			t.Fatal(err)
		}
		if r.FS.Path != "gone.txt" || r.FS.Path2 != "" || r.FS.Path2Truncated || r.FS.Dev != unix.Mkdev(0, 42) {
			t.Fatalf("unlink %+v", r.FS)
		}
	})

	t.Run("net", func(t *testing.T) {
		h := head
		h.Kind = KindConnect
		r, err := Decode(netSample(h, 2, 6, 443, v4))
		if err != nil {
			t.Fatal(err)
		}
		if r.Net.Family != 2 || r.Net.Proto != 6 || r.Net.Port != 443 || r.Net.Addr != v4 {
			t.Fatalf("net %+v", r.Net)
		}
	})

	t.Run("cgroup", func(t *testing.T) {
		h := head
		h.Kind = KindCgroupMkdir
		r, err := Decode(cgroupSample(h, 100, 200))
		if err != nil {
			t.Fatal(err)
		}
		if r.Cgroup.ParentCgroupID != 100 || r.Cgroup.ChildCgroupID != 200 {
			t.Fatalf("cgroup %+v", r.Cgroup)
		}
	})

	t.Run("ssl", func(t *testing.T) {
		r, err := Decode(sslSample(head, 0xdead, 1, []byte("GET / HTTP/1.1")))
		if err != nil {
			t.Fatal(err)
		}
		if r.Kind != KindSSLChunk || r.PID != head.PID {
			t.Fatalf("ssl header %+v", r.Header)
		}
		// Only the header is decoded; a chunk shorter than struct tego_ev_ssl is still refused.
		short := sslSample(head, 0xdead, 1, nil)[:SSLSize-1]
		binary.NativeEndian.PutUint32(short[4:8], uint32(len(short)))
		if _, err := Decode(short); !errors.Is(err, ErrShortRecord) {
			t.Fatalf("a short ssl chunk decoded: %v", err)
		}
	})
}

// TestDecodeCarriesTheProcessStartTime: every record of a process names which process it was by its start time,
// an exec its parent's too, and the decoder puts it in Record.StartNS for each kind.
func TestDecodeCarriesTheProcessStartTime(t *testing.T) {
	h := sample{MonoNS: 1, PID: 11, TID: 12, PPID: 1, Start: 7_000_123, ParentStart: 5_000_456}
	var v4 [16]byte
	for name, raw := range map[string][]byte{
		"exec":   execSample(h, 7_000_123, "sh", "/bin/sh", []string{"sh"}, false),
		"exit":   exitSample(h, 0, 0),
		"open":   fsSample(func() sample { s := h; s.Kind = KindOpen; return s }(), 0, 1, 2049, "/etc/hosts", ""),
		"unlink": fsSample(func() sample { s := h; s.Kind = KindUnlink; return s }(), 0, 1, 2049, "x", ""),
		"rename": fsSample(func() sample { s := h; s.Kind = KindRename; return s }(), 0, 1, 2049, "x", "y"),
		"mkdir":  fsSample(func() sample { s := h; s.Kind = KindMkdir; return s }(), 0, 1, 2049, "d", ""),
		"net":    netSample(func() sample { s := h; s.Kind = KindConnect; return s }(), 2, 6, 443, v4),
	} {
		r, err := Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.StartNS != 7_000_123 {
			t.Errorf("%s: StartNS %d, want the process's 7000123", name, r.StartNS)
		}
		if name == "exec" && r.Exec.ParentStartNS != 5_000_456 {
			t.Errorf("exec: ParentStartNS %d, want 5000456", r.Exec.ParentStartNS)
		}
	}
}

func TestDecodeMalformed(t *testing.T) {
	head := sample{PID: 1}
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, ErrShortRecord},
		{"header only for an exec", func() []byte { h := head; h.Kind, h.Size = KindExec, HeaderSize; return h.bytes(nil) }(), ErrShortRecord},
		{"truncated fs", fsSample(func() sample { h := head; h.Kind = KindOpen; return h }(), 0, 0, 0, "/x", "")[:FSSize-1], ErrShortRecord},
		{"size beyond the sample", func() []byte {
			b := fsSample(func() sample { h := head; h.Kind = KindOpen; return h }(), 0, 0, 0, "/x", "")
			binary.NativeEndian.PutUint32(b[4:8], uint32(len(b)+1))
			return b
		}(), ErrShortRecord},
		{"unknown kind", func() []byte { h := head; h.Kind = Kind(99); h.Size = HeaderSize; return h.bytes(nil) }(), ErrKind},
		{"kind zero", func() []byte { h := head; h.Kind = 0; h.Size = HeaderSize; return h.bytes(nil) }(), ErrKind},
		{"future version", func() []byte {
			h := head
			h.Kind, h.Version, h.Size = KindExit, Version+1, HeaderSize
			return h.bytes(nil)
		}(), ErrVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("Decode = %v, want %v", err, tc.want)
			}
		})
	}
	if err := DecodeInto(nil, make([]byte, HeaderSize)); !errors.Is(err, ErrShortRecord) {
		t.Fatalf("DecodeInto(nil) = %v", err)
	}
}

func TestDecodeTruncationAndUTF8(t *testing.T) {
	head := sample{PID: 1}
	long := strings.Repeat("a", PathMax) // exactly fills the buffer: no NUL, so truncated
	r, err := Decode(execSample(head, 1, "c", long, []string{"x"}, true))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Exec.PathTruncated || len(r.Exec.Path) != PathMax {
		t.Fatalf("path truncation not reported: %d bytes, truncated=%v", len(r.Exec.Path), r.Exec.PathTruncated)
	}
	if !r.Exec.ArgvTruncated {
		t.Fatal("argv truncation flag lost")
	}
	h := head
	h.Kind = KindOpen
	r, err = Decode(fsSample(h, 0, 0, 0, "/tmp/\xff\xfe", ""))
	if err != nil {
		t.Fatal(err)
	}
	// The bytes the kernel matched on are the bytes the recorder matches on; the ledger line replaces them.
	if r.FS.Path != "/tmp/\xff\xfe" {
		t.Fatalf("the decoder changed the kernel's path bytes: %q", r.FS.Path)
	}
}

func TestDecodeIntoReusesTheRecord(t *testing.T) {
	head := sample{PID: 1}
	var rec Record
	if err := DecodeInto(&rec, execSample(head, 1, "a", "/bin/a", []string{"a", "b", "c"}, false)); err != nil {
		t.Fatal(err)
	}
	if len(rec.Exec.Argv) != 3 {
		t.Fatalf("argv %q", rec.Exec.Argv)
	}
	if err := DecodeInto(&rec, execSample(head, 2, "b", "/bin/b", []string{"z"}, false)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rec.Exec.Argv, []string{"z"}) {
		t.Fatalf("argv from the previous record leaked: %q", rec.Exec.Argv)
	}
	h := head
	h.Kind = KindConnect
	if err := DecodeInto(&rec, netSample(h, 2, 6, 80, [16]byte{1, 2, 3, 4})); err != nil {
		t.Fatal(err)
	}
	if rec.Exec.Path != "" || len(rec.Exec.Argv) != 0 {
		t.Fatalf("exec body survived a net record: %+v", rec.Exec)
	}
}

// TestUserDevIsStatEncoding pins the device conversion the directory index depends on. A record's dev is the
// super block's s_dev, the kernel's internal dev_t (major<<20 | minor); fstat reports the other encoding.
// For a disk the two never agree — (8,1) is 0x800001 in one and 0x801 in the other — so comparing them raw
// left every unlink, rename and mkdir on a disk unresolved.
func TestUserDevIsStatEncoding(t *testing.T) {
	for _, dm := range [][2]uint32{{8, 1}, {259, 3}, {0, 42}, {0, 300}, {4095, 1<<20 - 1}} {
		kdev := uint64(dm[0])<<20 | uint64(dm[1])
		if got, want := userDev(kdev), unix.Mkdev(dm[0], dm[1]); got != want {
			t.Errorf("userDev(%d:%d as %#x) = %#x, want stat's %#x", dm[0], dm[1], kdev, got, want)
		}
	}
}

func TestKindString(t *testing.T) {
	if KindExec.String() != "exec" || KindCgroupRmdir.String() != "cgroup_rmdir" {
		t.Errorf("kind names: %s %s", KindExec, KindCgroupRmdir)
	}
	if got := Kind(200).String(); got != "kind(200)" {
		t.Errorf("unknown kind renders as %q", got)
	}
	if KindPlaneFS.String() != "plane_fs" || !KindPlaneFS.Valid() || !KindPlaneControl.Valid() || KindBindResult.String() != "bind_result" || !KindBindResult.Valid() || !KindListenResult.Valid() || !KindSockCreate.Valid() || !KindSockopt.Valid() || !KindPlaneExecKill.Valid() || !KindPlaneExecHeld.Valid() || Kind(32).Valid() ||
		KindPlaneExecKill.String() != "plane_exec_kill" || KindPlaneExecHeld.String() != "plane_exec_held" {
		t.Errorf("plane/control/bind kind boundaries are wrong")
	}
	if Kind(0).Valid() || Kind(13).Valid() || !KindSSLChunk.Valid() {
		t.Error("Kind.Valid is wrong at the boundaries")
	}
}

func FuzzDecode(f *testing.F) {
	head := sample{PID: 1}
	f.Add(execSample(head, 1, "a", "/bin/a", []string{"a"}, false))
	f.Add(fsSample(func() sample { h := head; h.Kind = KindOpen; return h }(), 0, 1, 2, "/x", ""))
	f.Add(netSample(func() sample { h := head; h.Kind = KindConnect; return h }(), 2, 6, 443, [16]byte{1}))
	f.Add(sslSample(head, 1, 0, []byte("x")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var rec Record
		if err := DecodeInto(&rec, raw); err == nil && !rec.Kind.Valid() {
			t.Fatalf("decoded an invalid kind %d", rec.Kind)
		}
	})
}

func BenchmarkDecodeInto(b *testing.B) {
	raw := execSample(sample{PID: 1}, 1, "python3", "/usr/bin/python3.12", []string{"python3", "-m", "pytest", "-q"}, false)
	var rec Record
	b.ReportAllocs()
	for b.Loop() {
		if err := DecodeInto(&rec, raw); err != nil {
			b.Fatal(err)
		}
	}
}
