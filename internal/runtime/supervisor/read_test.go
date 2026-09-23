// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// testReader builds a reader over a fake target with a live notification.
func testReader(t *testing.T, f *fakeKernel) (*reader, *Loop, *notif) {
	t.Helper()
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	n := notifFor(connectNR(), 42, 0, 0, 0)
	return l.newReader(n), l, n
}

// TestCStringBounds covers the NUL-scan bound, a string with no NUL, and the page-crossing read (R3, E20).
func TestCStringBounds(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		addr      uint64
		max       int
		want      string
		truncated bool
		failed    bool
	}{
		{name: "short string", data: cstr("/etc/hosts"), addr: 0x1000, max: pathMax, want: "/etc/hosts"},
		{
			name: "no NUL within the bound", data: []byte(strings.Repeat("a", 64)), addr: 0x1000, max: 64,
			want: strings.Repeat("a", 64), truncated: true,
		},
		{
			name: "exactly PATH_MAX+1 with a NUL at the end",
			data: cstr(strings.Repeat("b", pathMax-1)), addr: 0x1000, max: pathMax,
			want: strings.Repeat("b", pathMax-1),
		},
		{
			name: "crosses a page boundary", data: cstr("/work/project/file.txt"), addr: 0x2000 - 8,
			max: pathMax, want: "/work/project/file.txt",
		},
		{name: "unmapped", data: nil, addr: 0x9999, max: pathMax, failed: true},
		{name: "null pointer", data: nil, addr: 0, max: pathMax, failed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			if tc.data != nil {
				f.put(tc.addr, tc.data)
			}
			r, _, _ := testReader(t, f)
			got, cut := r.cstring(tc.addr, tc.max)
			if !tc.failed && cut != tc.truncated {
				t.Errorf("cut = %v, want %v", cut, tc.truncated)
			}
			if got != tc.want {
				t.Errorf("cstring = %q (len %d), want len %d", trim(got), len(got), len(tc.want))
			}
			if r.failed != tc.failed {
				t.Errorf("failed = %v, want %v", r.failed, tc.failed)
			}
			if !tc.failed && (r.note == rulePathTruncated) != tc.truncated {
				t.Errorf("note = %q, want truncated %v", r.note, tc.truncated)
			}
			if len(got) > tc.max {
				t.Errorf("read %d bytes past the %d bound", len(got), tc.max)
			}
		})
	}
}

// TestResolveDirfd covers R6's three shapes and E8's unlinked directory.
// supervisor.md E12: a /proc/<pid>/{cwd,fd/N} link is read once and never followed again (the "loop" case below).
func TestResolveDirfd(t *testing.T) {
	tests := []struct {
		name       string
		dirfd      int32
		in         string
		links      map[string]string
		want       string
		unreliable bool
	}{
		{name: "absolute ignores the dirfd", dirfd: 9, in: "/etc/hosts", want: "/etc/hosts"},
		{
			name: "AT_FDCWD", dirfd: atFDCWD, in: "sub/f",
			links: map[string]string{"/proc/42/cwd": "/work"}, want: "/work/sub/f",
		},
		{
			name: "dirfd", dirfd: 9, in: "f",
			links: map[string]string{"/proc/42/fd/9": "/work/d"}, want: "/work/d/f",
		},
		{
			name: "deleted dirfd", dirfd: 9, in: "f",
			links: map[string]string{"/proc/42/fd/9": "/work/d (deleted)"}, want: "/work/d/f", unreliable: true,
		},
		{
			name: "dirfd is not a directory", dirfd: 9, in: "f",
			links: map[string]string{"/proc/42/fd/9": "socket:[12345]"}, want: "f", unreliable: true,
		},
		{name: "missing link", dirfd: 9, in: "f", want: "f", unreliable: true},
		{name: "negative dirfd", dirfd: -7, in: "f", want: "f", unreliable: true},
		{
			// E12: a link whose value is itself a /proc magic link is not followed a second time.
			name: "a link to another proc link is one hop", dirfd: atFDCWD, in: "f",
			links: map[string]string{"/proc/42/cwd": "/proc/42/root", "/proc/42/root": "/elsewhere"}, want: "/proc/42/root/f",
		},
		{
			name: "cleaned", dirfd: atFDCWD, in: "./a/../b",
			links: map[string]string{"/proc/42/cwd": "/work"}, want: "/work/b",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			for k, v := range tc.links {
				f.links[k] = v
			}
			r, _, _ := testReader(t, f)
			got := r.resolve(tc.dirfd, tc.in)
			if got != tc.want {
				t.Errorf("resolve = %q, want %q", got, tc.want)
			}
			if (r.note == rulePathUnreliable) != tc.unreliable {
				t.Errorf("note = %q, want unreliable %v", r.note, tc.unreliable)
			}
		})
	}
}

// TestResolveOverlongPath is E6: a join past PATH_MAX is dropped, not returned half-formed.
func TestResolveOverlongPath(t *testing.T) {
	f := newFake()
	f.links["/proc/42/cwd"] = "/" + strings.Repeat("d", pathMax-2)
	r, _, _ := testReader(t, f)
	if got := r.resolve(atFDCWD, strings.Repeat("x", 64)); got != "" {
		t.Errorf("resolve = %q (len %d), want an empty path", trim(got), len(got))
	}
}

// TestSockaddrReadClamps is R3/E4: the read never exceeds sockaddr_storage whatever addrlen claims.
func TestSockaddrReadClamps(t *testing.T) {
	f := newFake()
	f.put(0x1000, make([]byte, 512))
	r, _, _ := testReader(t, f)
	got := r.sockaddr(0x1000, 4096)
	if len(got) != sockaddrMax {
		t.Errorf("read %d bytes, want the %d-byte clamp", len(got), sockaddrMax)
	}
}

// TestReadMemErrorFailsClosed is E18: an unreadable target fails the session rather than inventing data.
func TestReadMemErrorFailsClosed(t *testing.T) {
	f := newFake()
	f.readErr = unix.EPERM
	r, _, _ := testReader(t, f)
	if got := r.sockaddr(0x1000, 16); got != nil || !r.failed {
		t.Errorf("sockaddr = %v, failed = %v; want nil, true", got, r.failed)
	}
}

// TestReadsAreBracketed is R2/I1: every logical read checks ID_VALID before and after.
func TestReadsAreBracketed(t *testing.T) {
	f := newFake()
	f.put(0x1000, cstr("/etc/hosts"))
	r, _, n := testReader(t, f)
	before := f.idValid
	if got := r.path(atFDCWD, 0x1000); got != "/etc/hosts" {
		t.Fatalf("path = %q", got)
	}
	if f.idValid-before < 2 {
		t.Errorf("ID_VALID calls = %d, want the read bracketed on both sides", f.idValid-before)
	}
	f.stale[n.id] = true
	if got := r.path(atFDCWD, 0x1000); got != "" {
		t.Errorf("path = %q after the target died, want nothing (R19)", got)
	}
	if !n.gone {
		t.Error("the notification was not marked gone")
	}
}

// TestPointersCap is E11: the pointer array is capped before a single string is read.
func TestPointersCap(t *testing.T) {
	f := newFake()
	ptrs := make([]byte, 8*(argvEntries+10))
	for i := range argvEntries + 10 {
		putU64(ptrs[i*8:], 0x900000)
	}
	f.put(0x20000, ptrs)
	f.put(0x900000, cstr("a"))
	r, _, _ := testReader(t, f)
	got, more := r.pointers(0x20000)
	if len(got) != argvEntries || !more {
		t.Errorf("pointers = %d (more %v), want %d and more", len(got), more, argvEntries)
	}
}

// TestPointersExactlyTheCapIsWhole: an array of exactly argvEntries pointers and its NULL is the whole argv,
// and argv_truncated must not say otherwise. Reaching the cap used to be read as running past it.
func TestPointersExactlyTheCapIsWhole(t *testing.T) {
	f := newFake()
	ptrs := make([]byte, 8*(argvEntries+1)) // the last word is the NULL
	for i := range argvEntries {
		putU64(ptrs[i*8:], 0x900000)
	}
	f.put(0x20000, ptrs)
	f.put(0x900000, cstr("a"))
	r, _, _ := testReader(t, f)
	got, more := r.pointers(0x20000)
	if len(got) != argvEntries || more {
		t.Errorf("pointers = %d (more %v), want %d and not more", len(got), more, argvEntries)
	}
	argv, truncated := r.argv(0x20000, 1<<20)
	if len(argv) != argvEntries || truncated {
		t.Errorf("argv = %d entries (truncated %v), want %d, not truncated", len(argv), truncated, argvEntries)
	}
}

// TestArgvShortPointerArrayIsTruncated: an argv array that runs into an unmapped page is a prefix of the
// real vector, and the exec event has to say so (E10, E11).
func TestArgvShortPointerArrayIsTruncated(t *testing.T) {
	const ptrAddr, strAddr = 0x20000, 0x30000
	f := newFake()
	ptrs := make([]byte, 16) // two pointers and then nothing: no NULL terminator
	putU64(ptrs[0:], strAddr)
	putU64(ptrs[8:], strAddr)
	f.put(ptrAddr, ptrs)
	f.put(strAddr, cstr("arg"))
	r, _, _ := testReader(t, f)
	argv, truncated := r.argv(ptrAddr, 1024)
	if len(argv) != 2 {
		t.Fatalf("argv = %q, want the two entries that were readable", argv)
	}
	if !truncated {
		t.Error("truncated = false; the array ended in an unmapped page")
	}
}

// FuzzReadPath feeds arbitrary bytes to the path reader through the fake target and asserts the result
// never exceeds the R3 bound and never panics (§9 "Fuzzing").
func FuzzReadPath(f *testing.F) {
	f.Add([]byte("/etc/hosts\x00"), true)
	f.Add([]byte(strings.Repeat("a", 5000)), false)
	f.Add([]byte{0}, true)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, data []byte, absolute bool) {
		fk := newFake()
		fk.links["/proc/42/cwd"] = "/work"
		if len(data) > 0 {
			fk.put(0x1000, data)
		}
		l, _ := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: fk, Workers: 1})
		n := notifFor(connectNR(), 42, 0, 0, 0)
		r := l.newReader(n)
		dirfd := int32(atFDCWD)
		if !absolute {
			dirfd = 9
		}
		got := r.path(dirfd, 0x1000)
		if len(got) > pathMax {
			t.Fatalf("path of %d bytes exceeds the %d bound", len(got), pathMax)
		}
		if strings.Contains(got, "\x00") {
			t.Fatal("a NUL survived the scan")
		}
	})
}

// trim keeps a failure message readable when a fixture is long.
func trim(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// FuzzReadArgv feeds an arbitrary pointer array and string region to the argv reader and asserts the two
// bounds of R3 hold whatever the target laid out: at most argvEntries entries, and at most the byte
// budget plus one terminator per entry (§9 "Fuzzing", tickets README "a fuzz target for every reader of
// foreign memory").
func FuzzReadArgv(f *testing.F) {
	f.Add([]byte{}, []byte("a\x00b\x00"), 64)
	f.Add(bytes.Repeat([]byte{0x10, 0, 0, 0, 0, 0, 0, 0}, 4), []byte("arg\x00"), 128)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, []byte{}, 1)
	f.Fuzz(func(t *testing.T, ptrs, strs []byte, budget int) {
		if budget < 0 {
			budget = -budget
		}
		budget %= 1 << 20
		fk := newFake()
		const ptrAddr, strAddr = 0x10000, 0x20000
		if len(ptrs) > 0 {
			fk.put(ptrAddr, ptrs)
		}
		if len(strs) > 0 {
			fk.put(strAddr, strs)
		}
		l, _ := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: fk, Workers: 1})
		n := notifFor(connectNR(), 42, 0, 0, 0)
		r := l.newReader(n)
		argv, _ := r.argv(ptrAddr, budget)
		if len(argv) > argvEntries {
			t.Fatalf("%d entries exceed the %d cap", len(argv), argvEntries)
		}
		total := 0
		for _, a := range argv {
			if len(a) > argMax {
				t.Fatalf("one argument of %d bytes exceeds the %d cap", len(a), argMax)
			}
			total += len(a) + 1
		}
		if total > budget+argMax+1 {
			t.Fatalf("%d bytes collected against a %d budget", total, budget)
		}
	})
}

// FuzzSendMsgHeader drives the sendmsg path over arbitrary header, iovec and address bytes: the handler
// must answer exactly once and never read past its bounds, whatever the target's struct msghdr says.
func FuzzSendMsgHeader(f *testing.F) {
	hdr := make([]byte, msgHdrSize)
	putU64(hdr[msgNameOff:], 0x40000)
	putU32(hdr[msgNameLenOff:], 16)
	putU64(hdr[msgIovOff:], 0x70000)
	putU64(hdr[msgIovLenOff:], 1)
	f.Add(hdr, sockaddrIn4("10.0.0.1", 53), make([]byte, iovecSize))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0xff}, msgHdrSize), bytes.Repeat([]byte{0xff}, 64), bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, header, sa, iov []byte) {
		fk := newFake()
		const hdrAddr, saAddr, iovAddr = 0x60000, 0x40000, 0x70000
		if len(header) > 0 {
			fk.put(hdrAddr, header)
		}
		if len(sa) > 0 {
			fk.put(saAddr, sa)
		}
		if len(iov) > 0 {
			fk.put(iovAddr, iov)
		}
		l, _ := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: fk, Workers: 1})
		l.handle(notifFor(sendMsgNR(), 42, 5, hdrAddr, 0))
		if got := fk.respCount(); got != 1 {
			t.Fatalf("responses = %d, want exactly one (I11)", got)
		}
		if fk.fdBalance() != 0 {
			t.Fatalf("%d descriptors left open", fk.fdBalance())
		}
	})
}
