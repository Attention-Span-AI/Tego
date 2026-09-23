// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// Fixed attach cookies are the wire between the Go offset planner and the C
// dispatcher. A mismatch would capture a call with a different handler ABI.
func TestSSLMultiCookiesMatchDispatcher(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "bpf", "uprobe_ssl.bpf.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value uint64
	}{
		{"WRITE", SSLCookieWrite}, {"WRITE_EX", SSLCookieWriteEx},
		{"READ", SSLCookieRead}, {"READ_EX", SSLCookieReadEx}, {"FREE", SSLCookieFree},
	} {
		pattern := `(?m)^#define TEGO_SSL_COOKIE_` + tc.name + ` ([0-9]+)(?:UL)?$`
		match := regexp.MustCompile(pattern).FindStringSubmatch(string(b))
		if match == nil {
			t.Fatalf("missing fixed cookie %s", tc.name)
		}
		value, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || value != tc.value {
			t.Fatalf("%s cookie C=%s Go=%d", tc.name, match[1], tc.value)
		}
	}
}

// TestSSLStructSizes pins the capture wire widths to what bpf/include/events.h produces, the same way
// TestStructSizes does for the record's own structs.
func TestSSLStructSizes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"SSLKey", unsafe.Sizeof(SSLKey{}), 16},
		{"SSLScratch", unsafe.Sizeof(SSLScratch{}), 32},
		{"SSLMeta", unsafe.Sizeof(SSLMeta{}), 80},
		{"SSLEvent", unsafe.Sizeof(SSLEvent{}), 80 + SSLChunkMax},
		{"SSLClose", unsafe.Sizeof(SSLClose{}), 56},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("sizeof(%s) = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		v    any
		size uintptr
	}{
		{"SSLKey", SSLKey{}, unsafe.Sizeof(SSLKey{})},
		{"SSLScratch", SSLScratch{}, unsafe.Sizeof(SSLScratch{})},
		{"SSLMeta", SSLMeta{}, unsafe.Sizeof(SSLMeta{})},
		{"SSLEvent", SSLEvent{}, unsafe.Sizeof(SSLEvent{})},
	} {
		if got := binary.Size(tc.v); got < 0 || uintptr(got) != tc.size {
			t.Errorf("%s: packed size %d, Go size %d", tc.name, got, tc.size)
		}
	}
}

// sslRecord builds one chunk record the way the kernel would.
func sslRecord(kind Kind, size uint32, length uint32, dir uint8, payload []byte) []byte {
	b := make([]byte, SSLEventSize)
	o := binary.NativeEndian
	o.PutUint16(b[0:2], EventsVersion)
	o.PutUint16(b[2:4], uint16(kind))
	o.PutUint32(b[4:8], size)
	o.PutUint64(b[8:16], 4242)
	o.PutUint64(b[16:24], 99)
	o.PutUint32(b[24:28], 1234)
	o.PutUint32(b[28:32], 1235)
	o.PutUint64(b[HeaderSize:HeaderSize+8], 0xdeadbeef)
	o.PutUint32(b[HeaderSize+8:HeaderSize+12], length)
	b[HeaderSize+12] = dir
	copy(b[sslDataOffset:], payload)
	return b
}

// TestDecodeSSLChunk covers the decoder's happy path and every way a record can be wrong: it must never
// panic and never hand back a slice that runs past the record.
func TestDecodeSSLChunk(t *testing.T) {
	t.Parallel()
	payload := []byte("POST /v1/messages HTTP/1.1\r\n")

	t.Run("round trip", func(t *testing.T) {
		got, err := DecodeSSLChunk(sslRecord(KindSSLChunk, uint32(SSLEventSize), uint32(len(payload)), SSLWrite, payload))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if string(got.Data) != string(payload) {
			t.Errorf("data = %q, want %q", got.Data, payload)
		}
		if got.SSLPtr != 0xdeadbeef || got.Direction != SSLWrite || got.Truncated {
			t.Errorf("chunk = %+v", got)
		}
		if got.Hdr.CgroupID != 99 || got.Hdr.PID != 1234 || got.Hdr.TID != 1235 {
			t.Errorf("header = %+v", got.Hdr)
		}
	})

	// The length of the hole after a chunk's data reaches the reader, which is what lets it step over R6's dropped tail
	// inside a body instead of waiting for bytes that never come.
	t.Run("hole after the data", func(t *testing.T) {
		rec := sslRecord(KindSSLChunk, uint32(SSLEventSize), uint32(len(payload)), SSLWrite, payload)
		binary.NativeEndian.PutUint64(rec[sslSkippedOffset:sslSkippedOffset+8], 400061-4*SSLChunkMax)
		got, err := DecodeSSLChunk(rec)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Skipped != 400061-4*SSLChunkMax || string(got.Data) != string(payload) {
			t.Errorf("skipped %d, data %q", got.Skipped, got.Data)
		}
	})

	t.Run("empty chunk", func(t *testing.T) {
		got, err := DecodeSSLChunk(sslRecord(KindSSLChunk, uint32(SSLEventSize), 0, SSLRead, nil))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Data) != 0 || got.Direction != SSLRead {
			t.Errorf("chunk = %+v", got)
		}
	})

	bad := []struct {
		name string
		rec  []byte
		want error
	}{
		{"short", make([]byte, 8), ErrShortRecord},
		{"truncated record", sslRecord(KindSSLChunk, uint32(SSLEventSize), 4, SSLWrite, payload)[:1024], ErrShortRecord},
		{"wrong kind", sslRecord(KindExec, uint32(SSLEventSize), 4, SSLWrite, payload), ErrKind},
		{"wrong declared size", sslRecord(KindSSLChunk, 64, 4, SSLWrite, payload), ErrShortRecord},
		{"length past the cap", sslRecord(KindSSLChunk, uint32(SSLEventSize), SSLChunkMax+1, SSLWrite, payload), ErrShortRecord},
		{"unknown direction", sslRecord(KindSSLChunk, uint32(SSLEventSize), 4, 7, payload), ErrKind},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeSSLChunk(tc.rec); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("wrong version", func(t *testing.T) {
		rec := sslRecord(KindSSLChunk, uint32(SSLEventSize), 4, SSLWrite, payload)
		binary.NativeEndian.PutUint16(rec[0:2], EventsVersion+1)
		if _, err := DecodeSSLChunk(rec); !errors.Is(err, ErrVersion) {
			t.Fatalf("error = %v, want ErrVersion", err)
		}
	})

	t.Run("full chunk", func(t *testing.T) {
		big := make([]byte, SSLChunkMax)
		for i := range big {
			big[i] = byte(i)
		}
		got, err := DecodeSSLChunk(sslRecord(KindSSLChunk, uint32(SSLEventSize), SSLChunkMax, SSLRead, big))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Data) != SSLChunkMax || got.Data[SSLChunkMax-1] != big[SSLChunkMax-1] {
			t.Fatalf("full chunk decoded %d bytes", len(got.Data))
		}
	})
}

// TestDecodeSSLChunkSizeClasses: the kernel reserves each chunk record at the smallest size class that holds
// it, and a stale read's hole as the head alone (R6, edge case #3). One fixed 32 KiB record let about 255
// chunks fill the default 8 MiB ring however few bytes a streamed response's reads carried. Every class
// decodes, a length past its own record's data is refused, and a size that is no class is refused.
func TestDecodeSSLChunkSizeClasses(t *testing.T) {
	t.Parallel()
	payload := []byte("data: {\"type\":\"ping\"}\n\n")
	for _, size := range SSLRecordSizes {
		room := size - sslDataOffset
		n := min(len(payload), room)
		rec := sslRecord(KindSSLChunk, uint32(size), uint32(n), SSLRead, payload[:n])[:size]
		got, err := DecodeSSLChunk(rec)
		if err != nil {
			t.Fatalf("a %d-byte record: %v", size, err)
		}
		if string(got.Data) != string(payload[:n]) {
			t.Errorf("a %d-byte record decoded %q", size, got.Data)
		}
		over := sslRecord(KindSSLChunk, uint32(size), uint32(room+1), SSLRead, nil)
		if _, err := DecodeSSLChunk(over); !errors.Is(err, ErrShortRecord) {
			t.Errorf("a %d-byte record declaring %d bytes of data: %v, want ErrShortRecord", size, room+1, err)
		}
	}
	for _, size := range []int{sslDataOffset + 8, sslDataOffset + SSLClassSmall + 8, SSLEventSize + 8} {
		rec := append(sslRecord(KindSSLChunk, uint32(size), 0, SSLRead, nil), make([]byte, 8)...)
		if _, err := DecodeSSLChunk(rec); !errors.Is(err, ErrShortRecord) {
			t.Errorf("a %d-byte record, which is no size class: %v, want ErrShortRecord", size, err)
		}
	}
	if SSLRecordSizes[1] != 80+SSLClassSmall || SSLRecordSizes[2] != 80+SSLClassMedium {
		t.Errorf("record sizes %v", SSLRecordSizes)
	}

	hole := sslRecord(KindSSLChunk, uint32(sslDataOffset), 0, SSLRead, nil)[:sslDataOffset]
	hole[HeaderSize+14] = SSLHoleStale
	binary.NativeEndian.PutUint64(hole[sslSkippedOffset:sslSkippedOffset+8], 21)
	got, err := DecodeSSLChunk(hole)
	if err != nil {
		t.Fatalf("a stale read's hole: %v", err)
	}
	if got.Hole != SSLHoleStale || got.Skipped != 21 || len(got.Data) != 0 {
		t.Errorf("a stale read's hole decoded as %+v", got)
	}
}

// TestSSLSizingMatchesEventsH reads bpf/include/events.h and asserts the capture sizing this package mirrors:
// the size classes, the read bound and the hole reasons. A drift makes the decoder refuse every record of a
// class, or read a hole's reason as another.
func TestSSLSizingMatchesEventsH(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "bpf", "include", "events.h"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	value := func(name string) uint64 {
		t.Helper()
		m := regexp.MustCompile(`(?m)^\s*(?:#define\s+)?` + name + `\s*=?\s*\(?([0-9UL* ]+)\)?,?\s`).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("events.h names no %s", name)
		}
		v := uint64(1)
		for _, f := range strings.Split(m[1], "*") {
			f = strings.TrimRight(strings.TrimSpace(f), "UL")
			var n uint64
			for _, c := range f {
				n = n*10 + uint64(c-'0')
			}
			v *= n
		}
		return v
	}
	for name, want := range map[string]uint64{
		"TEGO_SSL_CHUNK_MAX":       SSLChunkMax,
		"TEGO_SSL_CLASS_SMALL":     SSLClassSmall,
		"TEGO_SSL_CLASS_MEDIUM":    SSLClassMedium,
		"TEGO_SSL_MAX_CALL_NS":     SSLMaxCallNS,
		"TEGO_SSL_HOLE_NONE":       uint64(SSLHoleNone),
		"TEGO_SSL_HOLE_UNREADABLE": uint64(SSLHoleUnreadable),
		"TEGO_SSL_HOLE_STALE":      uint64(SSLHoleStale),
		"TEGO_SSL_HOLE_EVICTED":    uint64(SSLHoleEvicted),
		"TEGO_SSL_HOLE_NOLENGTH":   uint64(SSLHoleNoLength),
	} {
		if got := value(name); got != want {
			t.Errorf("%s is %d in events.h, %d in ssl.go", name, got, want)
		}
	}
	if SSLMaxCallNS < 10*60*1_000_000_000 {
		t.Errorf("SSLMaxCallNS %d is below the SDKs' 10-minute request timeout: a slow answer would be a hole",
			uint64(SSLMaxCallNS))
	}
}

// TestDecodeSSLClose covers SSL_free's record: its pointer and header come back, and a record that is short, of
// another kind or of another size is refused rather than read.
func TestDecodeSSLClose(t *testing.T) {
	t.Parallel()
	rec := func(kind Kind, size uint32) []byte {
		b := make([]byte, SSLCloseSize)
		o := binary.NativeEndian
		o.PutUint16(b[0:2], EventsVersion)
		o.PutUint16(b[2:4], uint16(kind))
		o.PutUint32(b[4:8], size)
		o.PutUint32(b[24:28], 4321)
		o.PutUint64(b[HeaderSize:HeaderSize+8], 0x5200)
		return b
	}
	got, err := DecodeSSLClose(rec(KindSSLClose, uint32(SSLCloseSize)))
	if err != nil || got.SSLPtr != 0x5200 || got.Hdr.PID != 4321 {
		t.Fatalf("close = %+v, %v", got, err)
	}
	if k := PeekKind(rec(KindSSLClose, uint32(SSLCloseSize))); k != KindSSLClose {
		t.Errorf("PeekKind = %s", k)
	}
	if k := PeekKind(make([]byte, 3)); k != 0 {
		t.Errorf("PeekKind of 3 bytes = %s, want 0", k)
	}
	for name, b := range map[string][]byte{
		"short":      rec(KindSSLClose, uint32(SSLCloseSize))[:HeaderSize+4],
		"chunk kind": rec(KindSSLChunk, uint32(SSLCloseSize)),
		"size":       rec(KindSSLClose, uint32(SSLCloseSize)+8),
	} {
		if _, err := DecodeSSLClose(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// FuzzDecodeSSLChunk fuzzes the one decoder that reads kernel-supplied lengths: no input may panic, and a
// success may never alias past the record (§9 "every reader of foreign memory gets one").
func FuzzDecodeSSLChunk(f *testing.F) {
	f.Add(sslRecord(KindSSLChunk, uint32(SSLEventSize), 3, SSLWrite, []byte("abc")))
	f.Add(sslRecord(KindSSLChunk, uint32(SSLEventSize), SSLChunkMax, SSLRead, nil))
	f.Add(make([]byte, HeaderSize))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeSSLChunk(b)
		if err != nil {
			return
		}
		if len(got.Data) > SSLChunkMax {
			t.Fatalf("decoded %d bytes of plaintext", len(got.Data))
		}
		if sslDataOffset+len(got.Data) > len(b) {
			t.Fatalf("data slice runs past the record")
		}
	})
}

// TestSSLSourceMatchesBinding reads bpf/uprobe_ssl.bpf.c and asserts that the required and optional program names and their
// sections are exactly what this package promises. bpf/tests pins the sections of the objects it knows;
// this is the capture object's own half of that check, and it needs neither clang nor a kernel.
func TestSSLSourceMatchesBinding(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "bpf", "uprobe_ssl.bpf.c")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)
	re := regexp.MustCompile(`(?m)^SEC\("(uprobe(?:\.multi)?|uretprobe(?:\.multi)?)"\)\nint ([A-Za-z0-9_]+)\(`)
	var names, sections []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		sections = append(sections, m[1])
		names = append(names, m[2])
	}
	if !slices.Equal(names, SSLPrograms) {
		t.Fatalf("programs in the C = %v, SSLPrograms = %v", names, SSLPrograms)
	}
	want := []string{"uprobe", "uprobe", "uprobe", "uprobe", "uretprobe", "uprobe", "uprobe.multi", "uretprobe.multi"}
	if !slices.Equal(sections, want) {
		t.Errorf("sections = %v, want %v", sections, want)
	}
	for _, m := range CaptureMaps {
		if !strings.Contains(src, m) {
			t.Errorf("the C never mentions %s", m)
		}
	}
	// R2 is a userspace rule, but the object must not make it impossible: one program serves both _ex
	// write variants, so the two symbols share a hook and userspace picks exactly one of them.
	if got := SSLEntryPrograms[ProgSSLWriteEx]; !slices.Equal(got, []string{"SSL_write_ex2", "SSL_write_ex"}) {
		t.Errorf("SSLEntryPrograms[%s] = %v, want SSL_write_ex2 before SSL_write_ex (R2)", ProgSSLWriteEx, got)
	}
}
