// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// rec lays one struct fanotify_event_metadata out the way the kernel writes it: event_len, vers, reserved,
// metadata_len, mask, fd, pid, in the machine's byte order. pad extra bytes follow the 24, standing in for the
// info records a group that asked for FAN_REPORT_* would get; event_len covers them.
func rec(vers uint8, mask uint64, fd, pid int32, pad int) []byte {
	b := make([]byte, metadataLen+pad)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	b[4] = vers
	binary.NativeEndian.PutUint16(b[6:8], metadataLen)
	binary.NativeEndian.PutUint64(b[8:16], mask)
	binary.NativeEndian.PutUint32(b[16:20], uint32(fd))
	binary.NativeEndian.PutUint32(b[20:24], uint32(pid))
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestParseEventsReadsTheLayoutFanotify7Gives decodes bytes written out by hand from the structure's definition
// (event_len 24, vers 3, metadata_len 24, mask FAN_OPEN_PERM 0x10000, fd 7, pid 100, little-endian), so a mistake
// rec makes the same way in both directions cannot hide.
func TestParseEventsReadsTheLayoutFanotify7Gives(t *testing.T) {
	t.Parallel()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the fixture is little-endian; every platform this repo builds for is")
	}
	raw, err := hex.DecodeString("18000000" + "03" + "00" + "1800" + "0000010000000000" + "07000000" + "64000000")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseEvents(raw)
	if err != nil {
		t.Fatalf("parseEvents: %v", err)
	}
	want := []event{{Len: 24, Mask: unix.FAN_OPEN_PERM, Fd: 7, Pid: 100}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseEvents = %+v, want %+v", got, want)
	}
}

func TestParseEventsWalksEveryRecordOfABatch(t *testing.T) {
	t.Parallel()
	buf := cat(
		rec(3, unix.FAN_OPEN_PERM, 7, 100, 0),
		// A record with 16 bytes of info records behind its metadata is stepped over by its event_len.
		rec(3, unix.FAN_OPEN_EXEC_PERM, 8, 200, 16),
		rec(3, unix.FAN_OPEN_PERM|unix.FAN_OPEN_EXEC_PERM, 9, 300, 0),
	)
	got, err := parseEvents(buf)
	if err != nil {
		t.Fatalf("parseEvents: %v", err)
	}
	want := []event{
		{Len: 24, Mask: unix.FAN_OPEN_PERM, Fd: 7, Pid: 100},
		{Len: 40, Mask: unix.FAN_OPEN_EXEC_PERM, Fd: 8, Pid: 200},
		{Len: 24, Mask: unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM, Fd: 9, Pid: 300},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseEvents = %+v, want %+v", got, want)
	}
}

func TestParseEventsAnEmptyReadHoldsNoEvents(t *testing.T) {
	t.Parallel()
	got, err := parseEvents(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("parseEvents(nil) = %+v, %v; want no events and no error", got, err)
	}
}

// TestParseEventsRefusesWhatItCannotTrust: a record the kernel could not have written stops the walk with an
// error naming it, and everything decoded before it is still returned, because those events carry descriptors
// somebody is blocked behind (the listener answers them, whatever the tail looks like).
func TestParseEventsRefusesWhatItCannotTrust(t *testing.T) {
	t.Parallel()
	good := rec(3, unix.FAN_OPEN_PERM, 7, 100, 0)
	wantGood := []event{{Len: 24, Mask: unix.FAN_OPEN_PERM, Fd: 7, Pid: 100}}

	shortMeta := rec(3, unix.FAN_OPEN_PERM, 7, 100, 0)
	binary.NativeEndian.PutUint16(shortMeta[6:8], 16) // metadata_len below the 24 bytes every field needs
	lenBelow := rec(3, unix.FAN_OPEN_PERM, 7, 100, 0)
	binary.NativeEndian.PutUint32(lenBelow[0:4], 20) // event_len below metadata_len
	lenZero := rec(3, unix.FAN_OPEN_PERM, 7, 100, 0)
	binary.NativeEndian.PutUint32(lenZero[0:4], 0) // would not advance the walk
	lenPast := rec(3, unix.FAN_OPEN_PERM, 7, 100, 0)
	binary.NativeEndian.PutUint32(lenPast[0:4], 4096) // past the end of the read

	cases := []struct {
		name string
		buf  []byte
		want []event
		msg  string
		is   error
	}{
		{"a header cut short", make([]byte, 23), nil, "need 24", nil},
		{"a tail cut short", cat(good, make([]byte, 10)), wantGood, "need 24", nil},
		{"metadata_len below the structure", cat(good, shortMeta), wantGood, "metadata_len", nil},
		{"event_len below metadata_len", cat(good, lenBelow), wantGood, "event_len", nil},
		{"event_len zero", cat(good, lenZero), wantGood, "event_len", nil},
		{"event_len past the read", cat(good, lenPast), wantGood, "remain", nil},
		{"another ABI version", cat(good, rec(2, unix.FAN_OPEN_PERM, 8, 1, 0)), wantGood, "version 2", errVersion},
		{"version 4", rec(4, unix.FAN_OPEN_PERM, 8, 1, 0), nil, "version 4", errVersion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseEvents(c.buf)
			if err == nil {
				t.Fatalf("parseEvents accepted %x", c.buf)
			}
			if !strings.Contains(err.Error(), c.msg) {
				t.Errorf("error %q lacks %q", err, c.msg)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("error %q is not %v", err, c.is)
			}
			if c.is == nil && errors.Is(err, errVersion) {
				t.Errorf("error %q is the version error, which ends the listener, for a damaged record", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("events before the bad record = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestEventClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		mask       uint64
		permission bool
		exec       bool
	}{
		{"open permission", unix.FAN_OPEN_PERM, true, false},
		{"exec permission", unix.FAN_OPEN_EXEC_PERM, true, true},
		{"both bits on one record", unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM, true, true},
		{"queue overflow", unix.FAN_Q_OVERFLOW, false, false},
		{"a notification open", 0x20, false, false},
		{"no bits", 0, false, false},
		{"overflow beside a permission bit", unix.FAN_Q_OVERFLOW | unix.FAN_OPEN_PERM, true, false},
	}
	for _, c := range cases {
		e := event{Mask: c.mask}
		if got := e.isPermission(); got != c.permission {
			t.Errorf("%s: isPermission = %v, want %v", c.name, got, c.permission)
		}
		if got := e.isExec(); got != c.exec {
			t.Errorf("%s: isExec = %v, want %v", c.name, got, c.exec)
		}
	}
}

// TestResponseIsStructFanotifyResponse: the 8 bytes the kernel's write handler reads, fd first, then the
// response word.
func TestResponseIsStructFanotifyResponse(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fd   int32
		resp uint32
	}{{7, unix.FAN_ALLOW}, {1023, unix.FAN_DENY}, {0, unix.FAN_ALLOW}} {
		raw := encodeResponse(c.fd, c.resp)
		if len(raw) != 8 {
			t.Fatalf("response is %d bytes, want 8", len(raw))
		}
		if got := int32(binary.NativeEndian.Uint32(raw[0:4])); got != c.fd {
			t.Errorf("response names fd %d, want %d", got, c.fd)
		}
		if got := binary.NativeEndian.Uint32(raw[4:8]); got != c.resp {
			t.Errorf("response word %d, want %d", got, c.resp)
		}
	}
}

// FuzzParseEvents: whatever the bytes are, the parser does not panic, never walks past the read, and stops
// only with an error: a clean parse consumes the whole buffer.
func FuzzParseEvents(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(rec(3, unix.FAN_OPEN_PERM, 7, 100, 0))
	f.Add(cat(rec(3, unix.FAN_OPEN_EXEC_PERM, 8, 200, 16), rec(3, unix.FAN_OPEN_PERM, 9, 300, 0)))
	f.Add(cat(rec(3, unix.FAN_OPEN_PERM, 7, 100, 0), make([]byte, 10)))
	f.Add(rec(2, unix.FAN_OPEN_PERM, 7, 100, 0))
	f.Fuzz(func(t *testing.T, buf []byte) {
		got, err := parseEvents(buf)
		total := 0
		for _, e := range got {
			if e.Len < metadataLen {
				t.Fatalf("event of %d bytes, below the %d every record has", e.Len, metadataLen)
			}
			total += int(e.Len)
		}
		if total > len(buf) {
			t.Fatalf("events cover %d bytes of a %d byte read", total, len(buf))
		}
		if err == nil && total != len(buf) {
			t.Fatalf("a clean parse covered %d of %d bytes", total, len(buf))
		}
	})
}
