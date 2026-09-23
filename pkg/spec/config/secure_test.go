// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/binary"
	"strconv"
	"testing"
)

func auxv(wordSize int, pairs ...uint64) []byte {
	var b []byte
	for _, v := range pairs {
		if wordSize == 4 {
			b = binary.NativeEndian.AppendUint32(b, uint32(v))
		} else {
			b = binary.NativeEndian.AppendUint64(b, v)
		}
	}
	return b
}

func TestParseAuxv(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		word int
		want bool
		ok   bool
	}{
		{"secure set", auxv(8, 33, 1, atSecure, 1, 0, 0), 8, true, true},
		{"secure zero", auxv(8, 33, 1, atSecure, 0, 0, 0), 8, false, true},
		{"absent", auxv(8, 33, 1, 6, 4096, 0, 0), 8, false, true},
		{"after AT_NULL ignored", auxv(8, 0, 0, atSecure, 1), 8, false, true},
		{"32-bit", auxv(4, atSecure, 1, 0, 0), 4, true, true},
		{"trailing partial pair", append(auxv(8, atSecure, 1), 1, 2, 3), 8, true, true},
		{"empty", nil, 8, false, true},
		{"bad word size", auxv(8, atSecure, 1), 3, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAuxv(tc.data, tc.word)
			if (err == nil) != tc.ok || got != tc.want {
				t.Errorf("parseAuxv = %v, %v; want %v ok=%v", got, err, tc.want, tc.ok)
			}
		})
	}
}

// The test binary is not a file-capability copy: AT_SECURE must read as false.
func TestDetectSecureExec(t *testing.T) {
	secure, err := DetectSecureExec()
	if err != nil {
		t.Fatal(err)
	}
	if secure {
		t.Error("test binary reports AT_SECURE")
	}
}

// TestSecureFromPairs is DetectSecureExec's reading of the runtime's own copy of the auxiliary vector. It cannot
// read /proc/self/auxv in exactly the case it exists for: a file-capability or setuid exec leaves the process
// non-dumpable, and /proc/self/auxv then refuses its own process (EACCES; measured in the 6.17 KVM guest by
// TestFileCapabilityCopyIsRefused, 2026-10-05).
func TestSecureFromPairs(t *testing.T) {
	for _, tc := range []struct {
		pairs [][2]uintptr
		want  bool
	}{
		{nil, false},
		{[][2]uintptr{{6, 4096}, {atSecure, 0}, {0, 0}}, false},
		{[][2]uintptr{{6, 4096}, {atSecure, 1}, {0, 0}}, true},
		{[][2]uintptr{{0, 0}, {atSecure, 1}}, false}, // AT_NULL ends the vector
	} {
		if got := secureFromPairs(tc.pairs); got != tc.want {
			t.Errorf("secureFromPairs(%v) = %v, want %v", tc.pairs, got, tc.want)
		}
	}
}

// T-config-sudo-1 (R19, E8).
//
// A case between 2^31 and 2^32-2: uid_t is unsigned 32-bit, so a uid up there
// (e.g. a container/CI uid-mapping scheme starting high) is legal and must parse, not overflow or
// be rejected. invokingUID parses an unsigned 32-bit value, excluding the (uid_t)-1 sentinel,
// then returns Go's int. The release targets (amd64 and arm64 in .goreleaser.yaml) have 64-bit
// ints and must preserve the entire valid range. Supplemental 32-bit tests skip only positive
// expectations their int cannot represent; keeping the table's expectations as uint64 makes
// those tests build without pretending the production API supports high UIDs on a 32-bit int.
// identity-config.md E8: a corrupted SUDO_UID (abc, -1, out of range) is treated as unset and falls back to the real uid, never another uid.
func TestInvokingUID(t *testing.T) {
	cases := []struct {
		real    int
		sudo    string
		want    uint64
		viaSudo bool
	}{
		{1000, "", 1000, false},
		{1000, "1001", 1000, false},
		{0, "", 0, false},
		{0, "1000", 1000, true},
		{0, "abc", 0, false},
		{0, "-1", 0, false},
		{0, "99999999999", 0, false},
		{0, "0", 0, true},
		{0, "2147483647", 2147483647, true}, // largest uid a signed 32-bit int can hold
		{0, "2147483648", 2147483648, true}, // 2^31: the first uid a signed 32-bit int could not hold
		{0, "3000000000", 3000000000, true}, // representative mid-range value above 2^31
		{0, "4294967294", 4294967294, true}, // 2^32-2: the last valid uid_t below the sentinel
		{0, "4294967295", 0, false},         // 2^32-1: (uid_t)-1 sentinel, never a real user
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.real)+"/"+tc.sudo, func(t *testing.T) {
			if tc.want > uint64(^uint(0)>>1) {
				t.Skipf("valid uid %d is not representable by a %d-bit Go int; release targets have 64-bit ints", tc.want, strconv.IntSize)
			}
			got, via := invokingUID(tc.real, tc.sudo, true)
			if got < 0 || uint64(got) != tc.want || via != tc.viaSudo {
				t.Errorf("invokingUID(%d, %q) = %d, %v; want %d, %v", tc.real, tc.sudo, got, via, tc.want, tc.viaSudo)
			}
			// ADR 0042 (5)(d): SUDO_UID is read only by uid 0 of the initial user namespace. Under `unshare -r` the
			// real uid is 0 and the caller sets SUDO_UID, so it names no invoking user there.
			if got, via := invokingUID(tc.real, tc.sudo, false); got != tc.real || via {
				t.Errorf("invokingUID(%d, %q) outside the initial user namespace = %d, %v; want %d, false",
					tc.real, tc.sudo, got, via, tc.real)
			}
		})
	}
	if uid, _ := InvokingUID(); uid < 0 {
		t.Error("negative uid")
	}
}
