// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// auxvPath is the process's own auxiliary vector.
const auxvPath = "/proc/self/auxv"

// atSecure is the AT_SECURE auxv type: non-zero when the kernel executed the binary with elevated
// credentials (setuid, or file capabilities).
const atSecure = 23

// DetectSecureExec reports whether this process runs with AT_SECURE set (the file-capability copy
// of the binary). Post: true iff auxv type 23 is present and non-zero. It reads the copy of the vector
// the Go runtime took at start (unix.Auxv), and /proc/self/auxv only when the runtime has none: a
// file-capability or setuid exec leaves the process non-dumpable, and /proc/self/auxv then refuses
// the process itself (EACCES), in exactly the case this exists for (ADR 0042 (3)(a)). An I/O error
// is returned, not swallowed: a process that cannot read its own auxv must not resolve $HOME or
// $TEGO_CONFIG either. A static binary gets no loader secure-execution stripping, so the binary
// decides from these values itself.
func DetectSecureExec() (bool, error) {
	if pairs, err := unix.Auxv(); err == nil {
		return secureFromPairs(pairs), nil
	}
	data, err := os.ReadFile(auxvPath)
	if err != nil {
		return false, fmt.Errorf("config: read %s: %w", auxvPath, err)
	}
	return parseAuxv(data, int(unsafe.Sizeof(uintptr(0))))
}

// parseAuxv scans (type, value) pairs of wordSize bytes each in native byte order and returns
// whether AT_SECURE is non-zero. A trailing partial pair is ignored; wordSize must be 4 or 8.
func parseAuxv(data []byte, wordSize int) (bool, error) {
	if wordSize != 4 && wordSize != 8 {
		return false, fmt.Errorf("config: auxv word size %d unsupported", wordSize)
	}
	pair := 2 * wordSize
	for off := 0; off+pair <= len(data); off += pair {
		typ, val := auxvWord(data[off:], wordSize), auxvWord(data[off+wordSize:], wordSize)
		if typ == 0 {
			break // AT_NULL terminates the vector
		}
		if typ == atSecure {
			return val != 0, nil
		}
	}
	return false, nil
}

// secureFromPairs is DetectSecureExec over the runtime's (type, value) pairs: true iff AT_SECURE comes before
// AT_NULL with a non-zero value.
func secureFromPairs(pairs [][2]uintptr) bool {
	for _, p := range pairs {
		if p[0] == 0 {
			return false
		}
		if p[0] == atSecure {
			return p[1] != 0
		}
	}
	return false
}

func auxvWord(b []byte, wordSize int) uint64 {
	if wordSize == 4 {
		return uint64(binary.NativeEndian.Uint32(b))
	}
	return binary.NativeEndian.Uint64(b)
}
