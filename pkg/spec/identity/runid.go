// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RunID is a run identifier of the form r-<host8>-<time36>-<rand6>. It is immutable once minted
// and sorts by mint time within one host (R1). The zero value is not Valid.
type RunID string

// runIDPattern is the exact shape of a valid run id (R2).
var runIDPattern = regexp.MustCompile(`^r-[0-9a-f]{8}-[0-9a-z]{13}-[0-9a-z]{6}$`)

// crockford32 is the base32-Crockford alphabet in lower case: 5 bits per character.
const crockford32 = "0123456789abcdefghjkmnpqrstvwxyz"

// time36Width is the zero-padded width of the base36 UnixNano field; every positive int64
// fits in 13 base36 digits.
const time36Width = 13

// HostID hashes the bytes of a machine id (the content of /etc/machine-id, read by the caller)
// into the 32-byte host identity NewRunID consumes. Surrounding whitespace is ignored so a trailing
// newline does not change the digest. Pure; the caller decides where the bytes come from (Q7).
func HostID(machineID []byte) [32]byte {
	return sha256.Sum256([]byte(strings.TrimSpace(string(machineID))))
}

// NewRunID mints a run id from the host identity, the mint time and a random source.
//
// Pre: now is after the Unix epoch and before the year 2262 (out-of-range is a caller bug, E32);
// rnd yields at least 4 bytes without blocking indefinitely. Post: the result is Valid.
// Errors: rnd's read error wrapped, never a partial id (E1). Not idempotent by design.
//
// R1: host8 = lower hex of hostID[0:4]; time36 = now.UTC().UnixNano() in base36, zero-padded to 13
// characters; rand6 = 4 random bytes read big-endian as a uint32, right-shifted by 2 (the low two
// bits are dropped) to exactly 30 bits, then base32-Crockford lower-case, 6 characters.
func NewRunID(hostID [32]byte, now time.Time, rnd io.Reader) (RunID, error) {
	var raw [4]byte
	if _, err := io.ReadFull(rnd, raw[:]); err != nil {
		return "", fmt.Errorf("identity: read random bytes for run id: %w", err)
	}
	nanos := now.UTC().UnixNano()
	if nanos < 0 {
		return "", errors.New("identity: run id mint time before the Unix epoch")
	}
	host8 := fmt.Sprintf("%08x", hostID[:4])
	time36 := padLeft(strconv.FormatInt(nanos, 36), time36Width)
	rand6 := encodeRand6(binary.BigEndian.Uint32(raw[:]) >> 2)
	return RunID("r-" + host8 + "-" + time36 + "-" + rand6), nil
}

// encodeRand6 encodes the low 30 bits of v as 6 base32-Crockford characters, most significant first.
func encodeRand6(v uint32) string {
	var out [6]byte
	for i := 5; i >= 0; i-- {
		out[i] = crockford32[v&0x1f]
		v >>= 5
	}
	return string(out[:])
}

// padLeft zero-pads s to width characters.
func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat("0", width-len(s)) + s
}

// Valid reports whether r matches ^r-[0-9a-f]{8}-[0-9a-z]{13}-[0-9a-z]{6}$ exactly (R2).
func (r RunID) Valid() bool {
	return runIDPattern.MatchString(string(r))
}

// String returns the id as text.
func (r RunID) String() string { return string(r) }

// Slug returns the id with every dash removed, the form used wherever a systemd slice segment
// must name the run (R2).
func (r RunID) Slug() string { return RunSlug(string(r)) }

// RunSlug strips every '-' from a run id (R2). It accepts any string so callers holding an id as
// plain text need no conversion.
func RunSlug(id string) string { return strings.ReplaceAll(id, "-", "") }

// Host8 returns the host component of a valid run id, or "" when r is not Valid.
func (r RunID) Host8() string {
	if !r.Valid() {
		return ""
	}
	return string(r)[2:10]
}

// ExecID identifies one process of a run: <run id>/<pid>/<start-boot-ns>. It is stable across pid
// reuse within one pid namespace because the start time (nanoseconds since boot) differs (E30).
type ExecID string

// NewExecID formats the exec id of process pid whose start time is startBootNS nanoseconds after
// boot. Pure; no validation of run beyond formatting.
func NewExecID(run RunID, pid int, startBootNS uint64) ExecID {
	return ExecID(string(run) + "/" + strconv.Itoa(pid) + "/" + strconv.FormatUint(startBootNS, 10))
}

// String returns the exec id as text.
func (e ExecID) String() string { return string(e) }

// AgentID is the contract name: [a-z0-9-]{1,40}.
type AgentID string

var agentIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// ErrAgentID is the sentinel wrapped by ParseAgentID on a malformed name.
var ErrAgentID = errors.New("identity: invalid agent id")

// ParseAgentID validates s as an agent id. Errors wrap ErrAgentID and name the offending value.
func ParseAgentID(s string) (AgentID, error) {
	if !agentIDPattern.MatchString(s) {
		return "", fmt.Errorf("%w: %q does not match [a-z0-9-]{1,40}", ErrAgentID, s)
	}
	return AgentID(s), nil
}

// String returns the agent id as text.
func (a AgentID) String() string { return string(a) }
