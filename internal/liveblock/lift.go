// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// KeyName is an Adjustable run's lift key in its run directory: 32 random bytes, mode 0600, made by the launcher
// (WriteKey). The run directory is under the ledger root, which no run can read (ADR 0113), so only a process outside
// every run can MAC a lift (ADR 0125 decision 5).
const KeyName = "live-key"

// keyBytes is the lift key's length.
const keyBytes = 32

// liftDomain separates a lift's MAC from every other HMAC Tego computes.
const liftDomain = "tego-live-lift-v1"

// Lift asks the launcher of an Adjustable run to allow the fence entry of kind on value (normalized) until until (zero:
// the rest of the run), recording a lift change MAC'ed under key (LiftMAC). It does not touch Blocks: the launcher
// holds the fence's state in its own memory, checks the MAC and the fence, and writes the ledger line of what took
// effect. kind is read, net or exec (FenceKinds); a set until must be after at.
func (o *Overlay) Lift(kind Kind, value, by string, at, until time.Time, key []byte) (Change, error) {
	c, err := o.fenceOp(OpLift, kind, value, by, at, until)
	if err != nil {
		return Change{}, err
	}
	if len(key) != keyBytes {
		return Change{}, fmt.Errorf("%w: a lift key of %d bytes, want %d", ErrInvalid, len(key), keyBytes)
	}
	c = o.record(c)
	c.MAC = LiftMAC(key, o.Run, c)
	o.Changes[len(o.Changes)-1].MAC = c.MAC
	return c, nil
}

// Restore asks the launcher of an Adjustable run to refuse the fence entry of kind on value (normalized) again,
// recording a restore change. It narrows, so it carries no MAC and no time limit, and it does not touch Blocks.
func (o *Overlay) Restore(kind Kind, value, by string, at time.Time) (Change, error) {
	c, err := o.fenceOp(OpRestore, kind, value, by, at, time.Time{})
	if err != nil {
		return Change{}, err
	}
	return o.record(c), nil
}

// fenceOp is a lift or a restore of kind on value, unnumbered, after the checks Validate makes of it.
func (o *Overlay) fenceOp(op string, kind Kind, value, by string, at, until time.Time) (Change, error) {
	if !slices.Contains(FenceKinds, kind) {
		return Change{}, fmt.Errorf("%w: a fence entry is of kind read, net or exec, not %q", ErrInvalid, kind)
	}
	v, err := Normalize(kind, value)
	if err != nil {
		return Change{}, err
	}
	at, until = at.UTC().Round(time.Millisecond), until.UTC()
	if !until.IsZero() && !until.After(at) {
		return Change{}, fmt.Errorf("%w: a %s that ends at %s, not after %s", ErrInvalid, op, until.Format(time.RFC3339), at.Format(time.RFC3339))
	}
	return Change{Op: op, Kind: kind, Value: v, By: by, At: at, Until: until}, nil
}

// LiftMAC is a lift's MAC under the run's key: the hex HMAC-SHA256, in the domain "tego-live-lift-v1", of the run and
// the change's serial (decimal), op, kind, value, by, at and until (RFC3339Nano in UTC, "" when zero), each prefixed
// by its length as internal/control/rules/ack.go does, so no two changes share one input. c's own MAC is not read.
// Binding the serial makes a replayed lift fail: the launcher reads each serial once.
func LiftMAC(key []byte, run string, c Change) string {
	m := hmac.New(sha256.New, key)
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	for _, f := range []string{liftDomain, run, strconv.FormatUint(c.Serial, 10), c.Op, string(c.Kind), c.Value, c.By,
		stamp(c.At), stamp(c.Until)} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		m.Write(n[:])
		m.Write([]byte(f))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// LiftMACOK reports whether c's MAC is LiftMAC's under key, compared in constant time.
func LiftMACOK(key []byte, run string, c Change) bool {
	if len(key) != keyBytes {
		return false
	}
	want := LiftMAC(key, run, c)
	return len(c.MAC) == len(want) && hmac.Equal([]byte(c.MAC), []byte(want))
}

// WriteKey makes dir's KeyName: 32 bytes from crypto/rand in a new 0600 file (no symlink followed, none already
// there), with the file and the directory synced, and returns the key.
func WriteKey(dir string) ([]byte, error) {
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, KeyName), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("live key: %w", err)
	}
	// The create's 0600 is masked by the umask: under umask 0277 the key would be 0400, which ReadKey refuses, and
	// every lift would fail. Chmod sets it exactly.
	werr := f.Chmod(0o600)
	if werr == nil {
		_, werr = f.Write(key)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(filepath.Join(dir, KeyName))
		return nil, fmt.Errorf("live key: %w", werr)
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("live key: %w", err)
	}
	serr := d.Sync()
	if cerr := d.Close(); serr == nil {
		serr = cerr
	}
	if serr != nil {
		return nil, fmt.Errorf("live key: %w", serr)
	}
	return key, nil
}

// ReadKey is dir's KeyName, read with no symlink followed. It is ErrUntrusted unless the file is regular, owned by
// this process's effective user, of mode 0600 exactly and 32 bytes long.
func ReadKey(dir string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Join(dir, KeyName), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUntrusted, KeyName)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := sys.FstatFile(f, &st); err != nil {
		return nil, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUntrusted, KeyName)
	case st.Uid != uint32(os.Geteuid()):
		return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrUntrusted, KeyName, st.Uid)
	case st.Mode&0o7777 != 0o600:
		return nil, fmt.Errorf("%w: %s has mode %04o, not 0600", ErrUntrusted, KeyName, st.Mode&0o7777)
	case st.Size != keyBytes:
		return nil, fmt.Errorf("%w: %s holds %d bytes, not %d", ErrUntrusted, KeyName, st.Size, keyBytes)
	}
	key, err := io.ReadAll(io.LimitReader(f, keyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(key) != keyBytes {
		return nil, fmt.Errorf("%w: %s holds %d bytes, not %d", ErrUntrusted, KeyName, len(key), keyBytes)
	}
	return key, nil
}
