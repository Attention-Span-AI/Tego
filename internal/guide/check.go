// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The stored machine check: ~/.tego/state/check.json, written only by `tego setup` (StoreCheck) from doctor's own
// probes. `tego doctor` stays read-only, so a monitoring script that runs it changes nothing (ADR 0142 (2)).
const (
	// CheckSchema is check.json's schema line.
	CheckSchema = "tego.check/1"
	// StateDir is the folder under ~/.tego that holds it.
	StateDir = "state"
	// CheckFile is its name there.
	CheckFile = "check.json"
	// MaxCheckBytes bounds what ReadChecks reads: three entries are well under a kilobyte.
	MaxCheckBytes = 16 << 10
	// maxFixBytes bounds a stored fix: doctor's longest fix line is a few hundred bytes.
	maxFixBytes = 1024
	// maxBuildBytes bounds a stored build and boot id.
	maxBuildBytes = 256
)

// The places a check was made from (Check.Where). A check says what a run started from that place gets: a login
// over SSH starts outside the user manager's cgroup, where tier 1 cannot place a run, and the same person's
// systemd-run --user shell is inside it.
const (
	// WhereShell is a process outside the user manager's cgroup tree (an SSH or console login's session scope).
	WhereShell = "shell"
	// WhereUserManager is a process inside user@<uid>.service's cgroup tree: a desktop terminal, or a
	// systemd-run --user scope.
	WhereUserManager = "user-manager"
	// WhereRoot is a root process in the initial user namespace.
	WhereRoot = "root"
)

// CauseOutsideUserManager is Check.Cause for a place that starts no run only because it is outside the user manager's
// cgroup: an SSH or console login. The next step there opens a shell inside it (OpenScope), never tego doctor again.
const CauseOutsideUserManager = "outside-user-manager"

// CauseNoUserManager is Check.Cause for a place that starts no run only because no user manager runs for the user
// (doctor.Report.NoUserManager): an account reached through su or sudo -u that never logged in and has no linger
// (acceptance 2B, 2026-11-11). The next step starts that manager (Inputs.Linger), never tego doctor and tego setup in
// turn with a delegation fix that changes nothing.
const CauseNoUserManager = "no-user-manager"

// places is every Where, in the order a fact names them.
var places = []string{WhereShell, WhereUserManager, WhereRoot}

// Check is one stored check: what doctor's no-root probes (tier landlock's checks) said from one place, on one boot,
// with one build.
type Check struct {
	// Where is the place the probes ran from: WhereShell, WhereUserManager or WhereRoot.
	Where string `json:"where"`
	// Build is the build that ran them (BuildID): a check of another build is never used.
	Build string `json:"build"`
	// BootID is /proc/sys/kernel/random/boot_id then: a check of another boot is never used.
	BootID string `json:"boot_id"`
	// Tier is the tier a run started from Where gets, "" when none runs there (it can only record).
	Tier string `json:"tier"`
	// FirstFix is doctor's first fix when no tier runs there (doctor.Report.Verdict), "" otherwise.
	FirstFix string `json:"first_fix"`
	// Cause is CauseOutsideUserManager when no tier runs there only because the place is outside the user manager's
	// cgroup (doctor.Report.OutsideUserManager), so a shell opened inside it gets a tier; CauseNoUserManager when only
	// because no user manager runs for the user (doctor.Report.NoUserManager); "" otherwise. It is left out
	// of the file when "", so a check stored by an older build reads the same, and a file without it decodes.
	Cause string `json:"cause,omitempty"`
	// Time is when the probes ran.
	Time time.Time `json:"time"`
}

// checkFile is check.json's shape.
type checkFile struct {
	Schema string  `json:"schema"`
	Checks []Check `json:"checks"`
}

// rawCheckFile and rawCheck are checkFile and Check with every field required: a missing key decodes to nil, which
// DecodeChecks refuses, so a truncated or hand-made file is never read as a default.
type rawCheckFile struct {
	Schema *string     `json:"schema"`
	Checks *[]rawCheck `json:"checks"`
}

type rawCheck struct {
	Where    *string `json:"where"`
	Build    *string `json:"build"`
	BootID   *string `json:"boot_id"`
	Tier     *string `json:"tier"`
	FirstFix *string `json:"first_fix"`
	Time     *string `json:"time"`
	// Cause may be left out (an older build's file); every other key is required. Raw, so a null is told from absent.
	Cause json.RawMessage `json:"cause"`
}

// ErrBadCheck is a check.json that is not one this package wrote: it gives "not known", never a default.
var ErrBadCheck = errors.New("not a check file tego setup writes")

// DecodeChecks reads check.json's bytes strictly: one object, schema CheckSchema, every key present and of its type
// (cause alone may be left out), no unknown key, no trailing data, at most one entry per place, each Where a known
// place, each Tier "" or an enforcing tier, a cause only CauseOutsideUserManager or CauseNoUserManager on a shell entry
// with no tier, Time
// RFC 3339, and the strings short and printable. Anything else is ErrBadCheck.
func DecodeChecks(b []byte) ([]Check, error) {
	if len(b) > MaxCheckBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrBadCheck, MaxCheckBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var raw rawCheckFile
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCheck, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the object", ErrBadCheck)
	}
	if raw.Schema == nil || *raw.Schema != CheckSchema {
		return nil, fmt.Errorf("%w: schema is not %s", ErrBadCheck, CheckSchema)
	}
	if raw.Checks == nil {
		return nil, fmt.Errorf("%w: no checks list", ErrBadCheck)
	}
	if len(*raw.Checks) > len(places) {
		return nil, fmt.Errorf("%w: more than %d checks", ErrBadCheck, len(places))
	}
	out := make([]Check, 0, len(*raw.Checks))
	for i, rc := range *raw.Checks {
		c, err := rc.check()
		if err != nil {
			return nil, fmt.Errorf("%w: check %d: %v", ErrBadCheck, i, err)
		}
		if slices.ContainsFunc(out, func(o Check) bool { return o.Where == c.Where }) {
			return nil, fmt.Errorf("%w: two checks from %s", ErrBadCheck, c.Where)
		}
		out = append(out, c)
	}
	return out, nil
}

// check is rc validated.
func (rc rawCheck) check() (Check, error) {
	if rc.Where == nil || rc.Build == nil || rc.BootID == nil || rc.Tier == nil || rc.FirstFix == nil || rc.Time == nil {
		return Check{}, errors.New("a key is missing")
	}
	c := Check{Where: *rc.Where, Build: *rc.Build, BootID: *rc.BootID, Tier: *rc.Tier, FirstFix: *rc.FirstFix}
	if rc.Cause != nil {
		if err := json.Unmarshal(rc.Cause, &c.Cause); err != nil || string(rc.Cause) == "null" {
			return Check{}, errors.New("cause is not a string")
		}
	}
	switch {
	case c.Cause != "" && c.Cause != CauseOutsideUserManager && c.Cause != CauseNoUserManager:
		return Check{}, fmt.Errorf("cause %q is not one tego setup writes", c.Cause)
	case c.Cause != "" && (c.Tier != "" || c.Where != WhereShell):
		return Check{}, errors.New("a cause beside a tier, or for a place other than a shell outside the user manager")
	}
	if !slices.Contains(places, c.Where) {
		return Check{}, fmt.Errorf("where %q is not a place", c.Where)
	}
	switch backend.Tier(c.Tier) {
	case "", backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM:
	case backend.TierObserve, backend.TierAuto:
		return Check{}, fmt.Errorf("tier %q is not an enforcing tier", c.Tier)
	default:
		return Check{}, fmt.Errorf("tier %q is not an enforcing tier", c.Tier)
	}
	for _, f := range []struct {
		name, v string
		max     int
	}{{"build", c.Build, maxBuildBytes}, {"boot_id", c.BootID, maxBuildBytes}, {"first_fix", c.FirstFix, maxFixBytes}} {
		if len(f.v) > f.max || !plain(f.v) {
			return Check{}, fmt.Errorf("%s is longer than %d bytes or holds a character that does not print", f.name, f.max)
		}
	}
	if c.Build == "" || c.BootID == "" {
		return Check{}, errors.New("build or boot_id is empty")
	}
	if c.Tier != "" && c.FirstFix != "" {
		return Check{}, errors.New("a check with a tier has no fix")
	}
	t, err := time.Parse(time.RFC3339Nano, *rc.Time)
	if err != nil {
		return Check{}, fmt.Errorf("time: %v", err)
	}
	c.Time = t.UTC()
	return c, nil
}

// plain reports whether s is valid UTF-8 that record.Printable leaves as it is: no control or invisible character.
func plain(s string) bool { return utf8.ValidString(s) && record.Printable(s) == s }

// EncodeChecks is check.json's bytes for cs, one entry per place in places' order.
func EncodeChecks(cs []Check) ([]byte, error) {
	sorted := slices.Clone(cs)
	slices.SortStableFunc(sorted, func(a, b Check) int { return slices.Index(places, a.Where) - slices.Index(places, b.Where) })
	for i := range sorted {
		sorted[i].Time = sorted[i].Time.UTC()
	}
	b, err := json.MarshalIndent(checkFile{Schema: CheckSchema, Checks: sorted}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", CheckFile, err)
	}
	if _, err := DecodeChecks(b); err != nil {
		return nil, err // never write a file this package would refuse to read
	}
	return append(b, '\n'), nil
}

// CheckPath is check.json's path under home, the invoking user's home: ~/.tego/state/check.json.
func CheckPath(home string) string {
	return filepath.Join(home, ledger.StateDir, StateDir, CheckFile)
}

// ReadChecks reads home's check.json (DecodeChecks). ~/.tego is reached as the rest of tego reaches it; state and
// check.json are opened without following a link, the folder must be the reader's own and writable by no one else,
// and the file must be a regular file of at most MaxCheckBytes, read without blocking: a link, a FIFO, a directory
// or a large file there is an error, never a hang or a default. A file that does not exist is os.ErrNotExist.
func ReadChecks(home string) ([]Check, error) {
	state, err := openState(home, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = state.Close() }()
	return readChecksAt(state, CheckPath(home))
}

// readChecksAt is ReadChecks through state, the open ~/.tego/state; path names check.json in errors.
func readChecksAt(state *sys.FD, path string) ([]Check, error) {
	fd, err := state.Openat(CheckFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, pathErr("open", path, err)
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return nil, pathErr("stat", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = fd.Close()
		return nil, fmt.Errorf("%s: %w: not a regular file", path, ErrBadCheck)
	}
	if st.Size > MaxCheckBytes {
		_ = fd.Close()
		return nil, fmt.Errorf("%s: %w: larger than %d bytes", path, ErrBadCheck, MaxCheckBytes)
	}
	f, err := fd.Release(path)
	if err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxCheckBytes+1))
	if err != nil {
		return nil, pathErr("read", path, err)
	}
	cs, err := DecodeChecks(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cs, nil
}

// StoreCheck writes c into home's check.json, in place of the check from c.Where, keeping the checks from other places
// that are of c's boot and build and dropping the rest: a new file of mode 0600, synced, renamed over the old one, and
// the folder synced, as the repo's other state files are written. It makes ~/.tego and ~/.tego/state (0700) when they
// are missing. A link at state, a folder another user owns or can write, or a file this package would not read back
// is refused, and nothing is written; a link, a file or a FIFO at check.json is replaced by the rename, never written
// through, and a check.json that does not decode is replaced. A folder there is left as it is: the rename fails, the
// temporary file is removed, and the check is not stored (the error says so).
func StoreCheck(home string, c Check) error {
	if _, err := EncodeChecks([]Check{c}); err != nil {
		return err
	}
	state, err := openState(home, true)
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()
	keep := []Check{c}
	if old, err := readChecksAt(state, CheckPath(home)); err == nil {
		for _, o := range old {
			if o.Where != c.Where && o.BootID == c.BootID && o.Build == c.Build {
				keep = append(keep, o)
			}
		}
	}
	b, err := EncodeChecks(keep)
	if err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("store %s: %w", CheckFile, err)
	}
	tmp := "." + CheckFile + "." + hex.EncodeToString(rnd[:])
	fd, err := state.Openat(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return pathErr("create", filepath.Join(filepath.Dir(CheckPath(home)), tmp), err)
	}
	f, werr := fd.Release(tmp)
	if werr != nil {
		_ = fd.Close()
	} else {
		_, werr = f.Write(b)
		if werr == nil {
			werr = f.Sync()
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
	}
	if werr == nil {
		werr = state.Borrow(func(dir int) error { return unix.Renameat(dir, tmp, dir, CheckFile) })
	}
	if werr != nil {
		_ = state.Borrow(func(dir int) error { return unix.Unlinkat(dir, tmp, 0) })
		return fmt.Errorf("store %s: %w", CheckPath(home), werr)
	}
	_ = state.Fsync() // the rename is done; only its durability across a crash would be left unproved
	return nil
}

// openState opens ~/.tego/state under home: ~/.tego as the rest of tego opens it, state without following a link, and
// only a folder the effective user owns that no one else may write. With create, a missing ~/.tego or state is made
// 0700 first.
func openState(home string, create bool) (*sys.FD, error) {
	if !filepath.IsAbs(home) {
		return nil, fmt.Errorf("the home %q is not an absolute path", home)
	}
	tegoDir := filepath.Join(home, ledger.StateDir)
	if create {
		if err := os.Mkdir(tegoDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("make %s: %w", tegoDir, err)
		}
	}
	tfd, err := sys.Own(unix.Open(tegoDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, pathErr("open", tegoDir, err)
	}
	defer func() { _ = tfd.Close() }()
	stateDir := filepath.Join(tegoDir, StateDir)
	if create {
		err := tfd.Borrow(func(n int) error { return unix.Mkdirat(n, StateDir, 0o700) })
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, pathErr("make", stateDir, err)
		}
	}
	sfd, err := tfd.Openat(StateDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, pathErr("open", stateDir, err)
	}
	var st unix.Stat_t
	if err := sfd.Fstat(&st); err != nil {
		_ = sfd.Close()
		return nil, pathErr("stat", stateDir, err)
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		_ = sfd.Close()
		return nil, fmt.Errorf("%s is owned by uid %d with mode %o: tego setup keeps its check only in a folder "+
			"of yours that no one else can write", stateDir, st.Uid, st.Mode&0o7777)
	}
	return sfd, nil
}

// pathErr is err about path, with a link refused by O_NOFOLLOW said in words.
func pathErr(op, path string, err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return &os.PathError{Op: op, Path: path, Err: os.ErrNotExist}
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR) && op == "open":
		return fmt.Errorf("%s %s: a link or not a folder there; tego setup does not follow it: %w", op, path, err)
	}
	return &os.PathError{Op: op, Path: path, Err: err}
}

// usable splits stored checks into those of boot and build and a sentence for each other kind it left out.
func usable(cs []Check, boot, build string) (ok []Check, left []string) {
	var otherBoot, otherBuild bool
	for _, c := range cs {
		switch {
		case c.BootID != boot:
			otherBoot = true
		case c.Build != build:
			otherBuild = true
		default:
			ok = append(ok, c)
		}
	}
	if otherBoot {
		left = append(left, "a stored check from before this machine last started")
	}
	if otherBuild {
		left = append(left, "a stored check made by another tego build")
	}
	return ok, left
}

// whereWords is a place as a fact names it.
func whereWords(where string) string {
	switch where {
	case WhereShell:
		return "a shell outside your user manager's cgroup"
	case WhereUserManager:
		return "a shell in your user manager's cgroup"
	case WhereRoot:
		return "root"
	}
	return strings.TrimSpace(where)
}
