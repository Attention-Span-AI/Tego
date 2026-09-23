// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The own log's shape (docs/OPERATIONS.md "Logs of tego itself", limits-check-doctor-cli.md §3, P0-DESIGN
// §3.3): ~/.tego/tego.log, 0600, rotated at 10 MB keeping 5 files, one appender per process.
const (
	ownLogDir   = ".tego"
	ownLogName  = "tego.log"
	ownLogMax   = 10 << 20
	ownLogFiles = 5
)

// ownLogOwner is who a file or directory this process creates for the log is handed to. Under sudo it is
// the invoking user: a root run that created ~/.tego or tego.log as root would leave that user a log
// they can neither read nor append to, and a ~/.tego their own unprivileged runs cannot write into.
// uid < 0 leaves what the kernel chose, which is this process's own ids.
type ownLogOwner struct{ uid, gid int }

// ownLog is this process's one appender to tego.log: an io.Writer a slog handler writes one line to per
// record. It opens the file on the first write, so a command that logs nothing creates nothing.
//
// Every name is resolved against a descriptor of ~/.tego opened O_NOFOLLOW, and the log itself is opened
// O_NOFOLLOW and checked to be a regular file with one link. The directory is the invoking user's even
// when this process is root (sudo), so without those checks the user could point tego.log at any file
// on the machine by symlink or hard link and have root append to it.
//
// Several processes append to one file; each line is one write(2) on O_APPEND, so lines never
// interleave. Rotation takes flock(LOCK_EX|LOCK_NB) on the directory, so one process renames at a time
// and a process that finds the lock taken keeps writing to the file it has; a process whose file was
// rotated by another notices on its next write, because its file is past the size limit and no longer
// the one the name refers to, and reopens the name. Any process of the user's uid can open ~/.tego and
// hold that lock for as long as it likes — the agent among them — so a held lock is not only a brief
// overlap: once the file reaches twice its limit with the lock still taken, lines are dropped and
// counted rather than appended, and the count is written as the first line after the next rotation
// (docs/OPERATIONS.md). The file then never grows past twice the limit plus the lines already on their
// way to it.
type ownLog struct {
	mu    sync.Mutex
	home  string
	owner ownLogOwner
	// trusted reports whether a uid may own the log directory and file: root, this process, or the
	// invoking user. Anything else is someone else's file in a place this process is about to write.
	trusted func(uid uint32) bool
	max     int64
	files   int

	// dir is ~/.tego's descriptor, nil until the first write opens it. It is strict (ADR 0023): it holds the
	// rotation flock, and a strict owner never defers the close that would drop it.
	dir *sys.FD
	f   *os.File
	// dropped counts the lines not written because the file was at twice its limit and another
	// process held the rotation lock.
	dropped int
	// broken is the error that made the log unusable. It is kept rather than retried on every
	// line: the log is best effort and must never turn one failure into a stream of syscalls.
	broken error
}

// newOwnLog returns the appender for home/.tego/tego.log. Nothing is opened until the first write.
func newOwnLog(home string, owner ownLogOwner, trusted func(uint32) bool) *ownLog {
	return &ownLog{home: home, owner: owner, trusted: trusted, max: ownLogMax, files: ownLogFiles}
}

// errNoHome is a process with no home to keep its log in (see ownLogHome).
var errNoHome = errors.New("tego.log: no home directory for the invoking user")

// Write appends p as one line, rotating first when the file has reached its size limit. It is safe for
// concurrent use; slog handlers serialize their own writes too, but several loggers share this writer.
func (l *ownLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken != nil {
		return 0, l.broken
	}
	if l.f == nil {
		if err := l.openLocked(); err != nil {
			return 0, l.breakLocked(err)
		}
	}
	if st, err := l.f.Stat(); err == nil && st.Size() >= l.max {
		rotated, err := l.rotateLocked()
		if err != nil {
			return 0, l.breakLocked(err)
		}
		if !rotated && st.Size() >= 2*l.max {
			l.dropped++
			return 0, errLogFull
		}
	}
	if l.dropped > 0 {
		note := fmt.Sprintf("time=%s level=WARN msg=\"tego.log: %d lines dropped while the file was at twice "+
			"its size limit and another process held the rotation lock\" pid=%d\n",
			time.Now().Format("2006-01-02T15:04:05.000Z07:00"), l.dropped, os.Getpid())
		if _, err := l.f.Write([]byte(note)); err == nil {
			l.dropped = 0
		}
	}
	return l.f.Write(p)
}

// breakLocked keeps err as what made the log unusable and returns it. A broken appender is never retried, so
// it also closes ~/.tego and the file it holds, which would otherwise stay open for the life of the process
// with nothing ever writing through them.
func (l *ownLog) breakLocked(err error) error {
	l.broken = err
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
	_ = l.dir.Close()
	l.dir = nil
	return err
}

// errLogFull is a line Write dropped: the file is at twice its size limit and rotation's lock is held
// by another process.
var errLogFull = errors.New("tego.log: at twice its size limit and the rotation lock is held elsewhere; line dropped")

// ownLogMkdirHook runs between openDir's mkdir of ~/.tego and its open of the name; the root test that
// swaps the directory in that window sets it. It does nothing in the product.
var ownLogMkdirHook = func() {}

// openLocked opens ~/.tego (creating it 0700 when missing) and then tego.log (creating it 0600).
func (l *ownLog) openLocked() error {
	if l.home == "" {
		return errNoHome
	}
	if l.dir == nil {
		dir, err := l.openDir()
		if err != nil {
			return err
		}
		l.dir = dir
	}
	return l.openFileLocked()
}

// openDir returns a descriptor of home/.tego after checking it is a directory, owned by a trusted uid,
// and writable by nobody else: another user who can write there can replace the log between our checks.
func (l *ownLog) openDir() (*sys.FD, error) {
	home, err := sys.Own(unix.Open(l.home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, fmt.Errorf("tego.log: open %s: %w", l.home, err)
	}
	defer func() { _ = home.Close() }()
	created := false
	switch err := home.Borrow(func(n int) error { return unix.Mkdirat(n, ownLogDir, 0o700) }); {
	case err == nil:
		created = true
	case !errors.Is(err, unix.EEXIST):
		return nil, fmt.Errorf("tego.log: mkdir %s: %w", filepath.Join(l.home, ownLogDir), err)
	}
	ownLogMkdirHook()
	dir, err := sys.Strict(home.Openat(ownLogDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, fmt.Errorf("tego.log: open %s: %w", filepath.Join(l.home, ownLogDir), err)
	}
	var st unix.Stat_t
	if err := dir.Fstat(&st); err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("tego.log: stat %s: %w", filepath.Join(l.home, ownLogDir), err)
	}
	if created && l.owner.uid >= 0 {
		// The mkdir and the open are two lookups by name in the invoking user's home, so what the open
		// found need not be what the mkdir made: a directory renamed into place in between. Only a
		// directory this process owns and that is still empty is the one it made; anything else is
		// refused rather than handed to the user (ledger's giveTo applies the same rule).
		if int(st.Uid) != os.Geteuid() || !emptyDir(dir) {
			_ = dir.Close()
			return nil, fmt.Errorf("tego.log: %s is not the directory this process just made (uid %d)",
				filepath.Join(l.home, ownLogDir), st.Uid)
		}
		if err := dir.Borrow(func(n int) error { return unix.Fchown(n, l.owner.uid, l.owner.gid) }); err != nil {
			_ = dir.Close()
			return nil, fmt.Errorf("tego.log: chown %s: %w", filepath.Join(l.home, ownLogDir), err)
		}
		if err := dir.Fstat(&st); err != nil {
			_ = dir.Close()
			return nil, fmt.Errorf("tego.log: stat %s: %w", filepath.Join(l.home, ownLogDir), err)
		}
	}
	if !l.trusted(st.Uid) || st.Mode&0o022 != 0 {
		_ = dir.Close()
		return nil, fmt.Errorf("tego.log: %s is owned by uid %d with mode %o, want a trusted owner and no group or "+
			"other write", filepath.Join(l.home, ownLogDir), st.Uid, st.Mode&0o7777)
	}
	return dir, nil
}

// emptyDir reports whether the directory dir holds no entries, reading through a descriptor of its own so
// dir's offset is untouched.
func emptyDir(dir *sys.FD) bool {
	d, err := dir.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f, err := d.Release(".")
	if err != nil {
		_ = d.Close()
		return false
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(1)
	return len(names) == 0 && errors.Is(err, io.EOF)
}

// openFileLocked opens tego.log inside the directory descriptor and checks what it got.
func (l *ownLog) openFileLocked() error {
	const flags = unix.O_WRONLY | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	created := true
	fd, err := l.dir.Openat(ownLogName, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	if errors.Is(err, unix.EEXIST) {
		created = false
		fd, err = l.dir.Openat(ownLogName, flags, 0)
	}
	if err != nil {
		return fmt.Errorf("tego.log: open: %w", err)
	}
	// O_NONBLOCK above is for the open itself: a FIFO planted at the name would otherwise block this
	// process until someone read it. A regular file, the only thing accepted below, ignores the flag.
	if created && l.owner.uid >= 0 {
		if err := fd.Borrow(func(n int) error { return unix.Fchown(n, l.owner.uid, l.owner.gid) }); err != nil {
			_ = fd.Close()
			return fmt.Errorf("tego.log: chown: %w", err)
		}
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return fmt.Errorf("tego.log: stat: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || !l.trusted(st.Uid) {
		_ = fd.Close()
		return fmt.Errorf("tego.log: %s is not a regular, singly linked file owned by a trusted uid "+
			"(mode %o, links %d, uid %d)", filepath.Join(l.home, ownLogDir, ownLogName), st.Mode, st.Nlink, st.Uid)
	}
	if st.Mode&0o077 != 0 {
		// A log an older build or another tool left group- or world-readable: it carries paths and
		// errors about the user's runs, so it is tightened to the 0600 the layout names.
		if err := fd.Borrow(func(n int) error { return unix.Fchmod(n, 0o600) }); err != nil {
			_ = fd.Close()
			return fmt.Errorf("tego.log: chmod: %w", err)
		}
	}
	f, err := fd.Release(filepath.Join(l.home, ownLogDir, ownLogName))
	if err != nil {
		_ = fd.Close()
		return fmt.Errorf("tego.log: open: %w", err)
	}
	l.f = f
	return nil
}

// rotateLocked renames tego.log to tego.log.1 (and .1 to .2, up to files-1, the oldest dropping off)
// when the file this process holds is still the one the name refers to, then reopens the name. rotated
// is false when another process held the rotation lock and nothing was done.
func (l *ownLog) rotateLocked() (rotated bool, err error) {
	if err := l.dir.Flock(unix.LOCK_EX | unix.LOCK_NB); err != nil {
		// Another appender is rotating, or holds the lock for its own reasons: write where we are
		// rather than wait, since a log line must never stall the run that emits it. Write bounds
		// how far past the limit that goes.
		return false, nil
	}
	defer func() { _ = l.dir.Flock(unix.LOCK_UN) }()
	var cur, named unix.Stat_t
	if err := sys.FstatFile(l.f, &cur); err != nil {
		return false, fmt.Errorf("tego.log: stat: %w", err)
	}
	if l.dir.Fstatat(ownLogName, &named, unix.AT_SYMLINK_NOFOLLOW) == nil && named.Ino == cur.Ino && named.Dev == cur.Dev {
		for i := l.files - 1; i >= 1; i-- {
			from := ownLogName
			if i > 1 {
				from = ownLogName + "." + strconv.Itoa(i-1)
			}
			to := ownLogName + "." + strconv.Itoa(i)
			if err := l.dir.Borrow(func(n int) error { return unix.Renameat(n, from, n, to) }); err != nil &&
				!errors.Is(err, unix.ENOENT) {
				return false, fmt.Errorf("tego.log: rotate %s: %w", from, err)
			}
		}
	}
	// Rotated here or by another process: either way the name now refers to a different file, or
	// to none, and this process's lines belong in that one.
	_ = l.f.Close()
	l.f = nil
	return true, l.openFileLocked()
}

// ownLogLevel is the machine config's log.level as a slog level (spec/config/v0: debug | info | warn).
// A missing config, or a value the config parser would have refused, is info, the built-in default.
func ownLogLevel(m *config.Machine) slog.Level {
	if m == nil {
		return slog.LevelInfo
	}
	switch m.Log.Level.Value {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// newOwnLogger is a logger over w at m's log.level. Every line carries pid, which is what tells two
// concurrent tego processes apart in the one shared file; a run adds run=<id> itself.
func newOwnLogger(w io.Writer, m *config.Machine) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: ownLogLevel(m)})).With("pid", os.Getpid())
}

var (
	processLogOnce sync.Once
	processLog     *ownLog
)

// ownLogHomeOf is the home processOwnLog keeps tego.log under for the invoking uid: ownLogHome over this
// process's own AT_SECURE probe, $HOME and passwd database. It is a variable so this package's tests can
// point it into their own temporary directory (anchor_test.go's TestMain), and so can a binary built with
// the tegotesthooks tag (ownlog_testhook.go), for the tests that drive tego as a subprocess: without
// them one run of the suites appended two dozen ERROR lines and a panic stack to the developer's own
// ~/.tego/tego.log. Nothing in a product build reassigns it, and no environment
// variable can: under sudo, root appends to the file this names (identity-config.md R21).
var ownLogHomeOf = func(uid int) string {
	return ownLogHome(uid, config.DetectSecureExec, os.UserHomeDir, lookupHome)
}

// processOwnLog is this process's appender, built once (§3: one appender per process). Its home is the
// invoking user's, from ownLogHomeOf.
func processOwnLog() *ownLog {
	processLogOnce.Do(func() {
		uid, viaSudo := config.InvokingUID()
		home := ownLogHomeOf(uid)
		owner := ownLogOwner{uid: -1, gid: -1}
		if viaSudo && os.Geteuid() == 0 {
			if gid, ok := sudoGID(uid); ok {
				owner = ownLogOwner{uid: uid, gid: gid}
			}
		}
		euid := os.Geteuid()
		processLog = newOwnLog(home, owner, func(u uint32) bool {
			return u == 0 || int(u) == euid || int(u) == uid
		})
	})
	return processLog
}

// ownLogger is the logger `run` hands the runtime, the supervisor and the forwarder: this process's
// tego.log at the machine's log.level.
func ownLogger(m *config.Machine) *slog.Logger { return newOwnLogger(processOwnLog(), m) }

// ownLogHome is where tego.log lives: the invoking user's home from the passwd database, never $HOME
// for a process started with AT_SECURE (spec/config/v0 "Trust", identity-config.md R21) or under sudo,
// where $HOME may still be the caller's or already root's depending on sudo's own configuration. $HOME
// stands in only for an ordinary unprivileged process whose uid has no passwd entry, the same rule
// runtime.LedgerRoot applies to ledger_root. "" means no log.
func ownLogHome(uid int, secure func() (bool, error), envHome func() (string, error), lookup func(int) (string, error)) string {
	if h, err := lookup(uid); err == nil && h != "" {
		return h
	}
	if s, err := secure(); err != nil || s || os.Geteuid() == 0 {
		return ""
	}
	h, err := envHome()
	if err != nil {
		return ""
	}
	return h
}

// lookupHome is the passwd home of uid, never $HOME (config.LookupPasswd).
func lookupHome(uid int) (string, error) {
	u, err := config.LookupPasswd(uid)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// sudoGID is the group the invoking user's files are given: SUDO_GID when it parses, else uid's primary
// group from the passwd database.
func sudoGID(uid int) (int, bool) {
	if n, err := strconv.ParseUint(os.Getenv("SUDO_GID"), 10, 32); err == nil && n != 0xffffffff {
		return int(n), true
	}
	u, err := config.LookupPasswd(uid)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(u.Gid)
	return gid, err == nil
}
