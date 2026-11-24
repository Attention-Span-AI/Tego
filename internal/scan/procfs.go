// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/grouptrust"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/watch/sig"
)

// procAccess is consumed by the snapshot reader. Tests can fail on any forbidden read.
// There is no environment method and no default root.
type procAccess interface {
	pids(context.Context) ([]int, error)
	open(int) (processFiles, error)
}

type processFiles interface {
	owner() (uint32, error)
	read(string, int) ([]byte, error)
	link(string) (string, error)
	fileID() (sig.FileID, error)
	tasks(context.Context) ([]int, error)
	thread(int) (processFiles, error)
	close()
}

type procFS struct {
	dir     *sys.FD
	observe func(string)
}
type processFS struct {
	dir     *sys.FD
	observe func(string)
	locator string
}

func openProc(root string) (*procFS, error) {
	if !plainPath(root) {
		return nil, errSyntax
	}
	fd, err := sys.Own(unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, err
	}
	return &procFS{dir: fd}, nil
}

func (p *procFS) close()    { _ = p.dir.Close() } // read-only descriptor, no pending writes
func (p *processFS) close() { _ = p.dir.Close() }

func directoryIDs(ctx context.Context, dir *sys.FD, limit int) ([]int, error) {
	copyFD, err := dir.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f, err := copyFD.Release("scan-proc-directory")
	if err != nil {
		_ = copyFD.Close()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := make([]int, 0, 128)
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		names, err := f.Readdirnames(128)
		for _, name := range names {
			entries++
			if entries > 2*maxPIDs {
				return out, errLimit
			}
			if name == "" || strings.Trim(name, "0123456789") != "" {
				continue
			}
			n, e := strconv.ParseUint(name, 10, 31)
			if e != nil || n == 0 {
				continue
			}
			if len(out) == limit {
				sort.Ints(out)
				return out, errLimit
			}
			out = append(out, int(n))
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, err
		}
	}
	sort.Ints(out)
	return out, nil
}

func (p *procFS) pids(ctx context.Context) ([]int, error) { return directoryIDs(ctx, p.dir, maxPIDs) }
func (p *procFS) open(pid int) (processFiles, error) {
	if pid < 1 {
		return nil, errSyntax
	}
	fd, err := p.dir.Openat(strconv.Itoa(pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &processFS{dir: fd, observe: p.observe, locator: strconv.Itoa(pid)}, nil
}

func (p *processFS) owner() (uint32, error) {
	var st unix.Stat_t
	err := p.dir.Fstat(&st)
	return st.Uid, err
}

// read pins and checks the inode before opening it for data. A FIFO, device, socket or
// symlink never gets a data open. The kernel's proc-fd reopen is the only link exception.
func (p *processFS) read(name string, limit int) ([]byte, error) {
	if p.observe != nil {
		p.observe(p.locator + "/" + name)
	}
	switch name {
	case "status", "stat", "cmdline", "cgroup":
	default:
		return nil, errType
	}
	pin, err := p.dir.Openat(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pin.Close() }()
	var before unix.Stat_t
	if err := pin.Fstat(&before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return nil, errType
	}
	if before.Size < 0 || before.Size > int64(limit) {
		return nil, errSize
	}
	var data *sys.FD
	err = pin.ProcPath(func(path string) error {
		var e error
		data, e = sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
		return e
	})
	if err != nil {
		return nil, err
	}
	f, err := data.Release("scan-proc-file")
	if err != nil {
		_ = data.Close()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var opened, after unix.Stat_t
	if err := sys.FstatFile(f, &opened); err != nil {
		return nil, err
	}
	if !sameInode(before, opened) {
		return nil, errChanged
	}
	b, err := readBounded(f, limit)
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errSize
	}
	if err := sys.FstatFile(f, &after); err != nil {
		return nil, err
	}
	if !sameInode(before, after) {
		return nil, errChanged
	}
	return b, nil
}

func sameInode(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (p *processFS) link(name string) (string, error) {
	if name != "exe" && name != "cwd" {
		return "", errType
	}
	buf := make([]byte, maxProcText+1)
	var count int
	err := p.dir.Borrow(func(n int) error { var e error; count, e = unix.Readlinkat(n, name, buf); return e })
	if err != nil {
		return "", err
	}
	if count > maxProcText {
		return "", errSize
	}
	s := string(buf[:count])
	if !plainPath(s) {
		return "", errSyntax
	}
	return s, nil
}

func (p *processFS) fileID() (sig.FileID, error) {
	fd, err := p.dir.Openat("exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return sig.FileID{}, err
	}
	defer func() { _ = fd.Close() }()
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return sig.FileID{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return sig.FileID{}, errType
	}
	return sig.FileID{Dev: uint64(st.Dev), Ino: st.Ino}, nil
}

func (p *processFS) tasks(ctx context.Context) ([]int, error) {
	fd, err := p.dir.Openat("task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	return directoryIDs(ctx, fd, maxThreads)
}

func (p *processFS) thread(tid int) (processFiles, error) {
	if tid < 1 {
		return nil, errSyntax
	}
	task, err := p.dir.Openat("task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = task.Close() }()
	fd, err := task.Openat(strconv.Itoa(tid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &processFS{dir: fd, observe: p.observe, locator: p.locator + "/task/" + strconv.Itoa(tid)}, nil
}

func readStatus(p processFiles) (statusInfo, error) {
	b, e := p.read("status", maxProcText)
	if e != nil {
		return statusInfo{}, e
	}
	return parseStatus(b)
}
func readStat(p processFiles) (statInfo, error) {
	b, e := p.read("stat", maxProcText)
	if e != nil {
		return statInfo{}, e
	}
	return parseStat(b)
}

var errUnsupported = errors.New("unsupported")
var errUnresolved = errors.New("unit launch unresolved")

func fixedReason(err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrNotExist), errors.Is(err, unix.ESRCH):
		return "gone"
	case errors.Is(err, errChanged):
		return "changed"
	case errors.Is(err, errUnresolved):
		return "unresolved"
	case errors.Is(err, errUnsupported):
		return "unsupported"
	case errors.Is(err, errSyntax):
		return "syntax"
	case errors.Is(err, errSize):
		return "size"
	case errors.Is(err, errType):
		return "type"
	case errors.Is(err, grouptrust.ErrMode), errors.Is(err, errProjectMode):
		return "mode"
	case errors.Is(err, errOwner), errors.Is(err, grouptrust.ErrOwner):
		return "owner"
	case errors.Is(err, unix.ELOOP):
		return "symlink"
	case errors.Is(err, errLimit):
		return "limit"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "deadline"
	default:
		return "io"
	}
}

// processInputBudget has at least twofold headroom over 1,000 measured desktop
// shaped fixture processes. Each process and its threads also share a 256 KiB cap.
const processInputBudget = 8 << 20
const maxProcessInputBytes = 256 << 10

// budgetProc shares the total content bound across processes, identity rechecks and threads.
// It is local to one synchronous snapshot, so it needs no shared global or goroutine.
type budgetProc struct {
	procAccess
	remaining int
	limited   bool
}
type budgetProcess struct {
	processFiles
	budget    *budgetProc
	remaining *int
}

func (p *budgetProc) open(pid int) (processFiles, error) {
	f, e := p.procAccess.open(pid)
	if e != nil {
		return nil, e
	}
	remaining := maxProcessInputBytes
	return &budgetProcess{processFiles: f, budget: p, remaining: &remaining}, nil
}
func (p *budgetProcess) read(name string, limit int) ([]byte, error) {
	if p.budget.remaining <= 1 {
		p.budget.remaining = 0
		p.budget.limited = true
		return nil, errLimit
	}
	if *p.remaining <= 1 {
		*p.remaining = 0
		p.budget.limited = true
		return nil, errLimit
	}
	bounded := min(limit, p.budget.remaining-1, *p.remaining-1)
	b, e := p.processFiles.read(name, bounded)
	cost := len(b)
	// A rejected read may already have consumed limit+one bytes. Charging the
	// upper bound prevents discarded oversized/error input from becoming free.
	if e != nil {
		cost = bounded + 1
	}
	p.budget.remaining -= cost
	*p.remaining -= cost
	if len(b) > bounded || errors.Is(e, errSize) && bounded < limit {
		p.budget.limited = true
		return nil, errLimit
	}
	return b, e
}
func (p *budgetProcess) link(name string) (string, error) {
	if min(p.budget.remaining, *p.remaining) < maxProcText+1 {
		p.budget.limited = true
		return "", errLimit
	}
	s, e := p.processFiles.link(name)
	cost := len(s)
	if e != nil {
		cost = maxProcText + 1
	}
	p.budget.remaining -= cost
	*p.remaining -= cost
	return s, e
}
func (p *budgetProcess) thread(tid int) (processFiles, error) {
	f, e := p.processFiles.thread(tid)
	if e != nil {
		return nil, e
	}
	return &budgetProcess{processFiles: f, budget: p.budget, remaining: p.remaining}, nil
}

// readBounded uses a sentinel byte even when proc reports a file size of zero.
func readBounded(r io.Reader, limit int) ([]byte, error) {
	if limit < 0 || limit > maxArgvBytes {
		return nil, errSize
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errSize
	}
	return b, nil
}
