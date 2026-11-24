// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"io"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// contentFileCount leaves tenfold headroom above the measured desktop trees.
const contentFileCount = 2048

// contentBudget is shared by D/E. A parser can consume at most 1 MiB from a
// regular pinned inode; failed reads are charged too. Nothing buffers the file.
type contentBudget struct {
	remaining, files int
	fileLimit        int
	units            *unitWorkBudget
	unitCache        *unitReadCache
}

func (b *contentBudget) maxFiles() int {
	if b.fileLimit > 0 {
		return b.fileLimit
	}
	return contentFileCount
}

type chargedReader struct {
	r      io.Reader
	budget *contentBudget
}

func (r chargedReader) Read(p []byte) (int, error) {
	if r.budget.remaining <= 0 {
		return 0, errLimit
	}
	if len(p) > r.budget.remaining {
		p = p[:r.budget.remaining]
	}
	n, e := r.r.Read(p)
	r.budget.remaining -= n
	return n, e
}

func readContent(ctx context.Context, root *sys.FD, name string, uid uint32, budget *contentBudget, parse func(io.Reader) error) error {
	return readContentWithRootMode(ctx, root, name, uid, budget, nil, parse)
}

func readContentWithRootMode(ctx context.Context, root *sys.FD, name string, uid uint32, budget *contentBudget, rootMode func(unix.Stat_t) error, parse func(io.Reader) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if budget.files >= budget.maxFiles() || budget.remaining <= 0 {
		return errLimit
	}
	budget.files++
	pin, e := projectPath(root, name)
	if e != nil {
		return e
	}
	defer func() { _ = pin.Close() }()
	var before unix.Stat_t
	if e = pin.Fstat(&before); e != nil {
		return e
	}
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.ELOOP
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return errType
	}
	if before.Uid != 0 && before.Uid != uid {
		return errOwner
	}
	if e = checkPinnedMode(ctx, pin, before, uid); e != nil {
		return e
	}
	recheckParents, e := contentParentsWithRootMode(ctx, root, name, uid, rootMode)
	if e != nil {
		return e
	}
	if before.Size < 0 || before.Size > manifestBytes {
		return errSize
	}
	var fd *sys.FD
	e = pin.ProcPath(func(path string) error {
		var x error
		fd, x = sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
		return x
	})
	if e != nil {
		return e
	}
	f, e := fd.Release("scan-content")
	if e != nil {
		_ = fd.Close()
		return e
	}
	defer func() { _ = f.Close() }()
	var after unix.Stat_t
	if e = sys.FstatFile(f, &after); e != nil {
		return e
	}
	if !sameInode(before, after) {
		return errChanged
	}
	parseErr := parse(chargedReader{io.LimitReader(f, manifestBytes+1), budget})
	if e = sys.FstatFile(f, &after); e != nil {
		return e
	}
	if !sameInode(before, after) {
		return errChanged
	}
	current, e := projectPath(root, name)
	if e != nil {
		return errChanged
	}
	defer func() { _ = current.Close() }()
	if e = current.Fstat(&after); e != nil {
		return e
	}
	if !sameInode(before, after) {
		return errChanged
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = recheckParents(); e != nil {
		return e
	}
	return parseErr
}
