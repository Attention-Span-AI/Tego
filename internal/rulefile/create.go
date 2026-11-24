// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// OpCreate is the journal op of a contract file Create wrote where there was none.
const OpCreate = "create"

// ErrExists is a Create whose file name is taken (a file, a link, a directory, anything): nothing was written and
// what is there is untouched.
var ErrExists = errors.New("rulefile: a file is already there")

// createMode is a new contract's mode: the owner writes it, nobody else does, so it passes every guard of Read.
const createMode = 0o644

// Create writes text as a new contract file at path, never over anything: the directory is pinned and checked as
// Read pins it (resolved once, not under the ledger root or tego's home, this user's or root's, not writable by
// others unless sticky), the text goes to a temporary file (O_EXCL, O_NOFOLLOW, mode 0644, fsync'ed) and is moved to
// the name with renameat2 RENAME_NOREPLACE, which fails with EEXIST rather than replace a file that appeared
// meanwhile (a link and unlink where the filesystem has no RENAME_NOREPLACE, which refuses the same way), and the
// directory is fsync'ed. The write is recorded in g.LedgerRoot's journal as op "create" with the text as a blob, under
// the same per-contract lock a Replace takes, and prune.lock shared from the blob to the line, as a Replace holds it. A
// taken name is ErrExists; a journal append that fails after the file is written is ErrJournal with the entry, as
// Replace reports it.
func Create(ctx context.Context, g Guard, path string, text []byte, c Change) (*Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if g.LedgerRoot == "" {
		return nil, errors.New("rulefile: no ledger root to journal the new contract in, so nothing is written")
	}
	if len(text) > agent.MaxContractSize {
		return nil, fmt.Errorf("%w: the new text is %d bytes, more than a contract may be (%d)", ErrGuard, len(text), agent.MaxContractSize)
	}
	p, err := pin(path, g)
	if err != nil {
		return nil, err
	}
	defer p.close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j, err := openJournal(g.LedgerRoot)
	if err != nil {
		return nil, err
	}
	defer j.close()
	unlock, err := j.lock(ctx, Sum([]byte(p.path))+".lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if p.taken() {
		return nil, fmt.Errorf("%w: %s exists; a new agent's rules are never written over a file", ErrExists, p.path)
	}
	unshare, err := j.share(ctx)
	if err != nil {
		return nil, err
	}
	defer unshare()
	sum := Sum(text)
	if err := j.putBlob(text, sum); err != nil {
		return nil, fmt.Errorf("journal the new text: %w", err)
	}
	if err := p.create(ctx, text); err != nil {
		return nil, err
	}
	e := &Entry{V: JournalVersion, ID: newID(), Op: OpCreate, At: now().UTC(), Via: c.Via, UID: geteuid(), PID: os.Getpid(),
		Contract: p.path, NewSHA256: sum, Run: c.Run, Line: c.Line, Summary: c.Summary, Sentences: c.Sentences,
		Direction: c.Direction}
	if e.Via == "" {
		e.Via = progVia()
	}
	if err := step("journal"); err != nil {
		return e, fmt.Errorf("%w: %s is written: %v", ErrJournal, p.path, err)
	}
	if err := j.append(ctx, e); err != nil {
		return e, fmt.Errorf("%w: %s is written: %v", ErrJournal, p.path, err)
	}
	return e, nil
}

// taken is whether the pinned directory holds anything under the file's name, a dangling link included.
func (p *pinned) taken() bool {
	var st unix.Stat_t
	err := p.dir.Borrow(func(n int) error { return unix.Fstatat(n, p.name, &st, unix.AT_SYMLINK_NOFOLLOW) })
	return !errors.Is(err, unix.ENOENT)
}

// create writes b to a temporary file in the pinned directory and moves it to the file's name only while the name is
// free, then syncs the directory. A reader sees no file or the whole file, never part of one.
func (p *pinned) create(ctx context.Context, b []byte) error {
	err := registry.WriteFileAt(p.dir, p.name, b, registry.WriteOptions{Context: ctx, Mode: createMode,
		BeforePublish: func() error {
			if err := step("rename"); err != nil {
				return err
			}
			if p.beforePublish != nil {
				return p.beforePublish()
			}
			return nil
		}})
	if errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("%w: %s appeared while the new contract was being written; nothing was written over it", ErrExists, p.path)
	}
	return err
}
