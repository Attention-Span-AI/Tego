// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// AppendSync appends one bounded, validated event and durably records it before
// returning. A failure poisons further appends. Personal approvals use Append.
func (w *Writer) AppendSync(e *record.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.appendNext(e); err != nil {
		w.durability = err
		return err
	}
	return w.syncRequired()
}

// Sync makes the initial managed run record and its placement durable before the
// child is released. Unlike Close's historical best effort directories, every
// sync error here refuses activation or approval, including EINVAL and EROFS.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if !w.started {
		return ErrNotStarted
	}
	return w.syncRequired()
}

var syncApprovalFile = func(f *os.File) error { return f.Sync() }

func (w *Writer) syncRequired() error {
	if w.durability != nil {
		return w.durability
	}
	if w.torn != nil {
		return w.torn
	}
	// References in the chain may name earlier blobs. Persist those first.
	err := w.blobs.Sync()
	if err == nil {
		err = syncApprovalFile(w.events)
	}
	if err == nil {
		err = fsyncDir(w.dirFD)
	}
	if err == nil {
		var parent *sys.FD
		parent, err = sys.Strict(w.dirFD.Openat("..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
		if err == nil {
			err = errors.Join(fsyncDir(parent), parent.Close())
		}
	}
	if err != nil {
		w.durability = fmt.Errorf("ledger: required approval sync: %w", err)
	}
	return w.durability
}
