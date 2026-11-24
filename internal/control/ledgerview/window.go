// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// WindowBefore returns a bounded window ending before seq, with the run's full
// incremental summary. Old history stays on disk; this fallback scans it with
// bounded decoding rather than populating an unbounded index of line offsets.
// A replaced or rewritten source is rejected before and after the scan: new
// events cannot be mixed with the published run context and complete totals.
func WindowBefore(root string, r *Run, seq uint64) (*Run, error) {
	if !validRunID(r.ID) {
		return nil, os.ErrNotExist
	}
	f, err := os.OpenFile(filepath.Join(root, r.ID, "events.jsonl"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, os.ErrNotExist
	}
	const changedSource = "record changed; reload before opening older lines"
	if rewritten(idOf(fi), r.file, r.file.size) {
		return nil, errors.New(changedSource)
	}
	br := bufio.NewReaderSize(io.LimitReader(f, fi.Size()), 64<<10)
	st := newRunState(r.ID, "")
	var off int64
	for {
		raw, size, err := boundedLine(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, fmt.Errorf("line at %d: longer than %d bytes", off, maxLineBytes)
		}
		if raw != nil {
			if e, _, decodeErr := decodeLine(raw[:len(raw)-1]); decodeErr != nil {
				return nil, decodeErr
			} else {
				if e.Seq >= seq {
					break
				}
				e.off = off
				if e.blob != "" {
					resolveBlob(filepath.Join(root, r.ID), &e)
				}
				st.take(e)
			}
		}
		off += size
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if rewritten(idOf(after), r.file, r.file.size) {
		return nil, errors.New(changedSource)
	}
	out := *r
	out.Events = st.b.Events
	out.memo = &runMemo{}
	out.st = nil
	return &out, nil
}
