// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// WindowBefore returns a bounded window ending before seq, with the run's full
// incremental summary. Old history stays on disk; this fallback scans it with
// bounded decoding rather than populating an unbounded index of line offsets.
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
		if raw != nil {
			if e, _, ok := decodeLine(raw[:len(raw)-1]); ok {
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
	out := *r
	out.Events = st.b.Events
	out.memo = &runMemo{}
	out.st = nil
	return &out, nil
}
