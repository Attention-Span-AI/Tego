// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"syscall"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Hint is where a reader saw line seq of a run start in its events file: the byte offset of the line, and the file's
// device, inode and size when it read it. The dashboard's read model keeps it for every line it holds, so the event
// page can hand it on and FindAtIn need not decode every line before the one asked for.
type Hint struct {
	Off      int64
	Dev, Ino uint64
	Size     int64
}

// FindAtIn is FindIn with a hint of where line seq starts (from the dashboard's read model): it reads run_start (line
// 0) and the one line at h.Off instead of every line up to seq. The hint is never trusted: the file must be the one
// the hint names (device and inode) and no shorter than it was, h.Off must start a line, the line there must decode
// with seq and the run's id, and line 0 must be a run_start naming a contract file. On any mismatch (a file replaced,
// truncated and rewritten, or a hint from another run) it falls back to FindIn's scan, so a hint can make the lookup
// faster and never makes it pick another line. A write still goes through FindIn (rules.Service re-reads the line).
func FindAtIn(dir string, seq uint64, h Hint, g Guard) (*Found, error) {
	f, ok := foundAt(dir, seq, h)
	if !ok {
		return FindIn(dir, seq, g)
	}
	if f.Contract == "" {
		// The hint held and run_start names no contract file (a tego watch run): FindIn's scan would decode every line
		// up to seq only to say the same, on every load and live refresh of a long run's line page (r9 QG-1).
		return nil, ErrNoContract
	}
	f.Guard = g
	file, err := Read(f.Contract, g)
	if err != nil {
		return nil, err
	}
	f.Text, f.Mode = file.Text, file.Mode
	return f, nil
}

// foundAt reads run_start and the line at h.Off of dir's events file, as FindIn would have found them, and reports
// false whenever anything does not hold, for the caller to scan instead. A run_start that names no contract file
// leaves Contract "" on a Found that is otherwise whole: FindIn's answer for that line is ErrNoContract.
func foundAt(dir string, seq uint64, h Hint) (*Found, bool) {
	if h.Off < 0 || h.Off >= h.Size {
		return nil, false
	}
	ef, err := ledger.OpenRegular(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		return nil, false
	}
	defer func() { _ = ef.Close() }() // opened read-only
	fi, err := ef.Stat()
	if err != nil {
		return nil, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != h.Dev || st.Ino != h.Ino || fi.Size() < h.Size { //nolint:unconvert // Dev's type differs between platforms
		return nil, false
	}
	first, ok := lineAt(ef, 0)
	if !ok {
		return nil, false
	}
	start, err := record.Decode(first)
	if err != nil || start.Kind != record.KindRunStart {
		return nil, false
	}
	var p record.RunStartPayload
	if err := start.DecodePayload(&p); err != nil {
		return nil, false // FindIn's scan says what is wrong, in its words
	}
	f := &Found{Run: start.Run, Cwd: p.Cwd, Tier: p.Tier, RunCommandGrant: p.RunCommandGrant}
	if p.ContractSource != nil {
		f.Contract = p.ContractSource.Path
	}
	if h.Off == 0 {
		if start.Seq != seq {
			return nil, false
		}
		f.Event = start
		return f, true
	}
	// The byte before the hint must end a line, so the hint names a line's start, not the middle of one.
	var prev [1]byte
	if _, err := ef.ReadAt(prev[:], h.Off-1); err != nil || prev[0] != '\n' {
		return nil, false
	}
	line, ok := lineAt(ef, h.Off)
	if !ok {
		return nil, false
	}
	e, err := record.Decode(line)
	if err != nil || e.Seq != seq || e.Run != start.Run {
		return nil, false
	}
	f.Event = e
	return f, true
}

// lineAt is the terminated line that starts at off, without its "\n"; false for a line past ledger.MaxLineBytes, a
// line with no "\n" yet (a writer still writing it), or a read that fails.
func lineAt(r io.ReaderAt, off int64) ([]byte, bool) {
	br := bufio.NewReaderSize(io.NewSectionReader(r, off, ledger.MaxLineBytes+1), 16<<10)
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > ledger.MaxLineBytes {
			return nil, false
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, false
		}
		return bytes.TrimSuffix(line, []byte{'\n'}), true
	}
}
