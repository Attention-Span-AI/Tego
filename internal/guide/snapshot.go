// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
)

const (
	maxAgentChecks      = 32
	maxAgentCheckBytes  = 32 << 20
	maxAgentRecordBytes = 8 << 20
	maxSnapshotCache    = 256
	maxAgentAnchorBytes = 4 << 20
)

// recordStamp includes ctime as well as inode identity, size and mtime. The
// content digest below also prevents a cached verdict surviving an mmap edit.
type recordStamp struct {
	Dev, Ino     uint64
	Size         int64
	Mtime, Ctime syscall.Timespec
}

func stamp(info os.FileInfo) recordStamp {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return recordStamp{}
	}
	return recordStamp{uint64(s.Dev), s.Ino, s.Size, s.Mtim, s.Ctim}
}
func pathStamp(path string) (recordStamp, error) {
	i, err := os.Lstat(path)
	if err != nil {
		return recordStamp{}, err
	}
	if !i.Mode().IsRegular() {
		return recordStamp{}, errors.New("record is not a regular file")
	}
	return stamp(i), nil
}

type snapshotKey struct {
	Path, Anchor, Head string
	File               recordStamp
	Content            [32]byte
}
type snapshotValue struct {
	ended   bool
	verdict verdict
	at      time.Time
}

// Setup and the dashboard share this bounded record-verification cache. A hit
// still requires a pinned read and the current anchor head, never just a run id.
var snapshots = struct {
	sync.Mutex
	entries map[snapshotKey]snapshotValue
}{entries: make(map[snapshotKey]snapshotValue)}

func (f *facts) checkSnapshot(r *run) verdict {
	unknown := func(why string) verdict { return verdict{err: errors.New(why)} }
	if err := f.ctx.Err(); err != nil {
		return unknown("not checked yet: verification time budget ended")
	}
	if f.in.Anchor == "" {
		return unknown("the chain anchor could not be named")
	}
	if f.agentChecks >= maxAgentChecks || f.agentBytes >= maxAgentCheckBytes {
		return unknown("not checked yet: page verification budget reached")
	}
	f.agentChecks++
	path := filepath.Join(r.dir, ledger.EventsFile)
	file, err := ledger.OpenRegular(path)
	if err != nil {
		return unknown("record could not be opened for checking")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return unknown("record identity could not be checked")
	}
	before := stamp(info)
	if before != r.stamp {
		return unknown("record changed between discovery and verification; refresh and check it again")
	}
	if info.Size() > maxAgentRecordBytes || info.Size() > int64(maxAgentCheckBytes-f.agentBytes) {
		return unknown("not checked yet: record exceeds page verification byte budget; use tego events " + r.id + " --verify")
	}
	data, err := io.ReadAll(io.LimitReader(file, info.Size()))
	f.agentBytes += len(data)
	if err != nil || int64(len(data)) != info.Size() {
		return unknown("record could not be read within the verification byte budget")
	}
	// Metadata and verdict are derived from this immutable byte slice. No path is
	// reopened to get displayed fields after these bytes have passed their check.
	end := bytes.IndexByte(data, '\n')
	if end < 0 {
		end = len(data)
	}
	if sha256.Sum256(data[:end]) != r.first {
		return unknown("record changed between discovery and verification; refresh and check it again")
	}
	f.readAgentAnchor()
	if f.anchorErr != nil {
		return unknown("the chain anchor could not be read: " + errText(f.anchorErr))
	}
	ah := f.anchorHeads[r.id]
	if ah.Err != nil {
		return unknown("the chain anchor could not be read: " + errText(ah.Err))
	}
	head, present := ah.Head, ah.OK
	key := snapshotKey{path, f.in.Anchor, head, before, sha256.Sum256(data)}
	snapshots.Lock()
	cached, hit := snapshots.entries[key]
	snapshots.Unlock()
	v := cached.verdict
	ended := cached.ended
	if !hit || time.Since(cached.at) > 15*time.Second {
		w := chaincheck.NewWalk(r.id, true)
		var verr error
		for line, scanErr := range chaincheck.ScanLines(bytes.NewReader(data)) {
			if err := f.ctx.Err(); err != nil {
				return unknown("not checked yet: verification time budget ended")
			}
			stop, e := w.Step(line, scanErr)
			if e != nil {
				verr = e
				break
			}
			if stop {
				break
			}
		}
		if verr == nil {
			verr = w.Finish()
		}
		if verr == nil {
			next, e := w.Anchor(chaincheck.AnchorHead{Head: head, OK: present}, true)
			verr = e
			if next == chaincheck.AnchorAwait {
				return unknown("the ended run has no chain anchor; refresh if it just ended, otherwise inspect tego events " + r.id + " --verify")
			}
		}
		v = verdict{v: ledger.VerdictOf(w.Report(), verr), err: verr}
		ended = w.Report().Ended
		// An unanchored live chain is not checked evidence for inventory ticks.
		if v.v == ledger.Verified && !w.Report().Anchored {
			return unknown("the run has no chain anchor yet; check it again after it ends")
		}
		if v.v == ledger.Verified {
			snapshots.Lock()
			if len(snapshots.entries) >= maxSnapshotCache {
				clear(snapshots.entries)
			}
			snapshots.entries[key] = snapshotValue{ended: ended, verdict: v, at: time.Now()}
			snapshots.Unlock()
		}
	}
	after, err := file.Stat()
	if err != nil || stamp(after) != before {
		return unknown("record changed during verification; refresh and check it again")
	}
	named, err := pathStamp(path)
	if err != nil || named != before {
		return unknown("record changed during verification; refresh and check it again")
	}
	if err := f.ctx.Err(); err != nil {
		return unknown("not checked yet: verification time budget ended")
	}
	if v.v == ledger.Verified {
		event, e := record.Decode(data[:end])
		if e != nil {
			return unknown("checked run start could not be read")
		}
		var start record.RunStartPayload
		if e := event.DecodePayload(&start); e != nil {
			return unknown(fmt.Sprintf("checked run start could not be read: %v", e))
		}
		r.start, r.started = start, event.TS
		// The ended status comes from the same checked bytes, never the old tail.
		if ended {
			r.state = ledger.StateEnded
		} else {
			r.state = ledger.StateRunning
		}
	}
	return v
}

// checkAgents spends at most the remaining page budget; every skipped record
// remains visible as recorded, not checked. Existing guide checks are reused.
func (f *facts) checkAgents() {
	if f.runs == nil {
		return
	}
	for _, r := range f.runs.all {
		if _, ok := f.verdicts[r.id]; ok {
			continue
		}
		if f.agentChecks >= maxAgentChecks || f.agentBytes >= maxAgentCheckBytes || f.ctx.Err() != nil {
			break
		}
		f.verify(r)
	}
}

// readAgentAnchor takes one bounded anchor snapshot for the whole load rather
// than scanning an ever-growing chain.log again for every run or cache hit.
func (f *facts) readAgentAnchor() {
	if f.anchorRead {
		return
	}
	f.anchorRead = true
	file, err := ledger.OpenAnchorReader(f.in.Anchor)
	if err != nil {
		f.anchorErr = err
		return
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		f.anchorErr = err
		return
	}
	if info.Size() > maxAgentAnchorBytes {
		f.anchorErr = errors.New("anchor exceeds the 4 MiB page budget; use tego events with --verify")
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, info.Size()))
	if err != nil || int64(len(data)) != info.Size() {
		f.anchorErr = errors.New("anchor could not be read within the page budget")
		return
	}
	after, err := file.Stat()
	named, nerr := pathStamp(f.in.Anchor)
	if err != nil || nerr != nil || stamp(info) != stamp(after) || stamp(info) != named {
		f.anchorErr = errors.New("anchor changed during checking; refresh and check again")
		return
	}
	if err := f.ctx.Err(); err != nil {
		f.anchorErr = err
		return
	}
	ids := make([]string, 0, len(f.runs.all))
	for _, r := range f.runs.all {
		ids = append(ids, r.id)
	}
	f.anchorHeads = chaincheck.AnchorHeads(bytes.NewReader(data), ids)
}
