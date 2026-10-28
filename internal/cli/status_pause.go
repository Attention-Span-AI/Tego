// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pauseFact is a live run's pause as tego status shows it, read from what the dashboard reads: the launcher's
// last pause line in the ledger (internal/control/ledgerview LiveFacts.Paused) and the request its overlay holds
// (internal/control/runact PauseRequest).
type pauseFact struct {
	// Paused is the launcher's last pause line: run-paused, or resume-failed (still frozen), with no run-resumed
	// after it. A pause the launcher has not confirmed is not Paused.
	Paused bool
	// Pending is "pause" or "resume" while the overlay asks one with a serial above the last line's, which the
	// launcher answers within about half a second; "" otherwise.
	Pending string
}

// state is the STATE column for a run in st: "paused" for one held frozen, "pausing" or "resuming" while the
// launcher has yet to answer a request, the derived state otherwise. A paused run records nothing, so its derived
// state turns stalled once stall_after has passed; it still reads paused, which is why it is idle.
func (p pauseFact) state(st status.State) string {
	if !live(st) {
		return string(st)
	}
	switch {
	case p.Pending == pendPause:
		return "pausing"
	case p.Pending == pendResume:
		return "resuming"
	case p.Paused:
		return "paused"
	}
	return string(st)
}

// The words of pauseFact.Pending.
const (
	pendPause  = "pause"
	pendResume = "resume"
)

// live reports whether st is a state of a run its launcher still holds.
func live(st status.State) bool {
	return st != status.Done && st != status.Lost && st != status.NeverStarted
}

// runPauses is the pause of each snapshot whose launcher holds it and that has no run_end, by run id; a run it
// cannot read the pause of, or that never was paused, is left out (not paused). It reads the ledger of live runs only.
func runPauses(root string, snaps []*status.Snapshot) map[string]pauseFact {
	out := map[string]pauseFact{}
	for _, s := range snaps {
		if !s.LockHeld || s.Ended || !live(s.St) {
			continue
		}
		if p := readPause(filepath.Join(root, s.Run), s.Run); p != (pauseFact{}) {
			out[s.Run] = p
		}
	}
	return out
}

// readPause is run's pause from its directory: the last pause line in the ledger and the overlay's last pause or
// resume request.
func readPause(dir, run string) pauseFact {
	why, confirmed := lastPauseLine(filepath.Join(dir, ledger.EventsFile))
	p := pauseFact{Paused: why == record.GapRunPaused || why == record.GapResumeFailed}
	o, err := liveblock.Read(dir, run)
	if err != nil {
		return p // no overlay (never paused or blocked), or one that cannot be read: the ledger's word stands
	}
	var asked uint64
	for _, c := range o.Changes {
		if c.Control() {
			asked = c.Serial
		}
	}
	if asked > confirmed && o.Paused != p.Paused {
		p.Pending = map[bool]string{true: pendPause, false: pendResume}[o.Paused]
	}
	return p
}

// lastPauseLine is the why and overlay serial of the last gap line in the ledger at path that records a pause or a
// resume (record.GapPayload.LiveControl, what=enforce); "" and 0 when there is none or the file cannot be read.
func lastPauseLine(path string) (why string, serial uint64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer func() { _ = f.Close() }() // read-only
	rd := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := rd.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than the buffer: a blob-split field keeps live_control lines short, so it is not one.
			if _, err := skipLine(rd); err != nil {
				return why, serial
			}
			continue
		}
		if err != nil {
			return why, serial // no complete line left: one still being written is not read
		}
		if !bytes.Contains(line, []byte(`"live_control"`)) {
			continue
		}
		e, err := record.Decode(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil || e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if e.DecodePayload(&p) != nil || p.What != record.GapEnforce || p.LiveControl == nil {
			continue
		}
		switch p.Why {
		case record.GapRunPaused, record.GapRunResumed, record.GapPauseFailed, record.GapResumeFailed:
			why, serial = p.Why, p.LiveControl.Serial
		}
	}
}
