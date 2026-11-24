// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

// ScanState carries the one checked reader's answer, not data supplied by a view.
// The fields stay private so a surface cannot invent a successful scan.
type ScanState struct {
	read result.ReadResult
	err  error
}

// ReadScan uses the shared strict reader; it never collects or starts a process.
// Views may pass this to Compute and use Key to invalidate their guide cache.
func ReadScan(home string, uid int, boot string, now time.Time) *ScanState {
	if now.IsZero() {
		now = time.Now()
	}
	r, e := result.Read(home, uint32(uid), boot, now)
	return &ScanState{read: r, err: e}
}

// Key includes checked file identity and freshness, so replacement or a time
// boundary invalidates a view's guide even while the ledger is unchanged.
func (s *ScanState) Key() string {
	if s == nil {
		return ""
	}
	if s.err != nil {
		return scanError(s.err)
	}
	return s.read.Identity + "/" + s.read.Freshness + "/" + strconv.FormatUint(uint64(s.read.Snapshot.As.Recipient), 10)
}
func scanError(e error) string {
	switch {
	case errors.Is(e, os.ErrNotExist):
		return "No saved scan. Run tego scan from your project folder."
	case errors.Is(e, result.ErrMode):
		return "The saved scan could not be read: scan directory must have mode 0700. Run chmod 700 ~/.tego/scan, then tego scan from your project folder."
	default:
		return "The saved scan could not be read: invalid, unsafe or unavailable result. Run tego scan from your project folder."
	}
}
func (f *facts) findByScan() bool {
	in := f.in
	r := in.Scan
	if r == nil {
		r = ReadScan(in.Home, in.UID, in.Host.BootID, in.Now)
	}
	reason := ""
	if r.err != nil {
		reason = scanError(r.err)
	} else {
		s := r.read.Snapshot
		f.scanGaps(s)
		switch {
		case r.read.Freshness != "fresh":
			switch r.read.Freshness {
			case "stale":
				reason = "The saved scan is older than five minutes."
			case "another-boot":
				reason = "The saved scan is from another boot."
			case "future":
				reason = "The saved scan has a future finish time."
			default:
				reason = "The saved scan's boot or time could not be checked."
			}
		case s.Status == "failed":
			reason = "The saved scan failed."
		default:
			// An unreadable source cannot invalidate a positive observation from
			// another source. This ticks find, never completeness (ADR 0145 (6)).
			if len(ScanAgents(s, uint32(in.UID), filepath.Join(in.Home, ".tego", "scan", "last.json"))) > 0 {
				f.set(StepFind, Done, "found by scan at "+s.Finished.UTC().Format(time.RFC3339)+" (any program running as you can change it)", filepath.Join(in.Home, ".tego", "scan", "last.json"))
				return true
			}
			reason = "The saved scan found no running or installed candidate for you."
			if s.Status == "partial" {
				reason = "The saved scan is partial and found no running or installed candidate for you."
			}
		}
		reason += " Run tego scan from your project folder."
	}
	f.notKnown = append(f.notKnown, reason)
	return false
}

// scanGaps keeps partial coverage visible even when independent evidence ticks
// find. All words are fixed codes or checked paths/pids from the strict reader.
func (f *facts) scanGaps(s result.Snapshot) {
	if s.Counts.UnreadablePrograms > 0 {
		pids := make([]string, len(s.UnreadableProgramPIDs))
		for n, pid := range s.UnreadableProgramPIDs {
			pids[n] = strconv.Itoa(pid)
		}
		f.notKnown = append(f.notKnown, "The saved scan could not read the program files of "+strconv.Itoa(s.Counts.UnreadablePrograms)+" of your processes; pids: "+strings.Join(pids, ", ")+". "+result.UnreadableProgramsWarning)
	}
	for _, src := range s.Sources {
		if src.State != "not-read" && src.State != "partial" {
			continue
		}
		where := "kind " + src.Kind + " source"
		if src.Locator != nil {
			where += " " + strconv.Quote(*src.Locator)
		}
		f.notKnown = append(f.notKnown, "The saved scan could not fully read "+where+"; reason "+src.Reason+".")
	}
	if len(s.Limits) > 0 {
		f.notKnown = append(f.notKnown, "The saved scan stopped at "+strings.Join(s.Limits, ", ")+"; remaining scope is unknown.")
	}
}
