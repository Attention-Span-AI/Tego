// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() {
	register(cmdPause)
	register(cmdResume)
}

// codeNoPause is the diagnostic of a pause or a resume asked of a run whose launcher does not read one.
const codeNoPause = "no-pause"

// pauseConfirmWait bounds how long `tego pause` and `tego resume` wait for the launcher's line confirming the change.
// The launcher polls every half second and a freeze takes milliseconds, so two seconds is plenty when it works.
var pauseConfirmWait = 2 * time.Second

// cmdPause is `tego pause <run>`: it freezes a running run where it stands. The pause rides the run's live-block
// overlay (the file `tego block` and the dashboard write); the run's launcher, which owns the run's cgroup, freezes it
// (cgroup.freeze) within about half a second and records a gap run-paused line naming who asked. A paused run does
// no work: its processes neither run nor handle signals until `tego resume`. Its stall_after limit does not count
// the pause; its wall limit and a held ask's timeout keep counting. `tego stop` on a paused run thaws it first, so it
// ends as quickly as a running one. It works on a tego watch run too, since a freeze needs no contract decision. A
// process inside a tego run is refused (exit 1), as is a run that has ended.
func cmdPause() Command {
	return Command{
		Name:    "pause",
		Summary: "freeze a running run where it stands, until tego resume",
		Usage:   "<run>",
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			return pauseChange(ctx, "pause", true, fs, stdout, stderr)
		},
	}
}

// cmdResume is `tego resume <run>`: it lets a run `tego pause` or the dashboard paused carry on from where it stood.
// It lifts the pause only; every live block stays. The launcher records a gap run-resumed line.
func cmdResume() Command {
	return Command{
		Name:    "resume",
		Summary: "let a paused run carry on",
		Usage:   "<run>",
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			return pauseChange(ctx, "resume", false, fs, stdout, stderr)
		},
	}
}

// pauseChange is the body of pause and resume: find the run, refuse a governed caller and an ended run, write the
// change under the overlay's lock, and wait a moment for the launcher's confirming line.
func pauseChange(ctx context.Context, name string, on bool, fs *flag.FlagSet, stdout, stderr io.Writer) int {
	if fs.NArg() != 1 {
		message(stderr, "", 0, 0, "tego "+name+": exactly one run id", codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	if refuseGoverned(name, stderr) { // a governed agent may neither stop a run's work nor start it again
		return identity.ExitFinding
	}
	dir, run, code := blockRun(name, fs.Arg(0), stderr)
	if code != identity.ExitOK {
		return code
	}
	held, _, err := runlock.ProbeLock(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	if !held {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s is not running, so there is nothing to %s", name, run, name), codeNotRunning)
		return identity.ExitFinding
	}
	// Only a launcher that marked that it reads a pause gets one (liveblock.TakesControl). One that predates the
	// pause refuses the whole live-block file once it lists one: the pause would never take, and every later tego
	// block of the run would stay waiting. Nothing is written for it.
	if !liveblock.TakesControl(dir) {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %s cannot be paused: an older Tego started it, it was adopted, "+
			"or it has no cgroup of its own; tego stop %s ends it", name, run, run), codeNoPause)
		return identity.ExitFinding
	}
	by := liveblock.By("cli")
	from := eventsSize(dir) // the launcher's line comes after this
	var changed bool
	o, err := liveblock.Update(ctx, dir, run, func(o *liveblock.Overlay) (bool, error) {
		if on {
			_, changed = o.Pause(by, time.Now())
		} else {
			_, changed = o.Resume(by, time.Now())
		}
		return changed, nil
	})
	if err != nil {
		message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
		return identity.ExitError
	}
	if !changed {
		word := map[bool]string{true: "already paused", false: "was not paused"}[on]
		fmt.Fprintf(stdout, "%s: %s\n", run, word)
		return identity.ExitOK
	}
	why, seq := awaitControl(ctx, dir, o.Serial, from, pauseConfirmWait)
	switch why {
	case record.GapRunPaused:
		fmt.Fprintf(stdout, "%s: paused (line #%d). Its processes are frozen where they stood; tego resume %s lets it carry on.\n", run, seq, run)
	case record.GapRunResumed:
		fmt.Fprintf(stdout, "%s: resumed (line #%d). It carries on from where it stood.\n", run, seq)
	case record.GapPauseFailed:
		fmt.Fprintf(stdout, "%s: pause asked, but the launcher could not freeze the run yet (line #%d), so it keeps running. "+
			"If the agent waits on a request, it freezes once that is answered; otherwise the launcher tries again "+
			"in a few seconds. tego resume %s withdraws the pause.\n", run, seq, run)
		return identity.ExitFinding
	case record.GapResumeFailed:
		fmt.Fprintf(stdout, "%s: resume asked, but the launcher could not thaw the run (line #%d), so it stays frozen; "+
			"the launcher tries again every half second, and tego stop %s still ends it.\n", run, seq, run)
		return identity.ExitFinding
	default:
		fmt.Fprintf(stdout, "%s: %s asked; the run's launcher has not confirmed it yet (it reads the request about every half second)\n",
			run, name)
	}
	return identity.ExitOK
}

// awaitControl waits at most wait for the run's ledger in dir to hold the launcher's line for the pause or resume of
// overlay serial (or a later one), and returns that line's why and seq; "" when none came in time. It reads only the
// lines appended after from, the ledger's size before the change was written, and each poll only what the last one
// had not read, so a long-lived run's ledger is never scanned whole.
func awaitControl(ctx context.Context, dir string, serial uint64, from int64, wait time.Duration) (string, uint64) {
	sc := controlScan{path: filepath.Join(dir, ledger.EventsFile), off: from, serial: serial}
	for deadline := time.Now().Add(wait); ; {
		if why, seq := sc.next(); why != "" {
			return why, seq
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return "", 0
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// eventsSize is the size of dir's ledger now (0 when it cannot be read): where awaitControl starts reading.
func eventsSize(dir string) int64 {
	st, err := os.Stat(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		return 0
	}
	return st.Size()
}

// controlScan reads a ledger's lines forward from off, a byte offset, for the launcher's line about a pause or a
// resume of serial or later. Each next reads only the complete lines appended since the last; a line still being
// written is left for the next call.
type controlScan struct {
	path     string
	off      int64
	serial   uint64
	why      string
	seq      uint64
	resynced bool
}

// next reads what was appended since the last call and returns the last matching line's why and seq so far.
func (sc *controlScan) next() (string, uint64) {
	f, err := os.Open(sc.path)
	if err != nil {
		return sc.why, sc.seq
	}
	defer func() { _ = f.Close() }() // read-only
	start := sc.off
	if !sc.resynced && start > 0 {
		start-- // from the byte before: the line it ends (normally just its newline) is skipped below
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return sc.why, sc.seq
	}
	rd := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := rd.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than the buffer: a blob-split field keeps live_control lines short, so it is not one.
			n, skipErr := skipLine(rd)
			start += int64(len(line)) + n
			if skipErr != nil {
				break
			}
			sc.off, sc.resynced = start, true
			continue
		}
		if err != nil {
			break // no complete line left: what remains is read next time
		}
		start += int64(len(line))
		if !sc.resynced && sc.off > 0 {
			sc.off, sc.resynced = start, true
			continue // the end of the line before off
		}
		sc.off, sc.resynced = start, true
		sc.match(line)
	}
	return sc.why, sc.seq
}

// match keeps line's why and seq when it is the launcher's line for serial or later.
func (sc *controlScan) match(line []byte) {
	if !bytes.Contains(line, []byte(`"live_control"`)) {
		return
	}
	e, err := record.Decode(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil || e.Kind != record.KindGap {
		return
	}
	var p record.GapPayload
	if e.DecodePayload(&p) != nil || p.What != record.GapEnforce || p.LiveControl == nil || p.LiveControl.Serial < sc.serial {
		return
	}
	sc.why, sc.seq = p.Why, e.Seq
}

// skipLine reads past the rest of a line longer than rd's buffer and returns how many bytes it read.
func skipLine(rd *bufio.Reader) (int64, error) {
	var n int64
	for {
		b, err := rd.ReadSlice('\n')
		n += int64(len(b))
		if !errors.Is(err, bufio.ErrBufferFull) {
			return n, err
		}
	}
}
