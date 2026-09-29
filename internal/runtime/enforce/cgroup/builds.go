// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// BuildInfo is what `tego doctor` shows of one tier-2 build on the bpf filesystem (ADR 0022 (8)): whether a
// launcher holds it, how long it has been idle, and what of it is pinned, so root sees every program and probe
// tego left and where to remove it.
type BuildInfo struct {
	Hash string `json:"hash"`
	// InUse says a launcher of the build holds its lock; Idle is then zero.
	InUse bool `json:"in_use"`
	// Idle is how long ago the last launcher out left, from the build lock's mtime; IdleS is the same in seconds.
	Idle  time.Duration `json:"-"`
	IdleS float64       `json:"idle_s"`
	// Programs and Links count the build's pinned programs and host-wide links.
	Programs int `json:"programs"`
	Links    int `json:"links"`
	// Runs names the runs whose cgroup links are pinned under the build (links/run-<id>, ADR 0020 (1)): runs a
	// launcher enforces now, and orphans no reaper or sweep has removed yet.
	Runs []string `json:"runs,omitempty"`
	// CaptureLibraries names the libraries whose capture probes are pinned under the build (ADR 0026 (7)), one
	// being detached included, and CaptureProbes counts those probes' links.
	CaptureLibraries []string `json:"capture_libraries,omitempty"`
	CaptureProbes    int      `json:"capture_probes"`
	// Rings counts the runs' rings the build holds (ADR 0026 (1)), and RingBytes what they charge against
	// bpf.ring_budget.
	Rings     int    `json:"rings"`
	RingBytes uint64 `json:"ring_bytes"`
	// Path is the build's pin directory, where root sees and removes all of it.
	Path string `json:"path"`
	// Planes are the decision plane's modes pinned for the build, each in its own directory beside Path
	// (<hash>-<mode>, enforce-plane R20); PlanePrograms and PlaneLinks count what they pin.
	Planes        []string `json:"planes,omitempty"`
	PlanePrograms int      `json:"plane_programs,omitempty"`
	PlaneLinks    int      `json:"plane_links,omitempty"`
	// Kept says why a build no launcher holds stays, which gc --builds does not change: KeptLive (a run it enforces
	// is alive) or KeptUnread (its run set cannot be read, ADR 0022 (5); KeptCause is what the read met), the two
	// reasons gc --builds' Force does not override; or KeptSweepFailed, with the error in KeptCause. It is the sweep's
	// that ran before the listing for a build that sweep kept past its linger, and otherwise (a build the sweep left
	// inside its linger, or did not name) the build's run set read at the listing, as Force reads it. Empty when the
	// run set is empty or there is none: then gc --builds removes the build.
	Kept      string `json:"kept,omitempty"`
	KeptCause string `json:"kept_cause,omitempty"`
	// Timer says the build's linger timer runs (ADR 0022 (3)), as its timer file names it (timerPID), TimerPID being
	// its pid. (8)'s bound of bpf.linger holds only while it does; without one the next run's Prepare, tego stop or
	// tego gc re-arms or removes the build once it is past its linger.
	Timer    bool `json:"timer"`
	TimerPID int  `json:"timer_pid,omitempty"`
	// MemlockBytes is what the kernel charges for the build's objects (ADR 0022 (8)), the memlock of their fdinfo:
	// every program and map pinned under the build and its plane directories, every program a pinned link attaches
	// and every map those programs use, each counted once by its id. The run rings, whose maps are reached through
	// an outer map only, are RingBytes. MemlockUnreported counts the objects the sum leaves out: a pin that could not
	// be opened, or an object whose fdinfo has no memlock line (fdinfoMemlock); a line that says 0, an empty LPM trie's,
	// is a 0 the kernel reported.
	MemlockBytes      uint64 `json:"memlock_bytes"`
	MemlockUnreported int    `json:"memlock_unreported,omitempty"`
}

// KeptSweepFailed is BuildInfo.Kept for a build the sweep could not look at; KeptCause holds the error.
const KeptSweepFailed = "the sweep could not look at it"

// keptText is BuildInfo.Kept and KeptCause for the sweep's state of a build no launcher holds.
func keptText(st BuildState) (kept, cause string) {
	switch st.Why {
	case whyLive:
		return KeptLive, ""
	case whyUnread:
		return KeptUnread, st.Cause
	case "", whyGone, whyBusy, whyLingering:
		return "", ""
	}
	return KeptSweepFailed, st.Why
}

// runSetKept is BuildInfo.Kept and KeptCause from the run set pinned at path, read as sweepBuild reads it once a
// build is past its linger or forced: kept while a run it enforces is alive or while it cannot be read; nothing kept
// when it is empty or there is none.
func runSetKept(live func(path, mount string) (bool, error), path, mount string) (kept, cause string) {
	switch alive, err := live(path, mount); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return KeptUnread, err.Error()
	case alive:
		return KeptLive, ""
	}
	return "", ""
}

// ListBuilds reads every build under the bpf filesystem, changing none: its pins, whether a launcher holds it,
// whether its timer runs, what its objects charge, and why a build no launcher holds is kept: from swept (the states
// of the sweep the caller ran just before, nil for none) for a build that sweep kept, and from the build's run set,
// read without deleting a row, for any other (BuildInfo.Kept). A hold is told by a non-blocking exclusive attempt on
// the build lock, let go at once, as the sweep tells it; a timer by its timer file and its process, never its lock
// (timerPID). It needs root; an unprivileged caller gets the error of the directory it could not read.
func ListBuilds(opts SweepOptions, swept []BuildState) ([]BuildInfo, error) {
	if opts.BPFFS == "" {
		opts.BPFFS = DefaultBPFFS
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if _, err := lockRootOf(opts.BPFFS, opts.StateDir); err != nil {
		return nil, err
	}
	base := filepath.Join(opts.BPFFS, pinRoot)
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cgroup: list builds under %s: %w", base, err)
	}
	d, err := openState(opts.BPFFS, opts.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	states := make(map[string]BuildState, len(swept))
	for _, st := range swept {
		states[st.Hash] = st
	}
	objects := opts.objects
	if objects == nil {
		objects = kernelObjects
	}
	live := opts.runSetLive
	if live == nil {
		live = pinnedRunSetLiveReadOnly
	}
	if opts.CgroupMount == "" {
		opts.CgroupMount = identity.SystemCgroupRoot
	}
	var out []BuildInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, _, plane := planeDirOf(e.Name()); plane {
			continue // listed with its build
		}
		pins, err := newPinLayout(opts.BPFFS, e.Name())
		if err != nil {
			continue
		}
		b := BuildInfo{Hash: e.Name(), Path: pins.Root, Programs: countEntries(pins.Progs)}
		roots := []string{pins.Root}
		for _, m := range planeModes {
			pl := newPlaneLayout(pins, e.Name(), m)
			if _, err := os.Stat(pl.Root); err != nil {
				continue
			}
			roots = append(roots, pl.Root)
			b.Planes = append(b.Planes, string(m))
			b.PlanePrograms += countEntries(pl.Progs)
			b.PlaneLinks += countEntries(pl.Links)
		}
		links, _ := os.ReadDir(pins.Links)
		for _, l := range links {
			if l.IsDir() && strings.HasPrefix(l.Name(), runLinksPrefix) {
				b.Runs = append(b.Runs, strings.TrimPrefix(l.Name(), runLinksPrefix))
				continue
			}
			b.Links++
		}
		b.RingBytes, b.Rings, _ = buildRings(pins.Maps)
		uprobes := filepath.Join(pins.Root, uprobePins)
		libs, _ := os.ReadDir(uprobes)
		for _, lib := range libs {
			b.CaptureLibraries = append(b.CaptureLibraries, lib.Name())
			b.CaptureProbes += countEntries(filepath.Join(uprobes, lib.Name()))
		}
		switch f, busy, err := lockBuildExclusiveNB(d, e.Name(), false); {
		case busy, err != nil && errors.Is(err, ErrBuildLock):
			b.InUse = true
		case err == nil:
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			var st unix.Stat_t
			if unix.Fstat(int(f.Fd()), &st) == nil {
				b.Idle = max(opts.Now().Sub(time.Unix(st.Mtim.Unix())).Round(time.Second), 0)
			}
			_ = f.Close()
		}
		b.IdleS = b.Idle.Seconds()
		if st, ok := states[e.Name()]; ok && !b.InUse && !st.Removed {
			b.Kept, b.KeptCause = keptText(st)
		}
		if !b.InUse && b.Kept == "" {
			b.Kept, b.KeptCause = runSetKept(live, filepath.Join(pins.Maps, ebpfbindings.MapRunSet), opts.CgroupMount)
		}
		b.TimerPID = timerPID(d, e.Name(), opts.timerProcess)
		b.Timer = b.TimerPID > 0
		b.MemlockBytes, b.MemlockUnreported = objects.memlock(roots)
		out = append(out, b)
	}
	return out, nil
}

// countEntries is how many names a directory holds, 0 when it cannot be read.
func countEntries(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(entries)
}
