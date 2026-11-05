// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// linkedMisses holds the program executing through an active link, plus the link itself. Independent
// loaders can win the program pin and link pin races, so a program pin cannot identify that instance.
type linkedMisses struct {
	program   *ebpf.Program
	link      link.Link
	path      string
	linkID    link.ID
	programID ebpf.ProgramID
}

type programMisses []linkedMisses

type missCounter interface {
	LostCounter
	io.Closer
}

func (ps programMisses) Lost() (uint64, error) {
	var n uint64
	for _, p := range ps {
		// A replaced link or updated attachment invalidates the sampled window. Holding the old
		// descriptors prevents counter substitution but does not establish the new instance's coverage.
		info, err := p.link.Info()
		if err != nil {
			return 0, err
		}
		pinned, err := link.LoadPinnedLink(p.path, nil)
		if err != nil {
			return 0, err
		}
		pinInfo, err := pinned.Info()
		_ = pinned.Close()
		if err != nil {
			return 0, err
		}
		if info.Program != p.programID || pinInfo.ID != p.linkID || pinInfo.Program != p.programID {
			return 0, fmt.Errorf("shared tracing attachment changed: %s", p.path)
		}
		st, err := p.program.Stats()
		if err != nil {
			return 0, err
		}
		n += st.RecursionMisses
	}
	return n, nil
}

func (ps programMisses) Close() error {
	var err error
	for _, p := range ps {
		err = errors.Join(err, p.program.Close(), p.link.Close())
	}
	return err
}

func (r *Recorder) openMisses() (missCounter, error) {
	root := r.opts.PinRoot
	if root == "" {
		root = PinDir
	}
	var ps programMisses
	for _, name := range bpf.TracePrograms {
		path := filepath.Join(root, r.opts.BPFHash, "links", name)
		l, err := link.LoadPinnedLink(path, nil)
		_, optionalFunction := bpf.OptionalTracePrograms[name]
		_, optionalResult := bpf.ExecResultTracepoints[name]
		_, listenerResult := bpf.ListenerTracepoints[name]
		if (optionalFunction || optionalResult || listenerResult) && errors.Is(err, os.ErrNotExist) {
			// The loader omits optional hooks on unsupported kernels or when listener control is off.
			// A program pin with no link is not proof of an omitted hook; it may be an attachment we cannot resolve.
			if _, statErr := os.Stat(filepath.Join(root, r.opts.BPFHash, "progs", name)); errors.Is(statErr, os.ErrNotExist) {
				continue
			}
		}
		if err != nil {
			_ = ps.Close()
			return nil, fmt.Errorf("trampoline link for %s: %w", name, err)
		}
		info, err := l.Info()
		if err != nil {
			_ = l.Close()
			_ = ps.Close()
			return nil, fmt.Errorf("trampoline link info for %s: %w", name, err)
		}
		p, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			_ = l.Close()
			_ = ps.Close()
			return nil, fmt.Errorf("attached trampoline program for %s: %w", name, err)
		}
		ps = append(ps, linkedMisses{program: p, link: l, path: path, linkID: info.ID, programID: info.Program})
	}
	return ps, nil
}

func (r *Recorder) startMisses() {
	var err error
	if r.misses == nil && r.opts.BPFHash != "" {
		r.misses, err = r.openMisses()
	}
	if err == nil && r.misses != nil {
		r.missStart, err = r.misses.Lost()
	}
	if err != nil {
		r.gap(GapTrampolineCounterUnavailable, 1)
		r.logWarn("observe: shared tracing program miss counters unavailable", "err", err)
		if r.misses != nil {
			_ = r.misses.Close()
		}
		r.misses = nil
	}
}

func (r *Recorder) stopMisses() {
	if r.misses == nil {
		return
	}
	defer func() { _ = r.misses.Close() }() // descriptor cleanup; counter failures are handled below
	n, err := r.misses.Lost()
	if err != nil || n < r.missStart {
		r.gap(GapTrampolineCounterUnavailable, 1)
		r.logWarn("observe: shared tracing program miss counters unreadable", "err", err)
		return
	}
	if n > r.missStart {
		r.gap(GapTrampolineMiss, int64(n-r.missStart))
	}
}
