// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// PinDir is where a build pins its maps, one directory per bpf_hash (docs/p0/enforce-cgroup-observe.md §3).
const PinDir = "/sys/fs/bpf/tego"

// Pinned names of the capture ring buffer and its lost counter inside a build's map directory. The
// ring buffer is capture's own and not the record's: two readers on one ring would each have to skip the
// other's records (§3's "Chunk ring buffer" row).
//
// They are the maps' ELF names and nothing else. Every map in bpf/include/maps.h is LIBBPF_PIN_BY_NAME, and
// a collection loaded with MapOptions.PinPath pins each one at <PinPath>/<name> — LoadCollection below and
// the tier-2 loader alike — so a second spelling here opens a path no loader creates. "capture_events" and
// "lost" were exactly that.
const (
	// CaptureEventsMapName is the capture ring outer, each run's plaintext-chunk ring at its slot.
	CaptureEventsMapName = bpf.MapCaptureEvents
	// LostMapName is capture's own per-run counter of failed ring-buffer reserves. It was the record's
	// tego_lost, which both mechanisms incremented, so each reported the other's drops as its own gap.
	LostMapName = bpf.MapCaptureLost
)

// ErrNoPinDir is LoadCollection over a build whose pin directory does not exist. The directory is the tier-2
// backend's to create at Prepare and to remove when its last launcher leaves (docs/p0/enforce-cgroup-observe.md
// §5 R14); a capture object pinned into one this package made would outlive every run with nothing to
// remove it.
var ErrNoPinDir = errors.New("uprobe: the build has no pin directory")

// LoadCollection loads the capture object with its maps pinned under a build's directory, once per run, after
// the tier-2 backend has pinned the build's shared maps. Every map the object declares is shared by name with
// whatever tier 2 already pinned, so the run set the probes filter on is the same one the cgroup programs
// write (R9).
//
// A map that is already pinned keeps the size it was pinned with: the pinned map is authoritative while it
// exists, and cilium/ebpf refuses a spec that disagrees with it (ErrMapIncompatible) for the whole collection.
// No ring is sized here: each run's rings are the tier-2 backend's to make at Prepare (ADR 0026 (1)).
//
// It returns bpf.ErrNotGenerated when this binary was built without the compiled objects, which callers
// turn into a mechanism-unavailable gap, never a panic.
func LoadCollection(pinRoot, bpfHash string) (*ebpf.Collection, error) {
	dir := mapDir(pinRoot, bpfHash)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNoPinDir, dir)
	}
	spec, compact, err := bpf.LoadAdoption(bpf.ObjectUprobeSSL)
	if err != nil {
		return nil, err
	}
	multi := features.HaveBPFLinkUprobeMulti() == nil
	selectSSLPrograms(spec, multi)
	if compact {
		applyPinnedSizes(spec, dir)
		if coll, ok := adoptPrograms(spec, dir, filepath.Join(buildDir(pinRoot, bpfHash), progDir)); ok {
			return coll, nil
		}
		// An adoption description has no instructions or BTF. A cold or
		// incomplete set of pins needs the ordinary complete object.
		spec, err = bpf.Load(bpf.ObjectUprobeSSL)
		if err != nil {
			return nil, err
		}
		selectSSLPrograms(spec, multi)
	}
	// cilium/ebpf opens a map that is pinned and creates and pins one that is not, and between the two a
	// concurrent first run of the build can pin the same name: this load's pin then fails with EEXIST, and the
	// run was refused [capture-unavailable] (TestTier2ConcurrentRunsOfOneBuild's round of 2 on a starved guest).
	// The name is now pinned, so the next attempt opens it (bpf.PinAttempts bounds how many it can take).
	for attempt, attempts := 1, bpf.PinAttempts(spec); ; attempt++ {
		coll, err := loadSSLCollection(spec, func(s *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			return loadCollection(s, dir, filepath.Join(buildDir(pinRoot, bpfHash), progDir))
		})
		if err == nil || !errors.Is(err, os.ErrExist) || attempt >= attempts {
			return coll, err
		}
	}
}

// Optional multi programs never prevent the ordinary capture object loading.
// The feature probe is not a promise that this kernel's verifier accepts the
// complete dispatcher; a load failure retries only the required programs.
//
// A pin race (EEXIST) is not such a failure: it goes back to LoadCollection, which retries the whole spec. Taken
// as one, it left the run without the dispatchers for its life, and the run then refused the multi pair another
// run of the build had placed on a library, a capture gap for every process of it there (capture-1).
func loadSSLCollection(spec *ebpf.CollectionSpec,
	load func(*ebpf.CollectionSpec) (*ebpf.Collection, error)) (*ebpf.Collection, error) {
	coll, err := load(spec)
	if err == nil || errors.Is(err, os.ErrExist) || spec.Programs[bpf.ProgSSLMultiEnter] == nil {
		return coll, err
	}
	fallback := spec.Copy()
	selectSSLPrograms(fallback, false)
	return load(fallback)
}

func selectSSLPrograms(spec *ebpf.CollectionSpec, multi bool) {
	if !multi {
		delete(spec.Programs, bpf.ProgSSLMultiEnter)
		delete(spec.Programs, bpf.ProgSSLMultiReturn)
	}
}

// loadCollection is one attempt of LoadCollection: the pinned maps' sizes, then the pinned programs adopted or
// the object loaded and its programs pinned.
func loadCollection(spec *ebpf.CollectionSpec, dir, progs string) (*ebpf.Collection, error) {
	applyPinnedSizes(spec, dir)
	if coll, ok := adoptPrograms(spec, dir, progs); ok {
		return coll, nil
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: dir},
	})
	if err != nil {
		return nil, fmt.Errorf("uprobe: load %s: %w", bpf.ObjectUprobeSSL, err)
	}
	// The programs are pinned with the build's own, so the build's next run adopts them rather than loading
	// and verifying them again (about 20 ms a run on 6.17). A pinned program without a link costs the host
	// nothing, and it goes with the build (ADR 0022). Only a build whose program directory exists, which the
	// tier-2 backend makes: this package creates nothing under a build it does not own. A pin that fails (a
	// concurrent first run pinned first) leaves this run with its own programs, which work the same: a shared
	// multi pair placed with either run's dispatchers is adopted by the other (sameProgram).
	if st, err := os.Stat(progs); err == nil && st.IsDir() {
		for name, p := range coll.Programs {
			_ = p.Pin(filepath.Join(progs, name))
		}
	}
	return coll, nil
}

// applyPinnedSizes keeps the pinned maps authoritative for each run's ring sizes.
func applyPinnedSizes(spec *ebpf.CollectionSpec, dir string) {
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinByName {
			continue
		}
		if size, ok := pinnedMaxEntries(filepath.Join(dir, name)); ok {
			m.MaxEntries = size
		}
	}
}

// progDir is the build's program pin directory, beside maps (enforce/cgroup's pin layout).
const progDir = "progs"

// buildDir is a build's pin directory.
func buildDir(pinRoot, bpfHash string) string {
	if pinRoot == "" {
		pinRoot = PinDir
	}
	return filepath.Join(pinRoot, bpfHash)
}

// adoptPrograms opens the capture programs a previous run of the build pinned, with the build's pinned maps,
// and reports false, keeping nothing open, unless every program the spec declares is pinned, of the spec's
// type, and reads no map but the build's pinned ones and its own global sections. Anything less is loaded
// afresh (enforce/cgroup's adoptObject asks the same of the build's own programs).
func adoptPrograms(spec *ebpf.CollectionSpec, maps, progs string) (*ebpf.Collection, bool) {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}, Maps: map[string]*ebpf.Map{}}
	fail := func() (*ebpf.Collection, bool) {
		coll.Close()
		return nil, false
	}
	if len(spec.Programs) == 0 {
		return fail()
	}
	ids := map[ebpf.MapID]bool{}
	var sections []*ebpf.MapSpec
	for name, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinByName {
			sections = append(sections, ms)
			continue
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(maps, name), nil)
		if err != nil {
			return fail()
		}
		coll.Maps[name] = m
		info, err := m.Info()
		if err != nil {
			return fail()
		}
		id, ok := info.ID()
		if !ok {
			return fail()
		}
		ids[id] = true
	}
	for name, ps := range spec.Programs {
		p, err := ebpf.LoadPinnedProgram(filepath.Join(progs, name), nil)
		if err != nil {
			return fail()
		}
		coll.Programs[name] = p
		if p.Type() != ps.Type {
			return fail()
		}
		info, err := p.Info()
		if err != nil {
			return fail()
		}
		used, ok := info.MapIDs()
		if !ok {
			return fail()
		}
		for _, id := range used {
			if !ids[id] && !ownSection(id, sections) {
				return fail()
			}
		}
	}
	return coll, true
}

// ownSection reports whether a map a pinned program reads is one of its own global-variable sections, which a
// load makes per program set and never pins: matched by shape, as enforce/cgroup matches them.
func ownSection(id ebpf.MapID, sections []*ebpf.MapSpec) bool {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return false
	}
	defer func() { _ = m.Close() }()
	for _, ms := range sections {
		if m.Type() == ms.Type && m.KeySize() == ms.KeySize && m.ValueSize() == ms.ValueSize &&
			m.MaxEntries() == ms.MaxEntries {
			return true
		}
	}
	return false
}

// pinnedMaxEntries reports a pinned map's max_entries, and whether there was a readable pin at all.
func pinnedMaxEntries(path string) (uint32, bool) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, false
	}
	defer func() { _ = m.Close() }()
	return m.MaxEntries(), true
}

// mapDir is a build's pinned map directory.
func mapDir(pinRoot, bpfHash string) string {
	if pinRoot == "" {
		pinRoot = PinDir
	}
	return filepath.Join(pinRoot, bpfHash, "maps")
}

// openPinned opens the capture ring outer and the per-run lost counter a build already pinned, from which the
// source opens its own run's ring and counter by the run's slot (Uprobe.openRing). The maps survive in the
// kernel through their pins; what Close releases is this process's own file descriptors.
//
// The lost counter is required: every object declares tego_capture_lost beside the capture ring outer, and
// draining a ring without it would make every chunk the kernel dropped a silence where §8 I4 and I7 require a
// ring-buffer-drop gap.
func openPinned(pinRoot, bpfHash string) (rings, lost *ebpf.Map, err error) {
	dir := mapDir(pinRoot, bpfHash)
	rings, err = ebpf.LoadPinnedMap(filepath.Join(dir, CaptureEventsMapName), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, nil, fmt.Errorf("uprobe: open pinned capture ring outer %s/%s: %w", dir, CaptureEventsMapName, err)
	}
	lost, err = ebpf.LoadPinnedMap(filepath.Join(dir, LostMapName), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		_ = rings.Close()
		return nil, nil, fmt.Errorf("uprobe: open pinned lost counter %s/%s: %w", dir, LostMapName, err)
	}
	return rings, lost, nil
}

// slotLost reads one run's capture lost counter, its slot of the build's per-run array.
type slotLost struct {
	m    *ebpf.Map
	slot uint32
}

// Lost reads the run's count.
func (p *slotLost) Lost() (uint64, error) {
	n, err := bpf.SlotCount(p.m, p.slot)
	if err != nil {
		return 0, fmt.Errorf("uprobe: read lost counter: %w", err)
	}
	return n, nil
}

// NewAttacher returns the production Attacher over a loaded capture collection. One binary's probes are
// placed back to back, so the executable handle is opened once for the run of them rather than once per
// probe (R1-R3 ask for up to six on a file).
//
// Close releases the executable handle this attacher holds. The links themselves belong to the attach
// cache, which closes them at refcount zero (R8, I9).
func NewAttacher(coll *ebpf.Collection) *EBPFAttacher {
	return &EBPFAttacher{coll: coll}
}

// EBPFAttacher places uprobes through cilium/ebpf. It is the one part of this package that needs
// privilege; everything else runs in an ordinary unit test.
type EBPFAttacher struct {
	coll *ebpf.Collection

	mu   sync.Mutex
	path string
	exec *link.Executable
}

// Attach places one probe and returns the link that holds it.
//
// The offset comes from this package's own ELF read rather than from cilium/ebpf's symbol lookup:
// UprobeOptions.Address is the file offset a uprobe attaches at, the same value link would compute, and
// supplying it is what lets the per-binary offset cache spare every process after the first an ELF parse.
func (a *EBPFAttacher) Attach(path string, p Probe) (io.Closer, error) {
	prog, ok := a.coll.Programs[p.Program]
	if !ok {
		return nil, fmt.Errorf("%w: no program %q in %s", ErrAttachFailed, p.Program, bpf.ObjectUprobeSSL)
	}
	ex, err := a.executable(path)
	if err != nil {
		return nil, err
	}
	opts := &link.UprobeOptions{Address: p.Offset}
	var l link.Link
	if p.Return {
		l, err = ex.Uretprobe(p.Symbol, prog, opts)
	} else {
		l, err = ex.Uprobe(p.Symbol, prog, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s on %s: %w", ErrAttachFailed, p, path, err)
	}
	return l, nil
}

// executable opens a binary and holds the handle for the probes that follow on the same path.
//
// Only the most recent path is held. A link.Executable keeps the path it was opened from and the kernel
// resolves that path again for every probe, so a handle is worth keeping only while the path is. Every path
// here is the /proc/self/fd link of the descriptor the caller holds on the candidate (R7), which a later
// candidate may reuse by number: the handle carries nothing but the path, and the kernel resolves the link to
// whatever that descriptor holds at the probe. Keyed by path and never evicted, this would grow by one entry
// per candidate for the life of the run, to buy a reuse that only ever spans one binary's consecutive probes.
func (a *EBPFAttacher) executable(path string) (*link.Executable, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exec != nil && a.path == path {
		return a.exec, nil
	}
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrAttachFailed, path, err)
	}
	a.path, a.exec = path, ex
	return ex, nil
}

// Close forgets the executable handle. The links stay open: they belong to the attach cache, which closes
// them when the last process mapping a binary exits (R8).
func (a *EBPFAttacher) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.path, a.exec = "", nil
	return nil
}
