// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// The ids the stand-in kernel gives the maps a capture program reads: the build's pinned run set and capture ring
// outer as this run opened them, the pinned pair a run placed its probes over before the build's maps were
// re-created, and each load's own global section.
const (
	buildRunSet, buildRings ebpf.MapID = 101, 102
	staleRunSet, staleRings ebpf.MapID = 201, 202
	loadSection             ebpf.MapID = 901
)

// buildMaps are the build's pinned maps as this run sees them (pinnedMapIDs).
var buildMaps = map[ebpf.MapID]bool{buildRunSet: true, buildRings: true}

// adoptionKernel stands in for what adopting a library's pinned probes asks of the kernel (loadPinnedProbe,
// pinnedLinkFacts, loadedFacts, programFacts, mapID): the links pinned at their paths, the facts of this run's
// programs and of every program by id, and the ids of this run's maps. coll is this run's capture collection, one
// program handle per name, and the build's pinned run set and ring outer with its own global section.
type adoptionKernel struct {
	links map[string]*pinnedStub
	own   map[*ebpf.Program]progFacts
	byID  map[ebpf.ProgramID]progFacts
	maps  map[*ebpf.Map]ebpf.MapID
	coll  *ebpf.Collection
}

// pinnedStub is one pinned link as the kernel reports it.
type pinnedStub struct {
	facts  linkFacts
	closed bool
}

func (l *pinnedStub) Close() error { l.closed = true; return nil }

// reported is what the stand-in kernel reports of the link.
func (l *pinnedStub) reported() linkFacts { return l.facts }

// newAdoptionKernel installs a stand-in kernel for the test, with this run's collection holding a program for each
// probe's name, numbered from 10, each reading the build's pinned run set and ring outer and its own section.
func newAdoptionKernel(t *testing.T, probes []Probe) *adoptionKernel {
	t.Helper()
	k := &adoptionKernel{
		links: map[string]*pinnedStub{},
		own:   map[*ebpf.Program]progFacts{},
		byID:  map[ebpf.ProgramID]progFacts{},
		maps:  map[*ebpf.Map]ebpf.MapID{},
		coll:  &ebpf.Collection{Programs: map[string]*ebpf.Program{}, Maps: map[string]*ebpf.Map{}},
	}
	for _, p := range probes {
		if k.coll.Programs[p.Program] != nil {
			continue
		}
		prog := new(ebpf.Program)
		f := codeOf(p.Program, ebpf.ProgramID(10+len(k.own)), buildRunSet, buildRings, loadSection)
		k.coll.Programs[p.Program] = prog
		k.own[prog] = f
		k.byID[f.id] = f
	}
	for name, id := range map[string]ebpf.MapID{
		bpf.MapRunSet: buildRunSet, bpf.MapCaptureEvents: buildRings, ".bss": loadSection,
	} {
		m := new(ebpf.Map)
		k.coll.Maps[name] = m
		k.maps[m] = id
	}
	load, facts, loaded, byID, ids := loadPinnedProbe, pinnedLinkFacts, loadedFacts, programFacts, mapID
	t.Cleanup(func() {
		loadPinnedProbe, pinnedLinkFacts, loadedFacts, programFacts, mapID = load, facts, loaded, byID, ids
	})
	mapID = func(m *ebpf.Map) (ebpf.MapID, bool) {
		id, ok := k.maps[m]
		return id, ok
	}
	loadPinnedProbe = func(path string) (io.Closer, error) {
		if l, ok := k.links[path]; ok {
			return l, nil
		}
		return nil, os.ErrNotExist
	}
	pinnedLinkFacts = func(c io.Closer) (linkFacts, error) {
		if l, ok := c.(interface{ reported() linkFacts }); ok {
			return l.reported(), nil
		}
		return linkFacts{}, errors.New("not a pinned link")
	}
	loadedFacts = func(p *ebpf.Program) (progFacts, error) {
		if f, ok := k.own[p]; ok {
			return f, nil
		}
		return progFacts{}, errors.New("not this run's program")
	}
	programFacts = func(id ebpf.ProgramID) (progFacts, error) {
		if f, ok := k.byID[id]; ok {
			return f, nil
		}
		return progFacts{}, os.ErrNotExist
	}
	return k
}

// codeOf is the facts of the build's program of the name, loaded as id over maps: its tag hashes the name's code,
// whichever load it is.
func codeOf(name string, id ebpf.ProgramID, maps ...ebpf.MapID) progFacts {
	return progFacts{id: id, idOK: true, typ: ebpf.Kprobe, tag: "tag-" + name, maps: maps, mapsOK: true}
}

// ownProgram is pinSet's program for a set this run placed: its own program for the probe.
func (k *adoptionKernel) ownProgram(_ int, p Probe) ebpf.ProgramID {
	return k.own[k.coll.Programs[p.Program]].id
}

// loaded is pinSet's program for a set another load placed: the build's program for each probe as that load holds
// it, numbered from base and reading maps, its tag tag when that is not empty.
func (k *adoptionKernel) loaded(base ebpf.ProgramID, tag string, maps ...ebpf.MapID) func(int, Probe) ebpf.ProgramID {
	return func(i int, p Probe) ebpf.ProgramID {
		f := codeOf(p.Program, base+ebpf.ProgramID(i), maps...)
		if tag != "" {
			f.tag = tag
		}
		k.byID[f.id] = f
		return f.id
	}
}

// pinSet lays a complete set out at dir as placeKind pins one, link i for probes[i], each a perf-event link the
// kernel reports running program(i) on the probe's own kind and offset, as 6.6 and later report a probe.
func (k *adoptionKernel) pinSet(t *testing.T, dir string, probes []Probe,
	program func(int, Probe) ebpf.ProgramID) []*pinnedStub {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var out []*pinnedStub
	for i, p := range probes {
		path := filepath.Join(dir, strconv.Itoa(i))
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		l := &pinnedStub{facts: linkFacts{typ: link.PerfEventType, program: program(i, p), event: eventOf(p),
			offset: uint32(p.Offset)}}
		k.links[path] = l
		out = append(out, l)
	}
	return out
}

// libraryProbes are a libssl's probes as probesFor places them: SSL_free, SSL_read's entry and return, SSL_write.
func libraryProbes() []Probe {
	return probesFor(&binary{Offsets: map[string]uint64{SymFree: 0x1000, SymRead: 0x2000, SymWrite: 0x3000}})
}

// unreported is how a kernel before 6.6 reports a single probe's link: its type and program, nothing of the probe.
func unreported(links []*pinnedStub) {
	for _, l := range links {
		l.facts.event, l.facts.offset = eventUnreported, 0
	}
}

// TestPinnedProbesAreTheBuildsOnlyWhenTheyRunItsProgramsOverItsMaps: a complete set of a library's individual
// probes is the build's when each link runs this run's program for its probe, or the same code over the build's
// pinned maps (another run's load of the object), on the probe's kind and offset where the kernel reports them.
// A set pinned before the build's maps were re-created runs the same code over the old maps, and its programs
// read a run set that names no run of the build now; a set of other programs reads what it likes. Adopted on its
// count alone, as both were, it captured nothing for the run and said nothing. Before 6.6 the kernel reports a
// single probe's program and no more, and the program decides alone.
func TestPinnedProbesAreTheBuildsOnlyWhenTheyRunItsProgramsOverItsMaps(t *testing.T) {
	probes := libraryProbes()
	type programs = func(*adoptionKernel) func(int, Probe) ebpf.ProgramID
	own := func(k *adoptionKernel) func(int, Probe) ebpf.ProgramID { return k.ownProgram }
	other := func(base ebpf.ProgramID, tag string, maps ...ebpf.MapID) programs {
		return func(k *adoptionKernel) func(int, Probe) ebpf.ProgramID { return k.loaded(base, tag, maps...) }
	}
	for _, c := range []struct {
		name     string
		adopted  bool
		programs programs
		edit     func([]*pinnedStub)
	}{
		{"this run's own programs", true, own, nil},
		{"another load's programs over the build's maps", true, other(20, "", buildRunSet, buildRings, loadSection+1), nil},
		{"own programs, reported as before 6.6", true, own, unreported},
		{"programs over the maps since re-created", false, other(30, "", staleRunSet, staleRings, loadSection+2), nil},
		{"programs over the maps since re-created, reported as before 6.6", false,
			other(30, "", staleRunSet, staleRings, loadSection+2), unreported},
		{"one program over a re-created map", false, other(30, "", buildRunSet, staleRings, loadSection+2), nil},
		{"programs of other code over the build's maps", false,
			other(40, "tag-other", buildRunSet, buildRings, loadSection+3), nil},
		{"a program the kernel no longer has", false, func(*adoptionKernel) func(int, Probe) ebpf.ProgramID {
			return func(int, Probe) ebpf.ProgramID { return 99 }
		}, nil},
		{"a multi link", false, own, func(l []*pinnedStub) { l[0].facts.typ = link.UprobeMultiType }},
		{"an entry probe where the return goes", false, own, func(l []*pinnedStub) { l[2].facts.event = eventUprobe }},
		{"a probe at another offset", false, own, func(l []*pinnedStub) { l[3].facts.offset++ }},
		{"a perf event that is no uprobe", false, own, func(l []*pinnedStub) { l[0].facts.event = eventOther }},
		{"two links swapped", false, own, func(l []*pinnedStub) { l[0].facts, l[3].facts = l[3].facts, l[0].facts }},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := newAdoptionKernel(t, probes)
			dir := filepath.Join(t.TempDir(), "lib")
			set := k.pinSet(t, dir, probes, c.programs(k))
			if c.edit != nil {
				c.edit(set)
			}
			links, ok := adoptLinks(dir, len(probes))
			if !ok {
				t.Fatal("the complete set did not open")
			}
			a := NewAttacher(k.coll)
			why := a.probeLinksDiffer(links, probes, a.pinnedMapIDs())
			if (why == "") != c.adopted {
				t.Fatalf("the build's: %v (%q), want %v", why == "", why, c.adopted)
			}
		})
	}
}

// TestSameProgramHoldsTheCodeAndTheBuildsMaps is sameProgram's own table, which a multi pair's adoption asks too:
// this run's program, or one of its type and tag reading the build's pinned maps position for position, where only
// a load's own section may differ.
func TestSameProgramHoldsTheCodeAndTheBuildsMaps(t *testing.T) {
	probes := libraryProbes()
	name := probes[0].Program
	for _, c := range []struct {
		name string
		same bool
		got  progFacts
	}{
		{"another load", true, codeOf(name, 50, buildRunSet, buildRings, loadSection+1)},
		{"a re-created run set", false, codeOf(name, 50, staleRunSet, buildRings, loadSection+1)},
		{"other code", false, codeOf("other", 50, buildRunSet, buildRings, loadSection)},
		{"another type", false, func() progFacts {
			f := codeOf(name, 50, buildRunSet, buildRings, loadSection)
			f.typ = ebpf.Tracing
			return f
		}()},
		{"a map more", false, codeOf(name, 50, buildRunSet, buildRings, loadSection, loadSection+1)},
		{"no maps reported", false, func() progFacts {
			f := codeOf(name, 50)
			f.maps, f.mapsOK = nil, false
			return f
		}()},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := newAdoptionKernel(t, probes)
			k.byID[50] = c.got
			if got := sameProgram(k.coll.Programs[name], 50, buildMaps); got != c.same {
				t.Fatalf("sameProgram = %v, want %v", got, c.same)
			}
		})
	}
	k := newAdoptionKernel(t, probes)
	if !sameProgram(k.coll.Programs[name], k.own[k.coll.Programs[name]].id, buildMaps) {
		t.Fatal("this run's own program is not its own")
	}
	if sameProgram(nil, 10, buildMaps) {
		t.Fatal("a program this run does not have matched")
	}
}

// adoptionFixture is a sharedAttacher over the stand-in kernel, the library it places on (a file, which the
// stand-in cannot attach to), and the library's pin directory.
func (k *adoptionKernel) adoptionFixture(t *testing.T) (s *sharedAttacher, lib string, id identity, dir string) {
	t.Helper()
	lib = filepath.Join(t.TempDir(), "libssl.so.3")
	if err := os.WriteFile(lib, []byte("\x7fELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	s = &sharedAttacher{EBPFAttacher: NewAttacher(k.coll), root: t.TempDir(), state: t.TempDir(), hash: "h1",
		detach: func(detachJob) {}, logf: t.Logf}
	id = identity{Dev: 2, Ino: 1497, BuildID: "abcd"}
	return s, lib, id, filepath.Join(s.root, UprobePinDir, libKey(id))
}

// holdLibrary takes a run's shared hold on a library's lock, as AttachBinary takes one.
func holdLibrary(t *testing.T, s *sharedAttacher, id identity) *os.File {
	t.Helper()
	j := detachJob{root: s.root, state: s.state, hash: s.hash, key: libKey(id)}
	f, err := os.OpenFile(filepath.Join(s.state, j.lockName()), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	return f
}

// lockFree reports whether nobody holds a library's lock: an exclusive attempt from a new open succeeds.
func lockFree(t *testing.T, s *sharedAttacher, id identity) bool {
	t.Helper()
	j := detachJob{hash: s.hash, key: libKey(id)}
	f, err := os.OpenFile(filepath.Join(s.state, j.lockName()), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil
}

// TestTheBuildsPinnedProbesAreAdopted: a complete set the build's runs placed is adopted as before, another load's
// as well as this run's: AttachBinary hands back its links and the library's hold, and places nothing.
func TestTheBuildsPinnedProbesAreAdopted(t *testing.T) {
	probes := libraryProbes()
	k := newAdoptionKernel(t, probes)
	s, lib, id, dir := k.adoptionFixture(t)
	set := k.pinSet(t, dir, probes, k.loaded(20, "", buildRunSet, buildRings, loadSection+1))
	links, err := s.AttachBinary(lib, id, probes)
	if err != nil {
		t.Fatalf("AttachBinary: %v", err)
	}
	if len(links) != len(probes)+1 {
		t.Fatalf("%d closers for %d probes, want the links and the hold", len(links), len(probes))
	}
	for i, l := range set {
		if links[i] != io.Closer(l) || l.closed {
			t.Fatalf("link %d: got %v (closed %v), want the pinned one, open", i, links[i], l.closed)
		}
	}
	if _, ok := links[len(probes)].(*libHold); !ok {
		t.Fatalf("the last closer is %T, want the library's hold", links[len(probes)])
	}
	if lockFree(t, s, id) {
		t.Fatal("the adopting run does not hold the library")
	}
	closeProbes(links)
	if !lockFree(t, s, id) {
		t.Fatal("the library's lock is still held after its last run let go")
	}
}

// TestProbesNotTheBuildsAreRefusedWhileAnotherRunHoldsTheLibrary: a complete set pinned over the build's maps
// before they were re-created is not adopted. While another run holds the library the set may still be that
// run's, and no second set is placed beside one in use (adoptMulti's rule): the library is refused, an attach
// failure that says why, the set is left pinned, and this run keeps no hold.
func TestProbesNotTheBuildsAreRefusedWhileAnotherRunHoldsTheLibrary(t *testing.T) {
	probes := libraryProbes()
	k := newAdoptionKernel(t, probes)
	s, lib, id, dir := k.adoptionFixture(t)
	stale := k.pinSet(t, dir, probes, k.loaded(30, "", staleRunSet, staleRings, loadSection+2))
	other := holdLibrary(t, s, id)
	links, err := s.AttachBinary(lib, id, probes)
	if err == nil {
		closeProbes(links)
		t.Fatalf("adopted the %d probes pinned over maps since re-created", len(links)-1)
	}
	if !errors.Is(err, ErrAttachFailed) || !strings.Contains(err.Error(), "another run holds the library") {
		t.Fatalf("AttachBinary: %v, want the library refused while another run holds it", err)
	}
	for i, l := range stale {
		if !l.closed {
			t.Errorf("link %d is still open in the refusing run", i)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != len(probes) {
		t.Fatalf("the set another run holds was changed: %v %v", entries, err)
	}
	_ = other.Close()
	if !lockFree(t, s, id) {
		t.Fatal("the refusing run kept a hold on the library")
	}
}

// TestProbesNotTheBuildsArePlacedAgainWhenNoOtherRunHoldsThem: with no other run holding the library, nothing
// captures through such a set: it is unpinned and its links closed, and the run goes on to place its own. The
// stand-in kernel refuses that placement, so the attach still fails here, with the placement's error.
func TestProbesNotTheBuildsArePlacedAgainWhenNoOtherRunHoldsThem(t *testing.T) {
	probes := libraryProbes()
	k := newAdoptionKernel(t, probes)
	s, lib, id, dir := k.adoptionFixture(t)
	stale := k.pinSet(t, dir, probes, k.loaded(30, "", staleRunSet, staleRings, loadSection+2))
	links, err := s.AttachBinary(lib, id, probes)
	if err == nil {
		closeProbes(links)
		t.Fatalf("adopted the %d probes pinned over maps since re-created", len(links)-1)
	}
	if strings.Contains(err.Error(), "another run holds") || !strings.Contains(err.Error(), probes[0].String()) {
		t.Fatalf("AttachBinary: %v, want the failure of placing %s", err, probes[0])
	}
	for i, l := range stale {
		if !l.closed {
			t.Errorf("link %d of the replaced set is still open", i)
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the replaced set is still pinned at %s: %v", dir, err)
	}
	if !lockFree(t, s, id) {
		t.Fatal("the failed attach kept a hold on the library")
	}
}

// TestAdoptProbesUnpinsASetNotTheBuildsAndKeepsTheHold: alone on the library, adoptProbes unpins the set before
// it closes the links (so the close is their last reference), reports nothing adopted, and leaves this run's hold
// shared, as AttachBinary goes on to place under it.
func TestAdoptProbesUnpinsASetNotTheBuildsAndKeepsTheHold(t *testing.T) {
	probes := libraryProbes()
	k := newAdoptionKernel(t, probes)
	s, _, id, dir := k.adoptionFixture(t)
	stale := k.pinSet(t, dir, probes, k.loaded(40, "tag-other", buildRunSet, buildRings, loadSection+3))
	load := loadPinnedProbe
	loadPinnedProbe = func(path string) (io.Closer, error) {
		c, err := load(path)
		if err != nil {
			return nil, err
		}
		return closeChecked{c.(*pinnedStub), func() {
			if _, err := os.Stat(path); err == nil {
				t.Errorf("%s was closed while it was still pinned", path)
			}
		}}, nil
	}
	hold := holdLibrary(t, s, id)
	links, adopted, err := s.adoptProbes(dir, probes, hold)
	if err != nil || adopted || links != nil {
		t.Fatalf("adoptProbes = %v, %v, %v; want nothing adopted and no error", links, adopted, err)
	}
	for i, l := range stale {
		if !l.closed {
			t.Errorf("link %d is still open", i)
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the set is still pinned: %v", err)
	}
	if lockFree(t, s, id) {
		t.Fatal("this run no longer holds the library")
	}
	j := detachJob{hash: s.hash, key: libKey(id)}
	f, err := os.OpenFile(filepath.Join(s.state, j.lockName()), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatalf("this run holds the library exclusively after the question: %v", err)
	}
}

// closeChecked is a pinned link whose Close checks something first.
type closeChecked struct {
	*pinnedStub
	check func()
}

func (c closeChecked) Close() error { c.check(); return c.pinnedStub.Close() }

// TestAloneOnLibraryAsksWithoutLosingTheHold: whether another run holds the library is asked by converting this
// run's shared hold to exclusive without waiting, which Linux does by dropping the shared hold first. Whatever the
// answer, this run holds the library shared again afterwards, and no other run's hold is disturbed.
func TestAloneOnLibraryAsksWithoutLosingTheHold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bpf-h1-lib-2-1497-abcd.lock")
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	try := func(f *os.File, how int) bool { return unix.Flock(int(f.Fd()), how|unix.LOCK_NB) == nil }
	mine, other, probe := open(), open(), open()
	if !try(mine, unix.LOCK_SH) {
		t.Fatal("no shared hold")
	}
	if alone, err := aloneOnLibrary(mine); !alone || err != nil {
		t.Fatalf("aloneOnLibrary = %v, %v with no other holder", alone, err)
	}
	// Shared again: another run's shared hold is granted, its exclusive attempt is not.
	if try(other, unix.LOCK_EX) || !try(other, unix.LOCK_SH) {
		t.Fatal("the hold is not shared after the answer")
	}
	if alone, err := aloneOnLibrary(mine); alone || err != nil {
		t.Fatalf("aloneOnLibrary = %v, %v while another run holds the library", alone, err)
	}
	_ = other.Close()
	if try(probe, unix.LOCK_EX) {
		t.Fatal("the hold was lost when another run held the library")
	}
	_ = mine.Close()
	if !try(probe, unix.LOCK_EX) {
		t.Fatal("the lock is held after both runs let go")
	}
}
