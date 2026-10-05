// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// The fixed TLS vocabulary has at most five entry offsets and two read returns.
// A library with no read symbols keeps its ordinary individual-probe path.
var errNoMulti = errors.New("uprobe: multi dispatch unavailable")

type multiPlan struct{ entry, returns link.UprobeMultiOptions }

func planMulti(probes []Probe) (multiPlan, error) {
	var plan multiPlan
	if len(probes) == 0 || len(probes) > 7 {
		return plan, fmt.Errorf("%w: TLS probe count outside 1..7", ErrAttachFailed)
	}
	entry, returns := map[uint64]uint64{}, map[uint64]uint64{}
	entryCookies := map[uint64]bool{}
	for _, p := range probes {
		cookie := uint64(0)
		switch {
		case !p.Return && p.Program == bpf.ProgSSLWrite && p.Symbol == SymWrite:
			cookie = bpf.SSLCookieWrite
		case !p.Return && p.Program == bpf.ProgSSLWriteEx && (p.Symbol == SymWriteEx || p.Symbol == SymWriteEx2):
			cookie = bpf.SSLCookieWriteEx
		case !p.Return && p.Program == bpf.ProgSSLRead && p.Symbol == SymRead:
			cookie = bpf.SSLCookieRead
		case !p.Return && p.Program == bpf.ProgSSLReadEx && p.Symbol == SymReadEx:
			cookie = bpf.SSLCookieReadEx
		case !p.Return && p.Program == bpf.ProgSSLFree && p.Symbol == SymFree:
			cookie = bpf.SSLCookieFree
		case p.Return && p.Program == bpf.ProgSSLReadReturn && p.Symbol == SymRead:
			cookie = bpf.SSLCookieRead
		case p.Return && p.Program == bpf.ProgSSLReadReturn && p.Symbol == SymReadEx:
			cookie = bpf.SSLCookieReadEx
		}
		if cookie == 0 || p.Offset == 0 {
			return multiPlan{}, fmt.Errorf("%w: invalid TLS multi operation %s", ErrAttachFailed, p)
		}
		set := entry
		if p.Return {
			set = returns
		}
		if _, exists := set[p.Offset]; exists {
			return multiPlan{}, fmt.Errorf("%w: repeated TLS multi offset %#x", ErrAttachFailed, p.Offset)
		}
		if !p.Return {
			if entryCookies[cookie] {
				return multiPlan{}, fmt.Errorf("%w: repeated TLS multi operation", ErrAttachFailed)
			}
			entryCookies[cookie] = true
		}
		set[p.Offset] = cookie
	}
	for offset, cookie := range returns {
		if entry[offset] != cookie {
			return multiPlan{}, fmt.Errorf("%w: read return lacks matching entry", ErrAttachFailed)
		}
	}
	for offset, cookie := range entry {
		if (cookie == bpf.SSLCookieRead || cookie == bpf.SSLCookieReadEx) && returns[offset] != cookie {
			return multiPlan{}, fmt.Errorf("%w: read entry lacks matching return", ErrAttachFailed)
		}
	}
	if len(returns) == 0 {
		return multiPlan{}, errNoMulti
	}
	fill := func(set map[uint64]uint64, out *link.UprobeMultiOptions) {
		for offset := range set {
			out.Addresses = append(out.Addresses, offset)
		}
		sort.Slice(out.Addresses, func(i, j int) bool { return out.Addresses[i] < out.Addresses[j] })
		for _, offset := range out.Addresses {
			out.Cookies = append(out.Cookies, set[offset])
		}
	}
	fill(entry, &plan.entry)
	fill(returns, &plan.returns)
	return plan, nil
}

// attachPair closes the first actual link if the second attachment fails.
// No single fallback can coexist with a partial multi pair.
func attachPair(enter, ret func() (io.Closer, error)) ([]io.Closer, error) {
	r, err := ret()
	if err != nil {
		return nil, err
	}
	e, err := enter()
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	return []io.Closer{e, r}, nil
}

func (a *EBPFAttacher) attachMulti(path string, plan multiPlan) ([]io.Closer, error) {
	entry, ret := a.coll.Programs[bpf.ProgSSLMultiEnter], a.coll.Programs[bpf.ProgSSLMultiReturn]
	if entry == nil || ret == nil {
		return nil, errNoMulti
	}
	ex, err := a.executable(path)
	if err != nil {
		return nil, err
	}
	return attachPair(func() (io.Closer, error) { return ex.UprobeMulti(nil, entry, &plan.entry) },
		func() (io.Closer, error) { return ex.UretprobeMulti(nil, ret, &plan.returns) })
}

// Multi adoption proves the pair runs this build's dispatchers (sameProgram), file identity, system-wide scope,
// entry/return flags and offset-cookie pairs. Shape alone is not enough to
// reinterpret two arbitrary pinned probes as a complete dispatcher pair.
func (a *EBPFAttacher) validMultiLinks(links []io.Closer, path string, plan multiPlan) bool {
	if len(links) != 2 {
		return false
	}
	var expected unix.Stat_t
	if unix.Stat(path, &expected) != nil {
		return false
	}
	pinned := a.pinnedMapIDs()
	for i, name := range []string{bpf.ProgSSLMultiEnter, bpf.ProgSSLMultiReturn} {
		program := a.coll.Programs[name]
		if program == nil {
			return false
		}
		l, isLink := links[i].(link.Link)
		if !isLink {
			return false
		}
		info, err := l.Info()
		if err != nil || info.Type != link.UprobeMultiType || !sameProgram(program, info.Program, pinned) {
			return false
		}
		multi := info.UprobeMulti()
		if multi == nil || multi.Flags != uint32(i) {
			return false
		}
		scope, ok := multi.Pid()
		if ok || scope != 0 {
			return false
		}
		var actual unix.Stat_t
		if unix.Stat(multi.File, &actual) != nil || actual.Dev != expected.Dev || actual.Ino != expected.Ino {
			return false
		}
		offsets, ok := multi.Offsets()
		want := plan.entry
		if i == 1 {
			want = plan.returns
		}
		if !ok || int(multi.Count) != len(want.Addresses) || len(offsets) != len(want.Addresses) {
			return false
		}
		for j, offset := range offsets {
			if offset.Offset != want.Addresses[j] || offset.Cookie != want.Cookies[j] || offset.ReferenceCount != 0 {
				return false
			}
		}
	}
	return true
}

// sameProgram reports whether the program id is want, or the same code over the same pinned maps: the copy of
// a dispatcher another run of the build loaded. Two cold runs each load their own programs (the loser of the
// program-pin race keeps its own, loadCollection), so a pair one of them placed names a program ID the other's
// collection does not have; requiring this run's own ID refused that pair and cost the run the library's
// capture (capture-1). The kernel's tag hashes the instructions with every map reference zeroed, so it is equal
// across loads of one object; the maps must then be the build's pinned ones, position for position, and only
// a load's own global sections (.bss) may differ. Nothing else is accepted.
func sameProgram(want *ebpf.Program, id ebpf.ProgramID, pinned map[ebpf.MapID]bool) bool {
	wi, err := want.Info()
	if err != nil {
		return false
	}
	if own, ok := wi.ID(); ok && own == id {
		return true
	}
	p, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return false
	}
	defer func() { _ = p.Close() }()
	gi, err := p.Info()
	if err != nil || p.Type() != want.Type() || wi.Tag == "" || gi.Tag != wi.Tag {
		return false
	}
	wm, ok := wi.MapIDs()
	if !ok {
		return false
	}
	gm, ok := gi.MapIDs()
	if !ok || len(gm) != len(wm) {
		return false
	}
	for i := range wm {
		if gm[i] != wm[i] && (pinned[wm[i]] || pinned[gm[i]]) {
			return false
		}
	}
	return true
}

// pinnedMapIDs are the IDs of the collection's maps that are not a load's own global sections: the build's
// pinned maps, which every run of the build shares by name.
func (a *EBPFAttacher) pinnedMapIDs() map[ebpf.MapID]bool {
	ids := map[ebpf.MapID]bool{}
	for name, m := range a.coll.Maps {
		if strings.HasPrefix(name, ".") {
			continue
		}
		if info, err := m.Info(); err == nil {
			if id, ok := info.ID(); ok {
				ids[id] = true
			}
		}
	}
	return ids
}

func closeProbes(links []io.Closer) {
	for _, l := range links {
		_ = l.Close()
	}
}

// adoptMulti rejects an existing multi pair it cannot prove is this build's
// dispatchers (validMultiLinks) rather than replacing it while another shared
// holder could still be using it, or placing individual probes beside it, which
// would capture every TLS call of the run set twice (ADR 0026 (7)). That is left
// to a run without the dispatchers (none loaded): a run of the same build with
// them adopts a pair any other run placed.
func (a *EBPFAttacher) adoptMulti(dir, path string, plan multiPlan) ([]io.Closer, bool, error) {
	links, ok := adoptLinks(dir, 2)
	if !ok {
		return nil, false, nil
	}
	if a.validMultiLinks(links, path, plan) {
		return links, true, nil
	}
	isMulti := false
	for _, c := range links {
		if l, ok := c.(link.Link); ok {
			info, err := l.Info()
			isMulti = isMulti || err == nil && info.Type == link.UprobeMultiType
		}
	}
	closeProbes(links)
	if isMulti {
		return nil, false, fmt.Errorf("%w: pinned multi pair ownership differs at %s", ErrAttachFailed, dir)
	}
	return nil, false, nil
}
