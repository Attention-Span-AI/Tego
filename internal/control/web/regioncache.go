// SPDX-License-Identifier: Apache-2.0

package web

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// The shared region cache (PF-4 item 6). Every open page asks for its changed regions each time the live state
// moves, so N tabs on the same address (two people watching the Overview, the demo's two browser windows) each ran
// the page's handler and rendered its regions for the same ledger revision. The cache keeps one address's rendered
// regions for regionTTL, keyed by the address, the regions asked for and the live state (ledgerview's Rev and the
// waiting asks' Sig); a second ask in that second, at that state, is answered from the kept renders, each viewer
// getting only the regions whose hash differs from the ones it shows. What a page shows that no revision covers (a
// live block written but not yet confirmed, a rules file, a kept panel) is at most regionTTL old, and every POST
// through this dashboard drops the cache before and after it acts (regionCache.bump), so a page refreshing after
// its own Block now or Save never gets an answer rendered before it. Region answers carry the session's form
// token, like the page: the cache is this server's, and a server has one session.

// regionTTL is how long a region render answers other asks at the same live state.
const regionTTL = time.Second

// maxRegionCache bounds the kept renders (an address and region set each); past it the cache starts again.
const maxRegionCache = 64

// regionEntry is one address's region render: when, at which generation (regionCache.gen), and what it answered.
type regionEntry struct {
	at     time.Time
	gen    uint64
	status int
	sig    string
	rev    string
	names  []string // the page's regions in order, as renderRegions writes them
	regs   map[string]*liveRegion
}

// regionCache is the kept region renders by key (cacheKey).
type regionCache struct {
	mu  sync.Mutex
	gen uint64 // moves on every POST; an entry of another generation is never served or stored
	m   map[string]regionEntry
}

// cacheKey is a region request's key: its address, the regions it asks for (sorted) and the live state it is
// answered at.
func cacheKey(path, rawQuery string, have map[string]string, st liveState) string {
	names := make([]string, 0, len(have))
	for n := range have {
		names = append(names, n)
	}
	slices.Sort(names)
	return path + "?" + rawQuery + "\x00" + strings.Join(names, ",") + "\x00" + st.Rev + "\x00" + st.Sig
}

// get is the entry under key kept less than regionTTL before now in this generation, and the generation a render
// begun now belongs to.
func (c *regionCache) get(key string, now time.Time) (regionEntry, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || e.gen != c.gen || now.Sub(e.at) >= regionTTL || now.Before(e.at) {
		return regionEntry{}, c.gen, false
	}
	return e, c.gen, true
}

// put keeps e under key, unless a POST moved the generation since its render began (e.gen).
func (c *regionCache) put(key string, e regionEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.gen != c.gen {
		return
	}
	if c.m == nil || len(c.m) >= maxRegionCache {
		c.m = map[string]regionEntry{}
	}
	c.m[key] = e
}

// bump drops every kept render: a POST may change what a page shows without moving the ledger's revision.
func (c *regionCache) bump() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.m = nil
}

// liveStateOf is the live state of the ledger as a region request is answered, or false when it cannot be read
// (the handler then answers, and says why).
func (s *Server) liveStateOf() (*ledgerview.Snapshot, liveState, bool) {
	snap, err := ledgerview.Load(s.cfg.Ledger)
	if err != nil {
		return nil, liveState{}, false
	}
	return snap, stateOf(snap), true
}
