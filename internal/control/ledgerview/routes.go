// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/attention-span-ai/tego/pkg/policy/modelroute"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The Model routes page and `tego route list` say, per models[] endpoint, how many of a run's requests went by each
// route and which route changes the forwarder recorded. Both used to walk the run's whole ledger for it. The read model
// takes every line once, as it reads it, so it folds those two facts into the run's summary as it goes (Run.add): the
// count of ssl_request lines per modelroute.RouteKey and the route-change records, over the whole run and not only the
// bounded window of lines it keeps. The page then answers from the summary (RouteFacts) for any models[] list, in time
// that does not grow with the run.

const (
	// maxRouteKeys bounds the distinct RouteKeys a run's summary holds, and maxRouteChanges its route-change records. A
	// run past either (a forwarder that names ever-new hosts, thousands of changes) is not indexed, and its reader walks
	// the ledger as before: the index is an answer that is exact or absent, never cut.
	maxRouteKeys    = 256
	maxRouteChanges = 4096
)

// routeIndex is what a run's lines said of its model routes, as the read model folded them.
type routeIndex struct {
	tally   map[modelroute.RouteKey]int
	changes []record.ModelRouteChange
	// unindexed is set when the index is not the whole truth: a payload that did not decode, or a bound passed.
	unindexed bool
}

// take folds one line into the index.
func (x *routeIndex) take(ev *Event) {
	switch ev.Kind {
	case string(record.KindSSLRequest):
		key, routed, err := modelroute.KeyOfPayload([]byte(ev.Raw))
		switch {
		case err != nil:
			x.unindexed = true
		case routed:
			if x.tally == nil {
				x.tally = map[modelroute.RouteKey]int{}
			}
			if _, seen := x.tally[key]; !seen && len(x.tally) >= maxRouteKeys {
				x.unindexed = true
				return
			}
			x.tally[key]++
		}
	case string(record.KindGap):
		// Every gap line is decoded, as the ledger walk did: a payload that does not decode as a gap's leaves the run
		// unindexed, so the page reads the ledger and says what it could not read.
		var p record.GapPayload
		if err := json.Unmarshal([]byte(ev.Raw), &p); err != nil {
			x.unindexed = true
			return
		}
		if p.Why != record.GapModelRouteChanged {
			return
		}
		if p.ModelRoute == nil || len(x.changes) >= maxRouteChanges {
			x.unindexed = true
			return
		}
		x.changes = append(x.changes, *p.ModelRoute)
	}
}

// clone is x as a published Run keeps it: its own copies, which later lines do not write to.
func (x routeIndex) clone() routeIndex {
	x.tally = maps.Clone(x.tally)
	x.changes = slices.Clone(x.changes)
	return x
}

// RouteFacts is a run's model-route facts from the read model: the ssl_request lines per route taken, and the
// route-change records in file order.
type RouteFacts struct {
	Tally   map[modelroute.RouteKey]int
	Changes []record.ModelRouteChange
}

// RouteFacts answers for the whole run, from the summary the read model built as it read the lines (no ledger walk).
// ok is false when it cannot answer exactly: a Run the store did not publish (one built for a bound, or a window), a
// run with a line it refused or could not read, or one past the index's bounds. The caller then reads the ledger. The
// maps and slices are shared with the run's version: do not modify them.
func (r *Run) RouteFacts() (RouteFacts, bool) {
	if r == nil || r.st == nil || r.routes.unindexed || r.Bad > 0 || len(r.LineErrors) > 0 || r.ReadError != "" {
		return RouteFacts{}, false
	}
	return RouteFacts{Tally: r.routes.tally, Changes: r.routes.changes}, true
}
