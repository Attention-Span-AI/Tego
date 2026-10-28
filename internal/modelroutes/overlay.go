// SPDX-License-Identifier: Apache-2.0

package modelroutes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Version is the overlay format's version.
const Version = 1

// Direct is the route of an endpoint itself (pkg/spec/agent.DirectRoute, which this leaf may not link).
const Direct = "direct"

// The ops a change records.
const (
	// OpSet puts a declared route in force for an endpoint.
	OpSet = "set"
	// OpClear drops it: the endpoint's requests go to the endpoint itself again.
	OpClear = "clear"
)

// Bounds: a run's routes are a person's handful of choices, never a database.
const (
	// MaxRoutes bounds the routes in force (one per endpoint).
	MaxRoutes = 256
	// MaxChanges bounds the history kept; older changes are dropped and counted in Lost.
	MaxChanges = 256
	// MaxFileBytes bounds the file read.
	MaxFileBytes = 1 << 20
)

// ErrInvalid is an overlay or a change that does not follow the format.
var ErrInvalid = errors.New("modelroutes: invalid")

// routeNameRE is a route's name rule (agent-contract.md R32), direct included.
var routeNameRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// ValidRoute reports whether s is a route name the overlay holds.
func ValidRoute(s string) bool { return routeNameRE.MatchString(s) }

// ValidModel reports whether s is an endpoint as the overlay names it: host:port with a port from 1 to 65535.
func ValidModel(s string) bool {
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" || len(s) > 300 {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// Entry is one endpoint's route in force.
type Entry struct {
	Model  string    `json:"model"`
	Route  string    `json:"route"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Serial uint64    `json:"serial"`
}

// Change is one change made, in serial order.
type Change struct {
	Serial uint64    `json:"serial"`
	Op     string    `json:"op"`
	Model  string    `json:"model"`
	Route  string    `json:"route,omitempty"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// RouteAfter is the route a change put in force: its route, or Direct for a clear.
func (c Change) RouteAfter() string {
	if c.Op == OpClear {
		return Direct
	}
	return c.Route
}

// Overlay is the run's live model routes.
type Overlay struct {
	Version int      `json:"version"`
	Run     string   `json:"run"`
	Serial  uint64   `json:"serial"`
	Routes  []Entry  `json:"routes"`
	Changes []Change `json:"changes"`
	// Lost counts changes dropped from Changes by MaxChanges.
	Lost uint64 `json:"lost,omitempty"`
}

// New is an empty overlay for run.
func New(run string) *Overlay {
	return &Overlay{Version: Version, Run: run, Routes: []Entry{}, Changes: []Change{}}
}

// Lookup is the route in force for model, if any. A nil overlay has none.
func (o *Overlay) Lookup(model string) (Entry, bool) {
	if o == nil {
		return Entry{}, false
	}
	for _, e := range o.Routes {
		if e.Model == model {
			return e, true
		}
	}
	return Entry{}, false
}

// Set puts route in force for model. It reports whether anything changed: an endpoint already on route records no
// change. Setting Direct is a Clear.
func (o *Overlay) Set(model, route, by string, at time.Time) (bool, error) {
	if !ValidModel(model) || !ValidRoute(route) {
		return false, fmt.Errorf("%w: model %q, route %q", ErrInvalid, model, route)
	}
	if route == Direct {
		return o.Clear(model, by, at)
	}
	at = at.UTC()
	for i := range o.Routes {
		e := &o.Routes[i]
		if e.Model == model {
			if e.Route == route {
				return false, nil
			}
			o.Serial++
			e.Route, e.By, e.At, e.Serial = route, by, at, o.Serial
			o.record(Change{Serial: o.Serial, Op: OpSet, Model: model, Route: route, By: by, At: at})
			return true, nil
		}
	}
	if len(o.Routes) >= MaxRoutes {
		return false, fmt.Errorf("%w: more than %d live routes", ErrInvalid, MaxRoutes)
	}
	o.Serial++
	o.Routes = append(o.Routes, Entry{Model: model, Route: route, By: by, At: at, Serial: o.Serial})
	o.record(Change{Serial: o.Serial, Op: OpSet, Model: model, Route: route, By: by, At: at})
	return true, nil
}

// Clear drops the route of model, so its requests go to the endpoint itself. It reports whether one was in force.
func (o *Overlay) Clear(model, by string, at time.Time) (bool, error) {
	if !ValidModel(model) {
		return false, fmt.Errorf("%w: model %q", ErrInvalid, model)
	}
	for i, e := range o.Routes {
		if e.Model == model {
			o.Routes = append(o.Routes[:i], o.Routes[i+1:]...)
			o.Serial++
			o.record(Change{Serial: o.Serial, Op: OpClear, Model: model, By: by, At: at.UTC()})
			return true, nil
		}
	}
	return false, nil
}

func (o *Overlay) record(c Change) {
	o.Changes = append(o.Changes, c)
	if over := len(o.Changes) - MaxChanges; over > 0 {
		o.Changes = append([]Change(nil), o.Changes[over:]...)
		o.Lost += uint64(over)
	}
}

// Since is the changes after serial, oldest first. A reader that remembers the serial it last put in force asks for
// what came after it; changes dropped by MaxChanges are not returned (the routes in force still say where each
// endpoint now goes).
func (o *Overlay) Since(serial uint64) []Change {
	if o == nil {
		return nil
	}
	var out []Change
	for _, c := range o.Changes {
		if c.Serial > serial {
			out = append(out, c)
		}
	}
	return out
}

// Encode is the overlay's file bytes: routes sorted by endpoint, one trailing newline.
func (o *Overlay) Encode() ([]byte, error) {
	if err := o.validate(o.Run); err != nil {
		return nil, err
	}
	sort.Slice(o.Routes, func(i, j int) bool { return o.Routes[i].Model < o.Routes[j].Model })
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Decode reads an overlay's bytes and validates them against run.
func Decode(b []byte, run string) (*Overlay, error) {
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%w: %d bytes, more than %d", ErrInvalid, len(b), MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var o Overlay
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := o.validate(run); err != nil {
		return nil, err
	}
	if o.Routes == nil {
		o.Routes = []Entry{}
	}
	if o.Changes == nil {
		o.Changes = []Change{}
	}
	return &o, nil
}

func (o *Overlay) validate(run string) error {
	switch {
	case o.Version != Version:
		return fmt.Errorf("%w: version %d, want %d", ErrInvalid, o.Version, Version)
	case o.Run != run:
		return fmt.Errorf("%w: overlay of run %q read for run %q", ErrInvalid, o.Run, run)
	case len(o.Routes) > MaxRoutes:
		return fmt.Errorf("%w: %d routes, more than %d", ErrInvalid, len(o.Routes), MaxRoutes)
	case len(o.Changes) > MaxChanges:
		return fmt.Errorf("%w: %d changes, more than %d", ErrInvalid, len(o.Changes), MaxChanges)
	}
	seen := make(map[string]bool, len(o.Routes))
	for _, e := range o.Routes {
		if !ValidModel(e.Model) || !ValidRoute(e.Route) || e.Route == Direct || seen[e.Model] || e.Serial == 0 || e.Serial > o.Serial {
			return fmt.Errorf("%w: route %q of %q", ErrInvalid, e.Route, e.Model)
		}
		seen[e.Model] = true
	}
	for _, c := range o.Changes {
		if c.Serial == 0 || c.Serial > o.Serial || c.Op != OpSet && c.Op != OpClear || !ValidModel(c.Model) ||
			c.Op == OpSet && (!ValidRoute(c.Route) || c.Route == Direct) || c.Op == OpClear && c.Route != "" {
			return fmt.Errorf("%w: change %d", ErrInvalid, c.Serial)
		}
	}
	return nil
}
