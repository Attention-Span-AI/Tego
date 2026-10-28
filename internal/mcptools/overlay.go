// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Version is the overlay format's version.
const Version = 1

// The decisions a switch can hold.
const (
	Allow = "allow"
	Ask   = "ask"
	Deny  = "deny"
)

// The ops a change records.
const (
	OpSet   = "set"
	OpReset = "reset"
)

// Bounds: a live overlay is a person's handful of switches, never a database.
const (
	// MaxTools bounds the switches in force.
	MaxTools = 1024
	// MaxChanges bounds the history kept; older changes are dropped and counted in Lost.
	MaxChanges = 256
	// MaxFileBytes bounds the file read.
	MaxFileBytes = 1 << 20
)

// ErrInvalid is an overlay or a change that does not follow the format.
var ErrInvalid = errors.New("mcptools: invalid")

// namePattern is the tool and server name rule of ADR 0126 §1: MCP's own, widened by ':' and '/'.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)

// ValidName reports whether s is a tool or server name the overlay and the seen file hold.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// ValidDecision reports whether d is allow, ask or deny.
func ValidDecision(d string) bool { return d == Allow || d == Ask || d == Deny }

// Entry is one switch in force.
type Entry struct {
	Server   string    `json:"server"`
	Tool     string    `json:"tool"`
	Decision string    `json:"decision"`
	By       string    `json:"by"`
	At       time.Time `json:"at"`
	Serial   uint64    `json:"serial"`
}

// Change is one change made, in serial order.
type Change struct {
	Serial   uint64    `json:"serial"`
	Op       string    `json:"op"`
	Server   string    `json:"server"`
	Tool     string    `json:"tool"`
	Decision string    `json:"decision,omitempty"`
	By       string    `json:"by"`
	At       time.Time `json:"at"`
}

// Overlay is the run's live MCP tool switches.
type Overlay struct {
	Version int      `json:"version"`
	Run     string   `json:"run"`
	Serial  uint64   `json:"serial"`
	Tools   []Entry  `json:"tools"`
	Changes []Change `json:"changes"`
	// Lost counts changes dropped from Changes by MaxChanges.
	Lost uint64 `json:"lost,omitempty"`
}

// New is an empty overlay for run.
func New(run string) *Overlay {
	return &Overlay{Version: Version, Run: run, Tools: []Entry{}, Changes: []Change{}}
}

// Lookup is the switch in force for server's tool, if any. A nil overlay has none.
func (o *Overlay) Lookup(server, tool string) (Entry, bool) {
	if o == nil {
		return Entry{}, false
	}
	for _, e := range o.Tools {
		if e.Server == server && e.Tool == tool {
			return e, true
		}
	}
	return Entry{}, false
}

// Set puts decision in force for server's tool. It reports whether anything changed: a switch already at decision is
// left alone and records no change.
func (o *Overlay) Set(server, tool, decision, by string, at time.Time) (bool, error) {
	if !ValidName(server) || !ValidName(tool) || !ValidDecision(decision) {
		return false, fmt.Errorf("%w: server %q, tool %q, decision %q", ErrInvalid, server, tool, decision)
	}
	at = at.UTC()
	for i := range o.Tools {
		e := &o.Tools[i]
		if e.Server == server && e.Tool == tool {
			if e.Decision == decision {
				return false, nil
			}
			o.Serial++
			e.Decision, e.By, e.At, e.Serial = decision, by, at, o.Serial
			o.record(Change{Serial: o.Serial, Op: OpSet, Server: server, Tool: tool, Decision: decision, By: by, At: at})
			return true, nil
		}
	}
	if len(o.Tools) >= MaxTools {
		return false, fmt.Errorf("%w: more than %d live MCP switches", ErrInvalid, MaxTools)
	}
	o.Serial++
	o.Tools = append(o.Tools, Entry{Server: server, Tool: tool, Decision: decision, By: by, At: at, Serial: o.Serial})
	o.record(Change{Serial: o.Serial, Op: OpSet, Server: server, Tool: tool, Decision: decision, By: by, At: at})
	return true, nil
}

// Reset removes the switch for server's tool, so the contract decides it again. It reports whether one was there.
func (o *Overlay) Reset(server, tool, by string, at time.Time) (bool, error) {
	if !ValidName(server) || !ValidName(tool) {
		return false, fmt.Errorf("%w: server %q, tool %q", ErrInvalid, server, tool)
	}
	for i, e := range o.Tools {
		if e.Server == server && e.Tool == tool {
			o.Tools = append(o.Tools[:i], o.Tools[i+1:]...)
			o.Serial++
			o.record(Change{Serial: o.Serial, Op: OpReset, Server: server, Tool: tool, By: by, At: at.UTC()})
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

// Since is the changes after serial, oldest first. A reader that remembers the serial it last put in force asks
// for what came after it; changes dropped by MaxChanges are not returned (the switches in force still say where
// each tool now stands).
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

// Encode is the overlay's file bytes: switches sorted by server then tool, one trailing newline.
func (o *Overlay) Encode() ([]byte, error) {
	if err := o.validate(o.Run); err != nil {
		return nil, err
	}
	sort.Slice(o.Tools, func(i, j int) bool {
		if o.Tools[i].Server != o.Tools[j].Server {
			return o.Tools[i].Server < o.Tools[j].Server
		}
		return o.Tools[i].Tool < o.Tools[j].Tool
	})
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
	if o.Tools == nil {
		o.Tools = []Entry{}
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
	case len(o.Tools) > MaxTools:
		return fmt.Errorf("%w: %d switches, more than %d", ErrInvalid, len(o.Tools), MaxTools)
	case len(o.Changes) > MaxChanges:
		return fmt.Errorf("%w: %d changes, more than %d", ErrInvalid, len(o.Changes), MaxChanges)
	}
	seen := make(map[[2]string]bool, len(o.Tools))
	for _, e := range o.Tools {
		k := [2]string{e.Server, e.Tool}
		if !ValidName(e.Server) || !ValidName(e.Tool) || !ValidDecision(e.Decision) || seen[k] || e.Serial > o.Serial {
			return fmt.Errorf("%w: switch %q/%q %q", ErrInvalid, e.Server, e.Tool, e.Decision)
		}
		seen[k] = true
	}
	for _, c := range o.Changes {
		if c.Serial > o.Serial || c.Op != OpSet && c.Op != OpReset || !ValidName(c.Server) || !ValidName(c.Tool) ||
			c.Op == OpSet && !ValidDecision(c.Decision) {
			return fmt.Errorf("%w: change %d", ErrInvalid, c.Serial)
		}
	}
	return nil
}
