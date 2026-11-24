// SPDX-License-Identifier: Apache-2.0

package contractsrc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// SystemPath is the authoritative general source. No environment or project overrides it.
const SystemPath = "/etc/tego/general.yaml"

// LoadedNote distinguishes a parsed source from launch support.
const LoadedNote = "Source loaded; general launch not built yet"

// Source is one selection observation. An empty digest is never an absence assertion.
type Source struct {
	Layer    string            `json:"layer"`
	Path     string            `json:"path,omitempty"`
	State    config.LayerState `json:"state"`
	SHA256   string            `json:"sha256,omitempty"`
	Resolved string            `json:"resolved,omitempty"`
	Owner    *int              `json:"owner,omitempty"`
	Mode     string            `json:"mode,omitempty"`
	Walk     []string          `json:"walk,omitempty"`
	Reason   string            `json:"reason,omitempty"`
}

// Profile identifies exact profile bytes in merge order, independently of the general hash.
type Profile struct {
	Name   string            `json:"name"`
	Kind   agent.ProfileKind `json:"kind"`
	SHA256 string            `json:"sha256"`
}

// Diagnostic is a loader finding safe for source inspection. Parser scalars are
// withheld because a malformed field may contain an environment value.
type Diagnostic struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// Error renders a source location, code and safe finding in the loader's format.
func (d Diagnostic) Error() string {
	return (agent.Diagnostic{File: d.File, Line: d.Line, Col: d.Column, Code: d.Code, Message: d.Message, Severity: d.Severity}).Error()
}

// General contains observation facts only. Hash covers profile-merged canonical bytes.
// Invalid/unknown sources never have a canonical hash or a loaded status.
type General struct {
	State       string       `json:"state"`
	Scope       string       `json:"scope,omitempty"`
	Name        string       `json:"name,omitempty"`
	Hash        string       `json:"general_hash,omitempty"`
	Sources     []Source     `json:"sources"`
	Profiles    []Profile    `json:"profiles"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
	Note        string       `json:"note"`
}

// Limits cover the whole graph, including intermediate expanded merge results.
var generalLoadLimits = agent.LoadLimits{SourceBytes: 8 << 20, Profiles: 128, ExpandedBytes: 16 << 20, Diagnostics: 64, DiagnosticBytes: 64 << 10}

type sourceReader func(string, bool, int, int64) (config.PolicySource, bool, error)

// ReadGeneral observes fixed paths, using only the selected passwd home from the machine
// snapshot. It never uses HOME, TEGO_CONFIG or the working folder to select a source.
func ReadGeneral(ctx context.Context, m *config.Machine, uid int) General {
	return ReadGeneralWithSource(ctx, m, uid, config.ReadPolicySource)
}

// ReadGeneralWithSource uses the fixed selector paths with an injected descriptor reader.
// It is a read-only source seam; it never authorizes a launch.
func ReadGeneralWithSource(ctx context.Context, m *config.Machine, uid int, read func(string, bool, int, int64) (config.PolicySource, bool, error)) General {
	return readGeneral(ctx, m, uid, SystemPath, read)
}

func readGeneral(ctx context.Context, m *config.Machine, uid int, systemPath string, read sourceReader) General {
	g := General{State: "absent", Sources: []Source{}, Profiles: []Profile{}, Note: "No general contract is selected. General launch is not built yet."}
	userPath := ""
	if m != nil && m.Home != "" {
		userPath = m.Home + "/.tego/general.yaml"
	}
	system := Source{Layer: "system", Path: systemPath, State: config.LayerUnknown}
	user := Source{Layer: "user", Path: userPath, State: config.LayerUnselected}
	g.Sources = []Source{system, user}
	if ctx == nil || read == nil {
		g.State, g.Note = "unknown", "General contract UNKNOWN: missing request context or source reader."
		return g
	}

	if m == nil || !m.BaselineKnown() {
		g.State, g.Note = "unknown", "General contract UNKNOWN: no complete machine config snapshot is available."
		g.Sources[0].Reason = g.Note
		return g
	}
	for i := range g.Sources {
		s := &g.Sources[i]
		if s.Path == "" {
			s.Reason = "No passwd home is selected"
			continue
		}
		if err := ctx.Err(); err != nil {
			g.problem(s, err)
			return g
		}
		if !filepath.IsAbs(s.Path) {
			g.problem(s, fmt.Errorf("general source needs an absolute passwd home"))
			return g
		}
		s.State = config.LayerUnknown
		data, absent, err := read(s.Path, i == 0, uid, agent.MaxContractSize)
		if err != nil {
			g.problem(s, err)
			return g
		}
		s.Walk = data.Walk
		if absent {
			s.State = config.LayerAbsent
			continue
		}
		s.State, s.SHA256, s.Resolved = config.LayerPresent, digest(data.Data), data.Resolved
		s.Owner, s.Mode = &data.Owner, fmt.Sprintf("%04o", data.Mode)
		g.Scope = "Your agents on this machine"
		if i == 0 {
			g.Scope = "Agents on this machine"
			g.Sources[1].Reason = "Not selected: the administrator supplied the general contract"
		}
		if err := ctx.Err(); err != nil {
			g.problem(s, err)
			return g
		}
		c, ds, err := agent.LoadBytesBounded(ctx, s.Path, data.Data, profilesrc.Chain(m), generalLoadLimits)
		if errors.Is(err, agent.ErrLoadBudget) || ctx.Err() != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			g.problem(s, err)
			return g
		}
		// YAML decoder errors can quote scalar values, including malformed env.set values.
		// The read-only view exposes locations and codes without disclosing those scalars.
		for i := range ds {
			if ds[i].Code == agent.CodeSchema {
				ds[i].Message = "Invalid contract syntax or field type; inspect this source location"
				ds[i].Fix = ""
			}
		}
		for _, d := range ds {
			g.Diagnostics = append(g.Diagnostics, Diagnostic{File: d.File, Line: d.Line, Column: d.Col, Code: d.Code, Message: d.Message, Severity: d.Severity})
		}
		if err != nil {
			g.State, g.Note = "invalid", "General contract could not be loaded. Review the source diagnostics."
			return g
		}
		if err := ctx.Err(); err != nil {
			g.problem(s, err)
			return g
		}
		canonical, err := c.Canonical()
		if err != nil {
			g.State, g.Note = "invalid", "General contract could not be canonicalised. Inspect the source."
			return g
		}
		if err := ctx.Err(); err != nil {
			g.problem(s, err)
			return g
		}
		if int64(len(canonical)) > generalLoadLimits.ExpandedBytes {
			g.problem(s, fmt.Errorf("%w: %s: canonical output; reduce the profile graph", agent.ErrLoadBudget, s.Path))
			return g
		}
		g.State, g.Name, g.Hash, g.Note = "loaded", c.Name, digest(canonical), LoadedNote
		for _, p := range c.Profiles() {
			g.Profiles = append(g.Profiles, Profile{Name: p.Name, Kind: p.Source, SHA256: hex.EncodeToString(p.SHA256[:])})
		}
		return g
	}
	return g
}

func (g *General) problem(s *Source, err error) {
	s.State, s.Reason = config.LayerUnknown, err.Error()
	g.State, g.Note = "unknown", "General contract UNKNOWN: "+err.Error()
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
