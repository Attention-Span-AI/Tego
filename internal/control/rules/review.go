// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/draftcompile"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
)

// reviewedWrite is the single acknowledgement vocabulary for new files and edits.
// Dependencies includes every profile/preset byte digest, each loaded machine layer,
// the machine settings and the complete compiled output. Destination identity is
// checked again on the descriptor used by the leaf writer.
type reviewedWrite struct {
	ReviewID                                                  string
	Edits                                                     []Edit
	Text, Kind, Path, Base, Dependencies, Setup, Draft, Input string
	Directory                                                 registry.DirectoryIdentity
}

func (s *Service) reviewAck(r reviewedWrite) string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	} // Fields are known structs, strings and slices; fail closed if encoding fails.
	return r.ReviewID + "." + s.ack("reviewed-write-v2", "", rulefile.Sum(b))
}

// The identity is carried inside the native acknowledgement form value. The MAC
// binds it with the proposal; both identity and full token comparisons are constant time.
func reviewIdentity(ack string) string {
	id, _, ok := strings.Cut(ack, ".")
	if !ok || len(id) != 48 {
		return ""
	}
	return id
}

func (s *Service) reviewOK(got string, r reviewedWrite) bool {
	if r.ReviewID == "" || !hmac.Equal([]byte(reviewIdentity(got)), []byte(r.ReviewID)) {
		return false
	}
	want := s.reviewAck(r)
	return got != "" && want != "" && hmac.Equal([]byte(got), []byte(want))
}

// openDirectory opens a reviewed folder with no link followed, a variable so a test can say it could not.
var openDirectory = registry.OpenDirectoryContext

func directoryIdentityContext(ctx context.Context, path string, create bool) (registry.DirectoryIdentity, error) {
	d, err := openDirectory(ctx, filepath.Dir(path), create)
	if err != nil {
		return registry.DirectoryIdentity{}, err
	}
	defer func() { _ = d.Close() }() // No buffered writes are held by this descriptor.
	return d.Identity()
}

// compileSnapshot adapts injected test compilers only. Production checks and
// bindings always run together in the bounded draft compiler child.
func (s *Service) compileSnapshot(ctx context.Context, cc CheckContext, text []byte) (*agent.RuleTable, string, error) {
	if s.Compile == nil && s.Check == nil {
		return nil, "", errNoCompiler
	}
	rt, err := s.compile(ctx, cc, text)
	return rt, rulefile.Sum(text), err
}

func (p *ChangePlan) reviewed() reviewedWrite {
	kind, input := "structured", ""
	if p.Raw {
		kind = "raw"
		input = rulefile.Sum(p.input)
	}
	return reviewedWrite{ReviewID: p.ReviewID, Text: rulefile.Sum(p.text), Kind: kind, Input: input, Edits: p.Edits, Path: p.Contract, Base: p.Base, Dependencies: p.dependencies, Directory: p.directory}
}
func (p *NewPlan) reviewed() reviewedWrite {
	kind := "project"
	if p.Registry {
		kind = "registry"
	}
	return reviewedWrite{ReviewID: p.ReviewID, Text: rulefile.Sum(p.Text), Kind: kind, Path: p.File, Dependencies: p.dependencies, Setup: p.setup, Draft: p.Draft, Directory: p.directory}
}

func (s *Service) newSnapshot(ctx context.Context, p *NewPlan) (string, error) {
	if s.Compile != nil || s.Check != nil {
		_, sum, err := s.compileSnapshot(ctx, CheckContext{Contract: p.File, Cwd: p.Dir}, p.Text)
		return sum, err
	}
	cc := s.nextrunContext(CheckContext{Contract: p.File, Cwd: p.Dir})
	cc.PlannedDirectories = p.planned
	result, err := draftcompile.Check(ctx, draftcompile.Request{Machine: s.Machine, Context: cc, Text: p.Text})
	if err == nil {
		p.merged = result.Canonical
		p.sources = result.Sources
	}
	return result.Digest, err
}

func (s *Service) compareSnapshots(ctx context.Context, cc CheckContext, before, after []byte, p *ChangePlan) ([]string, error) {
	result, err := draftcompile.Check(ctx, draftcompile.Request{Machine: s.Machine, Context: s.nextrunContext(cc), Text: after, Before: before, Compare: true})
	if err != nil {
		return nil, err
	}
	return comparisonResult(result, before, p), nil
}

func comparisonResult(result draftcompile.Result, before []byte, p *ChangePlan) []string {
	p.rows, p.compared, p.repair = result.Rows, !result.Repair, result.Repair
	p.dependencies = result.Digest
	p.sources = result.Sources
	p.old = append([]byte{}, before...)
	p.Compiled = result.Digest
	if result.Repair {
		p.ComparisonReview = append(p.ComparisonReview, "The previous file does not compile. Review every rule in the repaired contract.")
		return []string{"Start a run with a valid contract (the previous file could not compile)"}
	}
	var out []string
	for _, r := range result.Rows {
		out = append(out, r.NewlyAllowed...)
		if r.Direction == agentdiff.CannotClassify {
			p.ComparisonReview = append(p.ComparisonReview, "Also review: "+r.Family+" changed and Tego cannot tell whether it allows more")
		}
	}
	return out
}
func (s *Service) verifySources(ctx context.Context, cc CheckContext, text, before []byte, want string) error {
	if want == "" {
		return nil
	} // An injected test compiler provides no filesystem dependencies.
	result, err := draftcompile.Check(ctx, draftcompile.Request{Machine: s.Machine, Context: s.nextrunContext(cc), Text: text, Before: before, Compare: before != nil, SourceOnly: true})
	if err != nil {
		return err
	}
	if result.Sources != want {
		return fmt.Errorf("%w: the rules this contract inherits changed since you reviewed it", ErrStale)
	}
	return nil
}
