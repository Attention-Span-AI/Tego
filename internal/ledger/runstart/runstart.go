// SPDX-License-Identifier: Apache-2.0

package runstart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Load is the metadata-only ledger view for the contracts catalog. It
// uses the ledger repository's discovery and hardened readers, and the same
// Project function as the dashboard. It reads no action history or blobs and checks
// no chain. Unreadable starts are returned as findings rather than disappearing.
func Load(ctx context.Context, root string) (*Snapshot, []error) {
	return load(ctx, root, 100_000, 32<<20)
}

type repository interface {
	List(context.Context) ([]record.RunRef, error)
	Open(context.Context, string) (*ledger.Reader, error)
}

func load(ctx context.Context, root string, maxRuns, limit int) (*Snapshot, []error) {
	return loadFrom(ctx, root, ledger.NewRunRepository(root), maxRuns, limit)
}

func loadFrom(ctx context.Context, root string, repo repository, maxRuns, limit int) (*Snapshot, []error) {
	s := &Snapshot{Root: root, Runs: []*Run{}}
	retained, bytesCut := 0, false
	// A filesystem call may return after cancellation, so do not begin another
	// stage merely because the preceding repository operation returned success.
	if err := ctx.Err(); err != nil {
		return s, []error{err}
	}
	refs, err := repo.List(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return s, []error{ctxErr}
	}
	if errors.Is(err, os.ErrNotExist) && len(refs) == 0 {
		return s, nil
	}
	var problems []error
	if err != nil {
		problems = append(problems, err)
	}
	s.TotalRuns = len(refs)
	if len(refs) > maxRuns {
		refs = refs[:maxRuns]
		s.RunsCut = true
	}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			problems = append(problems, err)
			break
		}
		r, err := repo.Open(ctx, ref.ID)
		if ctxErr := ctx.Err(); ctxErr != nil {
			if r != nil {
				_ = r.Close() // the cancelled discovery owns this reader even when Open also reports an error
			}
			problems = append(problems, ctxErr)
			break
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		} // a directory before run_start
		if err != nil {
			problems = append(problems, fmt.Errorf("run %s: %w", ref.ID, err))
			continue
		}
		for event, err := range r.Iter() {
			if ctxErr := ctx.Err(); ctxErr != nil {
				problems = append(problems, ctxErr)
				break
			}
			if err == nil && (event.Kind != record.KindRunStart || event.Run != ref.ID) {
				err = errors.New("first record is not this run's run_start")
			}
			if err != nil {
				problems = append(problems, fmt.Errorf("run %s: %w", ref.ID, err))
				break
			}
			metadata, err := Project(event.Payload)
			if err != nil {
				problems = append(problems, fmt.Errorf("run %s: %w", ref.ID, err))
				break
			}
			metadata.ID, metadata.Agent, metadata.Start = ref.ID, event.Agent, event.TS
			size := 512 + len(metadata.ID) + len(metadata.Agent) + len(metadata.Contract) + len(metadata.Cwd) + len(metadata.Tier) + len(metadata.ContractHash) + len(metadata.EffectiveHash) + len(metadata.BaselineSHA256)
			if retained+size > limit {
				s.RunsCut = true
				bytesCut = true
				problems = append(problems, fmt.Errorf("run-start metadata exceeds %d bytes; some contracts may be missing", limit))
				break
			}
			retained += size
			s.Runs = append(s.Runs, &metadata)
			break
		}
		_ = r.Close()
		if bytesCut {
			break
		}
	}
	slices.SortFunc(s.Runs, func(a, b *Run) int {
		if n := b.Start.Compare(a.Start); n != 0 {
			return n
		}
		return strings.Compare(b.ID, a.ID)
	})
	return s, problems
}

// Run is the metadata a run_start records for contract discovery. Bad is reserved
// for callers projecting a partial ledger view; Load reports read errors separately.
type Run struct {
	ID, Agent, Contract, Cwd, Tier, ContractHash string
	EffectiveHash                                string
	BaselineSHA256                               string
	UID                                          int
	UIDKnown                                     bool
	Start                                        time.Time
	Bad                                          int
}

// Snapshot is a bounded collection of run-start metadata.
type Snapshot struct {
	Root             string
	Runs             []*Run
	TotalRuns        int
	RunsCut, Partial bool
}

// Project reads discovery metadata from a run_start payload. UIDKnown preserves
// the difference between a recorded uid 0 and an old record with no launcher uid.
// A decode error returns no metadata and its refusal reason.
func Project(payload []byte) (Run, error) {
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	var p struct {
		Tier           string `json:"tier"`
		DecisionPlane  string `json:"decision_plane"`
		Cwd            string `json:"cwd"`
		ContractSource struct {
			Path string `json:"path"`
		} `json:"contract_source"`
		UID           *int             `json:"launcher_uid"`
		ContractHash  string           `json:"contract_hash"`
		EffectiveHash string           `json:"effective_hash"`
		Baseline      *record.Baseline `json:"baseline"`
		RecordMinor   int              `json:"record_minor"`
	}
	if err := record.ValidateRunStartBaseline(payload); err != nil {
		return Run{}, err
	}
	err := json.Unmarshal(payload, &p)
	if err != nil {
		return Run{}, fmt.Errorf("run_start metadata: %w", err)
	}
	r := Run{Tier: p.Tier, Cwd: p.Cwd, Contract: p.ContractSource.Path, ContractHash: p.ContractHash}
	if p.Baseline != nil {
		r.EffectiveHash = p.EffectiveHash
		r.BaselineSHA256 = p.Baseline.SHA256
	}

	if p.UID != nil {
		r.UID, r.UIDKnown = *p.UID, true
	}
	return r, err
}
