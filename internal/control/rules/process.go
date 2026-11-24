// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/draftcompile"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type serviceState struct {
	DraftNow                   *time.Time
	CompilerPool               string
	Drafts                     *draftTransfer
	Caller                     *config.CallerContext
	Ledger, Home, Anchor, PATH string
	Refuse                     []string
	Machine                    []byte
	AckKey                     []byte
	Starts                     []start
}
type serviceRequest struct {
	State  serviceState
	Method string
	Args   []byte
}
type serviceReply struct {
	Drafts *draftTransfer
	Value  []byte
	Error  string
	Kinds  []int
	Starts []start
}

var serviceErrors = []error{ErrNoContract, ErrNoLine, ErrStale, ErrNeedsAck, ErrRefused, ErrNotWritable, ErrNotPending, ErrAckMismatch, rulefile.ErrJournal, rulefile.ErrGuard, rulefile.ErrStale, ErrReviewGone, ErrAlreadyApplied, contracts.ErrCompileUnfinished, ErrNotCompiled, rulefile.ErrNoChange}

func init() {
	pathcheck.Register("control.rules", serviceOperation)
	pathcheck.Register("control.resolve", func(ctx context.Context, payload []byte) ([]byte, error) {
		var p string
		if err := pathcheck.Decode(payload, &p); err != nil {
			return nil, err
		}
		return pathcheck.Encode(resolvedPath(p))
	})
}

// Explicit callback seams are test implementations. Production never supplies
// them and always runs path-dependent work in its bounded helper.
// unclassified is the context of a read made with no request (a context-free Contracts, Current, History or Feed of a
// remote service): its helper is started as a governed program's, never as a person's, so such a read cannot take the
// slots kept for a person's own checks (contracts.personHelperReserve). A request's read passes its own context
// (ForRequest), which says who asked.
func unclassified() context.Context {
	return contracts.WithGovernedCaller(context.Background(), func() bool { return true })
}

// compilerContext is ctx with the dashboard's compiler pool; a worker started for a governed request (it reads as a
// governed program's process, contracts.serveRequest) also marks its compilations governed, which never take the
// compiler slot kept for a person's own check (draftcompile.WithGoverned).
func compilerContext(ctx context.Context, pool string) context.Context {
	ctx = draftcompile.WithPool(ctx, pool)
	if contracts.GovernedCaller(ctx) {
		ctx = draftcompile.WithGoverned(ctx)
	}
	return ctx
}

func (s *Service) remote() bool {
	return !pathcheck.InHelper() && s.Compile == nil && s.Check == nil && s.Writer == nil && s.live == nil && s.readsHeld == nil && s.block == nil && s.facts == nil && s.unblock == nil && s.overlay == nil && s.Resolver == nil && s.clock == nil
}

func remoteService[T any](s *Service, ctx context.Context, method string, args any) (T, error) {
	ctx, cancel := pathcheck.Bound(ctx)
	defer cancel()
	ctx = contracts.WithCallerContext(ctx)
	var zero T
	encoded, err := pathcheck.Encode(args)
	if err != nil {
		return zero, err
	}
	caller := contracts.CallerContext(ctx)
	var draftNow *time.Time
	if s.Now != nil {
		selected := *caller
		now := s.Now()
		draftNow = &now
		selected.RuleDate = now.Format(time.DateOnly)
		caller = &selected
		ctx = contracts.ContextWithCaller(ctx, selected)
	}
	path := s.PATH
	if path == "" {
		path = caller.PATH
	}
	state := serviceState{DraftNow: draftNow, Caller: caller, Ledger: s.Ledger, Home: s.Home, Anchor: s.Anchor, PATH: path, Refuse: s.Refuse, AckKey: s.key()}
	pool := sha256.Sum256(state.AckKey)
	state.CompilerPool = fmt.Sprintf("%x", pool[:])
	if s.Machine != nil {
		state.Machine, err = json.Marshal(s.Machine.Snapshot())
		if err != nil {
			return zero, err
		}
	}
	if retainedDraftOperation(method, args) {
		var release func()
		state.Drafts, release, err = s.leaseDrafts(ctx)
		if err != nil {
			return zero, err
		}
		defer release()
	}
	s.mu.Lock()
	for _, st := range s.cache {
		state.Starts = append(state.Starts, st)
	}
	s.mu.Unlock()
	var reply serviceReply
	if err = pathcheck.Call(ctx, "control.rules", serviceRequest{State: state, Method: method, Args: encoded}, &reply); err != nil {
		return zero, err
	}
	if state.Drafts != nil {
		if err := s.importDrafts(reply.Drafts); err != nil {
			return zero, err
		}
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]start{}
	}
	for _, st := range reply.Starts {
		s.cache[st.Run] = st
	}
	s.mu.Unlock()
	if len(reply.Value) > 0 {
		if err = json.Unmarshal(reply.Value, &zero); err != nil {
			return zero, err
		}
	}
	if reply.Error != "" {
		var causes []error
		for _, kind := range reply.Kinds {
			if kind >= 0 && kind < len(serviceErrors) {
				causes = append(causes, serviceErrors[kind])
			}
		}
		return zero, &pathcheck.RemoteError{Message: reply.Error, Causes: causes}
	}
	return zero, nil
}
func (s *Service) pack(value any, err error) ([]byte, error) {
	reply := serviceReply{}
	if s.draftLease {
		reply.Drafts = s.exportDrafts()
	}
	if err != nil {
		reply.Error = pathcheck.LocationError(err).Error()
		for i, e := range serviceErrors {
			if errors.Is(err, e) {
				reply.Kinds = append(reply.Kinds, i)
			}
		}
	}
	var encodeErr error
	reply.Value, encodeErr = json.Marshal(value)
	if encodeErr != nil {
		return nil, encodeErr
	}
	for _, st := range s.cache {
		reply.Starts = append(reply.Starts, st)
	}
	return pathcheck.Encode(reply)
}
func serviceOperation(parent context.Context, payload []byte) ([]byte, error) {
	var req serviceRequest
	if err := pathcheck.Decode(payload, &req); err != nil {
		return nil, err
	}
	s, err := serviceFromState(parent, req.State)
	if err != nil {
		return nil, err
	}

	ctx, cancel := pathcheck.Context(parent)
	defer cancel()
	ctx = compilerContext(ctx, req.State.CompilerPool)
	switch req.Method {
	case "PendingOn":
		var a struct {
			Run string
			IDs []string
		}
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		return s.pack(s.PendingOn(ctx, a.Run, a.IDs), nil)
	case "CompareSource":
		var a struct{ Run string }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		return s.pack(s.CompareSource(ctx, a.Run), nil)
	case "Contracts":
		var a struct{}
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.Contracts()
		return s.pack(v, err)
	case "Current":
		var a struct{ Ref string }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.Current(a.Ref)
		return s.pack(v, err)
	case "PlanChange":
		var a struct{ Req ChangeReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.PlanChange(ctx, a.Req)
		return s.pack(v, err)
	case "ApplyChange":
		var a struct{ Req ChangeReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.ApplyChange(ctx, a.Req)
		return s.pack(v, err)
	case "PlanRaw":
		var a struct{ Req RawReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.PlanRaw(ctx, a.Req)
		return s.pack(v, err)
	case "ApplyRaw":
		var a struct{ Req RawReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.ApplyRaw(ctx, a.Req)
		return s.pack(v, err)
	case "History":
		var a struct{ Ref string }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.History(a.Ref)
		return s.pack(v, err)
	case "Revert":
		var a struct{ Req RevertReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.Revert(ctx, a.Req)
		return s.pack(v, err)
	case "Feed":
		var a struct{}
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.Feed()
		return s.pack(v, err)
	case "PlanNew":
		var a struct{ Req NewReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.PlanNew(ctx, a.Req)
		return s.pack(v, err)
	case "CreateNew":
		var a struct {
			Req  NewReq
			Base string
		}
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.CreateNew(ctx, a.Req, a.Base)
		return s.pack(v, err)
	case "DescribeNew":
		var a struct{ Ref string }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.DescribeNew(ctx, a.Ref)
		return s.pack(v, err)
	case "ActOn":
		var a struct{ R ActReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.ActOn(ctx, a.R)
		return s.pack(v, err)
	case "ApplyNow":
		var a struct{ R ApplyNowReq }
		if err := pathcheck.Decode(req.Args, &a); err != nil {
			return nil, err
		}
		v, err := s.ApplyNow(ctx, a.R)
		return s.pack(v, err)

	default:
		return nil, fmt.Errorf("unknown dashboard rules operation %q", req.Method)
	}
}

// A timed-out catalogue still lists every recorded source. These fallbacks use
// ledger data alone, never resolving or checking a source path in the service.
func (s *Service) unavailableContracts(reason error) []ContractRef {
	local := &Service{Ledger: s.Ledger, ledgerOnly: true}
	sts, err := local.starts()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []ContractRef
	for _, st := range sts {
		if st.Contract == "" {
			continue
		}
		ref := refOf(st.Contract)
		if seen[ref] {
			for i := range out {
				if out[i].Ref == ref {
					out[i].Runs++
				}
			}
			continue
		}
		seen[ref] = true
		out = append(out, ContractRef{Ref: ref, Path: st.Contract, Agent: filepath.Base(st.Contract), Runs: 1, LastRun: st.Run, LastAt: st.At, Why: reason.Error()})
	}
	es, _ := rulefile.ReadJournal(s.Ledger)
	for _, e := range es {
		if e.Op != rulefile.OpCreate || !filepath.IsAbs(e.Contract) {
			continue
		}
		ref := refOf(e.Contract)
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ContractRef{Ref: ref, Path: e.Contract, Agent: filepath.Base(e.Contract), LastAt: e.At, Why: reason.Error()})
		}
	}
	return out
}

func serviceFromState(_ context.Context, state serviceState) (*Service, error) {
	if state.Caller == nil {
		return nil, errors.New("missing caller context")
	}
	s := &Service{caller: state.Caller, Ledger: state.Ledger, Home: state.Home, Anchor: state.Anchor, PATH: state.PATH, Refuse: state.Refuse, AckKey: state.AckKey, cache: map[string]start{}}
	for _, st := range state.Starts {
		s.cache[st.Run] = st
	}
	if state.DraftNow != nil {
		now := *state.DraftNow
		s.Now = func() time.Time { return now }
	}
	if state.Drafts != nil {
		if err := s.importDrafts(state.Drafts); err != nil {
			return nil, err
		}
		s.draftLease = true
	}
	if state.Machine != nil {
		var snapshot config.Snapshot
		if err := json.Unmarshal(state.Machine, &snapshot); err != nil {
			return nil, err
		}
		s.Machine = snapshot.Restore()
	}
	return s, nil
}
