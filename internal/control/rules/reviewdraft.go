// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/setup"
)

// ErrReviewGone means the authenticated proposal is no longer held by this service.
var ErrReviewGone = errors.New("this draft is no longer available; review it again before saving")

// ErrAlreadyApplied is a stale Save whose reviewed bytes are already on disk.
var ErrAlreadyApplied = fmt.Errorf("%w: the reviewed bytes are already in the contract", ErrStale)

// Serialization owns every slice/map independently of both the caller and later
// saves. Private plan fields are captured explicitly beside the public rendering.
type reviewedDraft struct {
	Session   string
	Binding   reviewedWrite
	Sources   string
	Old, Text []byte
	New       *NewPlan
	Change    *ChangePlan
	Setup     *setup.Result
	Request   NewReq
	Writes    []string
	Input     []byte
}

func (s *Service) keepReview(session, ack string, r reviewedDraft) error {
	r.Session = session
	data, err := json.Marshal(r)
	id := reviewIdentity(ack)
	if err != nil || id == "" || len(data) > maxDraftBytes || !s.reviewOK(ack, r.Binding) {
		return ErrReviewGone
	}
	s.drafts.Lock()
	defer s.drafts.Unlock()
	// Even a random-source collision must refuse instead of replacing a review.
	if _, exists := s.drafts.entries[id]; exists {
		return ErrReviewGone
	}
	s.drafts.put(id, draftState{payload: data, session: session, at: s.draftTime()})
	return nil
}

func (s *Service) reviewedDraft(session, ack string) (*reviewedDraft, error) {
	return s.loadReview(session, ack, false)
}

func (s *Service) takeReview(session, ack string) (*reviewedDraft, error) {
	return s.loadReview(session, ack, true)
}

func (s *Service) loadReview(session, ack string, consume bool) (*reviewedDraft, error) {
	s.drafts.Lock()
	defer s.drafts.Unlock()
	s.drafts.expire(s.draftTime())
	id := reviewIdentity(ack)
	saved, ok := s.drafts.entries[id]
	if !ok {
		return nil, ErrReviewGone
	}
	var r reviewedDraft
	if json.Unmarshal(saved.payload, &r) != nil || !hmac.Equal([]byte(session), []byte(r.Session)) || !s.reviewOK(ack, r.Binding) {
		return nil, ErrReviewGone
	}
	// Claim atomically after validation and before publication so concurrent Saves
	// cannot reuse a review. A later publication failure requires a new Preview.
	if consume {
		delete(s.drafts.entries, id)
	}
	return &r, nil
}

func (s *Service) keepChange(session string, p *ChangePlan, input []byte) {
	if p.Err != "" {
		return
	}
	p.ReviewID = newDraftID()
	p.Ack = s.reviewAck(p.reviewed())
	if err := s.keepReview(session, p.Ack, reviewedDraft{Binding: p.reviewed(), Sources: p.sources, Old: p.old, Text: p.text, Change: p, Input: input}); err != nil {
		p.Err = err.Error()
		p.Ack = ""
	}
}

func (s *Service) savedChange(ctx context.Context, session, ack, ref, base string, edits []Edit, input []byte, raw bool) (*contractInfo, *ChangePlan, error) {
	if ack == "" {
		return nil, nil, ackErr(ack)
	}
	r, err := s.reviewedDraft(session, ack)
	if err != nil {
		return nil, nil, err
	}
	p := r.Change
	if p == nil || p.Raw != raw || p.Ref != ref {
		return nil, nil, ackErr(ack)
	}
	c, f, err := s.writable(ref)
	if err != nil {
		return nil, nil, err
	}
	if base == "" || base != p.Base || f.SHA256 != p.Base {
		if base == p.Base && f.SHA256 == rulefile.Sum(r.Text) {
			return nil, nil, ErrAlreadyApplied
		}
		return nil, nil, ErrStale
	}
	if raw && !bytes.Equal(input, r.Input) || !raw && !slices.Equal(edits, p.Edits) {
		return nil, nil, fmt.Errorf("%w: %w", ErrRefused, ackErr(ack))
	}
	if f.DirectoryIdentity != r.Binding.Directory {
		return nil, nil, ErrStale
	}
	p.text, p.old, p.input, p.sources, p.directory = r.Text, r.Old, r.Input, r.Sources, r.Binding.Directory
	// Compile and compare the held bytes against the current guarded source. This
	// never calls a proposal builder or regenerates comments, setup, or run output.
	check := &ChangePlan{}
	if _, err := s.newlyAllows(ctx, c.context(s), f.Text, p.text, check); err != nil {
		return nil, nil, refusedUnlessUnfinished(err)
	}
	p.dependencies = check.dependencies
	if !s.reviewOK(ack, p.reviewed()) {
		return nil, nil, fmt.Errorf("%w: the rules this contract inherits changed; review again", ackErr(ack))
	}
	// Stale described the old editor base. The submitted and current source now
	// both match this review; do not carry that historical warning into apply.
	p.Stale = false
	if _, err := s.takeReview(session, ack); err != nil {
		return nil, nil, err
	}
	return c, p, nil
}

// refusedUnlessUnfinished is err refused as the contract's own (ErrRefused, with its words), unless it is a check that
// did not finish (a busy or unfinished compile, a location that does not answer): that keeps its type, so the page
// answers it as every unfinished check (503, its cause) and not as a refusal of the contract, and the review is held.
func refusedUnlessUnfinished(err error) error {
	if pathcheck.IsNotFinished(err) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrRefused, err)
}

// directoryOpenFailure is what a Save says when the reviewed folder could not be opened again. A folder that is gone or
// replaced by a link (ENOENT, ENOTDIR, ELOOP) really differs from the one reviewed: stale. A location that does not
// answer, or a request that ran out of time, is a check that did not finish and keeps its own words. Anything else is
// refused in the system's own words: nothing is known to have changed.
func directoryOpenFailure(err error) error {
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("%w: %v", ErrStale, err)
	}
	if mapped := pathcheck.LocationError(err); pathcheck.IsNotFinished(mapped) {
		return mapped
	}
	return fmt.Errorf("%w: %v", ErrRefused, err)
}

func (s *Service) savedNew(ctx context.Context, req NewReq, ack string) (*NewPlan, *setup.Result, error) {
	r, err := s.reviewedDraft(req.Session, ack)
	if err != nil {
		return nil, nil, err
	}
	p := r.New
	if p == nil || r.Setup == nil {
		return nil, nil, ErrStale
	}
	dir, problem, unfinished := s.projectDir(ctx, req.Dir)
	if unfinished != nil {
		// The folder was not checked, so it is not known to differ from the one reviewed: say why, never "changed".
		return nil, nil, unfinished
	}
	name, _ := newName(req.Name, dir)
	if problem != "" || dir != p.Dir || name != p.Name || req.Registry != p.Registry {
		return nil, nil, ErrStale
	}
	if req.Draft != r.Request.Draft && req.Draft != p.Draft {
		return nil, nil, ErrStale
	}
	if req.Text != nil {
		// A native Save posts the redacted final text; direct callers may return the
		// original input. Neither becomes the proposal at this point.
		if len(req.Text) == 0 || !(bytes.Equal(req.Text, r.Request.Text) || string(req.Text) == rulesview.RedactEnvText(string(p.Text))) {
			return nil, nil, ErrStale
		}
	} else {
		original := r.Request
		original.PrepareDirectories, req.PrepareDirectories = false, false
		original.Draft, req.Draft = "", ""
		a, errA := json.Marshal(original)
		b, errB := json.Marshal(req)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			return nil, nil, ErrStale
		}
	}
	p.dependencies, p.setup, p.directory = r.Binding.Dependencies, r.Binding.Setup, r.Binding.Directory
	p.sources, p.planned = r.Sources, slices.Clone(r.Setup.MakeDirs)
	// Restore private publication metadata from the retained setup, not the form.
	p.writeDirs = slices.Clone(r.Writes)
	identity, err := directoryIdentityContext(ctx, p.File, false)
	if err != nil {
		return nil, nil, directoryOpenFailure(err)
	}
	if identity != p.directory {
		return nil, nil, ErrStale
	}
	if !p.Registry {
		if _, err := os.Lstat(p.File); err == nil {
			return nil, nil, fmt.Errorf("%w: %s already holds %s; review again", ErrStale, p.Dir, NewFile)
		} else if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%w: %v", ErrRefused, err)
		}
	}
	if p.Registry {
		if s.Machine != nil {
			if err := registryNoLinks(s.Machine.Registry.Value); err != nil {
				return nil, nil, fmt.Errorf("%w: %v", ErrRefused, err)
			}
		}
		if _, err := s.registrySave(p, p.Text).Check(); err != nil {
			var se *registry.SaveError
			if errors.As(err, &se) && (se.Step == registry.SaveExists || se.Step == registry.SaveTaken && se.Entry != nil) {
				return nil, nil, fmt.Errorf("%w: %s", ErrStale, saveProblem(err, p.Name))
			}
			return nil, nil, fmt.Errorf("%w: %s", ErrRefused, saveProblem(err, p.Name))
		}
	}
	digest, err := s.newSnapshot(ctx, p)
	if err != nil {
		return nil, nil, refusedUnlessUnfinished(err)
	}
	p.dependencies = digest
	if !s.reviewOK(ack, p.reviewed()) {
		return nil, nil, ErrStale
	}
	if _, err := s.takeReview(req.Session, ack); err != nil {
		return nil, nil, err
	}
	return p, r.Setup, nil
}
