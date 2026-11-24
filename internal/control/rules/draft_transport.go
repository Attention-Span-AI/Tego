// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"time"
)

// Only the trusted helper pipe carries this store. A request owns the entire
// bounded store until its reply arrives; on an abandoned exchange it stays empty.
// That loses pending reviews safely, including any Save whose outcome is uncertain.
type draftTransfer struct {
	Entries map[string]draftTransferEntry
	Next    uint64
}
type draftTransferEntry struct {
	Payload []byte
	At      time.Time
	Session string
	Order   uint64
}

func (s *Service) leaseDrafts(ctx context.Context) (*draftTransfer, func(), error) {
	s.drafts.Lock()
	if s.drafts.remoteGate == nil {
		s.drafts.remoteGate = make(chan struct{}, 1)
	}
	gate := s.drafts.remoteGate
	s.drafts.Unlock()
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-gate
		return nil, nil, err
	}
	transfer := s.exportDrafts()
	return transfer, func() { <-gate }, nil
}
func (s *Service) exportDrafts() *draftTransfer {
	s.drafts.Lock()
	defer s.drafts.Unlock()
	s.drafts.expire(s.draftTime())
	out := &draftTransfer{Entries: make(map[string]draftTransferEntry, len(s.drafts.entries)), Next: s.drafts.next}
	for id, e := range s.drafts.entries {
		out.Entries[id] = draftTransferEntry{e.payload, e.at, e.session, e.order}
	}
	s.drafts.entries = nil
	return out
}
func (s *Service) importDrafts(in *draftTransfer) error {
	if in == nil {
		return errors.New("missing reviewed-draft reply")
	}
	if len(in.Entries) > maxDrafts {
		return ErrReviewGone
	}
	entries := make(map[string]draftState, len(in.Entries))
	total := 0
	for id, e := range in.Entries {
		total += len(e.Payload)
		if len(id) != 48 || len(e.Payload) > maxDraftBytes || total > maxDraftStoreBytes || e.Order > in.Next {
			return ErrReviewGone
		}
		entries[id] = draftState{payload: e.Payload, size: len(e.Payload), at: e.At, session: e.Session, order: e.Order}
	}
	s.drafts.Lock()
	defer s.drafts.Unlock()
	s.drafts.entries, s.drafts.next = entries, in.Next
	return nil
}
func retainedDraftOperation(method string, args any) bool {
	switch method {
	case "PlanNew":
		a, ok := args.(struct{ Req NewReq })
		return !ok || !a.Req.PreviewOnly
	case "PlanChange":
		a, ok := args.(struct{ Req ChangeReq })
		return !ok || !a.Req.PreviewOnly
	case "PlanRaw", "ApplyRaw", "ApplyChange", "CreateNew":
		return true
	default:
		return false
	}
}
