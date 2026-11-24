// SPDX-License-Identifier: Apache-2.0

package rules

import "context"

// RequestService binds the legacy context-free reads to one HTTP request and its
// reusable helper. The service's caches and acknowledgement key stay shared.
type RequestService struct {
	*Service
	ctx context.Context
}

// ForRequest supplies cancellation and helper reuse to context-free view methods.
func (s *Service) ForRequest(ctx context.Context) *RequestService { return &RequestService{s, ctx} }

// Contracts lists the recorded sources within this request's bound.
func (s *RequestService) Contracts() ([]ContractRef, error) {
	if !s.remote() {
		return s.Service.Contracts()
	}
	out, err := remoteService[[]ContractRef](s.Service, s.ctx, "Contracts", struct{}{})
	if err != nil {
		return s.unavailableContracts(err), nil
	}
	return out, nil
}

// Current reads a guarded source within this request's bound.
func (s *RequestService) Current(ref string) (*Current, error) {
	if !s.remote() {
		return s.Service.Current(ref)
	}
	return remoteService[*Current](s.Service, s.ctx, "Current", struct{ Ref string }{ref})
}

// History reads a source's change history within this request's bound.
func (s *RequestService) History(ref string) ([]HistoryEntry, error) {
	if !s.remote() {
		return s.Service.History(ref)
	}
	return remoteService[[]HistoryEntry](s.Service, s.ctx, "History", struct{ Ref string }{ref})
}

// Feed reads change history within this request's bound.
func (s *RequestService) Feed() ([]FeedEntry, error) {
	if !s.remote() {
		return s.Service.Feed()
	}
	return remoteService[[]FeedEntry](s.Service, s.ctx, "Feed", struct{}{})
}
