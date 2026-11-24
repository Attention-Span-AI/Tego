// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/setup"
)

const draftTTL = 30 * time.Minute
const maxDrafts = 64
const maxDraftBytes = 8 << 20
const maxDraftStoreBytes = 32 << 20

type draftState struct {
	payload []byte
	size    int
	at      time.Time
	session string
	order   uint64
}
type compositionDraft struct {
	Session, Dir, Name string
	Registry           bool
	Writes, Withheld   []string
	Result             setup.Result
}
type draftStore struct {
	remoteGate chan struct{}
	sync.Mutex
	entries map[string]draftState
	next    uint64
}

// newDraftID uses 192 bits from the system random source and fails closed.
func newDraftID() string {
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(random[:])
}

func (s *Service) keepDraft(session string, r *setup.Result, p *NewPlan) string {
	id := newDraftID()
	if id == "" {
		return ""
	}
	now := s.draftTime()
	s.drafts.Lock()
	defer s.drafts.Unlock()
	encoded, err := json.Marshal(compositionDraft{Session: session, Dir: p.Dir, Name: p.Name, Registry: p.Registry, Writes: p.writeDirs, Withheld: p.Withheld, Result: *r})
	if err != nil || len(encoded) > maxDraftBytes {
		return ""
	}
	if _, exists := s.drafts.entries[id]; exists {
		return ""
	}
	s.drafts.put(id, draftState{payload: encoded, session: session, at: now})
	return id
}

func (s *Service) restoreDraft(req NewReq, p *NewPlan) (*setup.Result, error) {
	s.drafts.Lock()
	s.drafts.expire(s.draftTime())
	entry, ok := s.drafts.entries[req.Draft]
	s.drafts.Unlock()
	var saved compositionDraft
	if !ok || json.Unmarshal(entry.payload, &saved) != nil || saved.Session != req.Session {
		return nil, ErrReviewGone
	}
	if p.Dir != saved.Dir || p.Name != saved.Name || p.Registry != saved.Registry {
		return nil, errors.New("this draft belongs to another contract destination; preview its source again")
	}
	text, _, err := rulesview.RestoreEnv(string(req.Text), string(saved.Result.Contract))
	if err != nil {
		return nil, errors.New(envRefusal)
	}
	r := saved.Result
	r.Contract = []byte(text)
	p.writeDirs = slices.Clone(saved.Writes)
	p.Withheld = slices.Clone(saved.Withheld)
	return &r, nil
}

// Setup metadata can differ between two authenticated drafts with identical
// final YAML. Bind the folders and displayed setup context as well as the bytes.
func setupBinding(r *setup.Result, p *NewPlan) (string, error) {
	b, err := json.Marshal(struct {
		Result                   *setup.Result
		Dir, Name, Command, From string
		Writes, Withheld         []string
	}{r, p.Dir, p.Name, p.Command, p.FromRun, p.writeDirs, p.Withheld})
	if err != nil {
		return "", errors.New("setup metadata could not be bound; preview the source again")
	}
	return rulefile.Sum(b), nil
}

func (s *Service) draftTime() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (d *draftStore) expire(now time.Time) {
	for k, v := range d.entries {
		if now.Sub(v.at) >= draftTTL {
			delete(d.entries, k)
		}
	}
}

// Both source compositions and reviewed proposals share these memory limits.
// Caller holds the store lock. Evict the inserting session's oldest entry first;
// if it has none, evict the global oldest. Insertion order breaks clock ties.
func (d *draftStore) put(id string, v draftState) {
	if d.entries == nil {
		d.entries = map[string]draftState{}
	}
	d.expire(v.at)
	delete(d.entries, id)
	v.size = len(v.payload)
	if v.size > maxDraftBytes {
		return
	}
	for {
		total := v.size
		oldest, ownOldest := "", ""
		for k, e := range d.entries {
			total += e.size
			if oldest == "" || e.at.Before(d.entries[oldest].at) || e.at.Equal(d.entries[oldest].at) && e.order < d.entries[oldest].order {
				oldest = k
			}
			if e.session == v.session && (ownOldest == "" || e.at.Before(d.entries[ownOldest].at) || e.at.Equal(d.entries[ownOldest].at) && e.order < d.entries[ownOldest].order) {
				ownOldest = k
			}
		}
		if ownOldest != "" {
			oldest = ownOldest
		}
		if len(d.entries) < maxDrafts && total <= maxDraftStoreBytes {
			break
		}
		delete(d.entries, oldest)
	}
	d.next++
	v.order = d.next
	d.entries[id] = v
}
