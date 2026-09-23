// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"container/list"
	"crypto/sha256"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RetryKey identifies a request by what a retry repeats: the method, the path, the body and the
// credential — the credential and the body by hash, never by value (I5).
type RetryKey [32]byte

// RetryHeader is the count an Anthropic SDK puts on a retried request. A non-numeric or negative value
// is treated as absent, leaving only the hash match (edge case #29).
const RetryHeader = "x-stainless-retry-count"

// DefaultRetryEntries is the retry cache's size (R24).
const DefaultRetryEntries = 256

// DefaultRetryTTL is how long a request stays a candidate original: the longest observed client wait
// plus a margin (R24). Past it, a same-key request is a new step — indistinguishable from a legitimate
// late duplicate, a stated limit rather than a guess.
const DefaultRetryTTL = 650 * time.Second

// ComputeRetryKey is the R23 key: sha256(method ‖ 0 ‖ path ‖ 0 ‖ sha256(body) ‖ 0 ‖ sha256(credential)).
// It is deterministic and holds no credential or body bytes of its own.
func ComputeRetryKey(method, path string, body []byte, credential [32]byte) RetryKey {
	bodySum := sha256.Sum256(body)
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(bodySum[:])
	h.Write([]byte{0})
	h.Write(credential[:])
	var key RetryKey
	copy(key[:], h.Sum(nil))
	return key
}

// RetryCount reads the SDK's retry counter. ok is false when the header is absent, empty, not a number
// or negative (#29).
func RetryCount(h http.Header) (int, bool) {
	v := h.Get(RetryHeader)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// retrySlot is what a remembered request is found by: the process that sent it and its key. A retry is a
// repeat by the same caller, so a byte-identical request from another process of the run (a second subagent on
// the same credential) is a request of its own, never a retry of the first (R23).
type retrySlot struct {
	pid int
	key RetryKey
}

// retryEntry is one remembered request.
type retryEntry struct {
	slot retrySlot
	id   string
	seen uint64 // monotonic nanoseconds: NTP steps the wall clock, never this one (#25)
}

// retryCache is the per-listener LRU of recent requests (R24). It is run-scoped: a restart cannot
// outlive the run whose ids it holds.
type retryCache struct {
	mu      sync.Mutex
	max     int
	ttl     uint64
	entries map[retrySlot]*list.Element
	order   *list.List
	// latest is each process's most recent request, the fallback for a request whose SDK says it is a
	// retry but whose key matches nothing (a body the client changed between attempts). It holds at most
	// max processes; past that the one whose latest request is oldest is forgotten.
	latest map[int]retryEntry
}

func newRetryCache(entries int, ttl time.Duration) *retryCache {
	if entries <= 0 {
		entries = DefaultRetryEntries
	}
	if ttl <= 0 {
		ttl = DefaultRetryTTL
	}
	return &retryCache{
		max:     entries,
		ttl:     uint64(ttl.Nanoseconds()),
		entries: make(map[retrySlot]*list.Element, entries),
		order:   list.New(),
		latest:  map[int]retryEntry{},
	}
}

// lookup returns the id of the request this key last named from process pid, when it is still inside the TTL.
func (c *retryCache) lookup(pid int, key RetryKey, now uint64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	slot := retrySlot{pid: pid, key: key}
	el, ok := c.entries[slot]
	if !ok {
		return "", false
	}
	e := el.Value.(*retryEntry)
	if c.expired(e, now) {
		c.order.Remove(el)
		delete(c.entries, slot)
		return "", false
	}
	c.order.MoveToFront(el)
	return e.id, true
}

// recent returns the most recent request process pid sent through this listener, inside the TTL.
func (c *retryCache) recent(pid int, now uint64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.latest[pid]
	if !ok || e.id == "" || c.expired(&e, now) {
		return "", false
	}
	return e.id, true
}

// rememberLatest records a request whose identity the key cannot establish — a body capture the cap
// truncated, whose hash is over a prefix two different requests can share (R23). It stays pid's most recent
// request, which is all the SDK-counter fallback needs, and is never findable by that hash.
func (c *retryCache) rememberLatest(pid int, id string, now uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLatest(retryEntry{slot: retrySlot{pid: pid}, id: id, seen: now})
}

// remember records a request of process pid as a candidate original, evicting the least recently used entry
// at the cap.
func (c *retryCache) remember(pid int, key RetryKey, id string, now uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	slot := retrySlot{pid: pid, key: key}
	c.setLatest(retryEntry{slot: slot, id: id, seen: now})
	if el, ok := c.entries[slot]; ok {
		e := el.Value.(*retryEntry)
		e.id, e.seen = id, now
		c.order.MoveToFront(el)
		return
	}
	c.entries[slot] = c.order.PushFront(&retryEntry{slot: slot, id: id, seen: now})
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		if oldest == nil {
			return
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*retryEntry).slot)
	}
}

// setLatest makes e its process's most recent request, forgetting the process whose latest request is oldest
// when a new process would pass the cap. c.mu is held.
func (c *retryCache) setLatest(e retryEntry) {
	pid := e.slot.pid
	if _, ok := c.latest[pid]; !ok && len(c.latest) >= c.max {
		victim, first := 0, true
		for p, old := range c.latest {
			if first || old.seen < c.latest[victim].seen {
				victim, first = p, false
			}
		}
		delete(c.latest, victim)
	}
	c.latest[pid] = e
}

// expired reports whether e is older than the TTL. A monotonic clock never goes backwards, so a now
// below seen can only be a scripted clock in a test; it is treated as "not expired".
func (c *retryCache) expired(e *retryEntry, now uint64) bool {
	return now > e.seen && now-e.seen > c.ttl
}
