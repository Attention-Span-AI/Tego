// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The usage counters a cost budget charges at rates of their own (R29): the 1-hour cache writes
// (usage.cache_creation) and the server-side tool requests billed per request (usage.server_tool_use). They are
// read through derive's types, which the forwarder's wire usage scanner shares.
type (
	cacheCreation = derive.CacheCreation
	serverToolUse = derive.ServerToolUse
)

// validateExtra rejects a negative count in either object, as validate does in the four token counters.
func (u Usage) validateExtra() error {
	if c := u.CacheCreation; c != nil && (c.Ephemeral5m < 0 || c.Ephemeral1h < 0) {
		return fmt.Errorf("%w: usage.cache_creation has a negative count", ErrSchema)
	}
	if name, v, ok := u.ServerToolUse.Negative(); ok {
		return fmt.Errorf("%w: usage.server_tool_use.%s is %d", ErrSchema, name, v)
	}
	return nil
}

// recordExtra sets the ledger's cache_write_1h and server_tool from the two objects. cache_write stays the whole of
// the cache writes, raised to the sum of the two lifetimes when the response reported less, so a 1-hour count is
// never more than the whole it is part of.
func (u Usage) recordExtra(r *record.Usage) {
	if c := u.CacheCreation; c != nil {
		r.CacheWrite1h = c.Ephemeral1h
		if c.Ephemeral5m <= math.MaxInt-c.Ephemeral1h {
			r.CacheWrite = max(r.CacheWrite, c.Ephemeral5m+c.Ephemeral1h)
		} else {
			r.CacheWrite = math.MaxInt
		}
	}
	if len(u.ServerToolUse) > 0 {
		r.ServerTool = u.ServerToolUse
	}
}

// mergeExtra folds a later report's two objects into u's, each count the larger of the two, as merge does.
func (u *Usage) mergeExtra(n Usage) {
	if c := n.CacheCreation; c != nil {
		if u.CacheCreation == nil {
			u.CacheCreation = &cacheCreation{}
		}
		u.CacheCreation.Ephemeral5m = max(u.CacheCreation.Ephemeral5m, c.Ephemeral5m)
		u.CacheCreation.Ephemeral1h = max(u.CacheCreation.Ephemeral1h, c.Ephemeral1h)
	}
	if len(n.ServerToolUse) > 0 {
		u.ServerToolUse = u.ServerToolUse.Merge(n.ServerToolUse)
	}
}

// billingModified reports that the response was billed under a modifier the price table does not price: a
// speed, service_tier or inference_geo other than the plain one, or an iterations list that is more than the one
// message iteration (server-side compaction or a refusal fallback, whose extra attempts the top-level counts
// leave out and which may be at another model's rates). An unreadable value is a modifier, the fail-closed
// reading. Rate modifiers are unpriced (limits.PriceTable.Cost) and charged at MaxCost under a cost budget.
// Extra or unreadable iterations additionally leave accounting incomplete: no multiplier bounds spend on
// attempts omitted from the reported counters, so a token or cost budget fails closed on that exchange.
func (u Usage) billingModified() bool {
	return modifierSet(u.Speed, "standard") || modifierSet(u.ServiceTier, "standard") ||
		modifierSet(u.InferenceGeo, "global", "not_available") || iterationsExtra(u.Iterations)
}

// modifierSet reports a present, non-null value that is not one of the plain strings.
func modifierSet(raw json.RawMessage, plain ...string) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return true
	}
	return s != "" && !slices.Contains(plain, s)
}

// iterationsExtra reports an iterations value that is not absent, null, empty or a single message iteration.
func iterationsExtra(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var its []json.RawMessage
	if unmarshal(raw, &its) != nil || len(its) > 1 {
		return true
	}
	if len(its) == 0 {
		return false
	}
	var iteration struct {
		Type string `json:"type"`
	}
	return uniqueAccounting(its[0], iterationAccounting) != nil ||
		unmarshal(its[0], &iteration) != nil || iteration.Type != "message"
}
