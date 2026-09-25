// SPDX-License-Identifier: Apache-2.0

package httpstream

import "sync/atomic"

// DefaultMaxBytes is how much every body the uprobe path holds may add up to between them: the bodies in
// flight on every connection of the run, and each request body its source keeps until the response it
// derives with arrives (R14). Four MaxBody-sized arrays at the default MaxBody.
const DefaultMaxBytes = 256 << 20

// budgetBodies is the budget's floor in MaxBody-sized arrays: one exchange at its largest is a request body
// kept for derive while its response's body grows, and a body that grows holds its old array and its new
// one while it copies from one to the other.
const budgetBodies = 3

// Budget bounds the bytes of bodies the uprobe path holds in the launcher's heap, counted by the capacity of
// the arrays that hold them (R14).
//
// MaxBody bounds one body, but not how many are held at once: every connection of the run can have a body in
// flight, up to MaxConns (4096) of them, and the source keeps each request body until its response arrives
// so derive can read the pair. The traced agent chooses both multiplicands, and the launcher holding the
// arrays is the process that holds the ledger writer and the seccomp supervisor, which no cgroup of the run
// covers: 24 connections holding 48 MiB unfinished bodies grew it by 1.5 GiB, measured.
// Past the budget, capture keeps less of a body, marks it truncated and counts gap why=size-cap; the agent's
// own traffic is never touched. It is the forwarder's budget (forwarder/budget.go) in the form this path
// needs: there is no event copy of a body to track, because the uprobe source stores bodies as blobs.
//
// A connection's unparsed head bytes are counted too (conn.growBuf): R13 bounds one header block,
// not how many connections hold one, and 4096 connections parked on 63 KiB heads each way held 500 MiB outside
// this budget. A head it cannot hold gaps its connection why=size-cap. Each half's first headAllowance bytes
// (4 KiB) are not counted, so a line split across two chunks does not gap a connection while bodies elsewhere
// hold the budget: at most MaxConns x 2 x 4 KiB past it.
//
// A body's decoded form is counted too, as it grows, and the bodies one call completes are held against it
// until that call returns (feedAllowance, R15). What it does not count: a message once the call that
// completed it has returned, which its caller reserves again if it keeps the body, a decoder's own window, and
// arrays already let go of, which the collector reclaims at its own pace.
type Budget struct {
	limit int64
	used  atomic.Int64
}

// NewBudget sizes a budget. limit <= 0 is DefaultMaxBytes, and a limit below budgetBodies × maxBody is
// raised to that floor, so no configuration can turn capture into nothing by arithmetic.
func NewBudget(limit, maxBody int64) *Budget {
	if limit <= 0 {
		limit = DefaultMaxBytes
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	limit = max(limit, budgetBodies*maxBody)
	return &Budget{limit: limit}
}

// Take reserves up to want bytes and returns how many it granted, which is what is left when that is less:
// a caller short of what it needs keeps less, never more.
func (b *Budget) Take(want int64) int64 {
	if b == nil || want <= 0 {
		return 0
	}
	for {
		used := b.used.Load()
		room := min(b.limit-used, want)
		if room <= 0 {
			return 0
		}
		if b.used.CompareAndSwap(used, used+room) {
			return room
		}
	}
}

// Give returns bytes to the budget.
func (b *Budget) Give(n int64) {
	if b != nil && n > 0 {
		b.used.Add(-n)
	}
}

// Used is what is reserved now.
func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	return b.used.Load()
}

// Limit is the most that can be reserved at once.
func (b *Budget) Limit() int64 {
	if b == nil {
		return 0
	}
	return b.limit
}
