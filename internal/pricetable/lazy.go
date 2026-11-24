// SPDX-License-Identifier: Apache-2.0

package pricetable

import (
	"sync"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// Coster prices one response: the shape of internal/check/measure's Prices, which this package may not import (the read
// side imports it, never the other way).
type Coster interface {
	Cost(u ledger.TokenUsage) (float64, bool)
}

// Lazy is a Coster that loads its table the first time a response is priced, once. Every reader of a receipt prices
// through one (`tego receipt`, `tego measure`, the dashboard's Receipt tab), so a run with no metered response never
// reads the table and a table that cannot be used prices nothing: a load that gave nil prices nothing, as a nil Coster
// does, but still counts as prices given, so the receipt counts each response unpriced the same way in each of them.
type Lazy struct {
	once  sync.Once
	load  func() Coster
	table Coster
}

// NewLazy is a Lazy that loads its table with load on the first Cost call.
func NewLazy(load func() Coster) *Lazy { return &Lazy{load: load} }

// Cost prices u with the table, loading it on the first call.
func (l *Lazy) Cost(u ledger.TokenUsage) (float64, bool) {
	l.once.Do(func() { l.table = l.load() })
	if l.table == nil {
		return 0, false
	}
	return l.table.Cost(u)
}
