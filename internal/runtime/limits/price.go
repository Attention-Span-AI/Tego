// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"github.com/attention-span-ai/tego/internal/pricetable"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The price table is internal/pricetable's, which the dashboard reads too (it may not import this package), so a
// receipt prices a response one way wherever it is shown (`tego receipt`, `tego measure`, the Receipt tab). These are
// the names this package and its callers have always used for it.

// PriceVersion is the only price-table schema version this binary understands (pricetable.PriceVersion).
const PriceVersion = pricetable.PriceVersion

// The gap reasons a run records when it cannot price a response (pricetable.GapNoPriceTable and the others).
const (
	GapNoPriceTable    = pricetable.GapNoPriceTable
	GapVersionMismatch = pricetable.GapVersionMismatch
	GapUnpricedModel   = pricetable.GapUnpricedModel
)

// ErrPriceTable is the sentinel every price-table failure wraps (pricetable.ErrPriceTable).
var ErrPriceTable = pricetable.ErrPriceTable

type (
	// ModelPrice is one model's price (pricetable.ModelPrice).
	ModelPrice = pricetable.ModelPrice
	// PriceTable is the versioned price list (pricetable.PriceTable).
	PriceTable = pricetable.PriceTable
	// Warning is a price table this build declined to use, and why (pricetable.Warning).
	Warning = pricetable.Warning
)

// Load reads and validates the price table at path (pricetable.Load).
func Load(path string) (*PriceTable, error) { return pricetable.Load(path) }

// FromMachine loads the table the machine config names (pricetable.FromMachine).
func FromMachine(m *config.Machine) (*PriceTable, *Warning) { return pricetable.FromMachine(m) }
