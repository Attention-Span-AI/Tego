// SPDX-License-Identifier: Apache-2.0

package record

// The whys of a gap what=record about the price table, each spelled here once. The writers (internal/pricetable, for the
// run's launcher and its watcher) and every reader (the receipt, `tego status`, the dashboard's words) take them from
// here, so a reader built apart from the engine cannot spell one differently (C175).
const (
	// GapNoPriceTable is recorded once when the run has no usable price table.
	GapNoPriceTable = "no-price-table"
	// GapPriceTableVersion is recorded once when the table's version is not the one this binary reads.
	GapPriceTableVersion = "price-table-version-mismatch"
	// GapUnpricedModel is recorded once per model the table does not price.
	GapUnpricedModel = "unpriced-model"
)

// IsPriceGapWhy reports whether why is one of the price gaps: a gap that leaves only the cost unestimated.
func IsPriceGapWhy(why string) bool {
	return why == GapNoPriceTable || why == GapPriceTableVersion || why == GapUnpricedModel
}
