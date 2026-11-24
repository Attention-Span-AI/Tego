// SPDX-License-Identifier: Apache-2.0

package record

// liveChangeWords says what each live change did: the one sentence for a person's live block, lift, pause, resume, MCP
// tool switch or model route change. `tego status` (internal/check/gaps), the receipt and the dashboard's glossary
// (internal/control/linewords) all say it in these words (C175).
var liveChangeWords = map[string]string{
	GapLiveBlockAdded:     "a live block was added",
	GapLiveBlockRemoved:   "a live block was removed",
	GapLiveBlockExpired:   "a live block's time ran out; it no longer refuses",
	GapLiveUnblockExpired: "a live block's time off ran out; it refuses again",
	GapLiveRuleLifted:     "a rule in the fence was allowed for now",
	GapLiveRuleRestored:   "a rule in the fence refuses again",
	GapLiveLiftExpired:    "an allowed rule's time ran out; it refuses again",
	GapLiveLiftRefused:    "a request to allow a rule was refused; nothing was loosened",
	GapRunPaused:          "the run was paused",
	GapRunResumed:         "the run was resumed",
	GapPauseFailed:        "a pause could not be put in force; the run kept running",
	GapResumeFailed:       "a resume could not be put in force; the run stays paused",
	GapMCPToolChanged:     "an MCP tool's rule was changed live",
	GapModelRouteChanged:  "a model endpoint's requests were sent to another approved backend",
}

// LiveChangeWords is what a live change's why did, in words; false for a why that is not one.
func LiveChangeWords(why string) (string, bool) {
	w, ok := liveChangeWords[why]
	return w, ok
}

// LiveChangeWhys is every why LiveChangeWords has words for, so a test can hold a list of the live changes to it.
func LiveChangeWhys() []string {
	out := make([]string, 0, len(liveChangeWords))
	for why := range liveChangeWords {
		out = append(out, why)
	}
	return out
}

// priceGapWords says what each price gap means for the line that records it.
var priceGapWords = map[string]string{
	GapNoPriceTable:      "no price table was loaded, so the cost is not estimated",
	GapPriceTableVersion: "the price table is of a version this tego does not read, so the cost is not estimated",
	GapUnpricedModel:     "the price table has no price for a model the run used, so that model's cost is not estimated",
}

// PriceGapWords is what a price gap's why means, in words; false for a why that is not one.
func PriceGapWords(why string) (string, bool) {
	w, ok := priceGapWords[why]
	return w, ok
}
