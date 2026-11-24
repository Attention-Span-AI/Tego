// SPDX-License-Identifier: Apache-2.0

package receipt

// The levels of coverage a field can have. A field the receipt lists no gap for is complete: every value of it was read
// off a ledger that records it. A field with a gap is one of the other two.
const (
	// LevelComplete is a field with no gap. No gap carries it.
	LevelComplete = "complete"
	// LevelPartial is a field the ledger supports in part: what the receipt counts is a floor or an estimate.
	LevelPartial = "partial"
	// LevelNone is a field the ledger does not say anything about: the receipt shows no value for it that is evidence.
	LevelNone = "none"
)

// Code is one coverage code with the level its gap has and the one sentence that says what it means. The sentence is the
// code's meaning, not one run's words: a gap's Why adds the counts. A code never changes; its sentence may.
type Code struct {
	// Code is the value of CoverageGap.Code.
	Code string
	// Level is LevelPartial or LevelNone.
	Level string
	// Means is the one sentence for the code, shared by every reader of a receipt (`tego receipt`, the dashboard's Receipt
	// tab and `tego status`).
	Means string
}

// codes is every coverage code, in the order the constants are declared.
var codes = []Code{
	{CodeNoCapabilities, LevelNone, "the ledger has no capabilities line, so it does not say whether allowed writes were recorded"},
	{CodeRecordOff, LevelNone, "the run's tier records refused writes only, so the files it wrote are not recorded"},
	{CodeCaptureOff, LevelNone, "model traffic was not captured, so no model call or token is recorded"},
	{CodeCaptureGap, LevelPartial, "tego could not read some model traffic, so the token counts are a floor"},
	{CodeUnmetered, LevelPartial, "some model responses carried no token counts, so the token counts are a floor"},
	{CodeModelTimeUnseen, LevelPartial, "model traffic was not captured, so time spent waiting on the model counts as quiet"},
	{CodeTruncated, LevelPartial, "a list stops at its cap; the counts beside it are complete"},
	{CodeUnpriced, LevelPartial, "some metered responses had no price, so the cost is a floor"},
	{CodeNoPriceTable, LevelNone, "there was no usable price table, so the cost is not estimated"},
	{CodeMissedActions, LevelPartial, "tego knows it missed some actions, so the counts are a minimum"},
	{CodeMessagesDropped, LevelPartial, "MCP messages were too large for the relay and were dropped; no action went unrecorded"},
	{CodeAskRepeated, LevelPartial, "an ask line repeated an ask already asked; only the first counts"},
	{CodeAnswerUnpaired, LevelPartial, "an answer line pairs with no ask, and does not count as an answer"},
	{CodeModelRoutesKept, LevelPartial, "the model routes could not be read and the last ones read stayed in force; no action went unrecorded"},
	{CodeRecordUncertain, LevelPartial, "shared tracing counters cannot say whether this run lost actions"},
	{CodeRulesUncertain, LevelPartial, "the kernel skipped a shared program the run's rules rely on, so the receipt cannot say every rule held"},
	{CodeNoRunEnd, LevelPartial, "the run has no run_end line yet, so its time is measured to its last line"},
}

// Codes is every coverage code this version writes, with its level and sentence.
func Codes() []Code { return append([]Code(nil), codes...) }

// LevelOf is the level of a gap with this code: the code's own, and LevelNone for a code this version does not know (a
// newer receipt's), so a reader never takes a gap it cannot read for better than it is.
func LevelOf(code string) string {
	for _, c := range codes {
		if c.Code == code {
			return c.Level
		}
	}
	return LevelNone
}

// Means is the one sentence for a code, "" for a code this version does not know.
func Means(code string) string {
	for _, c := range codes {
		if c.Code == code {
			return c.Means
		}
	}
	return ""
}

// LevelWords is the one sentence for a level.
func LevelWords(level string) string {
	switch level {
	case LevelComplete:
		return "every value of the field was read off a ledger that records it"
	case LevelPartial:
		return "the ledger supports part of the field, so what is shown is a floor or an estimate"
	}
	return "the ledger is silent on this field, so what is shown for it is not evidence"
}

// EffectiveLevel is a gap's level as a reader must take it: what the receipt wrote when it is one of the two gap levels, else the
// level of its code, so a receipt from before the key, or one whose level was edited to something else, is never read as
// better than its code says.
func (g CoverageGap) EffectiveLevel() string {
	switch g.Level {
	case LevelNone:
		return LevelNone
	case LevelPartial:
		if LevelOf(g.Code) == LevelNone {
			return LevelNone
		}
		return LevelPartial
	}
	return LevelOf(g.Code)
}
