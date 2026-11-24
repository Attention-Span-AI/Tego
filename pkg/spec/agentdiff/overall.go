// SPDX-License-Identifier: Apache-2.0

package agentdiff

// Overall is the one direction a set of family results gives a change.
type Overall string

// The overall directions, spelled as the rule editor's directions.
const (
	// OverallNarrows: every family is unchanged or narrowed. The next run may do less or the same, in every family
	// the comparison orders; nothing it may do becomes looser.
	OverallNarrows Overall = "narrows"
	// OverallWidens: some family widened and none narrowed or could not be ordered.
	OverallWidens Overall = "widens"
	// OverallMixed: a family widened and another narrowed, or a family changed that the comparison cannot order. The
	// change is never shown as only narrowing then.
	OverallMixed Overall = "mixed"
)

// Fold folds the family results into one direction, and names the families that decided it. It is the only
// place a direction word comes from for a compiled change: a result that cannot be ordered is mixed, never narrowing.
func Fold(rows []Result) (Overall, []string) {
	var widened, narrowed, unclear []string
	for _, r := range rows {
		switch r.Direction {
		case Widened:
			widened = append(widened, r.Family)
		case Narrowed:
			narrowed = append(narrowed, r.Family)
		case CannotClassify:
			unclear = append(unclear, r.Family)
		case Unchanged:
		}
	}
	switch {
	case len(unclear) > 0 || len(widened) > 0 && len(narrowed) > 0:
		return OverallMixed, append(append(widened, narrowed...), unclear...)
	case len(widened) > 0:
		return OverallWidens, widened
	}
	return OverallNarrows, narrowed
}
