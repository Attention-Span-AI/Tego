// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"errors"
	"fmt"
)

// Auto is the config/contract sentinel meaning "the highest the machine allows". It is never a
// Tier or Capture value. ParseTier rejects it, and the capture compiler resolves it before use.
const Auto = "auto"

// Tier is an enforcement tier. Closed and ordered: landlock < cgroup < bpflsm. Observe is a run
// mode (record only) that ranks below every tier and is never selected by Select (R17).
type Tier string

// Tier values.
const (
	TierLandlock Tier = "landlock"
	TierCgroup   Tier = "cgroup"
	TierBPFLSM   Tier = "bpflsm"
	TierObserve  Tier = "observe"
	// TierAuto is the "auto" sentinel typed as a Tier for callers that carry config text around;
	// it is not Valid and never the result of ParseTier or Select.
	TierAuto Tier = Auto
	// ModeObserve is the older name of TierObserve, kept for readers of the baseline types.
	ModeObserve = TierObserve
)

// tiers lists the selectable tiers in ascending rank.
var tiers = [...]Tier{TierLandlock, TierCgroup, TierBPFLSM}

// Tiers returns the selectable tiers in ascending rank (landlock, cgroup, bpflsm); a fresh slice.
func Tiers() []Tier { return append([]Tier(nil), tiers[:]...) }

// Rank orders tiers for ceiling comparisons: landlock=1, cgroup=2, bpflsm=3, observe=0; -1 for
// anything else (including the auto sentinel). Total order with no ties among defined values (I6).
func (t Tier) Rank() int {
	switch t {
	case TierLandlock:
		return 1
	case TierCgroup:
		return 2
	case TierBPFLSM:
		return 3
	case TierObserve:
		return 0
	// The auto sentinel is no tier and has no rank.
	case TierAuto:
	}
	return -1
}

// Valid reports whether t is one of the four defined values (the three tiers and observe).
func (t Tier) Valid() bool { return t.Rank() >= 0 }

// AtOrBelow reports whether t may run under ceiling: Rank comparison of two Valid values.
// TierObserve is never at or below anything (R17: it is reached only by explicit request), and an
// invalid receiver or ceiling is never at or below either.
func (t Tier) AtOrBelow(ceiling Tier) bool {
	if t == TierObserve || !t.Valid() || !ceiling.Valid() {
		return false
	}
	return t.Rank() <= ceiling.Rank()
}

// String returns the tier name.
func (t Tier) String() string { return string(t) }

// ErrTier is the sentinel wrapped by ParseTier.
var ErrTier = errors.New("backend: unknown tier")

// ParseTier maps text to a Tier. It accepts the four defined names only; "auto" and "" are errors
// because they are sentinels the caller resolves before parsing (R17, R24).
func ParseTier(s string) (Tier, error) {
	if t := Tier(s); t.Valid() {
		return t, nil
	}
	return "", fmt.Errorf("%w: %q (want landlock, cgroup, bpflsm or observe)", ErrTier, s)
}

// Capture is a model-traffic capture mode. Closed and ordered: off < forwarder < uprobe; uprobe
// means uprobes plus the forwarder when it is a ceiling or auto resolved to it, and uprobes alone when
// a contract pins capture: uprobe (spec/config/v0, capture-derive.md §4); forwarder means the
// forwarder only.
type Capture string

// Capture values.
const (
	CaptureOff       Capture = "off"
	CaptureForwarder Capture = "forwarder"
	CaptureUprobe    Capture = "uprobe"
)
