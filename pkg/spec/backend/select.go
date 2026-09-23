// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"errors"
	"fmt"
)

// CodeTierUnavailable is the diagnostic code of a failed selection (exit 125 in tego run, R18).
const CodeTierUnavailable = "tier-unavailable"

// ErrTierUnavailable is the sentinel every selection failure wraps.
var ErrTierUnavailable = errors.New("backend: tier unavailable")

// Probe is the result of the machine check, one entry per tier the probe found usable; absent
// means unavailable. internal/doctor produces it; this package only reads it (R17).
type Probe map[Tier]bool

// Available reports whether the probe found t usable.
func (p Probe) Available(t Tier) bool { return p[t] }

// TierUnavailableError explains a failed Select: which tier was wanted and why it cannot run.
type TierUnavailableError struct {
	// Tier is the pinned tier, or the ceiling when nothing at or below it was available.
	Tier Tier
	// Pinned is true when a contract or the machine config pinned Tier explicitly (R18).
	Pinned bool
	// Fix is why the tier is unavailable and what would change that. Select leaves it empty (Probe
	// carries no text); the caller that holds the probe's reasons, enforce.Select, fills it.
	Fix string
}

// Error renders the one-sentence message; the caller appends the bracketed code via FormatMessage.
func (e *TierUnavailableError) Error() string {
	if e.Pinned {
		return fmt.Sprintf("tier %s pinned but not available", e.Tier)
	}
	return "no enforcement tier available on this machine"
}

// Unwrap returns ErrTierUnavailable so callers use errors.Is.
func (e *TierUnavailableError) Unwrap() error { return ErrTierUnavailable }

// Code returns CodeTierUnavailable.
func (e *TierUnavailableError) Code() string { return CodeTierUnavailable }

// Select picks the tier a run uses (R17, R18). ceiling is the machine's tier ceiling — "" or
// TierAuto means unbounded; pinned is the tier a contract or the machine config named explicitly
// ("" or TierAuto for none; a pin above the ceiling is lowered to it, since a layer may lower a
// ceiling and never raise it); probe says which tiers the machine can provide.
//
// Post: a pinned tier is returned iff the probe allows it, else *TierUnavailableError{Pinned:
// true}; otherwise the highest-ranked probe-allowed tier at or below the ceiling, scanning down to
// TierLandlock, else *TierUnavailableError. TierObserve is never a candidate and never a valid
// pin or ceiling (R17: reached only by explicit --observe). Pure; no kernel access.
func Select(ceiling, pinned Tier, probe Probe) (Tier, error) {
	limit, err := effectiveCeiling(ceiling)
	if err != nil {
		return "", err
	}
	if pinned != "" && pinned != TierAuto {
		if !pinned.AtOrBelow(TierBPFLSM) {
			return "", fmt.Errorf("%w: %q is not a selectable tier", ErrTierUnavailable, pinned)
		}
		if pinned.Rank() > limit.Rank() {
			pinned = limit
		}
		if !probe.Available(pinned) {
			return "", &TierUnavailableError{Tier: pinned, Pinned: true}
		}
		return pinned, nil
	}
	for i := len(tiers) - 1; i >= 0; i-- {
		t := tiers[i]
		if t.AtOrBelow(limit) && probe.Available(t) {
			return t, nil
		}
	}
	return "", &TierUnavailableError{Tier: limit}
}

// effectiveCeiling maps the auto sentinel to the top tier and refuses observe or unknown names.
func effectiveCeiling(ceiling Tier) (Tier, error) {
	if ceiling == "" || ceiling == TierAuto {
		return TierBPFLSM, nil
	}
	if !ceiling.AtOrBelow(TierBPFLSM) {
		return "", fmt.Errorf("%w: ceiling %q is not a selectable tier", ErrTierUnavailable, ceiling)
	}
	return ceiling, nil
}
