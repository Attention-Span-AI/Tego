// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// These helpers exercise the closed vocabulary and golden tables in tests.
// Production callers use WriteReport, MatrixDetail and config capture values.
// FormatReport renders lines as WriteReport would, into a string.
func FormatReport(lines []Line) string {
	var b strings.Builder
	_ = WriteReport(&b, lines) // strings.Builder never fails
	return b.String()
}

// WriteMatrix prints the whole static matrix as a table with one column per selectable tier,
// what doctor prints before the machine's actual values.
func WriteMatrix(w io.Writer) error {
	width := 0
	for _, c := range allCapabilities {
		if n := len(c.Title()); n > width {
			width = n
		}
	}
	header := fmt.Sprintf("%-*s", width, "capability")
	for _, t := range tiers {
		header += fmt.Sprintf("  %-8s", t)
	}
	if _, err := io.WriteString(w, strings.TrimRight(header, " ")+"\n"); err != nil {
		return fmt.Errorf("backend: write matrix: %w", err)
	}
	for _, c := range allCapabilities {
		row := fmt.Sprintf("%-*s", width, c.Title())
		for _, t := range tiers {
			row += fmt.Sprintf("  %-8s", yesNo(matrix[t][c].present))
		}
		if _, err := io.WriteString(w, strings.TrimRight(row, " ")+"\n"); err != nil {
			return fmt.Errorf("backend: write matrix: %w", err)
		}
	}
	return nil
}

// decisionPlane is CAPABILITIES.md's "decision plane" row, the mechanism that decides file and exec actions in each
// tier (ADR 0024, docs/p0/enforce-plane.md R18) and what the ledger's `decision_plane` field names. It is prose,
// not a capability, so no run_start row carries it. Tier 3 is one plane, so one value there. Hand-kept identical to
// the markdown cell, like the matrix (TestMatrixGolden).
var decisionPlane = map[Tier]string{
	TierLandlock: "none: the Landlock domain and the seccomp supervisor decide",
	TierCgroup:   "`lsm` or `fmod_ret`, chosen per boot by doctor's probe; `fanotify` where neither passes",
	TierBPFLSM:   "`lsm` (the plane's programs as `lsm/` hooks; needs `bpf` in the LSM list)",
}

// DecisionPlane returns the CAPABILITIES.md prose of tier's decision-plane row, "" for a tier outside the table.
func DecisionPlane(tier Tier) string { return decisionPlane[tier] }

// Rank orders capture modes for ceiling comparisons: off=0, forwarder=1, uprobe=2; -1 unknown.
func (c Capture) Rank() int {
	switch c {
	case CaptureOff:
		return 0
	case CaptureForwarder:
		return 1
	case CaptureUprobe:
		return 2
	}
	return -1
}

// Valid reports whether c is one of the three defined values (R25, symmetric with Tier.Valid).
func (c Capture) Valid() bool { return c.Rank() >= 0 }

// AtOrBelow reports whether c may run under ceiling: Rank comparison of two Valid values; false
// when either is invalid.
func (c Capture) AtOrBelow(ceiling Capture) bool {
	if !c.Valid() || !ceiling.Valid() {
		return false
	}
	return c.Rank() <= ceiling.Rank()
}

// String returns the capture mode name.
func (c Capture) String() string { return string(c) }

// ErrCapture is the sentinel wrapped by ParseCapture.
var ErrCapture = errors.New("backend: unknown capture mode")

// ParseCapture maps text to a Capture (R25, symmetric with ParseTier); "auto" and "" are errors.
func ParseCapture(s string) (Capture, error) {
	if c := Capture(s); c.Valid() {
		return c, nil
	}
	return "", fmt.Errorf("%w: %q (want off, forwarder or uprobe)", ErrCapture, s)
}
