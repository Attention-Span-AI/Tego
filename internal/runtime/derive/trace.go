// SPDX-License-Identifier: Apache-2.0

package derive

import "strings"

// ParseTraceparent reads a W3C version-00 traceparent header, the one rule both capture paths read a client's
// trace by (the forwarder to continue it, R20; the uprobe path to record it). Anything else is ok=false, "the
// client sent none": a bad field count or length, a field that is not lower-case hex, an all-zero trace or
// span id, or another version (ff is forbidden, and a later one is not a shape this reads).
func ParseTraceparent(v string) (traceID, spanID, flags string, ok bool) {
	parts := strings.Split(strings.TrimSpace(v), "-")
	if len(parts) != 4 {
		return "", "", "", false
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]
	if version != "00" || len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 {
		return "", "", "", false
	}
	for _, f := range []string{traceID, spanID, flags} {
		if !isLowerHex(f) {
			return "", "", "", false
		}
	}
	if traceID == strings.Repeat("0", 32) || spanID == strings.Repeat("0", 16) {
		return "", "", "", false
	}
	return traceID, spanID, flags, true
}

// isLowerHex reports whether s is non-empty lower-case hex.
func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
