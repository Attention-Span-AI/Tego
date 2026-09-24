// SPDX-License-Identifier: Apache-2.0

package status

import (
	"fmt"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// CapabilityLine renders a run's capability line, run_start.capabilities, as one line of text
// (docs/p0/limits-check-doctor-cli.md R-cap): the tier, how many rows of the matrix the run had out of how
// many were recorded, and then every row it did not have, by name — what was absent is the part a reader acts
// on (spec/backend/CAPABILITIES.md: "the gap report lists what was absent").
//
// Rows print in CAPABILITIES.md order so two runs' lines compare by eye; a row this binary does not know
// (written by a newer one) follows, sorted, rather than being dropped. A run_start written before the line
// existed renders as "not recorded", never as a run that could do nothing: those are opposite claims.
func CapabilityLine(tier string, caps map[string]bool) string {
	if caps == nil {
		return "not recorded"
	}
	var absent, unknown []string
	have := 0
	known := make(map[string]bool, len(caps))
	for _, c := range backend.AllCapabilities() {
		v, ok := caps[string(c)]
		if !ok {
			continue
		}
		known[string(c)] = true
		if v {
			have++
		} else {
			absent = append(absent, string(c))
		}
	}
	for k, v := range caps {
		if known[k] {
			continue
		}
		if v {
			have++
		} else {
			unknown = append(unknown, record.Printable(k))
		}
	}
	slices.Sort(unknown)
	absent = append(absent, unknown...)
	line := fmt.Sprintf("%d/%d", have, len(caps))
	if tier != "" {
		line = record.Printable(tier) + " " + line
	}
	if len(absent) > 0 {
		line += "; absent: " + strings.Join(absent, ", ")
	}
	return line
}
