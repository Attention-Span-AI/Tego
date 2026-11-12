// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// ovCharts is the Overview's charts: a sparkline of refusals and of secrets protected over the newest runs, and
// the secrets protected against exposed.
type ovCharts struct {
	RefSpark, SecretSpark *svgChart
	// SparkRuns is how many runs the sparklines cover (the newest, oldest left).
	SparkRuns int
	// Secrets are the bar's parts and SecretsBar the bar.
	Secrets            []chartSeg
	SecretsBar         *svgChart
	Protected, Exposed int
	// Unrecorded counts the runs that kept no file read (readGap): a secret read there may be in neither count (an
	// allowed one at every tier, and at tier landlock a refused one too).
	Unrecorded int
}

// sparkRuns is how many of the newest runs an Overview sparkline covers.
const sparkRuns = 12

// overviewCharts builds the Overview's charts from runs (newest first) and their verdicts.
func overviewCharts(runs []*ledgerview.Run, v map[string]ledgerview.Verdict) ovCharts {
	var c ovCharts
	n := min(len(runs), sparkRuns)
	ref, sec := make([]int, n), make([]int, n)
	for i, r := range runs {
		vd := v[r.ID]
		c.Protected += vd.Protected()
		c.Exposed += len(vd.Exposed)
		if r.ReadsUnrecorded {
			c.Unrecorded++
		}
		if i < n {
			ref[n-1-i], sec[n-1-i] = r.Refusals, vd.Protected()
		}
	}
	c.SparkRuns = n
	c.RefSpark = sparkline(ref, fmt.Sprintf("Refusals in each of the last %d runs", n))
	c.SecretSpark = sparkline(sec, fmt.Sprintf("Secrets protected in each of the last %d runs", n))
	c.Secrets = []chartSeg{{"Protected", c.Protected, "ch-refused"}, {"Exposed", c.Exposed, "ch-leak"}}
	c.SecretsBar = stackBar(c.Secrets, "Secrets protected and exposed, every run")
	return c
}
