// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func init() { funcs["cmpCharts"] = cmpCharts }

// cmpMetric is one of Compare's side-by-side bar pairs: what it counts and run A's and B's bar on one scale.
type cmpMetric struct {
	Label, Hint string
	Rows        [2]cmpBar
}

// cmpBar is one run's bar of a cmpMetric: "A" or "B", the run's agent, its count and the bar.
type cmpBar struct {
	Side, Agent string
	N           int
	Bar         *svgChart
}

// cmpCharts is Compare's three bar pairs, from the counts the read model's Comparison already holds (no new
// shaping here): the secrets each run reached and the sends to a destination off its list that got through (red,
// what got out), and the attempts on a secret Tego stopped (green; Verdict.Stopped, the number the stats above and
// the run's banner give).
func cmpCharts(c *ledgerview.Comparison) []cmpMetric {
	if c == nil {
		return nil
	}
	pair := func(label, hint, cls string, a, b int) cmpMetric {
		hi := max(a, b)
		m := cmpMetric{Label: label, Hint: hint}
		for i, s := range []struct {
			side string
			run  *ledgerview.Run
			n    int
		}{{"A", c.A.Run, a}, {"B", c.B.Run, b}} {
			agent := "run " + s.side
			if s.run != nil && s.run.Agent != "" {
				agent = s.run.Agent
			}
			m.Rows[i] = cmpBar{Side: s.side, Agent: agent, N: s.n, Bar: meter(s.n, hi, cls, fmt.Sprintf("%s, run %s (%s)", label, s.side, agent))}
		}
		return m
	}
	return []cmpMetric{
		pair("Secrets reached", "Secret files each run opened", "ch-leak", c.A.SecretsOpened, c.B.SecretsOpened),
		pair("Sends off the list", "Connections to a destination outside the allowed list that got through", "ch-leak", c.A.OffList, c.B.OffList),
		pair("Attempts stopped", "Secret reads and sends next to a secret that Tego refused: the count the run's banner gives", "ch-refused", c.A.Verdict.Stopped(), c.B.Verdict.Stopped()),
	}
}
