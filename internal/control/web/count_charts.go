// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
)

var chartIntegers = regexp.MustCompile(`[0-9][0-9,]*`)

// qualifyChart carries a source's qualification into a chart's text alternative, its hover labels and its two
// visible end values. A failed reader leaves no graph of its prefix: the chart says it could not read.
func qualifyChart(c *svgChart, id string, scope countScope) {
	if c == nil {
		return
	}
	c.NumberID = id
	c.Reason = scope.Reason
	if scope.Error != "" {
		c.Reason = scope.Error
	}
	if scope.Error != "" {
		c.First, c.Last, c.Line, c.Area, c.DotX, c.DotY = "", "", "", "", "", ""
		c.Parts = nil
		c.Desc = "Could not read: " + scope.Error
		c.Note = "Could not read"
		return
	}
	if !scope.Lower {
		return
	}
	if c.First != "" {
		c.First = "at least " + c.First
	}
	if c.Last != "" {
		c.Last = "at least " + c.Last
	}
	qualify := func(s string) string { return chartIntegers.ReplaceAllString(s, "at least $0") }
	c.Desc = qualify(c.Desc) + " " + scope.Reason
	for i := range c.Parts {
		c.Parts[i].Title = qualify(c.Parts[i].Title)
	}
	c.Label = strings.ReplaceAll(c.Label, "last ", "shown ")
}

// qualifyOverviewCharts qualifies the Overview's refusal and secret charts by their sources.
func qualifyOverviewCharts(c *ovCharts, n countScopes) {
	qualifyChart(c.RefSpark, "overview.refusal-series", n.Aggregate)
	qualifyChart(c.SecretSpark, "overview.secret-series", n.Window)
	qualifyChart(c.SecretsBar, "overview.secret-series", n.Window)
}
