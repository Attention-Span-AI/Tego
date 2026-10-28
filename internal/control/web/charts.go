// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"strconv"
	"strings"
)

// The dashboard's charts are server-side SVG: this file lays each one out as a svgChart (numbers and words only),
// and the "chart" template (templates/charts.tmpl) writes it, so html/template escapes every word as it does on any
// page and no trusted HTML type is built (forbidigo). The series come from the read model (ledgerview/series.go). No
// script and no library, so a chart is part of the page a live region resends (regions.go). Colours are CSS classes
// over the theme's tokens (app.css, .ch-*), so light and dark follow the theme switch. Every chart's words are
// screen-reader text beside an svg hidden from the accessibility tree (the page's rule for every svg, a11y_test),
// and its <title> and <desc> carry the same words for the hover. Each keeps a fixed height, so a chart arriving with
// a live update shifts nothing.

// svgChart is one chart for the "chart" template: its class and viewBox, its words, and its marks.
type svgChart struct {
	Class       string
	W, H        string // the viewBox's width and height
	Label, Desc string
	// Line and Area are a sparkline's polyline and the polygon under it, "" on other charts and on a sparkline with
	// fewer than two values (a line through one point says nothing); Note then says so in words ("spark" template).
	Line, Area, Note string
	// First and Last are a sparkline's oldest and newest values, written as text at its two ends, and DotX, DotY the
	// newest point, marked with a dot: the line has no axis, so its ends carry the numbers.
	First, Last, DotX, DotY string
	// Axis is the y of a horizontal rule across the chart, "" for none.
	Axis  string
	Parts []svgPart
}

// svgPart is one rect of a chart: its colour class, place and size, its hover title, and Href when it is a link.
type svgPart struct {
	Class, X, Y, W, H, Title, Href string
}

// num is f for an SVG attribute: one decimal, no exponent.
func num(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) }

// sparkline is a small line of vals oldest first, for a tile: 120×28, the area under it lightly filled, the newest
// point dotted, and the oldest and newest values kept for the "spark" template to write at its ends (the line has no
// axis, so a reader gets the numbers from its ends and the whole series from the hover desc). Fewer than two values
// draw no line, only Note: a flat line through one run would read as a trend that is not there.
func sparkline(vals []int, label string) *svgChart {
	const w, h, pad = 120.0, 28.0, 3.0
	c := &svgChart{Class: "ch-spark", W: num(w), H: num(h), Label: label, Desc: sparkDesc(vals)}
	if len(vals) < 2 {
		c.Note = "Trend after 2 runs"
		if len(vals) == 0 {
			c.Note = "No runs yet"
		}
		return c
	}
	hi := 0
	for _, v := range vals {
		hi = max(hi, v)
	}
	y := func(v int) float64 {
		if hi == 0 {
			return h - pad
		}
		return h - pad - float64(v)/float64(hi)*(h-2*pad)
	}
	pts := make([]string, len(vals))
	for i, v := range vals {
		pts[i] = pt(float64(i)*w/float64(len(vals)-1), y(v))
	}
	line := strings.Join(pts, " ")
	c.Line, c.Area = line, pt(0, h)+" "+line+" "+pt(w, h)
	c.First, c.Last = strconv.Itoa(vals[0]), strconv.Itoa(vals[len(vals)-1])
	c.DotX, c.DotY = num(w), num(y(vals[len(vals)-1]))
	return c
}

func pt(x, y float64) string { return num(x) + "," + num(y) }

// sparkDesc is the values in words, for the chart's <desc>.
func sparkDesc(vals []int) string {
	if len(vals) == 0 {
		return "No runs yet."
	}
	s := make([]string, len(vals))
	for i, v := range vals {
		s[i] = strconv.Itoa(v)
	}
	return "Oldest to newest: " + strings.Join(s, ", ") + "."
}

// chartSeg is one part of a stacked bar: what it counts, how many, and its colour class (app.css, .ch-*).
type chartSeg struct {
	Label string
	N     int
	Class string
}

// stackBar is one horizontal bar split into segs by count, a surface gap between parts, each part titled with its
// label and count for the hover. Parts with no count are left out; with no count at all the bar is the empty track.
// A part too thin to see (8 network sends beside 1,200 refused programs) is widened to minPart and the larger parts
// give up that room in proportion, so every kind the legend names has a visible mark; the legend and the hover keep
// the exact counts. The legend is HTML beside it, so its text never scales with the SVG.
func stackBar(segs []chartSeg, label string) *svgChart {
	const w, h, gap, minPart = 1000.0, 12.0, 4.0, 10.0
	total, shown := 0, 0
	for _, s := range segs {
		if s.N > 0 {
			total += s.N
			shown++
		}
	}
	c := &svgChart{Class: "ch-stack", W: num(w), H: num(h), Label: label, Desc: segDesc(segs, total)}
	if total == 0 {
		c.Parts = []svgPart{{Class: "ch-track", X: "0", Y: "0", W: num(w), H: num(h)}}
		return c
	}
	room := w - gap*float64(shown-1)
	thin := func(n int) bool { return room*float64(n)/float64(total) < minPart }
	nThin, bigTotal := 0, 0
	for _, s := range segs {
		if s.N > 0 && thin(s.N) {
			nThin++
		} else if s.N > 0 {
			bigTotal += s.N
		}
	}
	bigRoom := room - minPart*float64(nThin)
	x := 0.0
	for _, s := range segs {
		if s.N <= 0 {
			continue
		}
		sw := minPart
		if !thin(s.N) && bigTotal > 0 {
			sw = bigRoom * float64(s.N) / float64(bigTotal)
		}
		c.Parts = append(c.Parts, svgPart{Class: s.Class, X: num(x), Y: "0", W: num(sw), H: num(h), Title: fmt.Sprintf("%s: %d", s.Label, s.N)})
		x += sw + gap
	}
	return c
}

// segDesc is the parts in words, for the bar's <desc>.
func segDesc(segs []chartSeg, total int) string {
	if total == 0 {
		return "Nothing to count yet."
	}
	var parts []string
	for _, s := range segs {
		if s.N > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s.Label, s.N))
		}
	}
	return strings.Join(parts, ", ") + fmt.Sprintf(" (%d in all).", total)
}

// meter is one bar of n on a scale to hi (the larger of a pair), over the empty track: 200×10, so the two bars of a
// pair compare by length. n of 0 is the track alone.
func meter(n, hi int, cls, label string) *svgChart {
	const w, h = 200.0, 10.0
	c := &svgChart{Class: "ch-meter", W: num(w), H: num(h), Label: label, Desc: strconv.Itoa(n) + ".",
		Parts: []svgPart{{Class: "ch-track", X: "0", Y: "0", W: num(w), H: num(h)}}}
	if n > 0 && hi > 0 {
		c.Parts = append(c.Parts, svgPart{Class: cls, X: "0", Y: "0", W: num(max(w*float64(n)/float64(hi), 3)), H: num(h)})
	}
	return c
}
