// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// rgb is one palette color: 24-bit, and the nearest 256-color index for terminals without 24-bit color.
type rgb struct {
	r, g, b uint8
	idx     int
}

// Maze's palette (the banner keeps its own colors). Cream, navy and orange are the brand; the dark navy is for
// bars; muted, green and red are derived from them so a hint, a ✓ and a ✗ sit with the brand on dark and light
// terminals alike.
var (
	cream  = rgb{0xF6, 0xF1, 0xE7, 255}
	navy   = rgb{0x1C, 0x26, 0x38, 236}
	orange = rgb{accentR, accentG, accentB, accent256}
	muted  = rgb{0x8A, 0x93, 0xA6, 103}
	green  = rgb{0x7B, 0xC4, 0x8A, 114}
	red    = rgb{0xE0, 0x56, 0x4F, 167}
)

// code is the SGR parameter for c as a foreground (base 38) or background (base 48).
func (t *Term) code(base int, c rgb) string {
	if t.truecolor {
		return fmt.Sprintf("%d;2;%d;%d;%d", base, c.r, c.g, c.b)
	}
	return fmt.Sprintf("%d;5;%d", base, c.idx)
}

// fg colors s with c.
func (t *Term) fg(c rgb, s string) string { return t.style(t.code(38, c), s) }

// Step prints the bar at the top of a setup screen: "Step n of total · title" in cream on navy, with one dot
// per step (done and current in orange). Without color it is a plain line.
func (t *Term) Step(n, total int, title string) {
	label := fmt.Sprintf("  Step %d of %d  ·  %s", n, total, title)
	var dots strings.Builder
	for i := 1; i <= total; i++ {
		if i <= n {
			dots.WriteString("●")
		} else {
			dots.WriteString("○")
		}
		if i < total {
			dots.WriteString(" ")
		}
	}
	w := min(t.width-1, 72)
	if !t.color {
		t.Println(label + "   " + dots.String())
		return
	}
	pad := w - utf8.RuneCountInString(label) - utf8.RuneCountInString(dots.String()) - 2
	if pad < 2 {
		pad = 2
	}
	bar := t.code(48, navy)
	body := "\x1b[0;" + bar + ";" + t.code(38, cream) + ";1m" + label + strings.Repeat(" ", pad) +
		"\x1b[0;" + bar + ";" + t.code(38, orange) + "m" + dots.String() + "  \x1b[0m"
	t.Println(body)
}

// Brand prints the small header of a setup screen after the first: "maze" in orange and what is being set up.
func (t *Term) Brand(what string) {
	t.Println("  " + t.Bold(t.Accent("maze")) + t.Dim("  ·  "+what))
}
