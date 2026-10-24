// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The banner is "Maze" in TAAG's Hemispheres font with TheDraw colors (patorjk.com/software/taag, font
// HemispheresB), converted from its HTML export: each row of glyphs comes with a row of foreground colors and a
// row of background colors, one letter per glyph. The site's blue is swapped for Maze's orange; the grays stay.
//
// Foreground letters: g light gray, s dark gray, a accent, d dark accent. Background: . none, g light gray,
// d dark accent.
var bannerGlyphs = []string{
	" ▐█▄   ▄█▌  ▐█▀▀▀█▌   ▀▀▀▀█▌  ▐█▀▀▀ ",
	"█ █ ▀▄▀ █ ██ █ █ █ ███▄▄█ █ ██ █ ▄▄█",
	"█ █ ▄▄█ █ ██ █ ▀ █ ██▀▀▀▀ █ ██ █ ▀▀█",
	"█ █ ███ █ ██ █▀▀▀█ █▀ █▀▀▀▀ ██ █▀▀ █",
	"█ ░ ███ ░ ██ ░ █ ░ ██ ░ ▄▄▄▄██ ░ ▄▄█",
	"█ ▒ ███ ▒ ██ ▒ █ ▒ ██ ▒ ██████ ▒ ███",
	" ▐▓▌   ▐▓▌  ▐▓▌ ▐▓▌  ▐▓▄▄▄▄   ▐▓▄▄▄ ",
}

var bannerFG = []string{
	"gggggggggggggggggggggggggggggggggggg",
	"dgggggggggadgggdgggaaaaadgggadgggaaa",
	"dgggaddgggadgggdgggaaaaadgggadgggaaa",
	"dgggaadgggadgggggggaagggggggadggggga",
	"dgsgaadgsgadgsgdgsgadgsgaaaaadgsgaaa",
	"dgsgaadgsgadgsgdgsgadgsgaaaaadgsgaaa",
	"gsssgggsssggsssgsssggssssssgggsssssg",
}

var bannerBG = []string{
	"....................................",
	"......................dd.........dd.",
	"....d...............................",
	".....d..............d...............",
	"..g.....g....g...g....g.dddd...g.dd.",
	"..g.....g....g...g....g........g....",
	"..g.....g....g...g....g........g....",
}

// bannerColor is one palette letter's color: 24-bit RGB and the nearest 256-color index.
type bannerColor struct {
	r, g, b uint8
	idx     int
}

// bannerPalette maps the letters of bannerFG and bannerBG to colors.
var bannerPalette = map[byte]bannerColor{
	'g': {0xAA, 0xAA, 0xAA, 248},
	's': {0x55, 0x55, 0x55, 240},
	'a': {accentR, accentG, accentB, accent256},
	'd': {0x9C, 0x3D, 0x12, 130},
}

// Tagline is the one line that says what Maze is.
const Tagline = "Rules your AI assistant can't ignore."

// Banner prints the art and the tagline whenever color is on and the terminal is wide enough for it, whatever
// its height, so the opening pages always look the same. A pipe, --no-color or a very narrow window gets one
// plain line with the name instead. In a short window the spacing around the art goes first, then the page
// scrolls; the art itself never disappears.
func (t *Term) Banner() {
	if !t.color || t.width < utf8.RuneCountInString(bannerGlyphs[0])+4 {
		t.Println("  " + t.Accent(t.Bold("maze")) + t.Dim("  ·  ") + Tagline)
		t.Println()
		return
	}
	roomy := t.height >= 34
	if roomy {
		t.Println()
	}
	for i := range bannerGlyphs {
		t.Println("  " + t.bannerRow(i))
	}
	if roomy {
		t.Println()
	}
	t.Println("  " + t.Bold(Tagline))
	t.Println()
}

// bannerRow renders row i, changing color only where the palette letters change and resetting at the end.
func (t *Term) bannerRow(i int) string {
	glyphs := []rune(bannerGlyphs[i])
	fg, bg := bannerFG[i], bannerBG[i]
	var b strings.Builder
	prev := ""
	for j, r := range glyphs {
		code := t.sgr(fg[j], false)
		if bg[j] != '.' {
			code += ";" + t.sgr(bg[j], true)
		}
		if code != prev {
			b.WriteString("\x1b[0;" + code + "m")
			prev = code
		}
		b.WriteRune(r)
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

// sgr is the SGR parameter for a palette letter as foreground or background, in 24-bit or 256 colors.
func (t *Term) sgr(letter byte, background bool) string {
	c := bannerPalette[letter]
	base := 38
	if background {
		base = 48
	}
	if t.truecolor {
		return fmt.Sprintf("%d;2;%d;%d;%d", base, c.r, c.g, c.b)
	}
	return fmt.Sprintf("%d;5;%d", base, c.idx)
}
