// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The dashboard's colours live in static/tokens.css, one token per meaning, measured there in both themes
// (theme_test.go, colour_story_test.go). A literal colour in any other stylesheet is a colour no theme switch, no
// contrast test and no meaning table reaches, so it fails here (V020-PLAN A1-1).

// cssNamedColours is every CSS named colour (CSS Color 4) but transparent and currentcolor, which name no colour of
// their own.
var cssNamedColours = strings.Fields(`aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue
blueviolet brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan
darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon
darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue dimgray dimgrey
dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold goldenrod gray green greenyellow grey
honeydew hotpink indianred indigo ivory khaki lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral
lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue
lightslategray lightslategrey lightsteelblue lightyellow lime limegreen linen magenta maroon mediumaquamarine mediumblue
mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue
mintcream mistyrose moccasin navajowhite navy oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen
paleturquoise palevioletred papayawhip peachpuff peru pink plum powderblue purple rebeccapurple red rosybrown royalblue
saddlebrown salmon seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen steelblue tan
teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen`)

var (
	cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssString  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
	// Leave the terminating delimiter for the next match: minified adjacent declarations have no whitespace.
	// Starting only at a block or declaration boundary keeps selectors' pseudo-classes out of values.
	cssValue   = regexp.MustCompile(`(?:^|[;{])\s*(-{0,2}[a-zA-Z][\w-]*)\s*:([^;{}]*)`)
	cssLiteral = regexp.MustCompile(`(?i)#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(`)
	cssWord    = regexp.MustCompile(`[A-Za-z][\w-]*`)
)

// literalColours names each literal colour in the declarations of css: a #hex, a colour function, or a named colour.
// Comments and quoted strings (content, font names) are not declarations' colours and are left out.
func literalColours(css string) []string {
	css = cssString.ReplaceAllString(cssComment.ReplaceAllString(css, " "), `""`)
	var out []string
	for _, m := range cssValue.FindAllStringSubmatch(css, -1) {
		prop, val := m[1], m[2]
		for _, l := range cssLiteral.FindAllString(val, -1) {
			out = append(out, prop+": "+strings.TrimSpace(val)+" ("+l+")")
		}
		for _, w := range cssWord.FindAllString(val, -1) {
			if slices.Contains(cssNamedColours, strings.ToLower(w)) {
				out = append(out, prop+": "+strings.TrimSpace(val)+" ("+w+")")
			}
		}
	}
	return out
}

// TestNoLiteralColourOutsideTokens: every stylesheet the dashboard serves, but tokens.css, names its colours by token
// (var(--c-…), var(--ch-…)), or by a forced-colours system name (CanvasText, Highlight), transparent or currentColor.
func TestNoLiteralColourOutsideTokens(t *testing.T) {
	var sheets []string
	if err := fs.WalkDir(assets, "static", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".css") {
			sheets = append(sheets, p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sheets, "static/app.css") || !slices.Contains(sheets, "static/tokens.css") || len(sheets) < 10 {
		t.Fatalf("the walk found %v", sheets)
	}
	for _, p := range sheets {
		b, err := fs.ReadFile(assets, p)
		if err != nil {
			t.Fatal(err)
		}
		got := literalColours(string(b))
		if p == "static/tokens.css" {
			if len(got) == 0 {
				t.Error("tokens.css holds no literal colour: the scan reads nothing")
			}
			continue
		}
		for _, l := range got {
			t.Errorf("%s: a literal colour outside tokens.css: %s", p, l)
		}
	}
}

// TestLiteralColourScan holds the scan to what it must and must not find, so a pass above means something.
func TestLiteralColourScan(t *testing.T) {
	for _, bad := range []string{
		`.a { color: #fff; }`, `.a { border: 1px solid #F26327 }`, `.a { background: rgb(14 19 28 / 0.45); }`,
		`.a { color: rgba(0,0,0,.5); }`, `.a { color: hsl(10 50% 50%); }`, `.a { color: oklch(0.7 0.1 30); }`,
		`.a { color: red; }`, `.a { mask-image: linear-gradient(to right, black 90%, transparent); }`,
		`@media (min-width: 1px) { .a { box-shadow: 0 0 0 2px White; } }`, `.a{outline:2px solid navy}`,
		`.a { --x: #000; }`,
		`.a{margin:0;color:red}`, `.a{margin:0;color:#fff;padding:0;background:navy}`,
		`.a { color: RGB(0 0 0); }`, `.a { color: OKLCH(0.7 0.1 30); }`,
	} {
		if len(literalColours(bad)) == 0 {
			t.Errorf("the scan misses the literal in %q", bad)
		}
	}
	for _, good := range []string{
		`.a { color: var(--c-text); background: transparent; border-color: currentColor; }`,
		`.white-space { white-space: nowrap; }`, `.red:hover { color: var(--c-danger); }`,
		`/* red is High, green is #0f0 */ .a { color: var(--c-high); }`,
		`.a::before { content: "red #fff rgb("; font-family: "Black Ops", system-ui; }`,
		`@media (forced-colors: active) { .b { border: 1px solid CanvasText; background: Highlight; color: HighlightText; } }`,
		`.a { animation: live-new 2s ease-out; grid-template-areas: "what v"; }`,
	} {
		if got := literalColours(good); len(got) != 0 {
			t.Errorf("the scan reads %v in %q", got, good)
		}
	}
}
