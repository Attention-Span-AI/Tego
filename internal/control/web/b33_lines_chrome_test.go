// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// C126: line numbers beside the raw contract editor. In a real browser, at 1280 and 390 px, light and dark: the gutter
// has one number per line of the text and follows the textarea's scrolling (the last number sits beside the last
// line), it grows with a typed line, the cursor's line is marked, a diagnostic's "line N" link moves the cursor to
// that line, and a phone has the status words and no gutter. TEGO_CHROME_SHOTS saves each window.
func TestRawEditorLineNumbersInChrome(t *testing.T) {
	f := newChangeFix(t)
	if err := os.MkdirAll(filepath.Join(f.proj, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, addr, _ := liveServer(t, f.root, 10*time.Second, 30*time.Second)
	s.cfg.Rules, s.cfg.Setup, s.cfg.Machine = f.svc, f.svc, f.svc.Machine
	ref := f.ref(t, f.source).Ref
	c := placeChrome(t)
	for _, w := range []int{1280, 390} {
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("%d/%s", w, theme), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), w, 900, theme)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/rules/change?c=" + ref + "&raw=1&view=full&t=tok123"})
				tb.until(t, "the editor", `document.readyState==='complete'&&!!document.getElementById('yaml-text')&&!!document.querySelector('.ln-wrap')`)
				// A text of 60 lines whose 5th is the compile error, so the editor scrolls and a diagnostic names a line.
				var b strings.Builder
				b.WriteString("version: 0\nname: rules-demo\ncommand: [sh\n")
				for i := 4; i <= 60; i++ {
					fmt.Fprintf(&b, "# note %d\n", i)
				}
				tb.eval(t, `(function(){var ta=document.getElementById('yaml-text');ta.value=`+strconv.Quote(b.String())+`;ta.dispatchEvent(new Event('input',{bubbles:true}));return ''})()`)
				phone := w < 600
				got := tb.eval(t, `(function(){var g=document.querySelector('.ln-gutter'),ta=document.getElementById('yaml-text');
					return JSON.stringify({n:g.children.length,first:g.children[0].textContent,last:g.children[g.children.length-1].textContent,
					gutterShown:getComputedStyle(g).display!=='none',status:document.querySelector('.ln-status').textContent,
					lines:ta.value.split('\n').length})})()`)
				var st struct {
					N, Lines    int
					First, Last string
					GutterShown bool
					Status      string
				}
				var raw string
				_ = json.Unmarshal([]byte(got), &raw)
				if err := json.Unmarshal([]byte(raw), &st); err != nil {
					t.Fatalf("%v: %s", err, got)
				}
				if st.N != st.Lines || st.First != "1" || st.Last != strconv.Itoa(st.Lines) {
					t.Errorf("the gutter has %d numbers (%s..%s) for %d lines", st.N, st.First, st.Last, st.Lines)
				}
				if st.GutterShown == phone {
					t.Errorf("gutter shown = %v at %d px", st.GutterShown, w)
				}
				if !strings.HasPrefix(st.Status, "Line ") || !strings.Contains(st.Status, " of "+strconv.Itoa(st.Lines)) {
					t.Errorf("status %q", st.Status)
				}
				if !phone {
					// Scrolled to the end, the last number sits beside the last line, and only that one is marked once the cursor is there.
					tb.eval(t, `(function(){var ta=document.getElementById('yaml-text');ta.focus();ta.setSelectionRange(ta.value.length,ta.value.length);ta.scrollTop=ta.scrollHeight;ta.dispatchEvent(new Event('scroll'));ta.dispatchEvent(new Event('keyup'));return ''})()`)
					time.Sleep(150 * time.Millisecond)
					off := tb.eval(t, `(function(){var ta=document.getElementById('yaml-text'),g=document.querySelector('.ln-gutter'),n=g.children.length,
						cs=getComputedStyle(ta),lh=parseFloat(cs.lineHeight),r=ta.getBoundingClientRect(),
						want=r.top+parseFloat(cs.borderTopWidth)+parseFloat(cs.paddingTop)+(n-1)*lh-ta.scrollTop,
						have=g.children[n-1].getBoundingClientRect().top;
						return Math.abs(want-have)+':'+g.querySelectorAll('.ln-cur').length+':'+g.querySelector('.ln-cur').textContent+':'+ta.scrollTop})()`)
					parts := strings.Split(strings.Trim(off, `"`), ":")
					if d, _ := strconv.ParseFloat(parts[0], 64); d > 1.5 || parts[1] != "1" || parts[2] != "61" || parts[3] == "0" {
						t.Errorf("end of the text: offset/marked/line/scrollTop = %s", off)
					}
				}
				// A typed line grows the gutter by one.
				tb.eval(t, `(function(){var ta=document.getElementById('yaml-text');ta.value+='# added\n';ta.dispatchEvent(new Event('input',{bubbles:true}));return ''})()`)
				if v := tb.eval(t, `document.querySelector('.ln-gutter').children.length===document.getElementById('yaml-text').value.split('\n').length`); v != "true" {
					t.Errorf("the gutter did not follow a typed line")
				}
				// Check names line 3 (the unclosed flow sequence); its link moves the cursor there.
				tb.eval(t, `document.querySelector('#builder-edit button[value="check"]').click();''`)
				tb.until(t, "the diagnostic", `!!document.querySelector('.rc-diags a[data-goto-line]')&&!!document.querySelector('.ln-wrap')&&document.readyState==='complete'`)
				line := tb.eval(t, `document.querySelector('.rc-diags a[data-goto-line]').getAttribute('data-goto-line')`)
				tb.eval(t, `document.querySelector('.rc-diags a[data-goto-line]').click();''`)
				sel := tb.eval(t, `(function(){var ta=document.getElementById('yaml-text'),n=ta.value.slice(0,ta.selectionStart).split('\n').length;return n+':'+(document.activeElement===ta)+':'+ta.value.slice(ta.selectionStart,ta.selectionEnd)})()`)
				if want := strings.Trim(line, `"`) + ":true:"; !strings.HasPrefix(strings.Trim(sel, `"`), want) {
					t.Errorf("the link for line %s left the cursor at %s", line, sel)
				}
				if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
					tb.eval(t, `document.getElementById('yaml-text').scrollIntoView({block:'center'});''`)
					time.Sleep(150 * time.Millisecond)
					var r struct{ Data []byte }
					_ = json.Unmarshal(c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("c126-editor-%d-%s.png", w, theme)), r.Data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				pageChecks(t, tb, "raw editor", w, "", "")
			})
		}
	}
}
