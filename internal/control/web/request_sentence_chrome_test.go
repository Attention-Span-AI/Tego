// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestRequestSentenceKeepsIntentInChrome(t *testing.T) {
	c := placeChrome(t)
	type intentCase struct{ name, op, target, prefix string }
	var cases []intentCase
	for _, op := range []string{"", "connect", "send", "read", "write", "mkdir", "symlink", "link", "request", "mcp_tool", "exec"} {
		name := op
		if name == "" {
			name = "continue"
		}
		cases = append(cases, intentCase{name, op, "registry.npmjs.org", "reg"})
	}
	cases = append(cases, intentCase{"wide-latin", "connect", strings.Repeat("W", 30) + ".com", "WWW"}, intentCase{"wide-cjk", "connect", strings.Repeat("界", 30) + ".com", "界"}, intentCase{"visible-control", "connect", "\u202e" + strings.Repeat("W", 30), "⟦U+"})
	for _, tc := range cases {
		root := fixture(t)
		now := time.Now()
		name := strings.Repeat("Mira", 15)
		appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, now, "answer", `"ask_id":"ask-7","approved":false`))
		appendLine(t, root, harmRun, line(harmRun, name, 8, now, "ask", fmt.Sprintf(`"ask_id":"intent","hold":"net","op":%q,"target":%q`, tc.op, tc.target)))
		_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
		for _, width := range []int{320, 360, 390, 430} {
			for _, theme := range []string{"light", "dark"} {
				t.Run(fmt.Sprintf("%s/%d/%s", tc.name, width, theme), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 780, theme)
					defer a1Close(t, tb)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?t=tok123"})
					tb.until(t, "sentence", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('.ab-summary')`)
					// A long name never hides the action or the target's start: the FULL form shows the name whole
					// beside the quick answers; a LONG one (request_forms.go) cuts the name in the middle and offers
					// Review request alone. The accessible name is the whole sentence either way.
					v := requestOf(ledgerview.Ask{Agent: name, Op: tc.op, Hold: "net", Target: tc.target}, nil)
					probe := fmt.Sprintf(`(()=>{const b=document.getElementById('ask-banner'),p=b.querySelector('.ab-summary'),n=p.querySelector('.ab-name'),a=p.querySelector('.ab-intent');if(!n||!a)return false;const r=a.getBoundingClientRect(),q=p.getBoundingClientRect(),quick=[...b.querySelectorAll('button[name=decision]')].some(e=>e.checkVisibility()),review=!!b.querySelector('.ab-review a')&&b.querySelector('.ab-review a').checkVisibility();return getComputedStyle(n).textOverflow!=='ellipsis' && n.textContent===%s && r.right<=q.right+1 && r.left>=q.left-1 && a.textContent.includes('wants to ') && a.querySelector('.ab-short-target').textContent.includes(%q) && (p.getAttribute('aria-label').includes(%q)||p.getAttribute('aria-label').includes(%q)) && p.getAttribute('aria-label').includes('MiraMiraMira') && quick===%v && review===%v;})()`, jsString(v.Phone.Agent), tc.prefix, tc.target, visibleText(tc.target), !v.Phone.Long, v.Phone.Long)
					if tb.eval(t, probe) != "true" {
						t.Errorf("long name hides the action or target, or the %v form's answers are wrong", v.Phone.Long)
					}
					tb.clean(t, "request sentence")
				})
			}
		}
	}
}
