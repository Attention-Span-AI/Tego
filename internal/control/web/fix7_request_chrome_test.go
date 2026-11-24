// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// quickBesideLongProbe reads the shared banner (#ask-banner) with the DOM: whether a quick answer form is visible, and
// whether a cut sentence (the phone sentence or the wide LONG sentence) is.
const quickBesideLongProbe = `(()=>{const vis=e=>e.checkVisibility()&&e.getClientRects().length>0;
const b=document.querySelector('#ask-banner');if(!b)return {banner:false};
const allow=[...b.querySelectorAll('form[action="/approvals/answer"]')].filter(vis).some(f=>f.querySelector('button[name=decision][value=approve]'));
const long=[...b.querySelectorAll('.ab-summary,[data-number-exclude="layout.request-long"]')].filter(e=>vis(e)&&e.textContent.includes('…')).length>0;
let rules=0;const sheets=[];for(const s of document.styleSheets){let n=0;try{n=s.cssRules.length}catch(e){n=0}rules+=n;sheets.push((s.href||'inline')+':'+n)}
return {banner:true,allow,long,rules,sheets}})()`

// axBanner is what assistive technology can reach inside the banner: an Allow once button, and text holding a cut.
type axBanner struct {
	Allow, Cut bool
}

// bannerAX walks the accessibility tree under #ask-banner: ignored nodes (display none, hidden, aria-hidden) are not
// reachable.
func bannerAX(t *testing.T, c *cdp, tb *tab, cut string) axBanner {
	t.Helper()
	c.call(t, tb.session, "DOM.enable", map[string]any{})
	c.call(t, tb.session, "Accessibility.enable", map[string]any{})
	var doc struct{ Root struct{ NodeID int } }
	if err := json.Unmarshal(c.call(t, tb.session, "DOM.getDocument", map[string]any{"depth": 0}), &doc); err != nil {
		t.Fatal(err)
	}
	var found struct{ NodeID int }
	if err := json.Unmarshal(c.call(t, tb.session, "DOM.querySelector", map[string]any{"nodeId": doc.Root.NodeID, "selector": "#ask-banner"}), &found); err != nil || found.NodeID == 0 {
		t.Fatalf("no banner in the DOM: %v", err)
	}
	var described struct{ Node struct{ BackendNodeID int } }
	if err := json.Unmarshal(c.call(t, tb.session, "DOM.describeNode", map[string]any{"nodeId": found.NodeID}), &described); err != nil {
		t.Fatal(err)
	}
	raw := c.call(t, tb.session, "Accessibility.getFullAXTree", map[string]any{})
	var generic struct {
		Nodes []struct {
			NodeID           string
			BackendDOMNodeID int
			Ignored          bool
			Role             struct{ Value string }
			Name             struct{ Value string }
			ChildIDs         []string
		}
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	byID := map[string]int{}
	for i, n := range generic.Nodes {
		byID[n.NodeID] = i
	}
	var out axBanner
	var walk func(id string, seen map[string]bool)
	walk = func(id string, seen map[string]bool) {
		i, ok := byID[id]
		if !ok || seen[id] {
			return
		}
		seen[id] = true
		n := generic.Nodes[i]
		// An ignored node is not reachable, and neither is anything beneath a hidden one: its children are ignored
		// too, so keep walking through ignored generic wrappers only.
		if !n.Ignored {
			if n.Role.Value == "button" && n.Name.Value == "Allow once" {
				out.Allow = true
			}
			if n.Role.Value == "StaticText" && strings.Contains(n.Name.Value, "…") && strings.Contains(cut, n.Name.Value) {
				out.Cut = true
			}
		}
		for _, child := range n.ChildIDs {
			walk(child, seen)
		}
	}
	for _, n := range generic.Nodes {
		if n.BackendDOMNodeID == described.Node.BackendNodeID {
			walk(n.NodeID, map[string]bool{})
		}
	}
	return out
}

// TestFix7SafeAnswerNeedsNoStyleSheetInChrome holds the rule of ADR 0123 without trusting any style sheet: Allow once
// is never beside a cut request, with every style sheet loaded, with phone.css blocked (only the main sheets), and
// with every style sheet blocked, at 320 and 1280 px, for the sentence just under and over each bound and a
// 4,000-character command. The probes read the DOM and the accessibility tree.
func TestFix7SafeAnswerNeedsNoStyleSheetInChrome(t *testing.T) {
	c := placeChrome(t)
	wanted := map[string]bool{"under-phone": true, "over-phone": true, "under-wide": true, "over-wide": true, "long-command": true}
	for _, tc := range requestCases() {
		if !wanted[tc.Name] {
			continue
		}
		v := requestOf(ledgerview.Ask{Agent: tc.Agent, Op: tc.Op, Hold: tc.Hold, Target: tc.Target, Run: secondRequestRun, AskID: "long-request"}, nil)
		for _, sheets := range []string{"all", "main-only", "none"} {
			for _, width := range []int{320, 1280} {
				t.Run(fmt.Sprintf("%s/%s/%d", tc.Name, sheets, width), func(t *testing.T) {
					root := t.TempDir()
					id := secondRequestRun
					if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), nil, 0600); err != nil {
						t.Fatal(err)
					}
					at := time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC)
					appendLine(t, root, id, line(id, tc.Agent, 0, at, "run_start", `"tier":"landlock","command":["sh"]`))
					extra, err := json.Marshal(map[string]any{"ask_id": "long-request", "op": tc.Op, "hold": tc.Hold, "target": tc.Target})
					if err != nil {
						t.Fatal(err)
					}
					appendLine(t, root, id, line(id, tc.Agent, 1, at.Add(time.Second), "ask", string(extra[1:len(extra)-1])))
					markLive(t, root, id)
					_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
					tb := sweepTab(t, c, t.Name(), width, map[int]int{320: 640, 1280: 900}[width], "light")
					defer c.closeTarget(t, tb.target)
					c.call(t, tb.session, "Network.enable", map[string]any{})
					switch sheets {
					case "main-only":
						c.call(t, tb.session, "Network.setBlockedURLs", map[string]any{"urls": []string{"*/static/phone.css"}})
					case "none":
						c.call(t, tb.session, "Network.setBlockedURLs", map[string]any{"urls": []string{"*/static/*.css"}})
					}
					for _, page := range []string{"/runs", "/", "/approvals"} {
						c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, page)})
						tb.until(t, "banner", `document.readyState==='complete'&&!!document.querySelector('#ask-banner')`)
						var seen struct {
							Banner, Allow, Long bool
							Rules               int
							Sheets              []string
						}
						if err := json.Unmarshal([]byte(tb.eval(t, quickBesideLongProbe)), &seen); err != nil {
							t.Fatal(err)
						}
						ax := bannerAX(t, c, tb, v.Phone.Target+" "+v.Wide.Target)
						where := fmt.Sprintf("%s %s (%s, %d px)", tc.Name, page, sheets, width)
						if !seen.Banner {
							t.Errorf("%s: no banner", where)
							continue
						}
						if sheets == "none" && seen.Rules != 0 {
							t.Errorf("%s: %d style rules are applied; the block failed: %v", where, seen.Rules, seen.Sheets)
						}
						if seen.Allow && seen.Long {
							t.Errorf("%s: Allow once is visible beside a cut sentence (DOM)", where)
						}
						if ax.Allow && ax.Cut {
							t.Errorf("%s: Allow once is in the accessibility tree beside a cut sentence", where)
						}
						phone := width <= 600
						switch sheets {
						case "all":
							// The sentence of the width's form decides: FULL has the answers, LONG has none.
							form := v.Wide
							if phone {
								form = v.Phone
							}
							if seen.Allow == form.Long || ax.Allow == form.Long {
								t.Errorf("%s: LONG %v but Allow once is %v in the DOM and %v for assistive technology", where, form.Long, seen.Allow, ax.Allow)
							}
							if form.Long && !seen.Long && (phone || page != "/approvals") {
								t.Errorf("%s: the LONG form is not visible", where)
							}
							if phone && v.Phone.Long && !v.Wide.Long && !ax.Cut {
								t.Errorf("%s: the phone sentence is not in the accessibility tree", where)
							}
						default:
							// Only attributes hide anything: the answers are in the markup exactly where the wide
							// sentence is FULL, and the phone's cut sentence is hidden by its own attribute.
							if seen.Allow == v.Wide.Long || ax.Allow == v.Wide.Long {
								t.Errorf("%s: wide LONG %v but Allow once is %v in the DOM and %v for assistive technology", where, v.Wide.Long, seen.Allow, ax.Allow)
							}
							if v.Phone.Long && !v.Wide.Long && seen.Long {
								t.Errorf("%s: the phone's cut sentence shows without phone.css beside the answers", where)
							}
						}
					}
				})
			}
		}
	}
}
