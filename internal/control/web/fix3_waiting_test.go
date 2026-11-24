// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"golang.org/x/net/html"
)

func TestWaitingRepresentationsAgree(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name            string
		n               int
		scope           countScope
		short, sentence string
	}{
		{"known empty", 0, countScope{}, "", "Nothing waiting"},
		{"known", 3, countScope{}, "3", "3 waiting"},
		{"cut", 3, countScope{Lower: true, Reason: reasonQueueCut}, "3+", "at least 3 waiting: " + reasonQueueCut},
		{"unreadable with known", 3, countScope{Error: "run broken could not be read"}, "3+", "at least 3 waiting: run broken could not be read"},
		{"unknown", 0, countScope{Error: "run broken could not be read"}, "?", "could not tell whether a request is waiting: run broken could not be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pending := make([]ledgerview.Ask, tc.n)
			scopes := countScopes{Queue: tc.scope, Pending: tc.scope}
			source := attentionSource{PendingReason: tc.scope.Reason, PendingUnreadable: tc.scope.Error != ""}
			if tc.scope.Error != "" {
				source.PendingReason = tc.scope.Error
			}
			snap := &ledgerview.Snapshot{Runs: []*ledgerview.Run{{ID: numRichRun, Live: true, Pending: pending}}}
			if tc.scope.Error != "" {
				snap.ReadError = tc.scope.Error
			} else if tc.scope.Lower {
				snap.Runs[0].PendingCut = true
			}
			live := stateOf(snap).Waiting
			if live.Sentence != tc.sentence || live.Show != (tc.short != "") || tc.short != "" && live.Short != tc.short {
				t.Errorf("live title state=%+v", live)
			}
			p := page{chrome: chrome{Pending: tc.n, Numbers: scopes, GlobalNumbers: scopes, Nav: "approvals", Title: "Approvals"}, Data: approvalsData{Pending: pending, AttentionSource: source}}
			var b bytes.Buffer
			renderPageBuffer := func() {
				for _, name := range []string{"content"} {
					if err := pages["approvals"].ExecuteTemplate(&b, name, p); err != nil {
						t.Fatal(err)
					}
				}
			}
			renderPageBuffer()
			var compact *html.Node
			walk(parseHTML(t, "waiting tab", b.String()), func(n *html.Node) {
				id, _ := attr(n, "data-number")
				cl, _ := attr(n, "class")
				if id == "approvals.waiting" && cl == "n" {
					compact = n
				}
			})
			if compact == nil {
				t.Fatal("waiting tab has no quantity")
			}
			wantCompact := tc.short
			if wantCompact == "" {
				wantCompact = "0"
			}
			if got := text(compact); got != wantCompact {
				t.Errorf("waiting tab=%q want %q", got, wantCompact)
			}
			if label, _ := attr(compact, "aria-label"); label != tc.sentence {
				t.Errorf("waiting tab speech=%q want %q", label, tc.sentence)
			}

			// The actual document title is emitted by layout, with the same chrome.
			var full bytes.Buffer
			p.L, err = regions(pages["approvals"], "approvals", p, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := pages["approvals"].ExecuteTemplate(&full, "layout", p); err != nil {
				t.Fatal(err)
			}
			doc := parseHTML(t, tc.name, full.String())
			title, badge, spoken, label := "", "", "", ""
			walk(doc, func(n *html.Node) {
				if n.Data == "title" {
					title = text(n)
				}
				if cl, _ := attr(n, "class"); n.Data == "span" && cl == "count" {
					label, _ = attr(n, "aria-label")
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.TextNode {
							badge += c.Data
						}
						if cl, _ := attr(c, "class"); cl == "sr" {
							spoken = text(c)
						}
					}
				}
			})
			if badge != tc.short {
				t.Errorf("badge=%q want %q", badge, tc.short)
			}
			if tc.short != "" && !strings.HasPrefix(title, "("+tc.short+")") || tc.short == "" && strings.HasPrefix(title, "(") {
				t.Errorf("title=%q", title)
			}
			wantSpoken := tc.sentence
			if tc.short == "" {
				wantSpoken = ""
			}
			if label != wantSpoken {
				t.Errorf("spoken label=%q want %q", label, wantSpoken)
			}
			if spoken != wantSpoken {
				t.Errorf("spoken=%q want %q", spoken, tc.sentence)
			}
			if !strings.Contains(text(parseHTML(t, "page", b.String())), tc.sentence) {
				t.Errorf("page lacks %q", tc.sentence)
			}
		})
	}
}
