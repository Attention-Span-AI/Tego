// SPDX-License-Identifier: Apache-2.0

package web

import (
	"slices"
	"strconv"
	"testing"

	"golang.org/x/net/html"
)

// bandPrecedesQueue checks the actual document/tab positions of both answers
// against the queue's first link, without searching ahead for an answer label.
func bandPrecedesQueue(doc *html.Node) bool {
	var band, queue *html.Node
	walk(doc, func(n *html.Node) {
		if id, _ := attr(n, "id"); id == "ask-banner" {
			band = n
		}
		if cl, _ := attr(n, "class"); cl == "panel approval-queue" {
			queue = n
		}
	})
	if band == nil || queue == nil {
		return false
	}
	in := func(n, root *html.Node) bool {
		for p := n; p != nil; p = p.Parent {
			if p == root {
				return true
			}
		}
		return false
	}
	type control struct {
		node     *html.Node
		dom, tab int
	}
	var controls []control
	dom := 0
	walk(doc, func(n *html.Node) {
		dom++
		if !focusable(n) {
			return
		}
		tab := 0
		if raw, ok := attr(n, "tabindex"); ok {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				return
			}
			tab = parsed
		}
		controls = append(controls, control{n, dom, tab})
	})
	var firstQueue, allow, deny *html.Node
	positions := map[*html.Node]int{}
	for _, c := range controls {
		n := c.node
		positions[n] = c.dom
		if in(n, queue) && n.Data == "a" && firstQueue == nil {
			firstQueue = n
		}
		if in(n, band) && n.Data == "button" {
			switch v, _ := attr(n, "value"); v {
			case "approve":
				allow = n
			case "deny":
				deny = n
			}
		}
	}
	if firstQueue == nil || allow == nil || deny == nil || positions[allow] >= positions[firstQueue] || positions[deny] >= positions[firstQueue] {
		return false
	}
	slices.SortStableFunc(controls, func(a, b control) int {
		if a.tab > 0 && b.tab == 0 {
			return -1
		}
		if a.tab == 0 && b.tab > 0 {
			return 1
		}
		if a.tab != b.tab {
			return a.tab - b.tab
		}
		return a.dom - b.dom
	})
	for i, c := range controls {
		positions[c.node] = i
	}
	return positions[allow] < positions[firstQueue] && positions[deny] < positions[firstQueue]
}

func TestBandOrderRejectsQueueBeforeAnswers(t *testing.T) {
	s := newServer(t, twoRequestFixture(t))
	c := login(t, s)
	doc := parseHTML(t, "Approvals", getRaw(t, s, c, "/approvals"))
	if !bandPrecedesQueue(doc) {
		t.Fatal("answers are not before the queue")
	}
	var band, queue *html.Node
	walk(doc, func(n *html.Node) {
		if id, _ := attr(n, "id"); id == "ask-banner" {
			band = n
		}
		if cl, _ := attr(n, "class"); cl == "panel approval-queue" {
			queue = n
		}
	})
	band.Parent.RemoveChild(band)
	queue.Parent.AppendChild(band)
	if bandPrecedesQueue(doc) {
		t.Fatal("check accepts a queue before the band's answers")
	}
}

func TestBandOrderRejectsEarlierQueueTabIndex(t *testing.T) {
	s := newServer(t, twoRequestFixture(t))
	c := login(t, s)
	doc := parseHTML(t, "Approvals", getRaw(t, s, c, "/approvals"))
	var queue *html.Node
	walk(doc, func(n *html.Node) {
		if cl, _ := attr(n, "class"); cl == "panel approval-queue" {
			queue = n
		}
	})
	found := false
	walk(queue, func(n *html.Node) {
		if !found && n.Data == "a" && focusable(n) {
			n.Attr = append(n.Attr, html.Attribute{Key: "tabindex", Val: "1"})
			found = true
		}
	})
	if !found {
		t.Fatal("no queue link")
	}
	if bandPrecedesQueue(doc) {
		t.Fatal("check accepts the queue first in actual tab order")
	}
}
