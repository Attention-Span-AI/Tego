// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"testing"
	"time"
)

func TestLogsQueryWarningVisibleBesideResultsInChrome(t *testing.T) {
	c := placeChrome(t)
	root := fixture(t)
	appendLine(t, root, harmRun, line(harmRun, "demo", 7, time.Now(), "exec", `"verdict":"allow","path":"/bin/echo"`))
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	for _, width := range []int{390, 768, 1280} {
		for _, scripts := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/scripts=%t", width, scripts), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), width, 844, "light")
				defer c.closeTarget(t, tb.target)
				if !scripts {
					c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": true})
				}
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/logs?where=pid:abc%20kind:exec&t=tok123"})
				tb.until(t, "query results", `document.readyState==='complete' && !!document.querySelector('#log-results [role=alert]')`)
				if tb.eval(t, `(()=>{const e=document.querySelector('#log-results [role=alert]');return !!e&&e.checkVisibility()&&e.textContent.includes('could not be read in full')&&!e.closest('dialog')&&!document.querySelector('dialog.filter-sheet').open;})()`) != "true" {
					t.Error("the unread-query warning is hidden behind Filter")
				}
			})
		}
	}
}

func TestRunsDesktopFilterEntryAndScopedCountInChrome(t *testing.T) {
	c := placeChrome(t)
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	for _, scripts := range []bool{false, true} {
		t.Run(fmt.Sprint("scripts=", scripts), func(t *testing.T) {
			tb := sweepTab(t, c, t.Name(), 1280, 900, "light")
			defer c.closeTarget(t, tb.target)
			if !scripts {
				c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": true})
			}
			c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs?q=unfindable&t=tok123"})
			tb.until(t, "filtered runs", `document.readyState==='complete' && !!document.querySelector('.runs-panel .empty')`)
			if tb.eval(t, `(()=>{const e=document.querySelector('.runs-filter-control');return !!e&&e.checkVisibility()&&e.textContent.includes('0 runs')&&e.querySelector('[data-filter-open]').checkVisibility();})()`) != "true" {
				t.Fatal("desktop hides Filter or its scoped result count")
			}
			tb.eval(t, `document.querySelector('[data-filter-open]').focus();''`)
			tb.press(t, "Enter")
			if scripts {
				tb.until(t, "desktop modal opened through entry", `document.querySelector('dialog.filter-sheet').open`)
			} else {
				tb.until(t, "native desktop filters", `location.search.includes('filters=1')&&!!document.querySelector('.filter-fallback')`)
			}
			if tb.eval(t, `document.querySelector('#runs-filters input[name=q]').value==='unfindable'`) != "true" {
				t.Error("filter lost selected query")
			}
		})
	}
}
