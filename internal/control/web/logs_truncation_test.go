// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The shell's padding can narrow legacy ellipsized labels. Their full label
// must stay reachable even when an ancestor title only names a run or query.
func TestLogsTruncationHasFullValue(t *testing.T) {
	s := newServer(t, logsRuleTitleFixture(t))
	b := get(t, s, login(t, s), "/logs")
	for _, class := range []string{"lq-l", "lw-agent"} {
		matches := regexp.MustCompile(`<span class="`+class+`" title="([^"]*)">([^<]*)</span>`).FindAllStringSubmatch(b, -1)
		if len(matches) == 0 {
			t.Errorf("%s has no full-value title", class)
		}
		for _, m := range matches {
			if !strings.Contains(html.UnescapeString(m[1]), html.UnescapeString(m[2])) {
				t.Errorf("%s title omits its displayed value: %s", class, m[0])
			}
		}
	}
	// The rule's raw key alone cannot recover its rendered words, such as
	// "Not in contract" for unmatched. A native line clamp needs both in its title.
	rules := regexp.MustCompile(`<span class="clamp" title="([^"]*)">(?:<span>)?([^<]*)(?:</span>)?</span>`).FindAllStringSubmatch(b, -1)
	if len(rules) == 0 {
		t.Fatal("no rule labels with full-value titles")
	}
	seen := make(map[string]bool)
	for _, m := range rules {
		title, label := html.UnescapeString(m[1]), html.UnescapeString(m[2])
		seen[label] = true
		if !strings.Contains(title, label) {
			t.Errorf("rule title omits its displayed value %q: %q", label, title)
		}
		if label == "Never read: ~/.ssh" && !strings.Contains(title, "fs.deny_read[~/.ssh]") {
			t.Errorf("rule title omits its raw key: %q", title)
		}
	}
	for _, label := range []string{"Not in contract", "Never read: ~/.ssh", "—"} {
		if !seen[label] {
			t.Errorf("fixture lacks rule-label case %q", label)
		}
	}
}

// A few real-shaped rows are enough to exercise the audit's long agent and
// target values, without its thousand-line history.
func logsRuleTitleFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	const run = "r-7f3a9c41-0000000000003-supprt"
	const agent = "support-ticket-triage-worker-for-the-eu-billing-queue"
	t0 := time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	finishRun(t, root, run,
		line(run, agent, 0, t0, "run_start", `"tier":"landlock","command":["python3","/home/dana/projects/customer-support/automation/triage-worker/src/triage.py"],"cwd":"/home/dana/projects/customer-support/automation/triage-worker"`),
		line(run, agent, 1, t0.Add(time.Second), "fs", `"verdict":"allow","op":"open","path":"/home/dana/projects/customer-support/automation/triage-worker/out/tickets/2026-10-25/ticket-00998-labelled.json","flags":577`),
		line(run, agent, 2, t0.Add(2*time.Second), "refused", `"rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","target":"/home/dana/.ssh/id_ed25519.backup-before-rotation-2026-11-11T2104"`),
		line(run, agent, 3, t0.Add(3*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	return root
}
