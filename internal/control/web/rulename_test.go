// SPDX-License-Identifier: Apache-2.0

package web

import "testing"

// TestRuleNameLabels holds ruleName, the words a rule key reads in on the dashboard (the Rule column of Logs and the
// run timeline, the refusal bars, the line page), to its labels: every key form the engine writes reads as a label
// and the entry as declared, the command rules' among them, and a key with no label of its own reads as written (the
// key stays in the title and the ledger either way). The labels are inforce.Words's (TestWordsMatchesWebLabels):
// the dashboard keeps no table of its own. The fence labels are TestLogsRefusalsNameTheList's.
func TestRuleNameLabels(t *testing.T) {
	for rule, want := range map[string]string{
		"":                               "",
		"unmatched":                      "Not in contract",
		"net.resolver":                   "DNS lookup",
		"held-unsupported":               "Cannot hold",
		"host-sockets":                   "Host socket",
		"fs.write[./out/]":               "Write: ./out/",
		"fs.read[/etc/]":                 "Read: /etc/",
		"fs.deny_read[~/.ssh]":           "Never read: ~/.ssh",
		"fs.deny_write[.git/hooks/]":     "No changes: .git/hooks/",
		"fs.ask[./held/]":                "Ask first: ./held/",
		"fs.ask_read[~/.config/t/token]": "Ask first: ~/.config/t/token",
		"exec[git]":                      "Program: git",
		"exec[/usr/bin/python3]":         "Program: /usr/bin/python3",
		"live.block[exec:ls]":            "Blocked live: exec:ls",
		"net[api.github.com:443]":        "Host: api.github.com:443",
		"net[tcp://chatgpt.com:443]":     "Host: chatgpt.com:443",
		"net[udp://1.1.1.1:53]":          "Host: 1.1.1.1:53",
		"net[unix:/var/run/nscd/socket]": "Socket: /var/run/nscd/socket",
		"exec.deny[curl]":                "Never-run program: curl",
		"exec.allow[git status]":         "Allowed command: git status",
		"fs.watch[./notes/]":             "Watched: ./notes/",
		// No label of its own: a key ruleName does not name, or one that is not closed, reads as written.
		"net.http[0]":           "net.http[0]",
		"mcp[files]":            "mcp[files]",
		"signal-scope":          "signal-scope",
		"fs.write[./out/":       "fs.write[./out/",
		"exec":                  "exec",
		"fs.codex_home[/h/r/c]": "fs.codex_home[/h/r/c]",
	} {
		if got := ruleName(rule); got != want {
			t.Errorf("ruleName(%q) = %q, want %q", rule, got, want)
		}
	}
}
