// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// logsURL is the Logs view of one run's lines matching q (and the verdicts, when given): every Highlights item and
// refusal group links to the lines it counts.
func logsURL(run, q string, verdicts ...string) string {
	v := url.Values{"run": {run}}
	if q != "" {
		v.Set("q", q)
	}
	for _, x := range verdicts {
		v.Add("verdict", x)
	}
	return "/logs?" + v.Encode()
}

// secretWhy says what makes a touched path a secret: the contract entry that named it on the line, the entry it
// is under, or the well-known secret places (ledgerview.IsSecretPath).
func secretWhy(t ledgerview.SecretTouch) string {
	switch {
	case strings.HasPrefix(t.Rule, "fs.deny_read["):
		return "Never read"
	case strings.HasPrefix(t.Rule, "fs.ask_read["):
		return "Ask before read"
	case strings.HasPrefix(t.Rule, "fs.ask["):
		return "Ask first"
	case t.Entry != "":
		return "Policy: " + t.Entry
	}
	if k := fileKind(t.Path); k != "" {
		return k
	}
	return "Known secret"
}

// tailCut keeps a path's end, where its file name is: "…/home/.ssh/id_rsa".
func tailCut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}
