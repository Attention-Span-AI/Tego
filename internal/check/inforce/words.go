// SPDX-License-Identifier: Apache-2.0

package inforce

import "strings"

// Words is the plain label for a ledger rule key, the one vocabulary the dashboard's event pages and `tego rules`
// share: "fs.write[./tmp/]" is "Writable: ./tmp/", "unmatched" is "Not in the rules (default)".
// For every key the dashboard's ruleName labels it returns that label unchanged (TestWordsMatchesWebLabels), so the
// dashboard can call it in place of its own copy; it labels the command rules and fs.watch as well, and returns any
// other key as written.
func Words(ruleKey string) string {
	inner := func(prefix string) (string, bool) {
		if strings.HasPrefix(ruleKey, prefix+"[") && strings.HasSuffix(ruleKey, "]") {
			return ruleKey[len(prefix)+1 : len(ruleKey)-1], true
		}
		return "", false
	}
	switch ruleKey {
	case "":
		return ""
	case "unmatched":
		return "Not in the rules (default)"
	case "net.resolver":
		return "DNS lookup (always allowed)"
	case "held-unsupported":
		return "Held reads cannot hold this file"
	case "host-sockets":
		return "A socket of the host, refused by default (no net: section)"
	}
	for _, m := range []struct{ key, label string }{
		{"fs.write", "Writable: "}, {"fs.deny_read", "Secret, never readable: "}, {"fs.deny_write", "Protected from changes: "},
		{"fs.ask", "Asks you first: "}, {"fs.ask_read", "Asks you before a read: "}, {"fs.read", "Readable: "},
		{"exec", "Allowed program: "}, {"live.block", "Blocked live: "},
		{"fs.watch", "Watched: "}, {"exec.deny", "Never-run program: "},
		{"exec.ask", "Never-run program (asking first is not supported yet): "},
		{"exec.allow", "Allowed command: "}, {"exec.args", "Command not in the rules for: "},
	} {
		if v, ok := inner(m.key); ok {
			return m.label + v
		}
	}
	if v, ok := inner("net"); ok {
		v = strings.TrimPrefix(strings.TrimPrefix(v, "tcp://"), "udp://")
		if strings.HasPrefix(v, "unix:") {
			return "Allowed socket: " + strings.TrimPrefix(v, "unix:")
		}
		return "Allowed destination: " + v
	}
	return ruleKey
}
