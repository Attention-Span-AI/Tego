// SPDX-License-Identifier: Apache-2.0

package inforce

import "strings"

// Words is the plain label for a ledger rule key, the one vocabulary for rule keys: the dashboard shows it wherever
// it names a line's rule (web's ruleName reads it through rulesview.RuleWords), the key itself in the title, and
// `tego rules` is to share it. "fs.write[./tmp/]" is "Write: ./tmp/"; "unmatched" is "Not in policy": no entry of the
// contract names the action, so the contract's default decided it. It labels every key form the engine writes, the
// command rules, fs.watch and an Adjustable run's fence entries (live.fence[<kind>:<value>], named by the value as
// the Rules page's fence panel names them) among them, and returns any other key as written.
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
		return "Not in policy"
	case "net.resolver":
		return "DNS lookup"
	case "held-unsupported":
		return "Cannot hold"
	case "host-sockets":
		return "Host socket"
	case "builtin.host_ipc":
		return "Host IPC blocked"
	case "builtin.tego_surface":
		return "Tego control blocked"
	case "builtin.other_tty":
		return "Other terminal blocked"
	}
	for _, m := range []struct{ key, label string }{
		{"fs.write", "Write: "}, {"fs.deny_read", "Never read: "}, {"fs.deny_write", "No changes: "},
		{"fs.ask", "Ask first: "}, {"fs.ask_read", "Ask first: "}, {"fs.read", "Read: "},
		{"exec", "Program: "}, {"live.block", "Blocked live: "},
		{"fs.watch", "Watched: "}, {"exec.deny", "Never-run program: "},
		{"exec.ask", "Never-run program (asking first is not supported yet): "},
		{"exec.allow", "Allowed command: "}, {"exec.args", "Command not in the rules for: "},
	} {
		if v, ok := inner(m.key); ok {
			return m.label + v
		}
	}
	if v, ok := inner("live.fence"); ok {
		// The fence entry's kind is the line's own, so the label names its value alone.
		if _, val, cut := strings.Cut(v, ":"); cut {
			v = val
		}
		return "Fence: " + v
	}
	if v, ok := inner("net"); ok {
		v = strings.TrimPrefix(strings.TrimPrefix(v, "tcp://"), "udp://")
		if strings.HasPrefix(v, "unix:") {
			return "Socket: " + strings.TrimPrefix(v, "unix:")
		}
		return "Host: " + v
	}
	return ruleKey
}
