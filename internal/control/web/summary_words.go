// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strings"
)

// contractFilterURL carries a query through native Filter navigation without
// escaping query values twice through html/template's contextual URL escaping.
func contractFilterURL(query, state string) string {
	return "/rules?" + url.Values{"filters": {"1"}, "q": {query}, "state": {state}}.Encode()
}

// phoneRuleName identifies the access category. Exact targets and full rule
// sentences belong to the linked Rule page rather than the phone summary row.
func phoneRuleName(r ruleRow) string {
	key := strings.ToLower(r.Key)
	// Built-in rules have fixed names of their own: each row names its category, never a path.
	base, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(key, "built-in."), "builtin."), "[")
	if name, ok := builtinRuleNames[base]; ok && base != key {
		return name
	}
	switch base {
	case "host-sockets":
		return "Local sockets"
	case "route-query":
		return "Network setup"
	case "record":
		return "Recording rule"
	}
	switch {
	case strings.HasPrefix(key, "terminal-devices"):
		return "Terminal devices"
	case strings.HasPrefix(key, "fs"):
		if strings.Contains(key, "write") {
			return "File changes"
		}
		if strings.Contains(key, "read") {
			return "File reads"
		}
		return "File access"
	case strings.HasPrefix(key, "net"):
		return "Network access"
	case strings.HasPrefix(key, "exec"):
		return "Program access"
	case strings.HasPrefix(key, "env"):
		return "Environment rule"
	case key == "record":
		return "Recording rule"
	}
	switch r.Kind {
	case "read", "deny_read":
		return "File reads"
	case "write", "deny_write":
		return "File changes"
	case "net", "host":
		return "Network access"
	case "exec":
		return "Program access"
	}
	return "Access rule"
}

// builtinRuleNames are the phone names of the rules every contract carries (rulesview's built-in rows).
var builtinRuleNames = map[string]string{
	"deny_read":        "Secret files",
	"own-records":      "Tego's records",
	"contract":         "Rules file",
	"no-setuid":        "Root access",
	"host_ipc":         "Session services",
	"tego_surface":     "Tego controls",
	"other_tty":        "Terminal devices",
	"standard_devices": "Standard data devices",
}
