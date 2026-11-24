// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

// resolverSettings names process selectors the empty helper cannot reproduce.
// No values or alias-file contents cross the caller-context frame.
func resolverSettings(lookup func(string) (string, bool)) []string {
	var settings []string
	if _, present := lookup("LOCALDOMAIN"); present {
		settings = append(settings, "LOCALDOMAIN")
	}
	for _, name := range []string{"RES_OPTIONS", "HOSTALIASES"} {
		if value, _ := lookup(name); value != "" {
			settings = append(settings, name)
		}
	}
	// glibc's getaddrinfo also initializes host.conf from these overrides.
	// Presence matters: even an empty path overrides the default host.conf.
	for _, name := range []string{"RESOLV_HOST_CONF", "RESOLV_MULTI", "RESOLV_REORDER", "RESOLV_ADD_TRIM_DOMAINS", "RESOLV_OVERRIDE_TRIM_DOMAINS"} {
		if _, present := lookup(name); present {
			settings = append(settings, name)
		}
	}
	debug, _ := lookup("GODEBUG")
	values := map[string]string{}
	for _, part := range strings.Split(debug, ",") {
		if key, value, ok := strings.Cut(part, "="); ok {
			values[key] = value
		}
	}
	// Match net/conf.go: a mode may precede or follow a debug level.
	mode := ""
	parts := []string{values["netdns"]}
	if first, rest, ok := strings.Cut(values["netdns"], "+"); ok {
		parts = []string{first, rest}
	}
	for _, part := range parts {
		if part != "" && (part[0] < '0' || part[0] > '9') {
			mode = part
		}
	}
	if mode == "go" || mode == "cgo" {
		settings = append(settings, "GODEBUG/netdns")
	}
	if values["netedns0"] == "0" {
		settings = append(settings, "GODEBUG/netedns0")
	}
	if values["multipathtcp"] == "1" || values["multipathtcp"] == "3" {
		settings = append(settings, "GODEBUG/multipathtcp")
	}
	return settings
}
