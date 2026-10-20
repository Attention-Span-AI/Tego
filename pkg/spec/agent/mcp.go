// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// MCPRule is the rule name of everything the record says about one declared MCP server: the server's start or
// connection and each tool call (mcp lines), and the connections to an HTTP server's URL its derived net rule
// admits (net lines, NetRule.MCP).
func MCPRule(name string) string { return "mcp[" + name + "]" }

// MCPEndpoint is where an HTTP MCP server's URL connects: its host in CanonicalHost's spelling, its port (the
// scheme's default when the URL names none) and whether the scheme is https.
type MCPEndpoint struct {
	Host  string
	Port  int
	HTTPS bool
}

// String is the endpoint as a net.allow entry spells it, host:port.
func (e MCPEndpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// ParseMCPURL reads an mcp[].url (agent-contract.md R16a). It is an absolute http or https URL with a host. It
// carries no user information, which would put a credential in the contract, its hash and every printed table, and
// no query or fragment: a key in a query is a credential too, and neither names anything a rule could govern.
func ParseMCPURL(raw string) (MCPEndpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return MCPEndpoint{}, errors.New("is not a URL")
	}
	var e MCPEndpoint
	switch strings.ToLower(u.Scheme) {
	case "https":
		e.HTTPS, e.Port = true, 443
	case "http":
		e.Port = 80
	default:
		return MCPEndpoint{}, errors.New("must be an http or https URL")
	}
	switch {
	case u.Opaque != "":
		return MCPEndpoint{}, errors.New("must be an http or https URL with //host")
	case u.User != nil:
		return MCPEndpoint{}, errors.New("holds credentials (user:password@); keep them out of the contract")
	case u.RawQuery != "" || u.ForceQuery:
		return MCPEndpoint{}, errors.New("has a query; keys belong in the environment, not the contract")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return MCPEndpoint{}, errors.New("has a fragment")
	case u.Hostname() == "":
		return MCPEndpoint{}, errors.New("names no host")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return MCPEndpoint{}, errors.New("has a port outside 1-65535")
		}
		e.Port = n
	}
	e.Host = CanonicalHost(u.Hostname())
	return e, nil
}
