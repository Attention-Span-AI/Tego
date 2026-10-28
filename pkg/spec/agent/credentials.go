// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Credential is one entry of the contract's credentials: section (agent-contract.md R30). Load checks its shape, and
// Compile refuses the section.
type Credential struct {
	Name       string   `yaml:"name"`
	Env        string   `yaml:"env"`
	Allow      []string `yaml:"allow"`
	BaseURLEnv string   `yaml:"base_url_env,omitempty"`
}

// credentialNameRE is a credential's name rule.
var credentialNameRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// CredentialNameOK reports whether name is a valid credential name, ^[a-z0-9-]{1,40}$.
func CredentialNameOK(name string) bool { return credentialNameRE.MatchString(name) }

// ParseCredentialAuthority reads one allow entry, host or host:port (443 when the port is left out, an IPv6 address in
// brackets when a port follows), into the authority the forwarder's listeners name, host:port with the host in
// CanonicalHost's spelling. ok is false for anything else.
func ParseCredentialAuthority(entry string) (string, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" || strings.ContainsAny(entry, "/?#@ ") {
		return "", false
	}
	host, port := entry, 443
	if h, p, err := net.SplitHostPort(entry); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		host, port = h, n
	} else if strings.Count(entry, ":") == 1 {
		return "", false // host: with a bad or empty port
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", false
	}
	return net.JoinHostPort(CanonicalHost(host), strconv.Itoa(port)), true
}

// ModelAuthority is a models[] entry's authority, host:port in CanonicalHost's spelling: the forwarder listener's
// declared upstream a credential's allow entry must name exactly.
func (m ModelEndpoint) ModelAuthority() string {
	return net.JoinHostPort(CanonicalHost(m.Host), strconv.Itoa(m.Port))
}

// validateCredentials checks the credentials: section (agent-contract.md R30). Every refusal names the entry and the fix.
func validateCredentials(ds *diags, c *Contract) {
	if len(c.Credentials) == 0 {
		return
	}
	at := func(key string) Pos {
		if p, ok := c.origins[key]; ok {
			return p
		}
		return c.origins["credentials"]
	}
	if c.Capture != CaptureForwarder {
		ds.errorf(at("credentials"), CodeContradiction, "credentials: need capture: forwarder: only Tego's forwarder can put a key into a request").
			fix("write capture: forwarder")
	}
	if c.HostSockets {
		ds.errorf(at("host_sockets"), CodeContradiction, "credentials: cannot be used with host_sockets: true: the session bus is the OS keyring's door").
			fix("drop host_sockets: true")
	}
	declared := make([]string, 0, len(c.Models))
	for _, m := range c.Models {
		declared = append(declared, m.ModelAuthority())
		// A declared route's backend is a place the forwarder carries a request too (ADR 0127).
		declared = append(declared, m.RouteAuthorities()...)
	}
	names := map[string]int{}
	envs := map[string]int{}
	for i, cr := range c.Credentials {
		key := "credentials." + strconv.Itoa(i)
		switch {
		case !credentialNameRE.MatchString(cr.Name):
			ds.errorf(at(key+".name"), CodeSchema, "credential name %q must match ^[a-z0-9-]{1,40}$", cr.Name)
		default:
			if first, dup := names[cr.Name]; dup {
				ds.errorf(at(key+".name"), CodeSchema, "credential name %q already used by entry %d", cr.Name, first+1).
					fix("give every credential a distinct name")
			} else {
				names[cr.Name] = i
			}
		}
		validateCredentialEnv(ds, c, cr, at(key+".env"), envs, i)
		if cr.BaseURLEnv != "" {
			validateCredentialBaseURLEnv(ds, c, cr, at(key+".base_url_env"))
		}
		if len(cr.Allow) == 0 {
			ds.errorf(at(key+".allow"), CodeSchema, "credential %q allows no endpoint", cr.Name).
				fix("write allow: [<a models[] host>]")
		}
		for j, a := range cr.Allow {
			auth, ok := ParseCredentialAuthority(a)
			if !ok {
				ds.errorf(at(key+".allow."+strconv.Itoa(j)), CodeSchema, "credential %q allow entry %q is not host or host:port", cr.Name, a)
				continue
			}
			if !slices.Contains(declared, auth) {
				ds.errorf(at(key+".allow."+strconv.Itoa(j)), CodeContradiction,
					"credential %q allow entry %q (%s) is not a declared models[] endpoint or route (declared: %s); Tego's forwarder carries requests only there",
					cr.Name, a, auth, orNone(declared)).
					fix("name a models[] host and port, or declare the endpoint under models:")
			}
		}
	}
}

// validateCredentialEnv checks one credential's env variable: a valid name, unique, not Tego's or the forwarder's, and
// not set by env.set (which would put a real key in the contract); passed by env.pass is a warning.
func validateCredentialEnv(ds *diags, c *Contract, cr Credential, pos Pos, envs map[string]int, i int) {
	switch {
	case !envNameRE.MatchString(cr.Env):
		ds.errorf(pos, CodeSchema, "credential %q env %q must match ^[A-Za-z_][A-Za-z0-9_]*$", cr.Name, cr.Env)
		return
	case strings.HasPrefix(cr.Env, "TEGO_"):
		ds.errorf(pos, CodeEnvRuntimeReserved, "credential %q env %s is reserved for Tego", cr.Name, cr.Env).
			fix("name the variable the agent reads its key from, for example OPENAI_API_KEY")
	case identity.ForwarderVar(cr.Env):
		ds.errorf(pos, CodeEnvRuntimeReserved, "credential %q env %s is a forwarder base-URL variable", cr.Name, cr.Env).
			fix("name the variable the agent reads its key from, not its base URL")
	}
	if first, dup := envs[cr.Env]; dup {
		ds.errorf(pos, CodeSchema, "credential %q env %s is already credential entry %d's", cr.Name, cr.Env, first+1).
			fix("give every credential its own variable")
	} else {
		envs[cr.Env] = i
	}
	if _, set := c.Env.Set[cr.Env]; set {
		ds.errorf(c.origins["env.set."+cr.Env], CodeContradiction, "env.set %s is credential %q's variable: a real key in the contract", cr.Env, cr.Name).
			fix("remove %s from env.set: credential %s's value never goes in a contract", cr.Env, cr.Name)
	}
	if slices.Contains(c.Env.Pass, cr.Env) {
		ds.warnf(pos, CodeRedundantRule, "env.pass %s is credential %q's variable: the run does not get the value it inherited", cr.Env, cr.Name).
			fix("drop %s from env.pass", cr.Env)
	}
}

// validateCredentialBaseURLEnv checks base_url_env: a valid name, not Tego's, not the credential's own variable.
func validateCredentialBaseURLEnv(ds *diags, c *Contract, cr Credential, pos Pos) {
	switch {
	case !envNameRE.MatchString(cr.BaseURLEnv):
		ds.errorf(pos, CodeSchema, "credential %q base_url_env %q must match ^[A-Za-z_][A-Za-z0-9_]*$", cr.Name, cr.BaseURLEnv)
	case strings.HasPrefix(cr.BaseURLEnv, "TEGO_"):
		ds.errorf(pos, CodeEnvRuntimeReserved, "credential %q base_url_env %s is reserved for Tego", cr.Name, cr.BaseURLEnv)
	case cr.BaseURLEnv == cr.Env:
		ds.errorf(pos, CodeContradiction, "credential %q base_url_env is its env %s", cr.Name, cr.Env)
	}
	if _, set := c.Env.Set[cr.BaseURLEnv]; set {
		ds.errorf(c.origins["env.set."+cr.BaseURLEnv], CodeContradiction, "env.set %s is credential %q's base_url_env, which the launcher sets", cr.BaseURLEnv, cr.Name).
			fix("remove %s from env.set", cr.BaseURLEnv)
	}
}

func orNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ", ")
}

// credentialsLayer is nil, and a contract's credentials: is refused, never skipped.
var credentialsLayer func(*compiler)

// credentialsNoLayer refuses credentials:. Run on, the section would be a run whose variable holds nothing and whose
// requests carry no key, with nothing said.
func (k *compiler) credentialsNoLayer() {
	names, envs := make([]string, 0, len(k.c.Credentials)), make([]string, 0, len(k.c.Credentials))
	for _, cr := range k.c.Credentials {
		names, envs = append(names, cr.Name), append(envs, cr.Env)
	}
	k.ds.errorf(k.pos("credentials"), CodeContradiction, "credentials: Tego does not support this section, so nothing can put %s into a request",
		strings.Join(names, ", ")).
		fix("remove credentials: and pass the agent its own key (env.pass: [%s])", strings.Join(envs, ", "))
}

// credentialsAndRelayTier refuses credentials:, and relayed MCP servers under `tego run --observe`, where no enforcing
// tier keeps the agent from going around the relay.
func (k *compiler) credentialsAndRelayTier() {
	c := k.c
	relayed := false
	for _, s := range c.MCP {
		if s.Relayed() {
			relayed = true
			break
		}
	}
	if len(c.Credentials) > 0 {
		if credentialsLayer == nil {
			k.credentialsNoLayer()
		} else {
			credentialsLayer(k)
		}
	}
	if relayed && k.o.observe {
		k.ds.errorf(k.pos("mcp"), CodeContradiction, "mcp tools: rules cannot run under --observe: nothing would keep the agent from going around the relay").
			fix("run at an enforcing tier, without --observe")
	}
}
