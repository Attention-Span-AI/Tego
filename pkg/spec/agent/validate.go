// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// validateMerged runs the cross-field rules of §5 on the merged contract:
// required fields (R3, R4), the not-yet-supported sweep (R2), duplicate and
// redundant entries (E10, R16), env conflicts (R12), mcp uniqueness (E26),
// model bypass (E27) and the limits consistency checks.
func validateMerged(ds *diags, c *Contract, top string) {
	at := func(key string) Pos {
		if p, ok := c.origins[key]; ok {
			return p
		}
		return Pos{File: top, Line: 1, Col: 1}
	}
	if _, ok := c.origins["version"]; !ok {
		ds.errorf(at("version"), CodeSchema, "version is required").fix("write version: 0")
	}
	if c.Name == "" {
		ds.errorf(at("name"), CodeSchema, "name is required").fix("write name: <agent>, matching ^[a-z0-9-]{1,40}$")
	}
	if len(c.Command) == 0 || c.Command[0] == "" { // R4, E11
		ds.errorf(at("command"), CodeSchema, "command must name the program to run").fix("write command: [\"python\", \"agent.py\"]")
	}
	validateNotYetSupported(ds, c, at)
	validateLists(ds, c)
	validateEnv(ds, c)
	validateMCP(ds, c)
	validateMCPTools(ds, c)
	validateModelRoutes(ds, c) // before credentials, whose allow entries may name a route's backend
	validateCredentials(ds, c)
	validateExec(ds, c)
	validateModels(ds, c)
	validateNetAssurance(ds, c, at)
	validateFSAssurance(ds, c, at)
	validateFSReads(ds, c, at)
	validateExecAssurance(ds, c, at)
	validateListenerControl(ds, c, at)
	validateHTTP(ds, c, at)
	validateDNSPolicy(ds, c, at)
	validateProxyPolicy(ds, c, at)
	validateGate(ds, c, at)
	validateAsk(ds, c, at)
	validateLimits(ds, c)
}

// notYetSupported lists every schema-only field with the phase it ships in (R2).
type notYetSupported struct {
	key   string
	phase string
	empty func(c *Contract) bool
}

var schemaOnlyFields = []notYetSupported{
	{"exec.privileged", "P2", func(c *Contract) bool { return c.Exec == nil || len(c.Exec.Privileged) == 0 }},
	{"env.mask", "P2", func(c *Contract) bool { return len(c.Env.Mask) == 0 }},
	{"docker", "P1", func(c *Contract) bool { return nodeEmpty(&c.Docker) }},
	{"containers", "P1", func(c *Contract) bool { return c.Containers == "" || c.Containers == "none" }},
	{"prompt", "P1", func(c *Contract) bool { return strings.TrimSpace(c.Prompt) == "" }},
	{"skills", "P1", func(c *Contract) bool { return len(c.Skills) == 0 }},
	{"visibility", "P1", func(c *Contract) bool { return len(c.Visibility) == 0 }},
}

func validateNotYetSupported(ds *diags, c *Contract, at func(string) Pos) {
	for _, f := range schemaOnlyFields {
		if f.empty(c) {
			continue
		}
		ds.errorf(at(f.key), CodeNotYetSupported, "%s is not yet supported by this binary (arrives in %s)", f.key, f.phase).
			fix("remove %s: or leave it empty; it is accepted by the schema but has no effect in P0", f.key)
	}
}

// validateLists flags exact duplicates inside one list as redundant (E24: a
// map, never pairwise). Only a file's own repeat is one: an entry two files of
// the extends chain both declare merges silently (ADR 0066), since a profile
// cannot know what its users declare.
func validateLists(ds *diags, c *Contract) {
	if c.FS != nil {
		dupes(ds, c, "fs.write", c.FS.Write)
		dupes(ds, c, "fs.watch", c.FS.Watch)
		dupes(ds, c, "fs.deny_read", c.FS.DenyRead)
		dupes(ds, c, "fs.ask_read", c.FS.AskRead)
		dupes(ds, c, "fs.deny_write", c.FS.DenyWrite)
	}
	if c.Net != nil {
		dupes(ds, c, "net.allow", c.Net.Allow)
	}
	if c.Exec != nil {
		dupes(ds, c, "exec.allow", c.Exec.Allow)
		dupes(ds, c, "exec.deny", c.Exec.Deny)
		dupes(ds, c, "exec.ask", c.Exec.Ask)
	}
	dupes(ds, c, "env.pass", c.Env.Pass)
	dupes(ds, c, "env.deny", c.Env.Deny)
}

func dupes(ds *diags, c *Contract, key string, list []string) {
	normalize := func(v string) string {
		if strings.HasPrefix(key, "fs.") || key == "exec.allow" {
			return cleanEntry(v)
		}
		return v
	}
	pos := func(i int) Pos { return c.origins[key+"."+strconv.Itoa(i)] }
	// seen is each entry's first index, until the entry repeats. A repeat, the rare case, is redundant only where the same file wrote the
	// entry before, so a repeated entry's copies are then held by file too: one lookup each, whatever other files
	// wrote in between (E24: never pairwise), and a list with no repeat looks up no position at all.
	type entry struct{ norm, file string }
	seen := make(map[string]int, len(list))
	var byFile map[entry]int
	for i, v := range list {
		norm := normalize(v)
		first, ok := seen[norm]
		if !ok {
			seen[norm] = i
			continue
		}
		if byFile == nil {
			byFile = map[entry]int{}
		}
		if first >= 0 {
			byFile[entry{norm, pos(first).File}] = first
			seen[norm] = -1 // its first copy is held by file now
		}
		at := pos(i)
		if j, ok := byFile[entry{norm, at.File}]; ok {
			ds.warnf(at, CodeRedundantRule, "%s entry %q repeats entry %d", key, v, j+1).
				fix("remove the duplicate")
			continue
		}
		byFile[entry{norm, at.File}] = i
	}
}

// execLists are the exec: lists that hold command patterns, with the list each is matched as.
var execLists = []struct {
	key  string
	list execmatch.List
	of   func(*ExecSection) []string
}{
	{"exec.allow", execmatch.ListAllow, func(s *ExecSection) []string { return s.Allow }},
	{"exec.deny", execmatch.ListDeny, func(s *ExecSection) []string { return s.Deny }},
	{"exec.ask", execmatch.ListAsk, func(s *ExecSection) []string { return s.Ask }},
}

// validateExec checks every exec command pattern against its grammar with the tool rows (ADR 0048 (1)): an entry the
// grammar refuses is an exec-rule error naming the word and the fix, a $ or backtick in a word warns (it is matched
// literally), more than 512 patterns after extends is an error, and a deny-list section with no entry warns that it
// restricts nothing. A one-word exec.allow entry is an image, a path or a name, exactly as before ADR 0048, and is
// compile's to resolve. Classification is the text alone: an unquoted space makes a pattern on every machine.
func validateExec(ds *diags, c *Contract) {
	if c.Exec == nil {
		return
	}
	total := 0
	for _, l := range execLists {
		for i, e := range l.of(c.Exec) {
			if l.list == execmatch.ListAllow && !execmatch.IsPattern(e) {
				continue
			}
			pos := c.origins[l.key+"."+strconv.Itoa(i)]
			total++
			p, err := execmatch.Parse(e, l.list, rows.Builtin())
			var se *execmatch.SyntaxError
			warn := func(warnings []string) {
				for _, w := range warnings {
					fix := "correct the option spelling in this entry"
					if strings.Contains(w, "$ or a backtick") {
						fix = "drop the $ or backtick: no shell expands an entry"
					}
					ds.warnf(pos, CodeExecRule, "%s %q: %s", l.key, e, w).fix("%s", fix)
				}
			}
			if errors.As(err, &se) {
				warn(se.Warnings)
				ds.errorf(pos, CodeExecRule, "%s %q: %s", l.key, e, se.Msg).fix("%s", fixOr(se.Fix, "see docs/spec/exec-command-rows.md for the pattern grammar"))
				continue
			}
			if err != nil {
				ds.errorf(pos, CodeExecRule, "%s %q: %v", l.key, e, err)
				continue
			}
			warn(p.Warnings)
		}
	}
	if total > execmatch.MaxPatterns {
		ds.errorf(c.origins["exec"], CodeExecRule, "exec: %d command patterns after extends; at most %d", total, execmatch.MaxPatterns).
			fix("merge entries: deny a subcommand once rather than each of its option spellings")
	}
	if c.Exec.DenyList() && len(c.Exec.Deny)+len(c.Exec.Ask) == 0 {
		at := c.origins["exec.deny"]
		if at.File == "" {
			at = c.origins["exec.ask"]
		}
		ds.warnf(at, CodeExecRule, "this exec: section restricts nothing: with no allow key it is a deny-list, and its lists are empty").
			fix("add entries, or an allow key to restrict images")
	}
}

// fixOr is fix, or alt when fix is empty.
func fixOr(fix, alt string) string {
	if fix == "" {
		return alt
	}
	return fix
}

// cleanEntry normalizes a path entry for duplicate detection only: trailing
// slashes and "." segments are removed, nothing is resolved.
func cleanEntry(s string) string {
	if s == "" {
		return s
	}
	return path.Clean(s)
}

func validateEnv(ds *diags, c *Contract) {
	deny := make(map[string]int, len(c.Env.Deny))
	for i, n := range c.Env.Deny {
		deny[n] = i
	}
	for i, n := range c.Env.Pass {
		if _, ok := deny[n]; ok {
			ds.warnf(c.origins["env.pass."+strconv.Itoa(i)], CodeRedundantRule, "env.pass %s is removed again by env.deny", n).
				fix("drop it from one of the two lists")
		}
	}
	keys := make([]string, 0, len(c.Env.Set))
	for k := range c.Env.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := deny[k]; ok { // R12, SEMANTICS §9
			ds.errorf(c.origins["env.set."+k], CodeContradiction, "env.set %s is also in env.deny", k).
				fix("remove %s from env.deny or from env.set", k)
		}
	}
}

// validateMCPURLs reads every mcp[].url (R16a): a URL ParseMCPURL takes, one server per host and port, since
// capture tells two servers apart by where an exchange went and nothing else, and not a models[] endpoint, whose
// exchanges are the model's. A server on a model endpoint's host at another port is a warning: capture matches a
// models[] entry by host alone, so that server's exchanges are read as the model's and no tool call is derived
// from them.
func validateMCPURLs(ds *diags, c *Contract) {
	byOrigin := map[string]string{}
	for i, s := range c.MCP {
		if s.URL == "" || len(s.Command) > 0 {
			continue
		}
		at := c.origins["mcp."+strconv.Itoa(i)+".url"]
		e, err := ParseMCPURL(s.URL)
		if err != nil {
			ds.errorf(at, CodeSchema, "mcp %q url %q %v", s.Name, s.URL, err).
				fix("write the server's endpoint, for example url: \"https://mcp.example.com/mcp\"")
			continue
		}
		if other, dup := byOrigin[e.String()]; dup {
			ds.errorf(at, CodeContradiction, "mcp %q url reaches the same origin %s as mcp %q", s.Name, e, other).
				fix("declare one server per host and port")
		} else {
			byOrigin[e.String()] = s.Name
		}
		// Every models[] entry is read: an exact endpoint is the error even after one on the host at another port.
		var sameHost, exact *ModelEndpoint
		for j := range c.Models {
			m := &c.Models[j]
			if CanonicalHost(m.Host) != e.Host {
				continue
			}
			if sameHost == nil {
				sameHost = m
			}
			if m.Port == e.Port {
				exact = m
				break
			}
		}
		switch {
		case exact != nil:
			ds.errorf(at, CodeContradiction, "mcp %q url is the models[] endpoint %s of provider %q", s.Name, e, exact.Provider).
				fix("point url: at the MCP server, not at the model")
		case sameHost != nil:
			ds.warnf(at, CodeUnenforced, "mcp %q url shares host %s with models[] provider %q: capture reads that host's exchanges as the model's, and derives no tool call of this server", s.Name, e.Host, sameHost.Provider).
				fix("serve the MCP server on its own host name")
		}
	}
}

func validateMCP(ds *diags, c *Contract) {
	seen := make(map[string]int, len(c.MCP))
	for i, s := range c.MCP {
		key := "mcp." + strconv.Itoa(i)
		if first, dup := seen[s.Name]; dup { // E26
			ds.errorf(c.origins[key+".name"], CodeSchema, "mcp name %q already used by entry %d", s.Name, first+1).
				fix("give every mcp server a distinct name")
		} else {
			seen[s.Name] = i
		}
		if s.Name == "" {
			ds.errorf(c.origins[key], CodeSchema, "mcp entry %d has no name", i+1)
		}
		switch {
		case len(s.Command) > 0 && s.URL != "":
			ds.errorf(c.origins[key], CodeSchema, "mcp %q has both a command and a url", s.Name).
				fix("keep command: for a server the agent launches (stdio), url: for one it connects to (HTTP)")
		case s.URL != "":
			// Checked here rather than by the schema, so that every compile reads one spelling of it.
		case len(s.Command) == 0:
			ds.errorf(c.origins[key], CodeSchema, "mcp %q has no command and no url", s.Name).
				fix("write command: [\"mcp-%s\"] for a stdio server, or url: \"https://host/mcp\" for an HTTP one", s.Name)
		case s.Command[0] == "":
			ds.errorf(c.origins[key], CodeSchema, "mcp %q has no command", s.Name).fix("write command: [\"mcp-%s\"]", s.Name)
		}
	}
	validateMCPURLs(ds, c)
	if c.Exec == nil {
		return
	}
	// An mcp command also listed in exec.allow is redundant, not wrong.
	byName := map[string]string{}
	for _, s := range c.MCP {
		if len(s.Command) > 0 {
			byName[s.Command[0]] = s.Name
			byName[path.Base(s.Command[0])] = s.Name
		}
	}
	for i, e := range c.Exec.Allow {
		if name, ok := byName[e]; ok {
			ds.warnf(c.origins["exec.allow."+strconv.Itoa(i)], CodeRedundantRule, "exec.allow %q is already granted implicitly as the command of mcp %q", e, name).
				fix("remove it from exec.allow")
		}
	}
}

// modelAllow is a net.allow entry that names a models[] endpoint (E27).
type modelAllow struct {
	at       Pos
	raw      string
	provider string
}

// modelAllows lists the net.allow host entries that name a declared models[] endpoint, with their positions. Both
// sides are compared in CanonicalHost's spelling, so api.example.com. and [::1] match as the guard matches them.
func modelAllows(c *Contract) []modelAllow {
	if c.Net == nil || len(c.Models) == 0 {
		return nil
	}
	models := make(map[string]string, len(c.Models))
	for _, m := range c.Models {
		models[CanonicalHost(m.Host)+":"+strconv.Itoa(m.Port)] = m.Provider
	}
	var out []modelAllow
	for i, raw := range c.Net.Allow {
		e, err := ParseEndpoint(raw)
		if err != nil || e.Kind != EndpointHost {
			continue
		}
		if provider, ok := models[CanonicalHost(e.Host)+":"+strconv.Itoa(e.Port)]; ok {
			out = append(out, modelAllow{at: c.origins["net.allow."+strconv.Itoa(i)], raw: raw, provider: provider})
		}
	}
	return out
}

// validateModels is E27 as far as the contract alone decides it. A pinned capture: uprobe with the tier at
// cgroup or above, or left to the machine, is decided by Compile, which knows the machine's ceilings and the
// tiers this build has (modelBypassLowered).
func validateModels(ds *diags, c *Contract) {
	for _, m := range modelAllows(c) {
		switch {
		case c.Capture == CaptureUprobe && backend.TierCgroup.AtOrBelow(backend.Tier(c.Tier)):
			// A contract that pins capture: uprobe and a tier that runs uprobes runs no forwarder
			// (RuleTable.PinsUprobe) unless a machine ceiling lowers it, which Compile warns about: this entry
			// is the agent's one route to its model, the one the probes read, and there is no proxy to bypass.
			// Removing it, as the warning below says to, would refuse the agent its model.
		case c.Capture == CaptureUprobe && c.Tier != TierPin(backend.TierLandlock):
			// Pinned uprobe, tier left to the machine: whether the entry is a bypass depends on the tier the
			// machine gives, so Compile warns, once (modelBypassLowered). Warning here as well gave a contract
			// compiled on a tier-1 build two warnings about one entry with opposite fixes.
		default: // E27
			ds.warnf(m.at, CodeModelDirectBypass, "net.allow %q cannot grant direct access to the %s model when capture uses the forwarder", m.raw, m.provider).
				fix("remove it from net.allow; the forwarder reaches the model host on the run's behalf")
		}
	}
}

func validateLimits(ds *diags, c *Contract) {
	l := c.Limits
	if l.Memory != nil && l.MemoryHigh != nil && *l.MemoryHigh > *l.Memory {
		ds.errorf(c.origins["limits.memory_high"], CodeContradiction, "memory_high %s is above memory %s", l.MemoryHigh, l.Memory).
			fix("memory_high is the throttle point and must not exceed the memory cap")
	}
	if l.StallAfter != nil && l.Wall != nil && *l.StallAfter > *l.Wall {
		ds.warnf(c.origins["limits.stall_after"], CodeRedundantRule, "stall_after %s is longer than wall %s and can never fire", l.StallAfter, l.Wall)
	}
}
