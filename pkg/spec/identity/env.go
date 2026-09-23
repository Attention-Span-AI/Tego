// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"sort"
	"strings"
)

// Environment variable names of the identity+propagation set (spec/identity/RUN-IDENTITY.md).
const (
	EnvRunID     = "TEGO_RUN_ID"
	EnvAgent     = "TEGO_AGENT"
	EnvParentRun = "TEGO_PARENT_RUN"
	EnvLedger    = "TEGO_LEDGER"
	EnvTier      = "TEGO_TIER"
	// EnvReason names the file inside the run's reach that holds its last refusal (REASON-CHANNEL §2):
	// TEGO_LEDGER's last-refusal.json is in the ledger root, which the agent cannot read (agent-contract
	// R6a).
	EnvReason = "TEGO_REASON"
	// EnvClaudeSettings names a claude-code run's provisioned Claude Code settings file (ADR 0063).
	EnvClaudeSettings = "TEGO_CLAUDE_SETTINGS"

	// EnvOTELResourceAttributes receives tego.run and tego.agent (R4).
	EnvOTELResourceAttributes = "OTEL_RESOURCE_ATTRIBUTES"
	// EnvPGAppName is set to tego:<run id> only when absent (R5).
	EnvPGAppName = "PGAPPNAME"
	// EnvNoProxy and EnvNoProxyLower receive 127.0.0.1,localhost when a *_PROXY variable is present (R6).
	EnvNoProxy      = "NO_PROXY"
	EnvNoProxyLower = "no_proxy"
	// EnvDockerHost points at the per-run Docker proxy socket; EnvDockerContext is removed with it (R8).
	EnvDockerHost    = "DOCKER_HOST"
	EnvDockerContext = "DOCKER_CONTEXT"
	// EnvContainersConfOverride names the per-run containers.conf for rootless podman (R9).
	EnvContainersConfOverride = "CONTAINERS_CONF_OVERRIDE"
	// EnvRayRuntimeEnvHook and EnvRayEnableUVRun are the Ray adapter's variables (R9).
	EnvRayRuntimeEnvHook = "RAY_RUNTIME_ENV_HOOK"
	EnvRayEnableUVRun    = "RAY_ENABLE_UV_RUN_RUNTIME_ENV"
)

// Forwarder base-URL variable names set when capture is forwarder (R7).
const (
	EnvAnthropicBaseURL    = "ANTHROPIC_BASE_URL"
	EnvOpenAIBaseURL       = "OPENAI_BASE_URL"
	EnvOpenAIAPIBase       = "OPENAI_API_BASE"
	EnvGoogleGeminiBaseURL = "GOOGLE_GEMINI_BASE_URL"
	EnvGoogleVertexBaseURL = "GOOGLE_VERTEX_BASE_URL"
	EnvCodeAssistEndpoint  = "CODE_ASSIST_ENDPOINT"
	EnvCodexHome           = "CODEX_HOME"
)

var forwarderVarNames = [...]string{
	EnvAnthropicBaseURL, EnvOpenAIBaseURL, EnvOpenAIAPIBase,
	EnvGoogleGeminiBaseURL, EnvGoogleVertexBaseURL, EnvCodeAssistEndpoint, EnvCodexHome,
}

// ForwarderVarNames is every variable the capture forwarder may set in a run (R7): each provider's base-URL
// variables (ProviderBaseURLVars) and CODEX_HOME, which routes Codex through a generated config.toml. It is the
// fixed set recognized by ForwarderVar; Compile warns on a contract that sets or passes one of them wherever
// the forwarder runs (agent-contract R12). ProviderBaseURLVars supplies each provider's routing names.
// It is a listing copy; editing it does not change which variables are runtime-owned.
var ForwarderVarNames = forwarderVarNames

// ForwarderVar reports whether name is a fixed forwarder-owned variable.
func ForwarderVar(name string) bool {
	for _, n := range forwarderVarNames {
		if n == name {
			return true
		}
	}
	return false
}

// ProviderBaseURLVars is the base-URL variables the forwarder's listener for a models[] provider sets, nil for a
// provider it has no variable for. Codex ignores OPENAI_BASE_URL and reads CODEX_HOME's config.toml instead
// (RUN-IDENTITY.md), which the launcher writes; that is not a provider's variable and is not listed here.
func ProviderBaseURLVars(provider string) []string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "anthropic":
		return []string{EnvAnthropicBaseURL}
	case "openai":
		return []string{EnvOpenAIBaseURL, EnvOpenAIAPIBase}
	case "google", "gemini", "google-gemini":
		return []string{EnvGoogleGeminiBaseURL, EnvGoogleVertexBaseURL, EnvCodeAssistEndpoint}
	}
	return nil
}

// noProxyMembers are the members R6 appends to NO_PROXY/no_proxy.
var noProxyMembers = [...]string{"127.0.0.1", "localhost"}

// rayEnableUVRunValue is the fixed value of RAY_ENABLE_UV_RUN_RUNTIME_ENV in a Ray-enabled run.
const rayEnableUVRunValue = "0"

// Env is the identity+propagation set the launcher installs last, immediately before execve.
// A zero field ("" / nil) means "do not set this variable"; the one exception is ParentRun, which
// is set (possibly empty) whenever RunID is set, because TEGO_PARENT_RUN="" is itself a value.
type Env struct {
	RunID          RunID
	Agent          AgentID
	ParentRun      RunID             // "" is a valid value: TEGO_PARENT_RUN="" is still set
	LedgerDir      string            // the run directory
	ReasonFile     string            // the run's readable copy of last-refusal.json; "" when it has none
	Tier           string            // "landlock" | "cgroup" | "bpflsm" | "observe"
	ForwarderVars  map[string]string // ANTHROPIC_BASE_URL etc.; non-nil only when capture: forwarder (R7)
	DockerHost     string            // "" unless the contract has docker: (R8)
	ContainersConf string            // "" unless containers: rootless (R9)
	RayHook        string            // RAY_RUNTIME_ENV_HOOK value; "" unless the profile enables the Ray adapter (R9)
}

// Apply merges the identity set into base and returns a new slice; base is never mutated.
//
// Pre: base holds env.pass/deny/set-resolved KEY=VALUE entries (R3 steps 1–2). Post: every
// non-zero receiver field is present exactly once, replacing any same-named base entry at its
// original position (I5: no duplicate KEY= prefix survives); new variables are appended in a fixed
// order. Entries without '=' are kept untouched (E6). Pure, total and idempotent:
// Apply(Apply(base)) equals Apply(base) for the same receiver. Linear in len(base) (E22).
//
// R3: runtime variables win unconditionally over env.set. R4: OTEL_RESOURCE_ATTRIBUTES is
// appended to. R5: PGAPPNAME only if absent. R6: NO_PROXY/no_proxy gain 127.0.0.1,localhost iff a
// *_PROXY variable is present (suffix match). R7: forwarder vars overwrite. R8: DOCKER_HOST set and
// DOCKER_CONTEXT removed. R9: CONTAINERS_CONF_OVERRIDE and the Ray pair.
func (e Env) Apply(base []string) []string {
	over := e.overrides(scanBase(base))
	removeDockerContext := e.DockerHost != "" // R8

	out := make([]string, 0, len(base)+len(over))
	for _, entry := range base {
		key, ok := splitKey(entry)
		if !ok {
			out = append(out, entry) // E6
			continue
		}
		if removeDockerContext && key == EnvDockerContext {
			continue
		}
		if i := over.find(key); i >= 0 {
			if !over[i].emitted {
				out = append(out, over[i].entry())
				over[i].emitted = true
			}
			continue // I5: later duplicates of an overridden key are dropped
		}
		out = append(out, entry)
	}
	for i := range over {
		if !over[i].emitted {
			out = append(out, over[i].entry())
		}
	}
	return out
}

// baseScan is what one pass over base tells Apply about the keys it derives values from.
type baseScan struct {
	otel, noProxyUpper, noProxyLower                                  string
	hasOTEL, hasNoProxyUpper, hasNoProxyLower, hasPGAppName, hasProxy bool
}

// scanBase reads the first occurrence of every key Apply derives from (R4–R6) in one linear pass.
func scanBase(base []string) baseScan {
	var s baseScan
	for _, entry := range base {
		key, ok := splitKey(entry)
		if !ok {
			continue
		}
		value := entry[len(key)+1:]
		switch key {
		case EnvOTELResourceAttributes:
			if !s.hasOTEL {
				s.otel, s.hasOTEL = value, true
			}
		case EnvPGAppName:
			s.hasPGAppName = true
		case EnvNoProxy:
			if !s.hasNoProxyUpper {
				s.noProxyUpper, s.hasNoProxyUpper = value, true
			}
		case EnvNoProxyLower:
			if !s.hasNoProxyLower {
				s.noProxyLower, s.hasNoProxyLower = value, true
			}
		}
		if hasProxySuffix(key) {
			s.hasProxy = true
		}
	}
	return s
}

// override is one variable Apply installs.
type override struct {
	key, value string
	emitted    bool
}

func (o override) entry() string { return o.key + "=" + o.value }

// overrideList is the ordered, duplicate-free set of variables to install; a constant few, so a
// linear search is cheaper than a map.
type overrideList []override

func (l overrideList) find(key string) int {
	for i := range l {
		if l[i].key == key {
			return i
		}
	}
	return -1
}

func (l *overrideList) set(key, value string) {
	if i := l.find(key); i >= 0 {
		(*l)[i].value = value
		return
	}
	*l = append(*l, override{key: key, value: value})
}

// overrides computes the variables to install from the receiver and the scan of base.
func (e Env) overrides(s baseScan) overrideList {
	o := make(overrideList, 0, 12+len(e.ForwarderVars))
	if e.RunID != "" {
		o.set(EnvRunID, string(e.RunID))
		o.set(EnvParentRun, string(e.ParentRun))
	}
	if e.Agent != "" {
		o.set(EnvAgent, string(e.Agent))
	}
	if e.LedgerDir != "" {
		o.set(EnvLedger, e.LedgerDir)
	}
	if e.ReasonFile != "" {
		o.set(EnvReason, e.ReasonFile)
	}
	if e.Tier != "" {
		o.set(EnvTier, e.Tier)
	}
	if e.RunID != "" || e.Agent != "" {
		o.set(EnvOTELResourceAttributes, e.otelAttributes(s.otel)) // R4
	}
	if e.RunID != "" && !s.hasPGAppName {
		o.set(EnvPGAppName, "tego:"+string(e.RunID)) // R5
	}
	if s.hasProxy { // R6
		if s.hasNoProxyUpper {
			o.set(EnvNoProxy, appendNoProxy(s.noProxyUpper))
		}
		if s.hasNoProxyLower || !s.hasNoProxyUpper {
			o.set(EnvNoProxyLower, appendNoProxy(s.noProxyLower))
		}
	}
	for _, key := range sortedKeys(e.ForwarderVars) { // R7
		o.set(key, e.ForwarderVars[key])
	}
	if e.DockerHost != "" {
		o.set(EnvDockerHost, e.DockerHost) // R8
	}
	if e.ContainersConf != "" {
		o.set(EnvContainersConfOverride, e.ContainersConf) // R9
	}
	if e.RayHook != "" {
		o.set(EnvRayRuntimeEnvHook, e.RayHook) // R9
		o.set(EnvRayEnableUVRun, rayEnableUVRunValue)
	}
	return o
}

// otelAttributes appends tego.run and tego.agent to an existing OTEL_RESOURCE_ATTRIBUTES value.
// Members identical to the ones being added are not duplicated (keeps Apply idempotent); a stale
// member with a different value is left in place and the fresh one appended (E29). A trailing
// comma in the existing value is not normalized (E7).
func (e Env) otelAttributes(existing string) string {
	var add [2]string
	n := 0
	if e.RunID != "" {
		add[n] = "tego.run=" + percentEncode(string(e.RunID))
		n++
	}
	if e.Agent != "" {
		add[n] = "tego.agent=" + percentEncode(string(e.Agent))
		n++
	}
	return appendMembers(existing, add[:n])
}

// appendNoProxy appends 127.0.0.1 and localhost to a NO_PROXY value, skipping members already present.
func appendNoProxy(existing string) string {
	return appendMembers(existing, noProxyMembers[:])
}

// appendMembers appends every member of add that is not already a ','-separated member of existing;
// an empty existing value yields the members alone. Members are compared after trimming spaces.
func appendMembers(existing string, add []string) string {
	out := existing
	for _, m := range add {
		if hasMember(out, m) {
			continue
		}
		if out == "" {
			out = m
		} else {
			out += "," + m
		}
	}
	return out
}

// hasMember reports whether list (','-separated) contains member, ignoring surrounding spaces.
func hasMember(list, member string) bool {
	for list != "" {
		var head string
		if i := strings.IndexByte(list, ','); i >= 0 {
			head, list = list[:i], list[i+1:]
		} else {
			head, list = list, ""
		}
		if strings.TrimSpace(head) == member {
			return true
		}
	}
	return false
}

// percentEncode escapes ',' and '=' in an OTEL resource attribute value (R4).
func percentEncode(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, ",", "%2C")
	return strings.ReplaceAll(s, "=", "%3D")
}

// hasProxySuffix reports whether key ends in _PROXY, case-insensitively (R6: a suffix match,
// not an enumerated list, so SOCKS_PROXY and RSYNC_PROXY qualify).
func hasProxySuffix(key string) bool {
	const suffix = "_PROXY"
	return len(key) >= len(suffix) && strings.EqualFold(key[len(key)-len(suffix):], suffix)
}

// splitKey returns the KEY of a KEY=VALUE entry; ok is false when there is no '=' or the key is empty.
func splitKey(entry string) (string, bool) {
	i := strings.IndexByte(entry, '=')
	if i <= 0 {
		return "", false
	}
	return entry[:i], true
}

// sortedKeys returns the keys of m in ascending order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
