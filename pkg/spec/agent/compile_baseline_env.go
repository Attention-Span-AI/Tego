// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// baselineEnvConflicts predicts the names that bypass env.deny at startup. The final
// environment is checked again after runtime and harness additions, before the stage
// starts: provisioners and capture sources can supply names not known to Compile.
func (k *compiler) baselineEnvConflicts() {
	if k.rt.Baseline == nil || !k.rt.Baseline.Applied {
		return
	}
	source := k.rt.Contract
	injections := k.baselineEnvInjections()
	for i := range k.rt.Baseline.Entries {
		entry := &k.rt.Baseline.Entries[i]
		if entry.Key != config.BaselineDenyEnv {
			continue
		}
		for j, name := range source.Env.Pass {
			if name == entry.Value {
				k.baselineConflict(entry, "env.pass."+strconv.Itoa(j), "explicit environment pass of "+name)
			}
		}
		if _, exists := source.Env.Set[entry.Value]; exists {
			k.baselineConflict(entry, "env.set."+entry.Value, "explicit environment setting of "+entry.Value)
		}
		for _, injection := range injections {
			if injection.name == entry.Value {
				k.baselineConflict(entry, injection.key, injection.producer+" requires environment name "+entry.Value)
			}
		}
	}
}

type baselineEnvInjection struct {
	name, key, producer string
}

func (k *compiler) baselineEnvInjections() []baselineEnvInjection {
	var out []baselineEnvInjection
	add := func(name, key, producer string) {
		out = append(out, baselineEnvInjection{name: name, key: key, producer: producer})
	}
	for _, name := range []string{
		identity.EnvRunID, identity.EnvAgent, identity.EnvParentRun, identity.EnvLedger,
		identity.EnvTier, identity.EnvOTELResourceAttributes, identity.EnvPGAppName,
	} {
		add(name, "", "runtime identity producer")
	}
	// Reason mirrors, CODEX_HOME and harness additions depend on successful runtime
	// provisioning. Root deliberately creates none, and compile does not know that
	// a user launch has a usable runtime directory. CheckProvision and the final
	// ChildSpec check decide the actual additions instead of inventing delivery.
	forwarding := k.rt.Capture == CaptureForwarder || k.rt.Capture == CaptureUprobe && !k.rt.PinsUprobe()
	if forwarding {
		for i, model := range k.c.Models {
			key := "models." + strconv.Itoa(i)
			for _, name := range identity.ProviderBaseURLVars(model.Provider) {
				add(name, key, "capture forwarder producer")
			}
		}
	}
	for i, credential := range k.c.Credentials {
		key := "credentials." + strconv.Itoa(i)
		add(credential.Env, key+".env", "credential stand-in producer")
		if credential.BaseURLEnv != "" {
			add(credential.BaseURLEnv, key+".base_url_env", "credential routing producer")
		}
	}
	if k.rt.DNS.Mode == "broker" {
		add("TEGO_DNS_BROKER_DIR", "dns", "DNS broker producer")
		add("TEGO_DNS_BROKER_PID", "dns", "DNS broker producer")
	}
	if forwarding && len(k.c.Models) > 0 || k.rt.Gate.Has(gate.Net) {
		add("RES_OPTIONS", "net", "guarded resolver producer")
	}
	// identity.Env adds no_proxy when a surviving proxy name exists and NO_PROXY
	// does not. A denied NO_PROXY is removed before identity propagation and is
	// therefore not reintroduced. Keep this tied to names, never proxy values.
	if k.baselineEnvProxy() && !k.baselineEnvSurvives(identity.EnvNoProxy) {
		add(identity.EnvNoProxyLower, "env", "proxy routing producer")
	}
	return out
}

func (k *compiler) baselineEnvSurvives(name string) bool {
	if slices.Contains(k.rt.Deny, name) {
		return false
	}
	if _, exists := k.rt.Set[name]; exists {
		return true
	}
	return (k.rt.Env == nil || slices.Contains(k.rt.Env, name)) && slices.Contains(k.o.envVariableNames, name)
}

func (k *compiler) baselineEnvProxy() bool {
	for _, name := range k.o.envVariableNames {
		if strings.HasSuffix(strings.ToUpper(name), "_PROXY") && k.baselineEnvSurvives(name) {
			return true
		}
	}
	for name := range k.rt.Set {
		if strings.HasSuffix(strings.ToUpper(name), "_PROXY") && k.baselineEnvSurvives(name) {
			return true
		}
	}
	return false
}

// ErrBaselineEnvironment is a denied name that survived into the environment the
// launcher would deliver. It is a launch refusal, never an environment value.
var ErrBaselineEnvironment = errors.New("baseline-conflict: denied name remains in final child environment")

// ValidateBaselineEnv checks the actual environment after all startup producers.
// Recording-only tables have no applied baseline. Values never enter the error.
func (rt *RuleTable) ValidateBaselineEnv(env []string) error {
	if rt == nil || rt.Baseline == nil || !rt.Baseline.Applied {
		return nil
	}
	names := make(map[string]bool, len(env))
	for _, kv := range env {
		if name, _, ok := strings.Cut(kv, "="); ok {
			names[name] = true
		}
	}
	for _, entry := range rt.Baseline.Entries {
		if entry.Key != config.BaselineDenyEnv || !names[entry.Value] {
			continue
		}
		sources := make([]string, 0, min(len(entry.Sources), 4))
		for _, source := range entry.Sources[:min(len(entry.Sources), 4)] {
			sources = append(sources, source.Layer.String()+" layer "+source.String())
		}
		if len(entry.Sources) > 4 {
			sources = append(sources, fmt.Sprintf("and %d further sources", len(entry.Sources)-4))
		}
		return fmt.Errorf("%w: baseline.env.deny %s from %s (owner uid %d, tier %s); remove this baseline entry or the launch injection of this name",
			ErrBaselineEnvironment, entry.Value, strings.Join(sources, ", "), rt.Baseline.Owner.UID, rt.Tier)
	}
	return nil
}
