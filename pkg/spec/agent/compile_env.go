// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"strings"
)

// This file is the secret-env warning (ADR 0067, SEMANTICS §9): a contract with no env.pass passes the launcher's
// whole environment to the agent, and compile names the variables in it whose names look like a credential. It
// removes none: stripping them by default would break the tools that need one (a gh call with GH_TOKEN), and the
// author's fix is an env.pass list, or a profile that holds one.

// secretEnvExact are variable names that hold a credential by convention of the tool that reads them.
var secretEnvExact = []string{
	"GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
}

// secretEnvSuffixes are the endings of names that, after a prefix of their own, hold a credential.
var secretEnvSuffixes = []string{
	"_TOKEN", "_SECRET", "_SECRET_KEY", "_PASSWORD", "_API_KEY", "_ACCESS_KEY", "_PRIVATE_KEY", "_CREDENTIALS",
}

// WithEnviron gives the environment the launcher inherits, as os.Environ lists it, for the secret-env warning.
// Only the names are kept: no value reaches the compiler, so none can reach a diagnostic or the table. Compile
// never reads the process environment itself; without this option the warning cannot fire.
func WithEnviron(environ []string) CompileOption {
	names := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if name != "" {
			names = append(names, name)
		}
	}
	return func(o *compileOptions) { o.envNames = names }
}

// secretEnvName reports whether a variable's name looks like a credential's: one of secretEnvExact, or a name that
// ends in one of secretEnvSuffixes after at least one character of its own, compared without regard to case.
func secretEnvName(name string) bool {
	u := strings.ToUpper(name)
	if slices.Contains(secretEnvExact, u) {
		return true
	}
	for _, s := range secretEnvSuffixes {
		if len(u) > len(s) && strings.HasSuffix(u, s) && u[len(u)-len(s)-1] != '_' {
			return true
		}
	}
	return false
}

// secretEnv warns once when the merged contract passes the whole environment (no env.pass) and the launcher's
// environment holds secret-looking variables the run would hand on: those env.deny does not remove and env.set does
// not replace. The names come sorted, each once; values are never known here (WithEnviron).
func (k *compiler) secretEnv() {
	e := k.c.Env
	if e.Pass != nil || len(k.o.envNames) == 0 {
		return
	}
	var names []string
	for _, n := range k.o.envNames {
		if _, set := e.Set[n]; set || slices.Contains(e.Deny, n) || !secretEnvName(n) {
			continue
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return
	}
	slices.Sort(names)
	names = slices.Compact(names)
	k.ds.warnf(k.pos("env"), CodeSecretEnv, "the contract has no env.pass, so the agent inherits the whole environment, and %d variable(s) in it look like credentials: %s",
		len(names), strings.Join(names, ", ")).
		fix("add env.pass naming the variables the agent needs")
}
