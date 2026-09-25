// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// forwarderVars are the base-URL variables every loopback capture source contributes, merged into the
// one map identity.Env installs last, immediately before execve (R7).
//
// The ordering this depends on is §4.1's, and it already holds: the listeners are bound by the caller,
// before Run, so the URLs exist by step 6 where this is read; the child created in step 7 blocks on its
// ack; step 8 starts the sources, which is when the listeners begin accepting; and only then does
// run_start land and the ack release the child into execve. The agent therefore never sees a base URL
// whose socket is not both bound and served.
func (r *runner) forwarderVars() map[string]string {
	var out map[string]string
	for _, s := range r.allSources() {
		ls, ok := s.(source.LoopbackSource)
		if !ok {
			continue
		}
		for k, v := range ls.Vars() {
			if out == nil {
				out = make(map[string]string)
			}
			out[k] = v
		}
	}
	if r.codexHome != "" && out != nil {
		// Codex takes its base URL from the config.toml under CODEX_HOME, not from a variable
		// (capture-derive.md R19b); the run's own holds the openai listener's URL.
		out[identity.EnvCodexHome] = r.codexHome
	}
	return out
}

// buildEnv resolves env.pass/deny/set into the base the identity set is applied to (R3 steps 1-2):
// a nil pass-list inherits the launcher's environment, a non-nil one keeps exactly those names,
// env.deny removes names in either case, and env.set is applied last.
func buildEnv(rt *agent.RuleTable, environ []string) []string {
	denied := make(map[string]bool, len(rt.Deny))
	for _, name := range rt.Deny {
		denied[name] = true
	}
	pass := map[string]bool(nil)
	if rt.Env != nil {
		pass = make(map[string]bool, len(rt.Env))
		for _, name := range rt.Env {
			pass[name] = true
		}
	}
	out := make([]string, 0, len(environ)+len(rt.Set))
	for _, kv := range environ {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			// An entry with no '=' is not a variable and has no name to match a rule against; it
			// is carried through an inherited environment untouched (identity-config.md E6) and
			// dropped by an explicit pass-list, which names variables only.
			if pass == nil {
				out = append(out, kv)
			}
			continue
		}
		if denied[name] || (pass != nil && !pass[name]) {
			continue
		}
		out = append(out, kv)
	}
	// In name order, so the agent's environ is the same on every run.
	for _, name := range slices.Sorted(maps.Keys(rt.Set)) {
		if denied[name] {
			continue
		}
		out = setEnv(out, name, rt.Set[name])
	}
	return out
}

// agentBaseEnv is the launcher's environment as the agent's account would have it (rootAccountEnv), the base
// buildEnv applies the contract to. Only a root launcher changes it, and only when passwd names both accounts.
func (r *runner) agentBaseEnv() []string {
	environ := r.environ()
	if os.Geteuid() != 0 {
		return environ
	}
	uid, _, err := dropTarget()
	if err != nil {
		return environ // childSpec refuses this run with that error
	}
	root, err := config.LookupPasswd(0)
	if err != nil {
		return environ
	}
	target, err := config.LookupPasswd(uid)
	if err != nil {
		return environ
	}
	return rootAccountEnv(environ, root, target)
}

// rootAccountEnv rewrites what names root's own account in a root launcher's environment to the account the agent
// runs as (identity-config.md R3a). sudo resets HOME, USER and LOGNAME to root's and tego drops the agent to the
// invoking user, so the agent was told a home it cannot enter, beside a contract whose ~ is that user's. A value that
// does not name root is the caller's choice and stays, and a name the launcher does not have stays absent. env.pass,
// env.deny and env.set apply afterwards, as to any launcher's environment.
func rootAccountEnv(environ []string, root, target *user.User) []string {
	out := slices.Clone(environ)
	for i, kv := range out {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch {
		case name == "HOME" && value == root.HomeDir && target.HomeDir != "":
			out[i] = name + "=" + target.HomeDir
		case (name == "USER" || name == "LOGNAME") && value == root.Username && target.Username != "":
			out[i] = name + "=" + target.Username
		}
	}
	return out
}

// guardedResolverEnv keeps glibc's paired A/AAAA lookups on individual sends when the model guard or a
// network gate refuses mutable IP datagram batches (ENOSYS, supervisor R13b, gate.md R4). Modern glibc need
// not fall back from sendmmsg on ENOSYS. single-request is a resolver scheduling option, not a network grant:
// every send still passes the guard and the gate. Existing resolver options survive, including
// single-request-reopen; a run with neither, and observe, retain their environment. Amended 2026-10-05: a
// gate's batches are refused whatever the capture mode, so a gated run with capture uprobe or off, or with
// no models[], had every getaddrinfo(AF_UNSPEC) fail (TestGatedResolverEnvIsSingleRequest).
func guardedResolverEnv(rt *agent.RuleTable, tier backend.Tier, env []string) []string {
	if tier == backend.TierObserve || (len(rt.GuardedModels()) == 0 && !rt.Gate.Has(gate.Net)) {
		return env
	}
	value := lookupEnv(env, "RES_OPTIONS")
	single := false
	for _, option := range strings.Fields(value) {
		if option == "single-request" || option == "single-request-reopen" {
			single = true
			break
		}
	}
	if !single {
		if value != "" {
			value += " "
		}
		value += "single-request"
	}
	return setEnv(slices.Clone(env), "RES_OPTIONS", value)
}

// setEnv replaces name in env, keeping the first entry's position and dropping any later entry of the same
// name (a reader that takes the last one, as Python's os.environ does, must see the value set), or appends it.
func setEnv(env []string, name, value string) []string {
	found := false
	out := env[:0]
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && k == name {
			if found {
				continue
			}
			found = true
			kv = name + "=" + value
		}
		out = append(out, kv)
	}
	if !found {
		out = append(out, name+"="+value)
	}
	return out
}

// resolveCommand turns a bare command name into the path that will be execve'd: execve performs no
// PATH search, so the launcher must do it (docs/p0/runtime-launch.md §2 "Command[0] pre-resolved
// against PATH"). The compiled table is consulted first, so the binary that runs is the one the
// contract's exec entry resolved to and the tier granted; only then the run's effective PATH. A name
// that resolves nowhere is passed through unchanged, which makes the kernel's own ENOENT the
// verdict and ends the run with reason=exec-failed and exit 127 (§6 case 8) instead of a launcher
// error that would read as tego's own failure.
func resolveCommand(rt *agent.RuleTable, cmd []string) []string {
	if len(cmd) == 0 || strings.Contains(cmd[0], "/") {
		return cmd
	}
	resolved := ""
	for _, e := range rt.Exec {
		if !e.IsDir && e.Path != "" && e.Basename == cmd[0] {
			resolved = e.Path
			break
		}
	}
	if resolved == "" {
		resolved = lookPath(rt.PATH, cmd[0])
	}
	if resolved == "" {
		return cmd
	}
	out := slices.Clone(cmd)
	out[0] = resolved
	return out
}

// lookPath returns the first executable named name in the colon-separated list, or "".
func lookPath(path, name string) string {
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate
	}
	return ""
}
