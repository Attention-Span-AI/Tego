// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdDescribe) }

// cmdDescribe is `tego describe session <name>|--last`, `tego describe agent <name>` and `tego describe preset <name>`:
// one thing in full. A session's is its receipt (tego receipt), an agent's its rules in plain words, a preset's its
// promise and its rules.
func cmdDescribe() Command {
	var asJSON, last bool
	return Command{
		Name:    "describe",
		Summary: "one session, agent or preset in full",
		Usage:   "session <name> | session --last | agent <name> | preset <name> [--json]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object (a session only)")
			fs.BoolVar(&last, "last", false, "the newest session")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			kind := fs.Arg(0)
			if kind == "session" && fs.NArg() == 1 && last {
				return delegate(ctx, stdout, stderr, jsonArg([]string{"receipt", "--last"}, asJSON)...)
			}
			if fs.NArg() != 2 || last {
				message(stderr, "", 0, 0, "tego describe: give what and its name: session <name>, session --last, agent <name> or preset <name>", codeUsage)
				return identity.ExitUsage
			}
			name := fs.Arg(1)
			switch kind {
			case "session":
				return delegate(ctx, stdout, stderr, jsonArg([]string{"receipt", "--", name}, asJSON)...)
			case "agent":
				return describeAgent(name, stdout, stderr)
			case "preset":
				return describePreset(name, stdout, stderr)
			}
			message(stderr, "", 0, 0, fmt.Sprintf("tego describe: %q is not something tego describes: session, agent or preset", kind), codeUsage)
			return identity.ExitUsage
		},
	}
}

// jsonArg adds --json before any "--" in args when asJSON.
func jsonArg(args []string, asJSON bool) []string {
	if !asJSON {
		return args
	}
	return append([]string{args[0], "--json"}, args[1:]...)
}

// agentContract resolves an agent's name as tego run does and reads its rules file. It prints why it could not and
// returns a nil contract with the exit code.
func agentContract(verb, name string, m *config.Machine, stderr io.Writer) (contractRef, *agent.Contract, int) {
	if !registry.IsName(name) {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: %q is not an agent name; tego get agents lists them", verb, name), codeUsage)
		return contractRef{}, nil, identity.ExitUsage
	}
	ref, rerr := resolveContract(name, false, m)
	if rerr != nil {
		if rerr.Code == registry.CodeNotFound {
			message(stderr, "", 0, 0, fmt.Sprintf("tego %s: no agent named %s; tego get agents lists them", verb, name), rerr.Code)
			return contractRef{}, nil, identity.ExitUsage
		}
		printRefusedName(stderr, "tego "+verb, rerr)
		return contractRef{}, nil, identity.ExitError
	}
	c, ds, err := ref.load(profileSources(m))
	if err != nil {
		_ = agent.WriteDiagnostics(stderr, ds)
		message(stderr, ref.label(), 0, 0, "tego "+verb+": the rules file does not load: "+err.Error(), agent.CodeSchema)
		return ref, nil, identity.ExitFinding
	}
	return ref, c, identity.ExitOK
}

func describeAgent(name string, stdout, stderr io.Writer) int {
	m := verbMachine("describe", stderr)
	if m == nil {
		return identity.ExitError
	}
	ref, c, code := agentContract("describe", name, m, stderr)
	if c == nil {
		return code
	}
	home := func(ps []string) string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = tildeHome(p, m.Home)
		}
		return strings.Join(out, ", ")
	}
	var b strings.Builder
	line := func(label, v string) { fmt.Fprintf(&b, "%-17s%s\n", label, record.Printable(v)) }
	fmt.Fprintf(&b, "Agent %s\n", record.Printable(c.Name))
	line("Rules file:", tildeHome(ref.label(), m.Home))
	if len(c.Command) > 0 {
		line("Program:", strings.Join(c.Command, " "))
	}
	if len(c.Extends) > 0 {
		line("Presets:", strings.Join(c.Extends, ", "))
	}
	var writes, denyRead []string
	builtinReads := true
	if c.FS != nil {
		for _, w := range c.FS.Write {
			if w != "/dev/null" {
				writes = append(writes, w)
			}
		}
		denyRead = c.FS.DenyRead
		builtinReads = c.FS.DenyRead == nil || len(c.FS.DenyRead) > 0
	}
	switch {
	case len(writes) == 0:
		line("May change:", "nothing")
	default:
		line("May change:", home(writes))
	}
	const secrets = "your secret files (~/.ssh, ~/.aws, ~/.gnupg and the rest of Tego's list)"
	switch {
	case !builtinReads:
		line("Never reads:", "no limit: the rules file turns off the list of secret files")
	case len(denyRead) == 0:
		line("Never reads:", secrets)
	default:
		line("Never reads:", home(denyRead)+", and "+secrets)
	}
	switch {
	case c.Net == nil:
		line("May connect to:", "anywhere")
	case len(c.Net.Allow) == 0:
		line("May connect to:", "nowhere")
	default:
		line("May connect to:", strings.Join(c.Net.Allow, ", "))
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		message(stderr, "", 0, 0, "tego describe: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return identity.ExitOK
}

func describePreset(name string, stdout, stderr io.Writer) int {
	name = strings.TrimPrefix(name, presets.Prefix)
	for _, p := range presets.List() {
		if p.Name != name {
			continue
		}
		_, data, err := presets.Source{}.Resolve(p.Ref())
		if err != nil {
			message(stderr, "", 0, 0, "tego describe: "+err.Error(), codeIO)
			return identity.ExitError
		}
		fmt.Fprintf(stdout, "Preset %s (%s, revision %d)\n", p.Name, p.Ref(), p.Revision)
		fmt.Fprintf(stdout, "What it does: %s.\n", upperFirst(p.Promise))
		fmt.Fprintln(stdout, "Its rules:")
		for _, l := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
				fmt.Fprintln(stdout, "  "+l)
			}
		}
		return identity.ExitOK
	}
	var names []string
	for _, p := range presets.List() {
		names = append(names, p.Name)
	}
	message(stderr, "", 0, 0, fmt.Sprintf("tego describe: no preset named %s; the presets: %s", name, strings.Join(names, ", ")), codeUsage)
	return identity.ExitUsage
}
