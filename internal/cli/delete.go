// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdDelete) }

// cmdDelete is `tego delete agent <name> [--yes]`: it removes an agent's rules file from the agents saved for this
// user, after asking on a terminal. Without a terminal it needs --yes, so a script never removes one by accident.
func cmdDelete() Command {
	var yes bool
	return Command{
		Name:    "delete",
		Summary: "remove an agent (asks first)",
		Usage:   "agent <name> [--yes]",
		Flags:   func(fs *flag.FlagSet) { fs.BoolVar(&yes, "yes", false, "remove it without asking") },
		Run: func(_ context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 2 || fs.Arg(0) != "agent" {
				message(stderr, "", 0, 0, "tego delete: give the agent to remove: tego delete agent <name>", codeUsage)
				return identity.ExitUsage
			}
			name := fs.Arg(1)
			m := verbMachine("delete", stderr)
			if m == nil {
				return identity.ExitError
			}
			places, rerr := registryPlaces(m)
			if rerr != nil {
				printRefusedName(stderr, "tego delete", rerr)
				return identity.ExitError
			}
			places.Dir = "" // only the agents saved for this user; a project's own agent.yaml is the project's file
			e, err := places.Resolve(name)
			if re := (*registry.Error)(nil); errors.As(err, &re) && re.Code != registry.CodeNotFound {
				printRefusedName(stderr, "tego delete", re)
				return identity.ExitError
			} else if err != nil {
				message(stderr, "", 0, 0, fmt.Sprintf("tego delete: no agent named %s; tego get agents lists them", name), registry.CodeNotFound)
				return identity.ExitUsage
			}
			if !yes {
				if !stdinIsTerminal() {
					message(stderr, "", 0, 0, fmt.Sprintf("tego delete: ✗ not removed: there is no terminal to ask on; "+
						"tego delete agent %s --yes removes it without asking", name), codeUsage)
					return identity.ExitUsage
				}
				fmt.Fprintf(stdout, "Remove agent %s (%s)? [y/N] ", name, e.Path)
				line, _ := bufio.NewReader(confirmInput).ReadString('\n')
				if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
					fmt.Fprintln(stdout, "✗ Nothing removed")
					return identity.ExitFinding
				}
			}
			if err := os.Remove(e.Path); err != nil {
				message(stderr, e.Path, 0, 0, "tego delete: "+err.Error(), codeIO)
				return identity.ExitError
			}
			fmt.Fprintf(stdout, "✓ Agent %s removed\n", name)
			return identity.ExitOK
		},
	}
}
