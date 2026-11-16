// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdEdit) }

// cmdEdit is `tego edit agent <name>`: it opens the agent's rules file in $EDITOR (vi when unset), then checks it as
// tego run will compile it, and says ✓ or prints what is wrong.
func cmdEdit() Command {
	return Command{
		Name:    "edit",
		Summary: "edit an agent's rules file, then check it",
		Usage:   "agent <name>",
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 2 || fs.Arg(0) != "agent" {
				message(stderr, "", 0, 0, "tego edit: give the agent to edit: tego edit agent <name>", codeUsage)
				return identity.ExitUsage
			}
			m := verbMachine("edit", stderr)
			if m == nil {
				return identity.ExitError
			}
			ref, c, code := agentContract("edit", fs.Arg(1), m, stderr)
			if c == nil && ref.entry == nil {
				return code // no file to open; a file that does not load is opened to be fixed
			}
			path := ref.label()
			editor := strings.Fields(os.Getenv("EDITOR"))
			if len(editor) == 0 {
				editor = []string{"vi"}
			}
			cmd := exec.CommandContext(ctx, editor[0], append(editor[1:], path)...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				message(stderr, "", 0, 0, fmt.Sprintf("tego edit: ✗ the editor %s: %v", editor[0], err), codeIO)
				return identity.ExitError
			}
			text, err := os.ReadFile(path)
			if err != nil {
				message(stderr, path, 0, 0, "tego edit: "+err.Error(), codeIO)
				return identity.ExitError
			}
			if err := checkRules(ctx, m, path, text, stderr); err != nil {
				fmt.Fprintf(stdout, "✗ %s has errors (above); tego run %s refuses it until they are fixed\n", path, fs.Arg(1))
				return identity.ExitFinding
			}
			fmt.Fprintf(stdout, "✓ Agent %s's rules are valid: %s\n", fs.Arg(1), path)
			return identity.ExitOK
		},
	}
}

// checkRules compiles a rules file's text as the file at path, the way tego learn --save checks what it saves and
// tego compile --offline checks a file, and prints its errors.
func checkRules(ctx context.Context, m *config.Machine, path string, text []byte, stderr io.Writer) error {
	c, ds, err := agent.LoadBytes(path, text, profileSources(m))
	if err == nil {
		_, ds, err = agent.Compile(c, m, append(learnCompileOptions(ctx, m), agent.Offline())...)
	}
	if err != nil {
		if errs := slices.DeleteFunc(ds, func(d agent.Diagnostic) bool { return d.Severity != agent.SeverityError }); len(errs) > 0 {
			_ = agent.WriteDiagnostics(stderr, errs)
		} else {
			message(stderr, path, 0, 0, err.Error(), agent.CodeSchema)
		}
	}
	return err
}
