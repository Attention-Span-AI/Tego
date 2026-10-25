// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The nouns tego hands to tego-control (ADR 0100 (2)): `tego serve ...` and the rest open the tego-control beside
// this binary, verify its sealed copy against the build's pin, and exec it with the noun and every argument
// verbatim. tego links none of their code (TestEngineLinksNoControl); the list is internal/handoff's.
func init() {
	for _, n := range handoff.Nouns() {
		register(handOffCommand(n))
	}
}

// openControl is handoff.Open; a variable so a test can count the handoffs a command makes.
var openControl = handoff.Open

// handOffCommand is the engine's command for one of tego-control's nouns. Usage marks it "(tego-control)". A noun this
// build does not have yet is hidden from the command list (writeUsage names it on its "planned" line); calling it
// still hands off, and tego-control says it is not built [not-built].
func handOffCommand(n handoff.Noun) func() Command {
	return func() Command {
		return Command{
			Name:    n.Name,
			Hidden:  !n.Built,
			Summary: "(" + handoff.Name + ") " + n.Summary,
			Usage:   "... (" + handoff.Name + " " + n.Name + " -h lists its flags)",
			Raw: func(_ context.Context, args []string, _, stderr io.Writer) int {
				return handOff(n.Name, args, stderr)
			},
		}
	}
}

// handOff opens and execs tego-control. It returns only when the handoff was refused or the exec failed: one line on
// stderr with the reason code, and the code's exit.
func handOff(noun string, args []string, stderr io.Writer) int {
	b, err := openControl()
	if err == nil {
		err = handoff.Exec(b, append([]string{noun}, args...), nil)
		_ = b.Close()
	}
	var e *handoff.Error
	if errors.As(err, &e) {
		message(stderr, "", 0, 0, "tego "+noun+": "+e.Error(), e.Code)
		return handoff.Exit(e.Code)
	}
	message(stderr, "", 0, 0, "tego "+noun+": "+err.Error(), codeIO)
	return identity.ExitError // R25: Tego's own error
}
