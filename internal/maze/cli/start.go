// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// newTerm builds the Term a command talks through; tests swap in a scripted one.
var newTerm = func(s Streams, o ui.Options) *ui.Term { return ui.New(s.In, s.Out, o) }

// startChoices is the menu `maze` shows a person who runs it with no command. Only what works today is offered;
// what's coming is listed in the help.
var startChoices = []ui.Choice{
	{Label: "Get started", Hint: "maze init"},
	{Label: "Show all commands", Hint: "maze help"},
	{Label: "Quit"},
}

// Indexes of startChoices.
const (
	startInit = iota
	startHelp
	startQuit
)

// start is `maze` with no command at a terminal: a full screen with the banner and a menu to pick what to do.
// Back from the setup or the command list returns here; quitting leaves the terminal as it was.
func start(ctx context.Context, s Streams) int {
	t := newTerm(s, ui.Options{})
	choices := append([]ui.Choice(nil), startChoices...)
	if ws, err := scan.FindWorkspace("."); err == nil && ws.SetUp {
		choices[startInit] = ui.Choice{Label: "Review rules for " + ws.Name, Hint: "maze init"}
		if env, err := scan.FromOS(); err == nil {
			if a, err := scope.CheckApproval(env.Home, ws.Root); err != nil || !a.Same {
				choices[startInit].Hint = "changed: needs your OK"
			}
		}
	}
	t.Enter()
	defer t.Leave()
	for {
		t.Clear()
		t.Banner()
		t.Println("  " + t.Bold("What would you like to do?"))
		t.Println()
		i, err := t.Select(ctx, choices)
		switch {
		case errors.Is(err, context.Canceled):
			return exitInterrupted
		case errors.Is(err, ui.ErrQuit):
			return identity.ExitOK
		case err != nil:
			t.Leave()
			fmt.Fprintf(s.Err, "maze: %v\n", err)
			return identity.ExitError
		}
		switch i {
		case startInit:
			code, back := initFlow(ctx, initOptions{dir: ".", fromMenu: true}, s, t)
			if back {
				continue
			}
			return code
		case startHelp:
			// The full list is long. When it fits, it's a page like the others; when it doesn't, it prints on the
			// normal screen, where the terminal scrolls it, and Back returns to the full screen.
			t.Clear()
			if t.Room() < helpRows(t)+6 {
				t.Leave()
				t.Println()
			}
			t.Banner()
			helpBody(t, commands())
			j, err := t.Select(ctx, []ui.Choice{{Label: "Back"}, {Label: "Quit"}})
			if err == nil && j == 0 {
				t.Enter()
			}
			switch {
			case errors.Is(err, context.Canceled):
				return exitInterrupted
			case err != nil || j == 1:
				return identity.ExitOK
			}
		default:
			return identity.ExitOK
		}
	}
}

// helpRows is how many rows the command list takes.
func helpRows(t *ui.Term) int {
	var b strings.Builder
	helpBody(ui.NewPlain(strings.NewReader(""), &b, t.Width()), commands())
	return strings.Count(b.String(), "\n")
}
