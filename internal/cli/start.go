// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"io"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdStart) }

// cmdStart is `tego start`: the first-run guide, in a terminal. It welcomes the person and walks them, one numbered
// step at a time, to their first protected agent (runSetupGuide). tego setup prints the same machine's checklist for
// scripts.
func cmdStart() Command {
	return Command{
		Name:         "start",
		HoldsSecrets: true,
		Summary:      "set up your first protected agent, step by step",
		Usage:        "",
		Flags:        func(*flag.FlagSet) {},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego start: takes no arguments", codeUsage)
				return identity.ExitUsage
			}
			if !guideInteractive(stdout) {
				message(stderr, "", 0, 0, "tego start: asks you questions, so it runs in a terminal; for a script, tego setup --json says where this machine is", codeUsage)
				return identity.ExitUsage
			}
			if refuseSetup("start", stderr) {
				return identity.ExitError
			}
			return runSetupGuideCommand(rehearseUserScope(ctx, stderr), stdout, stderr)
		},
	}
}
