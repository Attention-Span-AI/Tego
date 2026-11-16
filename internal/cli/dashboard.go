// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"io"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdDashboard) }

// cmdDashboard is `tego dashboard`: the dashboard, opened in the browser. It is tego serve --open; on a Mac the tego
// command on the Mac opens it there instead, through Tego's VM.
func cmdDashboard() Command {
	return Command{
		Name:    "dashboard",
		Summary: "open the dashboard in your browser",
		Usage:   "",
		Flags:   func(*flag.FlagSet) {},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego dashboard: takes no arguments", codeUsage)
				return identity.ExitUsage
			}
			code, _ := dispatch(ctx, []string{"tego", "serve", "--open"}, stdout, stderr, commands())
			return code
		},
	}
}
