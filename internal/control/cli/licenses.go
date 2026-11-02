// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"io"

	"github.com/attention-span-ai/tego"
	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdLicenses) }

// cmdLicenses is `tego-control licenses` (docs/GAPS.md B12): the licence texts and third-party notices this binary
// carries, the licence files of the release's licenses archive, the same print as tego's own licenses.
func cmdLicenses() Command {
	return Command{
		Name:    "licenses",
		Summary: "print the licence texts and third-party notices this binary carries",
		Run: func(_ context.Context, args []string, stdout, stderr io.Writer) int {
			fs := flag.NewFlagSet(handoff.Name+" licenses", flag.ContinueOnError)
			fs.SetOutput(stderr)
			if err := fs.Parse(args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return identity.ExitOK
				}
				return exits[codeUsage]
			}
			if fs.NArg() != 0 {
				diag(stderr, handoff.Name+" licenses: takes no arguments", codeUsage, "run "+handoff.Name+" licenses")
				return exits[codeUsage]
			}
			if err := tego.WriteLicenses(stdout); err != nil {
				diag(stderr, handoff.Name+" licenses: "+err.Error(), codeIO, "check the output")
				return exits[codeIO]
			}
			return identity.ExitOK
		},
	}
}
