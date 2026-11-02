// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"io"

	"github.com/attention-span-ai/tego"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdLicenses) }

// cmdLicenses is `tego licenses` (docs/GAPS.md B12): the licence texts and third-party notices this binary carries,
// the licence files of the release's licenses archive, so a binary passed on without that archive still has them.
// tego-control has a licenses of its own, as it has a version.
func cmdLicenses() Command {
	return Command{
		Name:    "licenses",
		Summary: "print the licence texts and third-party notices this binary carries",
		Run: func(_ context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego licenses: takes no arguments", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if err := tego.WriteLicenses(stdout); err != nil {
				message(stderr, "", 0, 0, "tego licenses: "+err.Error(), codeIO)
				return identity.ExitError // R25: Tego's own error
			}
			return identity.ExitOK
		},
	}
}
