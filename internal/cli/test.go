// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/attention-span-ai/tego/internal/selftest"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdTest) }

// cmdTest is `tego test [--json] [--tier <t>]` (ADR 0074): the self-check of this machine's enforcement. It runs
// four harmless actions on decoys in a temporary folder, directly and under tego run, and reports each refusal with
// the rule its run recorded. Exit 0 when every action was refused, 1 when one got through or went unrecorded, 2 on
// usage, 125 when a check could not be judged or tego test could not run.
func cmdTest() Command {
	var asJSON bool
	var tier string
	return Command{
		Name:    "test",
		Summary: "self-check: four harmless actions on decoys, refused under tego run",
		Usage:   "[--json] [--tier auto|landlock|cgroup|bpflsm]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "print the report as one JSON object (schema tego.selftest/v1)")
			fs.StringVar(&tier, "tier", "", "pin the tier of each run, as tego run --tier does")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() > 0 {
				message(stderr, "", 0, 0, "tego test: takes no arguments", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			switch tier {
			case "", "auto", "landlock", "cgroup", "bpflsm":
			default:
				message(stderr, "", 0, 0, "tego test: --tier: one of auto, landlock, cgroup, bpflsm", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			exe, err := os.Executable()
			if err != nil {
				message(stderr, "", 0, 0, "tego test: find this tego binary: "+err.Error(), codeIO)
				return identity.ExitError // R25: tego's own failure
			}
			rep, err := selftestRun(ctx, selftest.Options{Tego: exe, Tier: tier})
			var ce *selftest.ConfigError
			if errors.As(err, &ce) {
				// The caller's $TEGO_CONFIG layer is one tego run refuses: the same sentence and code as tego run's.
				line := identity.FormatMessage("", 0, 0, "tego test: "+ce.Error(), identity.CodeConfigUntrusted)
				var ue *config.UntrustedError
				if errors.As(err, &ue) {
					line += " " + ue.Fix()
				}
				fmt.Fprintln(stderr, line)
				return identity.ExitConfig // = 125 [config-untrusted]
			}
			if err != nil {
				message(stderr, "", 0, 0, "tego test: "+err.Error(), codeIO)
				return identity.ExitError // R25: tego's own failure
			}
			if asJSON {
				err = rep.WriteJSON(stdout)
			} else {
				err = rep.WriteText(stdout)
			}
			if err != nil {
				return identity.ExitError // R25: the report could not be written
			}
			code := rep.ExitCode()
			switch {
			case asJSON:
			case code == identity.ExitOK:
				// Every decoy action was refused: the machine holds a run here, and the next step is the person's own
				// agent, which only they know how to start.
				writeHint(stderr, testNext, "tego watch -- "+startPlaceholder)
			case code == identity.ExitError && rep.Refused == 0 && (tier == "" || tier == "auto" || tier == "landlock") &&
				hintsOn(stderr):
				// No run under Tego started. When that is only because this shell is outside the user manager's cgroup,
				// the next step is the shell that is inside it (acceptance B, 2026-11-11): the check of doctor's D3 that
				// tego setup makes, which is what refused the runs.
				if m, _, err := loadMachine(config.TrustWarn); err == nil {
					if pa, err := testProbe(ctx, m); err == nil && pa.outside {
						outsideHint(stderr, "run this again there")
					}
				}
			}
			return code
		},
	}
}

// testNext is the sentence of tego test's hint once every decoy action was refused.
const testNext = "record your own agent. From its folder, start it as you always do:"

// selftestRun is selftest.Run; a variable so a test can stand in a report without running tego.
var selftestRun = selftest.Run

// testProbe is probeHere, asked after a self-check whose runs under Tego all failed to start; a variable so a test
// describes the shell without probing this one.
var testProbe = probeHere
