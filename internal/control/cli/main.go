// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Command is one tego-control command: its noun, the summary usage lists, its synopsis, and the function that runs
// it with the arguments after the noun and returns the exit code.
type Command struct {
	Name    string
	Summary string
	Usage   string
	Run     func(ctx context.Context, args []string, stdout, stderr io.Writer) int
}

// privilege is what the guard reads: the effective uid and the effective and permitted capability sets.
type privilege struct {
	euid      int
	effective uint64
	permitted uint64
}

// hostPrivilege reads this process's privilege. A capability set that cannot be read counts as privileged.
func hostPrivilege() privilege {
	eff, perm, _, err := sys.Capabilities()
	if err != nil {
		eff, perm = ^uint64(0), ^uint64(0)
	}
	return privilege{euid: os.Geteuid(), effective: eff, permitted: perm}
}

// Main runs tego-control's argv (argv[1] the noun) and returns the exit code. Every command, version and help
// included, is refused at euid 0 or with a capability [control-as-root]: the dashboard runs as the user.
// SIGINT and SIGTERM cancel the command's context.
func Main(argv []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return mainWith(ctx, argv, stdout, stderr, hostPrivilege())
}

// mainWith is Main with the privilege given.
func mainWith(ctx context.Context, argv []string, stdout, stderr io.Writer, p privilege) int {
	if p.euid == 0 || p.effective != 0 || p.permitted != 0 {
		what := handoff.Name + " runs as the user and never as root"
		if p.euid != 0 {
			what = fmt.Sprintf("%s holds capabilities (effective %#x, permitted %#x), and runs only without them",
				handoff.Name, p.effective, p.permitted)
		}
		diag(stderr, what, handoff.CodeAsRoot, "run it as yourself, without sudo, setcap or a unit that grants capabilities")
		return handoff.Exit(handoff.CodeAsRoot)
	}
	if len(argv) < 2 {
		writeUsage(stderr)
		return identity.ExitUsage
	}
	switch argv[1] {
	case "help", "-h", "--help":
		writeUsage(stdout)
		return identity.ExitOK
	}
	c, ok := Lookup(argv[1])
	if !ok {
		diag(stderr, fmt.Sprintf("%s: unknown command %q", handoff.Name, argv[1]), codeUsage, "run "+handoff.Name+" help for the list")
		return identity.ExitUsage
	}
	return c.Run(ctx, argv[2:], stdout, stderr)
}

// The reason codes tego-control gives of its own; handoff's [control-as-root] is the guard's.
const (
	codeUsage    = "usage"
	codeNotBuilt = "not-built"
	codeIO       = "io"
)

// exits is each of tego-control's own reason codes' exit code (TestControlCodesMapToIdentityExits).
var exits = map[string]int{
	codeUsage:    identity.ExitUsage,
	codeNotBuilt: identity.ExitError,
	codeIO:       identity.ExitError,
}

// diag writes one diagnostic line, "<what>; <fix> [<code>]", as tego's own lines are (RUN-IDENTITY.md "Messages").
func diag(w io.Writer, what, code, fix string) {
	_, _ = fmt.Fprintln(w, identity.FormatMessage("", 0, 0, what+"; "+fix, code))
}

// writeUsage prints the built commands, sorted, from the registry, and the nouns not built yet on one line.
func writeUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: "+handoff.Name+" <command> [flags]")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "commands:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, n := range listedNames() {
		c, _ := Lookup(n)
		_, _ = fmt.Fprintf(tw, "  %s\t%s\n", c.Name, c.Summary)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(w)
	if planned := handoff.Planned(); len(planned) > 0 {
		_, _ = fmt.Fprintln(w, "planned, not in this build: "+strings.Join(planned, ", "))
	}
	_, _ = fmt.Fprintln(w, "tego runs these as tego <command> too, through its verified handoff.")
}

// listedNames is Names without the nouns this build does not have yet (handoff.Planned), which help names apart.
func listedNames() []string {
	var out []string
	for _, n := range Names() {
		if !slices.Contains(handoff.Planned(), n) {
			out = append(out, n)
		}
	}
	return out
}
