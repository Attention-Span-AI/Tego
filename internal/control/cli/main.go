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

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/draftcompile"
	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

// Command is one tego-control command: its noun, the summary usage lists, its synopsis, and the function that runs
// it with the arguments after the noun and returns the exit code.
type Command struct {
	Name    string
	Summary string
	Usage   string
	// HoldsSecrets is a command whose process takes a secret into its memory (serve: the sign-in token, the CSRF and
	// acknowledgement keys, a Vault page value). It is made undumpable before it does anything else, and does not run
	// when that cannot be done (ADR 0100 (7), amended 2026-11-22).
	HoldsSecrets bool
	Run          func(ctx context.Context, args []string, stdout, stderr io.Writer) int
}

// privilege is what the guard reads: the effective uid, whether the real or the saved uid is 0 (a process that dropped
// only its effective uid keeps root in them, and the root-only approval floor admits an answer on the real uid), and
// the effective and permitted capability sets.
type privilege struct {
	euid      int
	rootReal  bool // the real or the saved uid is 0
	effective uint64
	permitted uint64
}

// hostPrivilege reads this process's privilege. A capability set that cannot be read counts as privileged.
func hostPrivilege() privilege {
	eff, perm, _, err := sys.Capabilities()
	if err != nil {
		eff, perm = ^uint64(0), ^uint64(0)
	}
	ruid, _, suid := unix.Getresuid()
	return privilege{euid: os.Geteuid(), rootReal: ruid == 0 || suid == 0, effective: eff, permitted: perm}
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
	if p.euid == 0 || p.rootReal || p.effective != 0 || p.permitted != 0 {
		what := handoff.Name + " runs as the user and never as root"
		if p.euid != 0 && p.rootReal {
			what = handoff.Name + " holds root as its real or saved user id, and runs only as the user"
		} else if p.euid != 0 {
			what = fmt.Sprintf("%s holds capabilities (effective %#x, permitted %#x), and runs only without them",
				handoff.Name, p.effective, p.permitted)
		}
		diag(stderr, what, handoff.CodeAsRoot, "run it as yourself, without sudo, setcap or a unit that grants capabilities")
		return handoff.Exit(handoff.CodeAsRoot)
	}
	if handled, code := draftcompile.Helper(argv, os.Stdin, stdout); handled {
		return code
	}
	if len(argv) < 2 {
		writeUsage(stderr)
		return identity.ExitUsage
	}
	if argv[1] == contracts.HelperCommand {
		return contracts.HelperMain(argv[2:])
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
	if c.HoldsSecrets {
		if err := makeUndumpable(); err != nil {
			diag(stderr, fmt.Sprintf("%s %s: this process could not be made undumpable, and it holds secrets (%v); it did not start",
				handoff.Name, c.Name, err), codeUndumpable, "run it on a kernel that allows prctl(PR_SET_DUMPABLE)")
			return exits[codeUndumpable]
		}
	}
	return c.Run(ctx, argv[2:], stdout, stderr)
}

// makeUndumpable is the one place this package sets PR_SET_DUMPABLE 0 on its own process, with a read-back
// (sys.MakeUndumpable): from then on no other process of this user reads its memory, descriptors or environment, ptraces
// it or takes a descriptor of it, and what the processes that read it need (stat, status, cmdline, cgroup, pidfd) stays
// readable. A variable so a test can fail it and the test binary, one process that runs every command, is not left
// undumpable (main_test.go).
var makeUndumpable = sys.MakeUndumpable

// The reason codes tego-control gives of its own; handoff's [control-as-root] is the guard's.
const (
	codeUsage    = "usage"
	codeNotBuilt = "not-built"
	codeNotFound = "not-found"
	codeIO       = "io"
	// codeUndumpable is a command that holds secrets and could not make its process undumpable.
	codeUndumpable = "undumpable"
)

// exits is each of tego-control's own reason codes' exit code (TestControlCodesMapToIdentityExits).
var exits = map[string]int{
	codeUsage:    identity.ExitUsage,
	codeNotBuilt: identity.ExitError,
	codeNotFound: identity.ExitError,
	codeIO:       identity.ExitError,

	codeUndumpable: identity.ExitError,
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
