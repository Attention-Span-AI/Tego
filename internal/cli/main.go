// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Command is one subcommand: its name, the usage synopsis after the name, the flags it declares
// and the function that runs it. Run receives the parsed FlagSet (positional arguments in
// fs.Args(), flags allowed before and after them) and returns the process exit code (R25).
type Command struct {
	Name string
	// Summary is the command's line in the usage. One that refuses to run without root ([privilege]) begins
	// "(root) ", as a handed-off noun's begins "(tego-control) ", so the usage says so before anyone runs it.
	Summary string
	Usage   string
	Hidden  bool
	Flags   func(*flag.FlagSet)
	Run     func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int
	// CommandAfter, when above zero, is how many positional arguments come before a command the user
	// passes on: after them, tego's flags run only up to the first non-flag token or "--", and
	// everything from the command on is verbatim, flags and any later "--" included (see parseArgs).
	// run sets it to 1, for the contract.
	CommandAfter int
	// Passthrough is a command whose exit is the agent's (RUN-IDENTITY.md): what it writes is tego's
	// advisory output, and a failed write of it never turns that exit into 125 (R25). Only run sets it.
	Passthrough bool
	// Supervises is a command whose process keeps a run going for as long as it lives (run, watch, adopt), so a
	// write to a closed pipe must not end it (holdBrokenPipe).
	Supervises bool
	// Raw, set instead of Run and Flags, is a noun tego hands to tego-control (handoff.go): it gets every argument
	// after the noun verbatim, flags included, and tego parses none of them.
	Raw func(ctx context.Context, args []string, stdout, stderr io.Writer) int
}

// Main runs argv (argv[0] is the program name, argv[1] the subcommand) and returns the exit code.
// SIGINT and SIGTERM cancel the command's context; a panic anywhere below becomes
// `tego: internal error: <msg> [bug]` on stderr, the stack in ~/.tego/tego.log, exit 125.
func Main(argv []string, stdout, stderr io.Writer) int {
	ctx, stop := notifyContext()
	defer stop()
	return mainWith(ctx, argv, stdout, stderr, commands())
}

// notifyContext is a context SIGINT and SIGTERM cancel, once: the first signal releases the
// handler, so a second one takes its default action and ends a command that did not stop on the
// first (one blocked in a read that no context reaches). The handler is released before the context
// is cancelled, so no second signal can fall between the two and be swallowed. `run` forwards signals
// to the agent through a subscription of its own (launch.Notify), which it holds until its shutdown
// is done and which releasing this one leaves in place.
func notifyContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
		case <-ctx.Done():
		}
		signal.Stop(ch)
		cancel()
	}()
	return ctx, cancel
}

// brokenPipe is the subscription holdBrokenPipe makes. Nothing reads it: a full channel drops the signal, and a
// subscription is all the runtime asks about.
var (
	brokenPipe     = make(chan os.Signal, 1)
	brokenPipeOnce sync.Once
)

// holdBrokenPipe keeps this process alive through a write to a closed pipe on its stdout or stderr, for the commands
// that supervise a run. The os package ends a process with SIGPIPE on EPIPE from fd 1 or 2 unless the signal is
// subscribed to, so `tego run agent.yaml 2>&1 | head -1` lost the launcher on the first line tego wrote after head
// left: the summary replaced the agent's exit code with 141, and a line during the run ended the supervisor under a
// live agent. tego's own words never decide a run (RUN-IDENTITY.md, "Warnings never change the code"). A subscription,
// not signal.Ignore: an ignored SIGPIPE survives execve and would reach the agent, which still dies of its own broken
// pipe, while a caught one reverts to the default there. Process-wide and once, like launch.HoldJobControl.
func holdBrokenPipe() {
	brokenPipeOnce.Do(func() { signal.Notify(brokenPipe, syscall.SIGPIPE) })
}

// mainWith is Main over an explicit command table (tests inject a panicking command).
func mainWith(ctx context.Context, argv []string, stdout, stderr io.Writer, cmds []Command) (code int) {
	defer func() {
		if r := recover(); r != nil {
			code = internalError(stderr, r, debug.Stack())
		}
	}()
	out, errs := &outputWriter{dst: stdout}, &outputWriter{dst: stderr}
	code, passthrough := dispatch(ctx, argv, out, errs, cmds)
	if code == identity.ExitOK && !passthrough {
		if err := errors.Join(out.failure(), errs.failure()); err != nil {
			message(stderr, "", 0, 0, "tego: write output: "+err.Error(), codeIO)
			return identity.ExitError // R25: a successful command must deliver its required output
		}
	}
	return code
}

// dispatch picks the command named by argv[1], parses its flags and runs it. passthrough is set when a
// Passthrough command ran: its exit is the agent's, not a statement that its output was delivered.
func dispatch(ctx context.Context, argv []string, stdout, stderr io.Writer, cmds []Command) (code int, passthrough bool) {
	if len(argv) < 2 {
		writeUsage(stderr, cmds)
		return identity.ExitUsage, false // R25: usage error
	}
	name := argv[1]
	switch name {
	case "help", "-h", "--help":
		writeUsage(stdout, cmds)
		return identity.ExitOK, false
	}
	cmd, ok := find(cmds, name)
	if !ok {
		message(stderr, "", 0, 0, fmt.Sprintf("tego: unknown command %q; run tego help for the list", name), codeUsage)
		return identity.ExitUsage, false // R25: usage error
	}
	if cmd.Raw != nil {
		return cmd.Raw(ctx, argv[2:], stdout, stderr), false
	}
	fs := flag.NewFlagSet("tego "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: tego %s %s\n", name, cmd.Usage)
		fs.PrintDefaults()
	}
	if cmd.Flags != nil {
		cmd.Flags(fs)
	}
	if err := parseArgs(fs, argv[2:], cmd.CommandAfter); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return identity.ExitOK, false // the usage text is -h's required output
		}
		return identity.ExitUsage, false // R25: usage error; the flag package printed the reason and usage
	}
	if cmd.Supervises {
		holdBrokenPipe() // here, past the flags: `tego run -h | head -1` is help text, which ends quietly
	}
	return cmd.Run(ctx, fs, stdout, stderr), cmd.Passthrough
}

// parseArgs parses flags wherever they appear before a "--" (so `compile agent.yaml --offline`
// works like `compile --offline agent.yaml`), keeps everything after "--" verbatim, and leaves
// the positional arguments in fs.Args().
//
// commandAfter > 0 is a command that passes a command on (run). Flags are parsed anywhere among the
// first commandAfter positional arguments (the contract); after them, flags are parsed only up to the
// first non-flag token. A "--" there ends tego's flags; any other non-flag token starts the passed-on
// command, and it and everything after it, a later "--" included, is the command verbatim. Parsed as
// flags, the agent's own arguments changed enforcement silently: `tego run a.yaml ./tool --observe`
// ran at tier observe, and `tego run d.yaml sh e.sh --observe -- tail` (a "--" anywhere once ended
// tego's flags there) ran observe mode and handed the agent only [tail].
func parseArgs(fs *flag.FlagSet, args []string, commandAfter int) error {
	if commandAfter <= 0 {
		// No command is passed on: every positional argument is the command's own, and flags are parsed among
		// all of them up to a "--". The same loop as run's, so a "--" that is a value flag's value
		// (`events R --kind --`) is that value in both, not the end of flags in one of them.
		commandAfter = math.MaxInt
	}
	return parseCommandArgs(fs, args, commandAfter)
}

// parseCommandArgs is parseArgs for a command that passes a command on (see parseArgs).
func parseCommandArgs(fs *flag.FlagSet, args []string, commandAfter int) error {
	var positional []string
	head := args
	for len(head) > 0 {
		if err := fs.Parse(head); err != nil {
			return err
		}
		rest := fs.Args()
		consumed := head[:len(head)-len(rest)]
		if n := len(consumed); n > 0 && consumed[n-1] == "--" && !flagTakesValue(fs, consumed, n-1) {
			// A "--" ended tego's flags: everything after it is positional, verbatim.
			positional = append(positional, rest...)
			break
		}
		if len(rest) == 0 {
			break
		}
		if len(positional) >= commandAfter {
			// The first non-flag token after the contract starts the passed-on command.
			positional = append(positional, rest...)
			break
		}
		positional = append(positional, rest[0])
		head = rest[1:]
	}
	return fs.Parse(append([]string{"--"}, positional...))
}

// flagTakesValue reports whether consumed[i] was read as the value of the flag before it
// (`--tier --`), not as the "--" that ends flags.
func flagTakesValue(fs *flag.FlagSet, consumed []string, i int) bool {
	if i == 0 {
		return false
	}
	prev := consumed[i-1]
	if !strings.HasPrefix(prev, "-") || prev == "-" || prev == "--" || strings.Contains(prev, "=") {
		return false
	}
	f := fs.Lookup(strings.TrimLeft(prev, "-"))
	if f == nil {
		return false
	}
	if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return false
	}
	return true
}

// find looks a command up by name.
func find(cmds []Command, name string) (Command, bool) {
	for _, c := range cmds {
		if c.Name == name {
			return c, true
		}
	}
	return Command{}, false
}

// writeUsage prints the command list, hidden commands excluded.
func writeUsage(w io.Writer, cmds []Command) {
	fmt.Fprintln(w, "usage: tego <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range cmds {
		if c.Hidden {
			continue
		}
		fmt.Fprintf(tw, "  %s\t%s\n", c.Name, c.Summary)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	if planned := handoff.Planned(); len(planned) > 0 {
		fmt.Fprintf(w, "planned, not in this build: %s\n", strings.Join(planned, ", "))
	}
	fmt.Fprintln(w, "tego <command> -h shows the command's flags.")
}
