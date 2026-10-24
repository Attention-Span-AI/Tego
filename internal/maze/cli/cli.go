// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Streams are the three standard streams a command reads and writes. Prompts read In; only cmd/maze passes
// the process's own.
type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// Command is one `maze` command: its name, a one-line summary, its usage, its flags and what it does.
// Run returns the process exit code; only cmd/maze turns it into os.Exit.
type Command struct {
	Name    string
	Summary string
	Usage   string
	Flags   func(fs *flag.FlagSet)
	Run     func(ctx context.Context, fs *flag.FlagSet, s Streams) int
}

// exitInterrupted is the code for a command stopped by Ctrl+C: 128 plus SIGINT's number, as shells report it.
const exitInterrupted = 130

// commands returns the built commands by name. The help screen lists the whole tree (tree in help.go) and
// marks what is not built yet; only names here run.
func commands() map[string]Command {
	cs := []Command{cmdInit(), cmdStatus(), cmdAllow(), cmdBlock(), cmdWorkspace(), cmdProfile(), cmdSystem(), cmdHelp()}
	out := make(map[string]Command, len(cs))
	for _, c := range cs {
		out[c.Name] = c
	}
	return out
}

// Main runs `maze` with args (without the program name) and returns the exit code.
func Main(ctx context.Context, args []string, s Streams) int {
	cs := commands()
	// --no-color works with every command, anywhere on the line.
	if i := slices.IndexFunc(args, func(a string) bool { return a == "--no-color" || a == "-no-color" }); i >= 0 {
		args = slices.Delete(slices.Clone(args), i, i+1)
		saved := newTerm
		newTerm = func(s Streams, o ui.Options) *ui.Term { o.NoColor = true; return saved(s, o) }
		defer func() { newTerm = saved }()
	}
	if len(args) == 0 {
		if t := newTerm(s, ui.Options{}); t.Interactive() {
			return start(ctx, s)
		}
		help(newTerm(s, ui.Options{}), cs)
		return identity.ExitOK
	}
	if args[0] == "-h" || args[0] == "--help" {
		help(newTerm(s, ui.Options{}), cs)
		return identity.ExitOK
	}
	if args[0] == "help" {
		if len(args) > 1 {
			return Main(ctx, []string{args[1], "-h"}, s)
		}
		help(newTerm(s, ui.Options{}), cs)
		return identity.ExitOK
	}
	if args[0] == "--version" || args[0] == "-v" || args[0] == "version" {
		fmt.Fprintln(s.Out, versionLine())
		return identity.ExitOK
	}
	c, ok := cs[args[0]]
	if !ok {
		if planned(args[0]) {
			fmt.Fprintf(s.Err, "maze %s is coming soon. Run maze help to see what works today.\n", args[0])
			return identity.ExitUsage
		}
		if strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(s.Err, "maze: unknown flag %s. Run maze help to see the commands.\n", args[0])
			return identity.ExitUsage
		}
		fmt.Fprintf(s.Err, "maze: unknown command %q.", args[0])
		if near := nearest(args[0], cs); near != "" {
			fmt.Fprintf(s.Err, " Did you mean: maze %s", near)
		}
		fmt.Fprintln(s.Err, "\nRun maze help to see the commands.")
		return identity.ExitUsage
	}
	fs := flag.NewFlagSet("maze "+c.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are worded below; asked-for help goes to stdout
	fs.Usage = func() {}
	if c.Flags != nil {
		c.Flags(fs)
	}
	if err := parseAnywhere(fs, args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(s.Out, c, fs)
			return identity.ExitOK
		}
		fmt.Fprintf(s.Err, "maze %s: %s\nRun maze %s --help to see its flags.\n", c.Name, flagProblem(err, args[1:]), c.Name)
		return identity.ExitUsage
	}
	return c.Run(ctx, fs, s)
}

// usage prints a command's help the way most CLIs do: what it does, how to call it, then its flags with
// GNU-style names (--explain; -C for a single letter).
func usage(w io.Writer, c Command, fs *flag.FlagSet) {
	fmt.Fprintf(w, "%s\n\nUsage:\n  maze %s %s\n", c.Summary, c.Name, c.Usage)
	type row struct{ name, help string }
	var rows []row
	width := 0
	fs.VisitAll(func(f *flag.Flag) {
		arg, help := flag.UnquoteUsage(f)
		name := "--" + f.Name
		if len(f.Name) == 1 {
			name = "-" + f.Name
		}
		switch {
		case strings.HasPrefix(arg, "<"):
			name += " " + arg
		case arg != "":
			name += " <" + arg + ">"
		}
		rows = append(rows, row{name, help})
		width = max(width, len(name))
	})
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(w, "\nFlags:\n")
	for _, r := range rows {
		fmt.Fprintf(w, "  %-*s   %s\n", width, r.name, r.help)
	}
}

// flagProblem rewords the flag package's errors: "flag provided but not defined: -x" becomes "unknown flag -x".
// The flag shows as it was typed (--bogus, not -bogus).
func flagProblem(err error, args []string) string {
	typed := func(name string) string {
		for _, a := range args {
			if strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-") == strings.TrimLeft(name, "-") {
				return strings.SplitN(a, "=", 2)[0]
			}
		}
		return name
	}
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: "); ok {
		return "unknown flag " + typed(name)
	}
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: "); ok {
		return typed(name) + " needs a value"
	}
	return msg
}

// nearest is the command name closest to a typo (at most two letters off), or "".
func nearest(typo string, cs map[string]Command) string {
	best, bestD := "", 3
	names := []string{}
	for n := range cs {
		names = append(names, n)
	}
	for _, s := range tree {
		for _, e := range s.entries {
			names = append(names, e.cmd)
		}
	}
	slices.Sort(names)
	for _, n := range names {
		if d := distance(strings.ToLower(typo), n); d < bestD {
			best, bestD = n, d
		}
	}
	return best
}

// distance is the edit distance between a and b: letters added, removed, changed or swapped.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range rb {
		d[0][j+1] = j + 1
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

// parseAnywhere parses flags wherever they stand among the arguments, the way most CLIs do: `maze workspace
// remove --yes` and `maze workspace --yes remove` mean the same. The flag package alone stops at the first
// argument that isn't a flag, which would silently ignore --yes there. "--" still ends the flags.
func parseAnywhere(fs *flag.FlagSet, args []string) error {
	var words []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		if i := len(args) - fs.NArg(); i > 0 && args[i-1] == "--" {
			words = append(words, fs.Args()...)
			break
		}
		words = append(words, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return fs.Parse(append([]string{"--"}, words...))
}

// cmdHelp is `maze help [command]`: the command list, or one command's help. Main answers it before flags are
// parsed (so `maze help init` works like `maze init --help`); it is a Command so help lists it like the others.
func cmdHelp() Command {
	return Command{
		Name:    "help",
		Summary: "Show the commands, or one command's help",
		Usage:   "[command]",
		Run: func(ctx context.Context, fs *flag.FlagSet, s Streams) int {
			return Main(ctx, append([]string{"help"}, fs.Args()...), s)
		},
	}
}
