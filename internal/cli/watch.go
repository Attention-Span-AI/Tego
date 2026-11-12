// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdWatch) }

// cmdWatch is `tego watch [--boundary <agent.yaml | name>] [--tier T] [--record M] [--offline] -- <command> [args]`
// (docs/poc/agent-watcher.md, M1): run any command, an agent whose own name tego never needs to know, as a black
// box. With no --boundary the command runs under a generic contract in record-only mode: every program it
// starts, every file it opens and every connection it makes is recorded to the ledger (at the --record level, full
// by default), and no rule refuses anything. The fixed syscall guards of every run still apply (watchNotice says
// which). With --boundary the same run is held to that contract, which is `tego run <agent.yaml> -- <command>` with the
// command given on the line. It is run's launch path, not a second one: the contract is built here, the rest is
// runRun, so the agent starts under the same filters, with the same terminal, and its exit code is the agent's.
func cmdWatch() Command {
	var (
		boundary   string
		tier       string
		recordMode string
		offline    bool
		verbose    bool
		noSummary  bool
	)
	return Command{
		Name:        "watch",
		Passthrough: true,
		Supervises:  true,
		Summary:     "run any command as a black box and record everything it does",
		Usage:       "[--boundary <agent.yaml | name>] [--tier <t>] [--record <full|summary|off>] [--offline] [--no-summary] [-v] -- <command> [args]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&boundary, "boundary", "", "hold the command to this contract (files, programs, connections, limits, approvals); without it no rule refuses anything and the run only records")
			fs.StringVar(&tier, "tier", "", "with --boundary, pin the enforcement tier (auto|landlock|cgroup|bpflsm)")
			fs.StringVar(&recordMode, "record", "", "record level (full|summary|off); without --boundary full, with it the contract's")
			fs.BoolVar(&offline, "offline", false, "an unresolvable host is a warning, not an error")
			fs.BoolVar(&verbose, "v", false, "print the full notice (what is and is not recorded, what is still refused) and every compile note")
			fs.BoolVar(&verbose, "verbose", false, "same as -v")
			fs.BoolVar(&noSummary, "no-summary", false, "when the command exits, print only where the record is, not what it did")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, _, stderr io.Writer) int {
			command := fs.Args()
			if len(command) == 0 || command[0] == "" {
				message(stderr, "", 0, 0, "tego watch: a command after \"--\", for example: tego watch -- codex", codeUsage)
				return identity.ExitUsage
			}
			if boundary == "" && flagGiven(fs, "boundary") {
				// An unset "$CONTRACT" would otherwise run the command under the record-only contract, no rule refusing
				// anything, with only the notice to say so.
				message(stderr, "", 0, 0, "tego watch: --boundary is an empty string; name a contract, or leave --boundary out to only record", codeUsage)
				return identity.ExitUsage
			}
			if boundary == "" && tier != "" {
				message(stderr, "", 0, 0, "tego watch: --tier needs --boundary: a run with no boundary only records", codeUsage)
				return identity.ExitUsage
			}
			if _, err := parseRecordMode(recordMode); recordMode != "" && err != nil {
				message(stderr, "", 0, 0, "tego watch: "+err.Error(), codeUsage)
				return identity.ExitUsage
			}
			path, cleanup := boundary, func() {}
			if boundary == "" {
				var err error
				if path, cleanup, err = writeGenericContract(command); err != nil {
					message(stderr, "", 0, 0, "tego watch: "+err.Error(), codeIO)
					return identity.ExitLauncher
				}
				if recordMode == "" {
					recordMode = "full"
				}
			}
			defer cleanup()
			sockets := stdioHasSocket(tegoruntime.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr})
			fmt.Fprint(stderr, watchNotice(command[0], boundary != "", agent.RecordMode(recordMode), verbose, sockets))
			// How a recording ends: a long-running agent has no end of its own, and nothing said that Ctrl-C keeps
			// what was recorded (the run forwards the signal and closes its record with run_end). Guidance, so not with
			// --no-summary. It is part of the notice, so it is said with it, before the run's own checks, which can
			// still refuse the run (exit 125) as they can after the notice.
			if !noSummary {
				writeGuide(stderr, watchStopLine)
			}
			cwd, _ := os.Getwd() // the folder the hint names the contract after; "" gives "<name>"
			// tego's own lines name the command the person typed: the run path writes "tego watch: " where a run writes
			// "tego run: " (runOptions.cmd).
			return runRun(ctx, runOptions{
				cmd: "tego watch", contract: path, generated: boundary == "", command: command, tier: tier, record: recordMode,
				observe: boundary == "", offline: offline, verbose: verbose, watched: true, noSummary: noSummary,
				report: func(res tegoruntime.Result, sum *endSummary) {
					// The footer, then the reads line (a bounded watch can refuse a read), then the next step.
					fmt.Fprint(stderr, watchFooter(res, sum)+sum.readsLine())
					if text, command := watchNext(ctx, stderr, res, sum, boundary, cwd); text != "" {
						writeHint(stderr, text, command)
					}
				},
			}, stderr)
		},
	}
}

// flagGiven says whether the command line set the flag name, an empty value included: a flag given as "" is not
// the flag left out.
func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	return given
}

// genericContract is the contract a watch with no --boundary runs under. It names the program and asks for the
// full record, and nothing else: no fs, net, exec or limits section, so it restricts nothing, which is what a
// record-only run is. The schema requires a command; the run takes the arguments from the command line, so only
// the program is written here and an argument the schema would refuse (an empty one) still reaches the agent.
type genericContract struct {
	Version int      `yaml:"version"`
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
	Record  string   `yaml:"record"`
}

// genericContractYAML is that contract for command, written by Canonical's writer (agent.EncodeYAML). The encoder
// quotes a program that would read as something else, so it cannot become a key or end the list, and the writer
// double-quotes one it would write as a block that does not load back: yaml.Marshal wrote "\tagent\n", "\nagent\n"
// and " agent\nx" as blocks the loader refused, so tego watch refused to run them.
func genericContractYAML(command []string) ([]byte, error) {
	return agent.EncodeYAML(genericContract{Version: 0, Name: watchName(command[0]), Command: command[:1], Record: "full"})
}

// watchName is a contract name for argv0: its base name, lower case, with every character outside [a-z0-9-]
// made a hyphen, prefixed "watch-", at most 40 characters (the schema's name pattern).
func watchName(argv0 string) string {
	var b strings.Builder
	prev := byte('-')
	for _, r := range strings.ToLower(filepath.Base(argv0)) {
		c := byte('-')
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			c = byte(r)
		}
		if c == '-' && prev == '-' {
			continue
		}
		b.WriteByte(c)
		prev = c
	}
	name := "watch-" + strings.Trim(b.String(), "-")
	if len(name) > 40 {
		name = strings.TrimRight(name[:40], "-")
	}
	return strings.TrimRight(name, "-")
}

// writeGenericContract writes the generic contract for command into a private temporary directory (0700, the
// file 0600) and returns its path and the function that removes it. The run copies the contract it compiled into
// its own directory, so the file is needed only until the run has started.
func writeGenericContract(command []string) (string, func(), error) {
	data, err := genericContractYAML(command)
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "tego-watch-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "watch.yaml")
	if err = os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// watchNotice is what tego says before the run starts, so nobody mistakes a recording for a cage. Without a boundary
// it is at most four lines (ten lines plus a warning filled the presenter's terminal): what is recorded at the
// level in force and that no rule refuses anything, that it is not a cage, and how to confine the command. verbose
// (watch -v) prints the full text: what is still refused and what is not recorded. record is the level the run uses;
// "" is full, the no-boundary default. sockets says a warning naming a socket the command can reach follows (one of
// its standard streams is a socket, warnStdio); the sentence pointing at those warnings is printed only then.
func watchNotice(argv0 string, bounded bool, record agent.RecordMode, verbose, sockets bool) string {
	if bounded {
		return fmt.Sprintf("tego watch: %s runs under your boundary contract; its refusals and approvals are in the log.\n", argv0)
	}
	socketsNote := ""
	if sockets {
		socketsNote = "; the warnings that follow name the sockets it can reach"
	}
	if !verbose {
		var recorded string
		switch record {
		case agent.RecordSummary:
			recorded = "every program, every file it changes, every connection; a file it only reads is not recorded (--record full records reads)"
		case agent.RecordOff:
			recorded = "only that it ran (--record full records what it does)"
		default:
			recorded = "every program it starts, every file it opens (reads included), every connection it makes"
		}
		return fmt.Sprintf(`tego watch: recording %[1]s and everything it starts. No rule refuses anything (details: tego watch -v -- %[1]s).
  recorded: %[2]s.
  not a cage: it can still ask another service (systemd --user, D-Bus, an SSH or GPG agent) to act for it%[3]s.
  to confine it: tego run <agent.yaml> -- %[1]s, or tego watch --boundary <agent.yaml> -- %[1]s
`, argv0, recorded, socketsNote)
	}
	var recorded string
	switch record {
	case agent.RecordSummary:
		recorded = `every program it starts, every file it writes, creates, removes or renames, every connection it makes. A file it only
  reads is not recorded (--record full records reads).`
	case agent.RecordOff:
		recorded = `only that it ran: the run's start and end. Nothing it does is
  recorded (--record full records what it does).`
	default:
		recorded = `every program it starts, every file it opens (reads included), creates, removes or renames, every connection it
  makes.`
	}
	notRecorded := ""
	if record != agent.RecordOff {
		notRecorded = "\n  not recorded: truncate, chmod, chown, setxattr, a unix socket bound to a path."
	}
	return fmt.Sprintf(`tego watch: recording %[1]s and everything it starts. No rule refuses anything.
  recorded: %[2]s%[3]s
  still refused, and not recorded: 32-bit programs; io_uring, openat2, clone3 and open_by_handle_at ("not implemented",
  programs fall back); the terminal-input ioctls TIOCSTI and TIOCLINUX; MPTCP sockets.
  not a cage: it can still ask another service on this machine (systemd --user, D-Bus, an SSH or GPG agent) to act
  for it outside the run%[4]s. To confine it, write a contract and run: tego run <agent.yaml> -- %[1]s,
  or tego watch --boundary <agent.yaml> -- %[1]s
`, argv0, recorded, notRecorded, socketsNote)
}

// stdioHasSocket reports whether one of the streams the command inherits is a socket, which warnStdio then names: a
// record-only run's generic contract has no write entry, so every socket stream is beyond it.
func stdioHasSocket(s tegoruntime.Stdio) bool {
	for _, st := range tegoruntime.DescribeStdio(s) {
		if st.Kind == record.StdioSocket {
			return true
		}
	}
	return false
}

// watchFooter is what tego watch says when the run is over: the run, how it ended and what it did (the end summary's
// numbers, from the receipt), a counts line of the connections it made and the sensitive files it read, which a
// recording shows and its refusals (none) do not, and where to read the rest. A run whose record was off (--record
// off, or a boundary's record: off) says "record off: refusals only" and has no counts line, since its ledger holds
// no connection or read it allowed. With no summary (--no-summary, or a run that never started) it is watchReport.
func watchFooter(res tegoruntime.Result, sum *endSummary) string {
	if sum == nil || res.RunID == "" {
		return watchReport(res)
	}
	var b strings.Builder
	run := record.Printable(res.RunID)
	if sum.rc == nil {
		fmt.Fprintf(&b, "tego watch: recorded as run %s: ended%s · summary not available (%s) · %s\n", run, sum.ended(), record.Printable(errText(sum.err)), sum.tail())
	} else {
		fmt.Fprintf(&b, "tego watch: recorded as run %s: ended (%s) · %s\n", run, sum.rc.Outcome(), strings.Join(append(sum.counts(true), sum.tail()), " · "))
		b.WriteString(sum.seen())
	}
	fmt.Fprintf(&b, "  more: tego receipt %[1]s    tego events %[1]s\n", run)
	return b.String()
}

// watchStopLine is the guidance line after a watch's notice: how to end the recording of an agent that runs until it
// is stopped, and that ending it so keeps the record.
const watchStopLine = "  stop: let it do a normal job, then Ctrl-C, or let it end; the record is kept.\n"

// watchAddresses is runAddresses, the second read of the record a watch's hint makes; a variable so a test can count
// the reads.
var watchAddresses = runAddresses

// watchNext is the next: block a watch ends with (watchHint). Whether the run reached addresses is a second read of the
// record, up to summaryBudget, so it is made only when the block names the learn step and stderr shows it: a bounded
// watch, a run whose record was off or not completed, and a script that does not see the hint do not wait for it.
func watchNext(ctx context.Context, stderr io.Writer, res tegoruntime.Result, sum *endSummary, boundary, cwd string) (text, command string) {
	if text, command = watchHint(res, sum, boundary, cwd, false); text == "" || !hintsOn(stderr) {
		return text, command
	}
	return watchHint(res, sum, boundary, cwd, watchAddresses(ctx, sum, res))
}

// watchHint is a record-only watch's "next:" block, the route from the recording to a contract (FIRST-TEN-MINUTES,
// stumble 3): tego learn of this run, saved under a name, which is the run folder's when tego run takes it there
// (proposedName). "" for a bounded watch (it has its contract), with no summary (--no-summary prints only where the record is), for a
// run whose record was off, whose ledger holds nothing to learn from, and for a run whose record could not be completed,
// which exits 125 [ledger].
// When the run reached addresses (runAddresses), the step names the host behind them with --allow-host, so that the
// contract allows the service by name: a later run may pick another address of the same name and be refused.
func watchHint(res tegoruntime.Result, sum *endSummary, boundary, cwd string, addresses bool) (text, command string) {
	if boundary != "" || res.RunID == "" || sum == nil || sum.recordOff || res.RecordErr != nil {
		return "", ""
	}
	command = "tego learn " + shortRun(sum.root, res.RunID) + " --save " + proposedName(sum.machine, cwd)
	if addresses {
		return watchNameHint, command + " --allow-host " + hostPlaceholder
	}
	return "make a contract from what it did, and read it before you use it:", command
}

// watchReport is what tego says when the run is over: where to read what happened.
func watchReport(res tegoruntime.Result) string {
	if res.RunID == "" {
		return ""
	}
	return fmt.Sprintf("tego watch: recorded as run %[1]s\n  tego status %[1]s    tego events %[1]s    tego drift %[1]s\n", res.RunID)
}
