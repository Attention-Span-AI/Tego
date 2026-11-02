// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// shortRunRef is the end of the message for a run argument too short to abbreviate a run id by either end, in a
// directory holding nothing of its name: an end needs four characters, a start four past r-<host8>-.
const shortRunRef = "give the run's id, or at least its last 4 characters or its first 15 (4 past r-<host8>-) [usage]"

// run invokes Main in-process (I6) and returns code, stdout, stderr.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(append([]string{"tego"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

// TestDispatchExitCodes is limits-check-doctor-cli.md R25 and R26: each failure class exits with its documented code and prints its diagnostic.
func TestDispatchExitCodes(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no command", nil, identity.ExitUsage, "", "usage: tego"},
		{"unknown command", []string{"bogus"}, identity.ExitUsage, "", `unknown command "bogus"`},
		{"unknown flag", []string{"version", "--bogus"}, identity.ExitUsage, "", "flag provided but not defined"},
		{"extra argument", []string{"version", "x"}, identity.ExitUsage, "", "[usage]"},
		{"help", []string{"help"}, identity.ExitOK, "commands:", ""},
		{"dash h", []string{"-h"}, identity.ExitOK, "compile", ""},
		{"command help", []string{"compile", "-h"}, identity.ExitOK, "", "usage: tego compile"},
		// The usage lines left out run's --offline and doctor's --require values, and doctor's refusal of a bad
		// --require did not say which tiers it takes.
		{"run help names --offline", []string{"run", "-h"}, identity.ExitOK, "", "[--observe] [--offline] [-- <cmd> [args]]"},
		{"doctor help names the tiers", []string{"doctor", "-h"}, identity.ExitOK, "", "usage: tego doctor [--json] [--require <landlock|cgroup|bpflsm>]"},
		{"doctor refuses a bad tier by name", []string{"doctor", "--require", "cgroups"}, identity.ExitUsage, "", `--require "cgroups" is not a tier: landlock, cgroup or bpflsm [usage]`},
		{"version", []string{"version"}, identity.ExitOK, "tego=", ""},
		// run, stop and status are implemented; these rows pin their argument handling,
		// each on an input that never touches a real ledger root.
		{"run without a contract", []string{"run", "a.yaml", "--", "true"}, identity.ExitLauncher, "", "[path-missing]"},
		// With no command the run execs the contract's own command, so it reaches the contract, missing here; with no
		// contract either it is a usage error.
		{"run without a command", []string{"run", "a.yaml"}, identity.ExitLauncher, "", "[path-missing]"},
		{"run without a contract or a command", []string{"run"}, identity.ExitUsage, "", "[usage]"},
		// status, stop and the ask commands take a run by its id alone, whole or abbreviated (runIDUnder).
		{"stop a malformed run id", []string{"stop", "r-1"}, identity.ExitUsage, "", `tego stop: "r-1" is not a run id: ` + shortRunRef},
		{"status of a malformed run id", []string{"status", "r-1"}, identity.ExitUsage, "", `tego status: "r-1" is not a run id: ` + shortRunRef},
		{"approve a malformed run id", []string{"approve", "r-1", "q-0123456789abcdef0123456789abcdef"}, identity.ExitUsage, "",
			`tego approve: "r-1" is not a run id: ` + shortRunRef},
		{"stop a path", []string{"stop", "./r-1"}, identity.ExitUsage, "", `tego stop: "./r-1" is not a run id [usage]`},
		// An empty argument listed every run, as if none were given.
		{"status of an empty run id", []string{"status", ""}, identity.ExitUsage, "", `"" is not a run id [usage]`},
		// A malformed run id is a usage error in every command that takes one. Three characters are too few to
		// abbreviate one (resolveRunDir), and the message says how many are enough.
		{"drift a malformed run id", []string{"drift", "r-1"}, identity.ExitUsage, "", `"r-1" is not a run id or a run directory: ` + shortRunRef},
		{"measure a malformed run id", []string{"measure", "r-1"}, identity.ExitUsage, "", `"r-1" is not a run id or a run directory: ` + shortRunRef},
		{"learn a malformed run id", []string{"learn", "r-1"}, identity.ExitUsage, "", `"r-1" is not a run id or a run directory: ` + shortRunRef},
		{"events a malformed run id", []string{"events", "r-1"}, identity.ExitUsage, "", `"r-1" is not a run id or a run directory: ` + shortRunRef},
		{"verify a malformed run id", []string{"events", "r-1", "--verify"}, identity.ExitUsage, "", `"r-1" is not a run id or a run directory: ` + shortRunRef},
		{"events bad kind", []string{"events", "r-1", "--kind", "fss"}, identity.ExitUsage, "", "unknown event kind"},
		// A negative --limit was taken, --all beside a run id was ignored, and init in a directory that does not exist
		// failed as 125 [io] on its first write.
		{"events rejects a negative limit", []string{"events", "r-1", "--limit", "-5"}, identity.ExitUsage, "", "--limit -5 is not a count of events"},
		{"status takes a run id or --all", []string{"status", "--all", "r-3f9c2a1b-0dllq06ts7400-k7m2pq"}, identity.ExitUsage, "", "a run id or --all, not both"},
		{"init a missing directory", []string{"init", "/nonexistent-tego-dir/project"}, identity.ExitUsage, "", "/nonexistent-tego-dir/project does not exist; init scaffolds an existing project directory [usage]"},
		{"init a file", []string{"init", "/etc/passwd"}, identity.ExitUsage, "", "/etc/passwd is not a directory"},
		{"gc rejects arguments", []string{"gc", "x"}, identity.ExitUsage, "", "[usage]"},
		{"gc rejects a negative window", []string{"gc", "--keep", "-1h"}, identity.ExitUsage, "", "[usage]"},
		// __child is not a CLI command: cmd/tego dispatches it from os.Args before cli.Main is
		// reached, so the child stage never runs any CLI setup inside the run's process. Main seeing
		// it means something bypassed that dispatch, and the honest answer is that it is not a
		// command here.
		{"child stage is not dispatched here", []string{"__child", "--run", "r-1"}, identity.ExitUsage, "", `unknown command "__child"`},
		{"compile no file", []string{"compile"}, identity.ExitUsage, "", "[usage]"},
		{"doctor extra arg", []string{"doctor", "x"}, identity.ExitUsage, "", "[usage]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, tc.wantCode, out, errs)
			}
			if !strings.Contains(out, tc.wantStdout) {
				t.Fatalf("stdout %q lacks %q", out, tc.wantStdout)
			}
			if !strings.Contains(errs, tc.wantStderr) {
				t.Fatalf("stderr %q lacks %q", errs, tc.wantStderr)
			}
			if tc.wantCode == identity.ExitError && strings.Count(strings.TrimSpace(errs), "\n") != 0 {
				t.Fatalf("error messages are one line: %q", errs)
			}
		})
	}
}

// TestUnknownRunIDIsUsageEverywhere: a well-shaped run id naming no run under the ledger root is the caller's typo in
// every command. events, drift and measure used to exit 125 [io] for it while status and stop exited 2 [usage].
func TestUnknownRunIDIsUsageEverywhere(t *testing.T) {
	gcRoot(t)
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	for _, args := range [][]string{
		{"events", id}, {"events", id, "--verify"}, {"drift", id}, {"measure", id}, {"learn", id}, {"status", id}, {"stop", id},
	} {
		code, out, errs := run(t, args...)
		if code != identity.ExitUsage || !strings.Contains(errs, "no such run") || !strings.Contains(errs, "[usage]") {
			t.Errorf("%v: exit %d, want %d with \"no such run\" [usage]\nstdout %s\nstderr %s", args, code, identity.ExitUsage, out, errs)
		}
	}
}

// TestUnstatableRunIsIONotUsage: only a run directory that is not there is "no such run". A run the caller
// cannot stat (here EACCES on the ledger root, as for a shared root it cannot traverse) may exist and may be
// running, so every command reports the errno, 125 [io] (E26). status and stop used to answer "no such run"
// [usage], exit 2, and an unstatable path argument read as "is not a run id".
func TestUnstatableRunIsIONotUsage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses a mode-000 directory")
	}
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	for _, args := range [][]string{
		{"status", id}, {"stop", id}, {"events", id}, {"drift", id}, {"measure", id}, {"learn", id},
		{"events", filepath.Join(root, id, "nested")},
		// An abbreviation is expanded from the root's names, which it cannot list: no word on whether the run is there.
		{"events", id[len(id)-6:]}, {"status", id[len(id)-6:]}, {"stop", id[len(id)-6:]}, {"ask", id[len(id)-6:]},
		{"approve", id[len(id)-6:], "q-0123456789abcdef0123456789abcdef"},
	} {
		code, out, errs := run(t, args...)
		if code != identity.ExitError || !strings.Contains(errs, "permission denied") || !strings.Contains(errs, "[io]") {
			t.Errorf("%v: exit %d, want %d with the errno [io]\nstdout %s\nstderr %s", args, code, identity.ExitError, out, errs)
		}
	}
}

func TestHiddenChildNotInUsage(t *testing.T) {
	_, out, _ := run(t, "help")
	if strings.Contains(out, "__child") {
		t.Fatal("__child is hidden")
	}
	for _, name := range []string{"init", "doctor", "compile", "run", "stop", "status", "drift", "measure", "learn", "events", "gc", "version"} {
		if !strings.Contains(out, "  "+name) {
			t.Errorf("usage lacks %s", name)
		}
	}
}

// TestUsageMarksTheRootCommands (H18): the commands that refuse to run without root ([privilege]) are marked (root) in
// the usage, so a reader learns it before running one, and no other command is.
func TestUsageMarksTheRootCommands(t *testing.T) {
	_, out, _ := run(t, "help")
	var marked []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); strings.HasPrefix(l, "  ") && len(f) > 1 && f[1] == "(root)" {
			marked = append(marked, f[0])
		}
	}
	if want := []string{"adopt", "agents"}; !slices.Equal(marked, want) {
		t.Fatalf("usage marks %v (root), want %v:\n%s", marked, want, out)
	}
}

func TestRecoverPanic(t *testing.T) {
	cmds := []Command{{
		Name: "boom",
		Run:  func(context.Context, *flag.FlagSet, io.Writer, io.Writer) int { panic("kaboom") },
	}}
	var out, errb bytes.Buffer
	code := mainWith(context.Background(), []string{"tego", "boom"}, &out, &errb, cmds)
	if code != identity.ExitError { // §4 cli.Main: a panic is 125 [bug]
		t.Fatalf("exit %d", code)
	}
	if got := errb.String(); got != "tego: internal error: kaboom [bug]\n" {
		t.Fatalf("stderr %q", got)
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		after    int
		wantFlag bool
		wantPos  []string
		wantErr  bool
	}{
		{"flag first", []string{"--x", "a"}, 0, true, []string{"a"}, false},
		{"flag last", []string{"a", "--x"}, 0, true, []string{"a"}, false},
		{"between", []string{"a", "--x", "b"}, 0, true, []string{"a", "b"}, false},
		{"double dash keeps tail", []string{"a", "--", "--x", "-v"}, 0, false, []string{"a", "--x", "-v"}, false},
		{"flag before double dash", []string{"--x", "a", "--", "b"}, 0, true, []string{"a", "b"}, false},
		{"unknown flag", []string{"a", "--nope"}, 0, false, nil, true},
		{"empty", nil, 0, false, nil, false},
		// run (CommandAfter 1): with no "--", everything after the contract is the agent's command, so its
		// own flags reach it and never change tego's settings.
		{"run: a flag after the command is the command's", []string{"a.yaml", "./tool", "--x"}, 1, false, []string{"a.yaml", "./tool", "--x"}, false},
		{"run: a flag before the contract is tego's", []string{"--x", "a.yaml", "./tool"}, 1, true, []string{"a.yaml", "./tool"}, false},
		{"run: with --, flags before it are tego's", []string{"a.yaml", "--x", "--", "./tool", "--x"}, 1, true, []string{"a.yaml", "./tool", "--x"}, false},
		// A "--" later in the agent's command is the command's: it does not reach back and make the command's own flags
		// tego's.
		{"run: a later -- is the command's", []string{"a.yaml", "./tool", "--x", "--", "y"}, 1, false, []string{"a.yaml", "./tool", "--x", "--", "y"}, false},
		{"run: sh -c x -- y is the command", []string{"a.yaml", "sh", "-c", "x", "--", "y"}, 1, false, []string{"a.yaml", "sh", "-c", "x", "--", "y"}, false},
		{"run: a flag between contract and command is tego's", []string{"a.yaml", "--x", "./tool", "--x"}, 1, true, []string{"a.yaml", "./tool", "--x"}, false},
		{"run: -- before the contract", []string{"--x", "--", "a.yaml", "--x"}, 1, true, []string{"a.yaml", "--x"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			x := fs.Bool("x", false, "")
			err := parseArgs(fs, tc.args, tc.after)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v", err)
			}
			if err != nil {
				return
			}
			if *x != tc.wantFlag {
				t.Fatalf("flag %v want %v", *x, tc.wantFlag)
			}
			if got := fs.Args(); strings.Join(got, " ") != strings.Join(tc.wantPos, " ") {
				t.Fatalf("positional %q want %q", got, tc.wantPos)
			}
		})
	}
}

func TestDoctorRuns(t *testing.T) {
	code, out, errs := run(t, "doctor")
	// From outside the delegated cgroup subtree (a login over ssh, a CI runner's step) doctor offers no tier
	// and exits 1, with D3 naming the remedy (runtime-launch.md case 41); every probe is still printed.
	outside := false
	if fs, err := cgroup.Detect(os.Getuid()); os.Getuid() != 0 && err == nil {
		outside = errors.Is(fs.CanPlace(), cgroup.ErrOutsideSubtree)
	}
	switch {
	case outside:
		if code != identity.ExitFinding || !strings.Contains(out, "systemd-run --user --scope") {
			t.Fatalf("outside the delegated subtree: exit %d, want %d with D3's remedy, in %q", code, identity.ExitFinding, out)
		}
	case code != identity.ExitOK || errs != "":
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.HasPrefix(lines[0], "tego=") {
		t.Fatalf("first line is the version banner: %q", lines[0])
	}
	for _, id := range []string{"kernel", "btf", "cgroupv2", "landlock", "seccomp", "lsm", "programs", "fanotify", "swap"} {
		if !strings.Contains(out, " "+id+": ") {
			t.Errorf("missing probe %s in %q", id, out)
		}
	}
	code, out, _ = run(t, "doctor", "--json")
	if want := map[bool]int{false: identity.ExitOK, true: identity.ExitFinding}[outside]; code != want {
		t.Fatalf("doctor --json exited %d, want %d", code, want)
	}
	var rep struct {
		Version struct{ Tego string }
		Results []struct{ ID string }
		Tier    string
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Results) != 9 || rep.Version.Tego == "" {
		t.Fatalf("json %q: %v", out, err)
	}
	if rep.Tier == "" && !outside {
		t.Errorf("--json carries no tier: %q", out)
	}

	// --require above what this machine offers is R25's 211; a bad tier name is a usage error.
	if code, _, _ := run(t, "doctor", "--require", "bpflsm"); code != identity.ExitOK && code != identity.ExitRequire {
		t.Errorf("--require bpflsm exited %d, want 0 or %d", code, identity.ExitRequire)
	}
	if code, _, _ := run(t, "doctor", "--require", "quantum"); code != identity.ExitUsage {
		t.Errorf("--require quantum exited %d, want %d", code, identity.ExitUsage)
	}
}

// TestParseArgsDashDashAsAFlagValue: a command that passes no command on split its arguments at the first "--"
// before parsing flags, so `events R --kind --` left --kind without a value, while run's parser, and Go's flag
// package, read that "--" as the flag's value. Both parsers now agree.
func TestParseArgsDashDashAsAFlagValue(t *testing.T) {
	for _, after := range []int{0, 1} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		k := fs.String("kind", "", "")
		if err := parseArgs(fs, []string{"R", "--kind", "--", "x"}, after); err != nil {
			t.Fatalf("after %d: %v", after, err)
		}
		if *k != "--" || strings.Join(fs.Args(), " ") != "R x" {
			t.Errorf("after %d: --kind %q, positional %q; want \"--\" and [R x]", after, *k, fs.Args())
		}
	}
}
