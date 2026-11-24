// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// secretCommands are the commands that take a secret into their process's memory, and so are made undumpable first
// (Command.HoldsSecrets), with what each one holds. A command added to the table is in neither list until someone
// decides which it belongs to; TestSecretHoldingCommandsAreExactlyThese fails until they do.
var secretCommands = map[string]string{
	"run":   "the caller's environment, the saved logins added to it, the vault's private key and the values the forwarder unseals",
	"watch": "the same as run: it is run, with the command held to no contract",
	"adopt": "the environment of the adopter and what its run's forwarder unseals",
	"start": "the token or key a person types or `claude setup-token` prints, and the saved logins",
	"setup": "the same as start, on the guided path",
}

// TestSecretHoldingCommandsAreExactlyThese: the commands that set HoldsSecrets in the real command table are the ones
// secretCommands names, no more and no fewer; one that holds no secret stays dumpable (a command a broker identifies
// must, since the broker refuses a peer whose cgroup namespace /proc hides).
func TestSecretHoldingCommandsAreExactlyThese(t *testing.T) {
	var got []string
	for _, c := range commands() {
		if c.HoldsSecrets {
			got = append(got, c.Name)
		}
	}
	var want []string
	for name := range secretCommands {
		want = append(want, name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("commands that hold secrets: %v, want %v", got, want)
	}
	// Every command outside the set says why. A command a broker or a dashboard identifies must stay dumpable (the
	// broker refuses a peer whose cgroup namespace /proc hides); the rest holds nothing a memory hold would protect.
	for name, why := range map[string]string{
		"ask": "a broker's client", "approve": "a broker's client", "deny": "a broker's client",
		"status": "reads the ledger and the lock", "stop": "signals through a pidfd", "events": "reads the ledger",
		"mcp": "the shim runs in the run, as the agent; it holds no secret", "route": "a live switch, no secret",
		"rule": "a live switch, no secret", "pause": "a live switch", "resume": "a live switch",
		"block": "a live switch", "unblock": "a live switch", "scan": "reads /proc, holds no secret",
		"dashboard":       "reads the sign-in token from a 0600 file the same user reads; the memory hold adds nothing, and it is the dashboard's client",
		"dashboard-relay": "the same token, for the Windows relay; it connects to the dashboard, which identifies its peer",
		"agents":          "root; `agents --follow --adopt` (the guard) only adopts, and every adoption's forwarder is guarded before any unseal",
	} {
		if c, ok := find(commands(), name); ok && c.HoldsSecrets {
			t.Errorf("%s (%s) must stay dumpable", name, why)
		}
	}
}

// recordedUndumpable gives makeUndumpable a recorder for the test and returns the events it writes to.
func recordedUndumpable(t *testing.T, fail error) *[]string {
	t.Helper()
	var events []string
	old := makeUndumpable
	makeUndumpable = func() error { events = append(events, "undumpable"); return fail }
	t.Cleanup(func() { makeUndumpable = old })
	return &events
}

// TestUndumpableBeforeAnyThingACommandDoes: for every command that holds secrets, in the real table, the process is made
// undumpable before the command declares a flag, parses an argument or runs; a command that holds none is not touched.
func TestUndumpableBeforeAnyThingACommandDoes(t *testing.T) {
	for name := range secretCommands {
		t.Run(name, func(t *testing.T) {
			events := recordedUndumpable(t, nil)
			cmd, ok := find(commands(), name)
			if !ok {
				t.Fatalf("no command %s", name)
			}
			flags, run := cmd.Flags, cmd.Run
			cmd.Flags = func(fs *flag.FlagSet) {
				*events = append(*events, "flags")
				if flags != nil {
					flags(fs)
				}
			}
			cmd.Run = func(ctx context.Context, fs *flag.FlagSet, so, se io.Writer) int {
				*events = append(*events, "run")
				return identity.ExitOK
			}
			_ = run
			var out, errs bytes.Buffer
			code, _ := runCommand(t.Context(), name, cmd, nil, &out, &errs)
			if len(*events) < 2 || (*events)[0] != "undumpable" || (*events)[1] != "flags" {
				t.Fatalf("order %v, want undumpable first, then flags (exit %d, %s)", *events, code, errs.String())
			}
		})
	}
	t.Run("a command that holds none", func(t *testing.T) {
		events := recordedUndumpable(t, nil)
		cmd := Command{Name: "plain", Flags: func(*flag.FlagSet) {}, Run: func(context.Context, *flag.FlagSet, io.Writer, io.Writer) int { return 0 }}
		var out, errs bytes.Buffer
		if code, _ := runCommand(t.Context(), "plain", cmd, nil, &out, &errs); code != 0 || len(*events) != 0 {
			t.Fatalf("exit %d, events %v: a command with HoldsSecrets false must not be touched", code, *events)
		}
	})
}

// TestACommandThatCannotBeMadeUndumpableDoesNotRun: the hold fails closed. The command declares no flag and runs no
// code, the exit is 125, and the line says which command, that it holds secrets and why it did not start.
func TestACommandThatCannotBeMadeUndumpableDoesNotRun(t *testing.T) {
	events := recordedUndumpable(t, errors.New("prctl(PR_SET_DUMPABLE, 0): operation not permitted"))
	cmd := Command{Name: "run", HoldsSecrets: true,
		Flags: func(*flag.FlagSet) { *events = append(*events, "flags") },
		Run: func(context.Context, *flag.FlagSet, io.Writer, io.Writer) int {
			*events = append(*events, "run")
			return 0
		}}
	var out, errs bytes.Buffer
	code, passthrough := runCommand(t.Context(), "run", cmd, nil, &out, &errs)
	if code != identity.ExitError || passthrough {
		t.Fatalf("exit %d passthrough %v, want %d", code, passthrough, identity.ExitError)
	}
	if !slices.Equal(*events, []string{"undumpable"}) {
		t.Fatalf("events %v: nothing may run after a refused hold", *events)
	}
	for _, want := range []string{"tego run:", "could not be made undumpable", "holds secrets", "did not start", "[undumpable]", "operation not permitted"} {
		if !strings.Contains(errs.String(), want) {
			t.Errorf("stderr %q does not say %q", errs.String(), want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("stdout %q", out.String())
	}
}

// undumpableHelperEnv names the environment variable that makes this test binary, re-executed by the integration test, a
// launcher stand-in. The stand-in is a real secret-holding command fed a fake secret: in the private build another command of this binary that holds a secret, and the public build has none.
const undumpableHelperEnv = "TEGO_CLI_UNDUMPABLE_HELPER"

// undumpableHelperMain runs the stand-in once TestMain has made its home; nil where no command can stand in.
var undumpableHelperMain func()

// TestARunCannotStartInsideARun: a `tego run`, `watch` or `adopt` in a process whose cgroup shows a run is refused before
// anything else, in words that name that run and say a run cannot start inside a run. Left to run on, it would hold
// itself undumpable (as every command that holds secrets does) and the outer run's supervisor, which can read neither
// the descriptors nor the working directory of an undumpable process of its run, would refuse its first file operation
// fail-closed, so the person read "chain anchor: permission denied" for a nested run instead of why. Nothing
// is held and nothing is loaded, and the exit stays 125. A command that holds secrets and starts no run (vault, start,
// setup) goes on as before, and so does a run outside every run.
func TestARunCannotStartInsideARun(t *testing.T) {
	const id = "r-0badf00d-0dn1hk3f70f5l-n3b4ec"
	old := selfCgroup
	t.Cleanup(func() { selfCgroup = old })
	insideRun := "0::/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-claude.slice/run-" + id + ".scope\n"
	outside := "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-r3f2.scope\n"
	for _, tc := range []struct {
		name     string
		cgroup   string
		supervis bool
		refused  bool
	}{
		{"a run inside a run", insideRun, true, true},
		{"a run inside the scope of an adoption", "0::/tego.slice/tego-claude.slice/adopt-" + id + ".scope/x\n", true, true},
		{"a run outside every run", outside, true, false},
		{"a command that starts no run, inside a run", insideRun, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := recordedUndumpable(t, nil)
			selfCgroup = func() ([]byte, error) { return []byte(tc.cgroup), nil }
			cmd := Command{Name: "run", HoldsSecrets: true, Supervises: tc.supervis,
				Flags: func(*flag.FlagSet) { *events = append(*events, "flags") },
				Run: func(context.Context, *flag.FlagSet, io.Writer, io.Writer) int {
					*events = append(*events, "run")
					return 0
				}}
			var out, errs bytes.Buffer
			code, _ := runCommand(t.Context(), "run", cmd, nil, &out, &errs)
			if !tc.refused {
				if code != 0 || !slices.Equal(*events, []string{"undumpable", "flags", "run"}) {
					t.Fatalf("exit %d, events %v: want the command run after the hold", code, *events)
				}
				return
			}
			if code != identity.ExitError || len(*events) != 0 {
				t.Fatalf("exit %d, events %v: want 125 and nothing held, no flag read, nothing run", code, *events)
			}
			for _, want := range []string{"tego run:", id, "a run cannot start inside a run", "[governed]"} {
				if !strings.Contains(errs.String(), want) {
					t.Errorf("stderr %q does not say %q", errs.String(), want)
				}
			}
			if strings.Contains(errs.String(), "undumpable") {
				t.Errorf("stderr %q blames the hold, which was never made", errs.String())
			}
		})
	}
}
