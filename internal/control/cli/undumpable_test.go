// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// secretCommands are the tego-control commands that take a secret into their process's memory, with what each holds. A
// command added to the registry is in neither this table nor the list below until someone decides which it belongs to.
var secretCommands = map[string]string{
	"serve": "the sign-in token, the CSRF key, the acknowledgement keys and a Vault page value while a form handles it",
}

// holdsNothingLayers are the commands a layer kept out of some builds adds to the list below, from its own test file.
var holdsNothingLayers = map[string]string{}

// TestSecretHoldingControlCommandsAreExactlyThese: the commands that set HoldsSecrets are the ones secretCommands names,
// no more and no fewer, and every other command says why it holds nothing a memory hold would protect.
func TestSecretHoldingControlCommandsAreExactlyThese(t *testing.T) {
	var got, want []string
	for _, n := range Names() {
		if c, _ := Lookup(n); c.HoldsSecrets {
			got = append(got, n)
		}
	}
	for n := range secretCommands {
		want = append(want, n)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("commands that hold secrets: %v, want %v", got, want)
	}
	const notBuilt = "a noun this build does not have yet: it prints that and exits"
	holdsNothing := map[string]string{
		"version":  "prints the build stamp and the hash of its image",
		"licenses": "prints the licence texts",
		"rules":    "reads one run's ledger and prints its rules; no key, no token",
		"access":   notBuilt, "control": notBuilt, "inbox": notBuilt, "people": notBuilt, "role": notBuilt, "whoami": notBuilt,
	}
	for n, why := range holdsNothingLayers {
		holdsNothing[n] = why
	}
	for _, n := range Names() {
		c, _ := Lookup(n)
		_, held := secretCommands[n]
		why, nothing := holdsNothing[n]
		switch {
		case held && nothing:
			t.Errorf("command %q is in both tables", n)
		case !held && !nothing:
			t.Errorf("command %q is neither in secretCommands nor in the list of commands that hold nothing", n)
		case nothing && c.HoldsSecrets:
			t.Errorf("%s (%s) must not hold secrets", n, why)
		}
	}
}

// recordedHold gives makeUndumpable a recorder for the test and returns the events it writes to.
func recordedHold(t *testing.T, fail error) *[]string {
	t.Helper()
	var events []string
	old := makeUndumpable
	makeUndumpable = func() error { events = append(events, "undumpable"); return fail }
	t.Cleanup(func() { makeUndumpable = old })
	return &events
}

// withRun replaces the registered command name's Run for the test.
func withRun(t *testing.T, name string, f func(context.Context, []string, io.Writer, io.Writer) int) {
	t.Helper()
	original := commands[name]
	registered, ok := Lookup(name)
	if !ok {
		t.Fatalf("no command %q", name)
	}
	registered.Run = f
	commands[name] = func() Command { return registered }
	t.Cleanup(func() { commands[name] = original })
}

// TestServeIsMadeUndumpableBeforeAnythingItDoes: the hold runs before serve reads a flag, a config or a key, and so
// before anything it could take a secret from (the dispatch seam: the hold is recorded before Run starts); a command that
// holds nothing is not made undumpable.
func TestServeIsMadeUndumpableBeforeAnythingItDoes(t *testing.T) {
	events := recordedHold(t, nil)
	withRun(t, "serve", func(_ context.Context, args []string, _, _ io.Writer) int {
		*events = append(*events, "run "+strings.Join(args, " "))
		return identity.ExitOK
	})
	var out, errs bytes.Buffer
	if code := mainWith(context.Background(), []string{handoff.Name, "serve", "--addr", "127.0.0.1:0"}, &out, &errs, user); code != identity.ExitOK {
		t.Fatalf("serve: exit %d, stderr %q", code, errs.String())
	}
	if want := []string{"undumpable", "run --addr 127.0.0.1:0"}; !slices.Equal(*events, want) {
		t.Errorf("serve ran in order %v, want %v", *events, want)
	}
	*events = nil
	if code, _, errs := run(t, user, "version"); code != identity.ExitOK || len(*events) != 0 {
		t.Errorf("version: exit %d (%s), events %v; a command that holds no secret is not made undumpable", code, errs, *events)
	}
}

// TestServeThatCannotBeMadeUndumpableDoesNotRun: the dashboard holds the token and the keys, so one that cannot be made
// undumpable starts nothing: exit 125 [undumpable], nothing on stdout, and its Run is never called.
func TestServeThatCannotBeMadeUndumpableDoesNotRun(t *testing.T) {
	events := recordedHold(t, errors.New("prctl: not permitted"))
	called := false
	withRun(t, "serve", func(context.Context, []string, io.Writer, io.Writer) int { called = true; return identity.ExitOK })
	code, out, errs := run(t, user, "serve", "--addr", "127.0.0.1:0")
	if code != identity.ExitError || out != "" || called || !strings.Contains(errs, "[undumpable]") || !strings.Contains(errs, "prctl: not permitted") {
		t.Errorf("serve: exit %d, stdout %q, stderr %q, Run called %v; want 125, nothing on stdout, [undumpable] naming the cause, and no Run", code, out, errs, called)
	}
	if len(*events) != 1 || strings.Count(errs, "\n") != 1 {
		t.Errorf("the hold was tried %d times, stderr %q; want once and one line", len(*events), errs)
	}
}
