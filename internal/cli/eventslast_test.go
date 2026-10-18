// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// passesLast is what `events --last` printed when it read the whole ledger twice: a first pass found the newest event
// the filter matched and pinned the filter to its instant, a second rendered the events stamped at that instant. It
// is kept here as the oracle the end-reading --last must agree with byte for byte.
func passesLast(t *testing.T, dir string, f events.Filter, asJSON bool) string {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	var at time.Time
	found := false
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		if f.Match(e) {
			at, found = e.TS, true
		}
	}
	if found {
		f.Since, f.Until = at, at.Add(time.Nanosecond)
	}
	var out bytes.Buffer
	render := events.TableOf
	if asJSON {
		render = events.JSONOf
	}
	if _, err := render(context.Background(), &out, r, r.Entries(), f); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// lastFilter is the filter `events --last` builds from these flags: refused, gap and limit when no --kind is given.
func lastFilter(t *testing.T, kinds, verdicts, rules, steps []string, limit int) events.Filter {
	t.Helper()
	if len(kinds) == 0 {
		kinds = []string{"refused", "gap", "limit"}
	}
	f, err := events.ParseFilter(kinds, nil, verdicts, rules, steps, limit)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestEventsLastIsWhatTwoPassesPrinted: `events --last` reads the ledger from its end now (the custom-agent POC,
// item 8: two whole passes took seconds on a 137,200-event run), and prints byte for byte what the two passes
// printed, table and --json, for every filter, on the fixture run and on a long run of it repeated.
func TestEventsLastIsWhatTwoPassesPrinted(t *testing.T) {
	type flags struct {
		kinds, verdicts, rules, steps []string
		limit                         int
	}
	sets := []flags{
		{},
		{kinds: []string{"fs"}},
		{kinds: []string{"exec"}},
		{kinds: []string{"decision"}},
		{kinds: []string{"ssl_request", "ssl_response"}},
		{kinds: []string{"run_start"}},
		{kinds: []string{"mcp", "net"}},
		{verdicts: []string{"refused"}},
		{verdicts: []string{"allow"}},
		{kinds: []string{"ask"}}, // nothing matches
		{rules: []string{"unmatched"}},
		{steps: []string{"1"}},
		{steps: []string{"3"}, kinds: []string{"decision", "fs"}},
		{limit: 3},
	}
	for _, dir := range []string{fixtureRun(t), longRun(t, 30)} {
		for _, fl := range sets {
			for _, asJSON := range []bool{false, true} {
				args := []string{"events", dir, "--last"}
				for _, k := range fl.kinds {
					args = append(args, "--kind", k)
				}
				for _, v := range fl.verdicts {
					args = append(args, "--verdict", v)
				}
				for _, r := range fl.rules {
					args = append(args, "--rule", r)
				}
				for _, s := range fl.steps {
					args = append(args, "--step", s)
				}
				if fl.limit > 0 {
					args = append(args, "--limit", "3")
				}
				if asJSON {
					args = append(args, "--json")
				}
				code, out, errs := run(t, args...)
				if code != identity.ExitOK {
					t.Fatalf("%v: exit %d: %s", args[2:], code, errs)
				}
				want := passesLast(t, dir, lastFilter(t, fl.kinds, fl.verdicts, fl.rules, fl.steps, fl.limit), asJSON)
				if out != want {
					t.Errorf("%v printed\n%s\nwant what two passes printed\n%s", args[2:], out, want)
				}
			}
		}
	}
}

// TestEventsLastIsOneEventWhenAnOlderSharesItsInstant: --last prints the newest event the filter matches (§3, "the
// single newest event"). Pinned to that event's instant, the second pass also printed an older event stamped at
// the same nanosecond; read from the end, the answer is the newest alone.
func TestEventsLastIsOneEventWhenAnOlderSharesItsInstant(t *testing.T) {
	dir := fixtureRun(t)
	path := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	tsOf := regexp.MustCompile(`"ts":"[^"]*"`)
	// seq 29 is the fixture's refusal, seq 96 its limit: the refusal is given the limit's instant.
	lines[29] = tsOf.ReplaceAllString(lines[29], tsOf.FindString(lines[96]))
	if !strings.Contains(lines[29], `"seq":29,`) || !strings.Contains(lines[96], `"seq":96,`) {
		t.Fatal("the fixture's lines moved")
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if two := passesLast(t, dir, lastFilter(t, nil, nil, nil, nil, 0), true); strings.Count(two, "\n") != 2 {
		t.Fatalf("the two passes printed %q, want both events sharing the instant (the case this test pins)", two)
	}
	code, out, errs := run(t, "events", dir, "--last", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, `"seq":96,`) {
		t.Errorf("--last --json printed\n%s\nwant the limit (seq 96) alone", out)
	}
}

// TestEventsLastReadsOnlyTheEnd: a ledger damaged far from its end still answers --last, as State answers for it:
// the lines --last does not reach are not read (the damage is --verify's, and a full view's, to report). Damage
// between the answer and the end is still refused [ledger-corrupt].
func TestEventsLastReadsOnlyTheEnd(t *testing.T) {
	dir := longRun(t, 30)
	path := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	lines[5] = "garbage"
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "events", dir, "--last", "--json")
	if code != identity.ExitOK || !strings.Contains(out, `"kind":"limit"`) {
		t.Fatalf("exit %d, out %q, stderr %q; want the last limit", code, out, errs)
	}
	if code, _, errs := run(t, "events", dir, "--json"); code != identity.ExitError || !strings.Contains(errs, "[ledger-corrupt]") {
		t.Fatalf("a full read of the damaged ledger exited %d, stderr %q; want 125 [ledger-corrupt]", code, errs)
	}
	// What --last leaves unread, --verify reports, and --last's help says so (§6 E3). A chain that
	// does not verify is --verify's finding, exit 1, as R29 and §6 E3 say, not 125.
	if code, _, errs := run(t, "events", dir, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "does not verify") ||
		!strings.Contains(errs, "[ledger-corrupt]") {
		t.Fatalf("--verify of the damaged ledger exited %d, stderr %q; want 1, does not verify ... [ledger-corrupt]", code, errs)
	}
	_, hout, herrs := run(t, "events", "--help")
	if !strings.Contains(hout+herrs, "damage before it is left to --verify") {
		t.Errorf("--last's help does not say damage before its answer is left to --verify:\n%s%s", hout, herrs)
	}
	lines[len(lines)-3] = "garbage" // after the last limit (seq 96 of 97)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs = run(t, "events", dir, "--last", "--json")
	if code != identity.ExitError || !strings.Contains(errs, "[ledger-corrupt]") {
		t.Fatalf("exit %d, stderr %q; want 125 [ledger-corrupt] for damage --last read", code, errs)
	}
}
