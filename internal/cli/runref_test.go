// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestABareRunIDIsNeverTheCwdDirectory is R25's run argument: a bare run id names the run under the ledger
// root, as status and stop resolve it, even when the current directory holds a directory of that name. The
// agent knows its run id (TEGO_RUN_ID) and can write the project, so a ./<id>/ it planted there used to win
// over the real record in events, drift, measure and events --verify run from the project. ./<id> still
// names the local directory.
func TestABareRunIDIsNeverTheCwdDirectory(t *testing.T) {
	id, _ := verifiedRun(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	// A decoy with no events.jsonl: resolving to it is "no such run" (2) or a ledger that does not verify.
	if err := os.Mkdir(filepath.Join(cwd, id), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"events", id}, {"drift", id}, {"measure", id}, {"learn", id}, {"events", id, "--verify"}} {
		if code, out, errs := run(t, args...); code != identity.ExitOK {
			t.Errorf("%v with a decoy ./%s: exit %d, want 0 from the ledger root\nstdout %s\nstderr %s",
				args, id, code, out, errs)
		}
	}
	if code, _, errs := run(t, "events", "./"+id); code != identity.ExitUsage || !strings.Contains(errs, "no such run") {
		t.Errorf("events ./<id>: exit %d, want 2 for the local directory holding no record\nstderr %s", code, errs)
	}
}

// mintedRun writes a complete run under root whose id is minted for the time given and ends in the six characters the
// four bytes of rnd make (identity.NewRunID's rand6), so a test can give two runs the same end.
func mintedRun(t *testing.T, root string, at time.Time, rnd uint32) string {
	t.Helper()
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], rnd)
	id, err := identity.NewRunID([32]byte{}, at, bytes.NewReader(b[:]))
	if err != nil {
		t.Fatal(err)
	}
	return endedRunNamed(t, root, id, "tester")
}

// plantRun copies the run directory src to name in the current directory: what an agent that knows a run id can write
// in the project, here a real record of another run, so a command that read it would print that run.
func plantRun(t *testing.T, src, name string) {
	t.Helper()
	if err := os.CopyFS(name, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
}

// TestARunAbbreviationNamesOneRun is H08's "events needs the full id": every command that resolves its run argument
// through resolveRunDir (events, events --verify, drift, measure, learn, receipt, rule, block and the other live
// controls) takes four or more characters from the start or the end of a run id when exactly one run under the
// ledger root has them, and reads that run as its whole id would. Like a whole id, the abbreviation never names a
// directory in the current directory: the agent knows every start and end of its own id and can write the project,
// so ./<abbreviation>/ planted there, a copy of another run's record, must not answer for the run. A bare name of
// that shape read the local directory before abbreviations, so a note on stderr names both: the run it names now,
// and ./<abbreviation> for the directory. With no such directory there is no note.
func TestARunAbbreviationNamesOneRun(t *testing.T) {
	root := gcRoot(t)
	now := time.Now()
	a := mintedRun(t, root, now.Add(-2*time.Hour), 0x12345678)
	b := mintedRun(t, root, now.Add(-time.Hour), 0x9abcdef0)
	useAnchor(t, ledger.DefaultAnchorPath(filepath.Join(root, a)))
	t.Chdir(t.TempDir())
	// a's random end, its last four characters, its id without the random end, and all of it but the last character.
	for _, ref := range []string{a[len(a)-6:], a[len(a)-4:], a[:len(a)-7], a[:len(a)-1]} {
		plantRun(t, filepath.Join(root, b), ref)
		note := func(cmd string) string {
			return "tego " + cmd + ": note: " + ref + " names run " + a + " under " + root + "; ./" + ref + " names the local directory\n"
		}
		code, out, errs := run(t, "events", ref, "--json")
		if code != identity.ExitOK || !strings.Contains(out, `"run":"`+a+`"`) || strings.Contains(out, b) || errs != note("events") {
			t.Errorf("events %s --json: exit %d, want run %s's lines and the note %q\nstdout %s\nstderr %s", ref, code, a, note("events"), out, errs)
		}
		if code, out, errs := run(t, "receipt", ref); code != identity.ExitOK || !strings.HasPrefix(out, "Receipt for run "+a+" ") ||
			!strings.Contains(errs, note("receipt")) {
			t.Errorf("receipt %s: exit %d, want run %s's receipt and the note\nstdout %s\nstderr %s", ref, code, a, out, errs)
		}
		if code, out, errs := run(t, "events", ref, "--verify"); code != identity.ExitOK || !strings.HasPrefix(out, a+": verified") ||
			!strings.Contains(errs, note("events")) {
			t.Errorf("events %s --verify: exit %d, want run %s verified and the note\nstdout %s\nstderr %s", ref, code, a, out, errs)
		}
		for _, cmd := range []string{"drift", "measure", "learn"} {
			if code, out, errs := run(t, cmd, ref); code != identity.ExitOK || strings.Contains(out+errs, b) || !strings.Contains(errs, note(cmd)) {
				t.Errorf("%s %s: exit %d, want 0 from run %s and the note\nstdout %s\nstderr %s", cmd, ref, code, a, out, errs)
			}
		}
		if code, out, errs := run(t, "block", "--list", ref); code != identity.ExitOK || !strings.Contains(errs, note("block")) {
			t.Errorf("block --list %s: exit %d, want the note\nstdout %s\nstderr %s", ref, code, out, errs)
		}
	}
	// Five of a's last characters, with nothing of that name here: the run, and no note.
	if code, out, errs := run(t, "events", a[len(a)-5:], "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+a+`"`) || errs != "" {
		t.Errorf("events %s --json: exit %d, want run %s's lines and nothing on stderr\nstdout %s\nstderr %s", a[len(a)-5:], code, a, out, errs)
	}
}

// TestAnAmbiguousRunAbbreviationIsUsage: an abbreviation more than one run under the root has is the caller's to make
// longer, a usage error naming the runs it matches, newest first and five at most. No command picks one of them.
func TestAnAmbiguousRunAbbreviationIsUsage(t *testing.T) {
	root := gcRoot(t)
	// Minted a minute apart at a fixed time, so that all six share the four characters after r-00000000- (time36's
	// fourth digit changes every 28 hours, which runs minted relative to now could straddle).
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	var runs []string
	// The last two share their random end.
	for i, rnd := range []uint32{0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x9abcdef0, 0x9abcdef0} {
		runs = append(runs, mintedRun(t, root, at.Add(time.Duration(i)*time.Minute), rnd))
	}
	end, start := runs[5][len(runs[5])-6:], runs[0][:runHostLen+minRunAbbrev]
	for _, r := range runs {
		if !strings.HasPrefix(r, start) {
			t.Fatalf("run %s does not start with %s", r, start)
		}
	}
	for ref, want := range map[string]string{
		end: end + " names more than one run under " + root + ": " + runs[5] + ", " + runs[4] + "; give more of its id [usage]",
		start: start + " names more than one run under " + root + ": " +
			strings.Join([]string{runs[5], runs[4], runs[3], runs[2], runs[1]}, ", ") + " and 1 more; give more of its id [usage]",
	} {
		for _, args := range [][]string{{"events", ref}, {"events", ref, "--verify"}, {"receipt", ref}, {"block", "--list", ref}} {
			code, out, errs := run(t, args...)
			if code != identity.ExitUsage || out != "" || !strings.Contains(errs, want) {
				t.Errorf("%v: exit %d, want 2 naming the runs it matches: %q\nstdout %s\nstderr %s", args, code, want, out, errs)
			}
		}
	}
}

// TestRunAbbrevShaped: what may abbreviate a run id is what could start or end one, a run id's characters with its
// dashes in their places. Anything else, and a whole id's length or more, stays a path, read as before.
func TestRunAbbrevShaped(t *testing.T) {
	const id = "r-00000000-0dmktimu5hrut-28t5cy"
	for s, want := range map[string]bool{
		"28t5cy": true, "t5cy": true, "5cy": true, "hrut-28t5cy": true, "-28t5cy": true, "0000-0dmktimu5hrut-28t5cy": true,
		"r": true, "r-": true, "r-00000000-": true, "r-00000000-0dmk": true, id[:len(id)-1]: true, id[1:]: true,
		"": false, ".": false, "..": false, "./28t5cy": false, "runs/x": false, "my_copy": false, "28T5CY": false,
		"28t5-cy": false, "r-0000000g-": false, "r-x": false, id: false, id + "x": false, "28t5cy\n": false,
	} {
		if got := runAbbrevShaped(s); got != want {
			t.Errorf("runAbbrevShaped(%q) = %t, want %t", s, got, want)
		}
	}
}

// TestAbbrevEnds: an end of a run id abbreviates it from four characters on, a start only from four past r-<host8>-,
// which every run of one host shares. Text that could begin an id and end one ("r-abcdef") is held to each end's own
// floor, so it names a run by its end alone.
func TestAbbrevEnds(t *testing.T) {
	const id = "r-00000000-0dmktimu5hrut-28t5cy"
	for s, want := range map[string][2]bool{
		"t5cy": {false, true}, "28t5cy": {false, true}, "hrut-28t5cy": {false, true}, id[1:]: {false, true},
		"5cy": {}, "r": {}, "r-": {}, "r-00": {}, "r-0000": {}, "r-40c9": {}, "r-00000000-": {}, id[:runHostLen+minRunAbbrev-1]: {},
		id[:runHostLen+minRunAbbrev]: {true, false}, id[:len(id)-1]: {true, false},
		"r-abcdef": {false, true}, "r-abcdef01-0dm": {}, "r-abcdef01-0dmk": {true, false},
		"": {}, "my_copy": {}, id: {},
	} {
		if start, end := abbrevEnds(s); start != want[0] || end != want[1] {
			t.Errorf("abbrevEnds(%q) = %t, %t, want %t, %t", s, start, end, want[0], want[1])
		}
	}
}

// TestARunIDStartCountsPastTheHost: a start of a run id names a run only with four characters past r-<host8>-, which
// every run minted on one host begins with. Counted from the id's first character, "r-00" and "r-0000" named
// whichever one run the root held, for pause, block and the other live controls as for receipt. They are too short
// now, as the host's whole start is, and the message says how much is enough. "r-abcdef" begins the id of a run
// minted on host abcdef01 and could end an id too: it names a run by its end only.
func TestARunIDStartCountsPastTheHost(t *testing.T) {
	root := gcRoot(t)
	t.Chdir(t.TempDir())
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	a := mintedRun(t, root, at, 0x12345678)
	hid, err := identity.NewRunID([32]byte{0xab, 0xcd, 0xef, 0x01}, at, bytes.NewReader([]byte{0x9a, 0xbc, 0xde, 0xf0}))
	if err != nil {
		t.Fatal(err)
	}
	h := endedRunNamed(t, root, hid, "tester")
	for _, ref := range []string{"r-00", "r-0000", "r-abcd", "r-00000000-", a[:runHostLen+minRunAbbrev-1]} {
		want := `"` + ref + `" is not a run id or a run directory: ` + shortRunRef
		for _, args := range [][]string{
			{"receipt", ref}, {"events", ref}, {"block", "--list", ref}, {"block", ref, "exec", "curl"}, {"pause", ref},
		} {
			if code, out, errs := run(t, args...); code != identity.ExitUsage || out != "" || !strings.Contains(errs, want) {
				t.Errorf("%v: exit %d, want 2: %q\nstdout %s\nstderr %s", args, code, want, out, errs)
			}
		}
	}
	// Four past the host's start name the one run that has them.
	for ref, id := range map[string]string{a[:runHostLen+minRunAbbrev]: a, h[:runHostLen+minRunAbbrev]: h} {
		if code, out, errs := run(t, "receipt", ref); code != identity.ExitOK || !strings.HasPrefix(out, "Receipt for run "+id+" ") {
			t.Errorf("receipt %s: exit %d, want run %s's receipt\nstdout %s\nstderr %s", ref, code, id, out, errs)
		}
	}
	want := "r-abcdef: no such run under " + root + ": no run id there ends with it; " + listRunsHint + " [usage]"
	if code, out, errs := run(t, "receipt", "r-abcdef"); code != identity.ExitUsage || out != "" || !strings.Contains(errs, want) {
		t.Errorf("receipt r-abcdef: exit %d, want 2: %q\nstdout %s\nstderr %s", code, want, out, errs)
	}
}

// TestARunAbbreviationThatNamesNoRunNamesNoDirectory: fewer than four characters, or four or more that no run under
// the root starts or ends with, is a usage error, never the directory of that name in the current directory, which
// the message points to and ./<name> still reads.
func TestARunAbbreviationThatNamesNoRunNamesNoDirectory(t *testing.T) {
	root := gcRoot(t)
	b := mintedRun(t, root, time.Now(), 0x12345678)
	t.Chdir(t.TempDir())
	short := b[len(b)-3:]
	for ref, want := range map[string]string{
		short: `"` + short + `" is not a run id or a run directory: ` + strings.TrimSuffix(shortRunRef, " [usage]") +
			"; ./" + short + " names the local directory [usage]",
		"zzzz": "zzzz: no such run under " + root + ": no run id there ends with it; tego status --all lists " +
			"the runs; ./zzzz names the local directory [usage]",
	} {
		plantRun(t, filepath.Join(root, b), ref)
		for _, args := range [][]string{{"events", ref}, {"events", ref, "--verify"}, {"receipt", ref}, {"drift", ref}} {
			code, out, errs := run(t, args...)
			if code != identity.ExitUsage || out != "" || !strings.Contains(errs, want) {
				t.Errorf("%v: exit %d, want 2: %q\nstdout %s\nstderr %s", args, code, want, out, errs)
			}
		}
		if code, out, errs := run(t, "events", "./"+ref, "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+b+`"`) {
			t.Errorf("events ./%s: exit %d, want the local directory's record\nstdout %s\nstderr %s", ref, code, out, errs)
		}
	}
	// A link to a run directory under a word that could end a run id, as ~/latest: the note names it too, and
	// ./latest reads the run it leads to.
	if err := os.Symlink(filepath.Join(root, b), "latest"); err != nil {
		t.Fatal(err)
	}
	want := "latest: no such run under " + root + ": no run id there ends with it; tego status --all lists the runs; " +
		"./latest names the local directory [usage]"
	if code, out, errs := run(t, "events", "latest"); code != identity.ExitUsage || out != "" || !strings.Contains(errs, want) {
		t.Errorf("events latest: exit %d, want 2: %q\nstdout %s\nstderr %s", code, want, out, errs)
	}
	if code, out, errs := run(t, "events", "./latest", "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+b+`"`) {
		t.Errorf("events ./latest: exit %d, want run %s's lines\nstdout %s\nstderr %s", code, b, out, errs)
	}
}

// TestRunIDOnlyCommandsTakeAnAbbreviation: status, stop, ask, approve, deny and alternate take a run by its id alone,
// and they take the abbreviation every other run command takes (runIDUnder), with the same floors and errors. They
// answered a well-formed one with a bare "is not a run id", so `tego status 28t5cy` looked broken beside
// `tego events 28t5cy`. They never read a directory, so one of the abbreviation's name changes nothing, and no note
// names it.
func TestRunIDOnlyCommandsTakeAnAbbreviation(t *testing.T) {
	root := gcRoot(t)
	t.Chdir(t.TempDir())
	now := time.Now()
	a := mintedRun(t, root, now.Add(-2*time.Hour), 0x12345678)
	b := mintedRun(t, root, now.Add(-time.Hour), 0x9abcdef0)
	c := mintedRun(t, root, now.Add(-30*time.Minute), 0x9abcdef0) // b's end too
	const askID = "q-0123456789abcdef0123456789abcdef"
	// Every command with ref in its run's place; a and the ask commands' answer an ended run gets.
	commands := func(ref string) [][]string {
		return [][]string{
			{"status", ref}, {"stop", ref}, {"ask", ref}, {"ask", ref, askID}, {"approve", ref, askID}, {"deny", ref, askID},
			{"alternate", ref, askID, "--file", "x"},
		}
	}
	// a's random end, which ./28t5cy, a copy of b, does not answer for, and its id without the random end.
	plantRun(t, filepath.Join(root, b), a[len(a)-6:])
	for _, ref := range []string{a[len(a)-6:], a[:len(a)-7]} {
		if code, out, errs := run(t, "status", ref, "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+a+`"`) ||
			strings.Contains(out, b) || errs != "" {
			t.Errorf("status %s --json: exit %d, want run %s and nothing on stderr\nstdout %s\nstderr %s", ref, code, a, out, errs)
		}
		if code, out, errs := run(t, "stop", ref); code != identity.ExitOK || out != a+": not running\n" {
			t.Errorf("stop %s: exit %d, want %s not running\nstdout %s\nstderr %s", ref, code, a, out, errs)
		}
		for _, args := range commands(ref)[2:] {
			want := "tego " + args[0] + ": " + a + " has ended; nothing waits for an answer [not-running]"
			if code, out, errs := run(t, args...); code != identity.ExitFinding || out != "" || !strings.Contains(errs, want) {
				t.Errorf("%v: exit %d, want 1: %q\nstdout %s\nstderr %s", args, code, want, out, errs)
			}
		}
	}
	end := b[len(b)-6:]
	for ref, want := range map[string]string{
		end:    end + " names more than one run under " + root + ": " + c + ", " + b + "; give more of its id [usage]",
		"zzzz": "zzzz: no such run under " + root + ": no run id there ends with it; " + listRunsHint + " [usage]",
		"r-00": `"r-00" is not a run id: ` + shortRunRef,
	} {
		for _, args := range commands(ref) {
			if ref == "r-00" && len(args) == 2 && args[0] == "ask" {
				continue // one argument may be an ask id: below
			}
			code, out, errs := run(t, args...)
			if code != identity.ExitUsage || out != "" || !strings.Contains(errs, "tego "+args[0]+": "+want) ||
				strings.Count(errs, listRunsHint) > 1 {
				t.Errorf("%v: exit %d, want 2: %q\nstdout %s\nstderr %s", args, code, want, out, errs)
			}
		}
	}
	// One argument too short for a run, or one that begins q- (eight characters of which could end a run id), is
	// neither a run nor an ask id (QG-11).
	for _, ref := range []string{"r-00", "q-abc123"} {
		want := `tego ask: "` + ref + `" is neither a run id (r-…) nor an ask id (q-…)`
		if code, out, errs := run(t, "ask", ref); code != identity.ExitUsage || out != "" || !strings.Contains(errs, want) {
			t.Errorf("ask %s: exit %d, want 2: %q\nstdout %s\nstderr %s", ref, code, want, out, errs)
		}
	}
	// status names the command that lists the runs once, for a whole id as for an abbreviation.
	const unknown = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	if code, _, errs := run(t, "status", unknown); code != identity.ExitUsage || strings.Count(errs, listRunsHint) != 1 {
		t.Errorf("status %s: exit %d, want 2 naming %q once\nstderr %s", unknown, code, listRunsHint, errs)
	}
}

// TestStatusOrdersRunsByMintTimeAcrossHosts: newest and oldest are the runs' mint times, never their host
// prefix. A ledger root holding two host8 prefixes (a machine-id change, a shared home) sorted by the whole
// id put every run of the higher prefix after every run of the lower, so bare status kept showing the last
// run from before a reinstall and --all was grouped by host.
func TestStatusOrdersRunsByMintTimeAcrossHosts(t *testing.T) {
	root := gcRoot(t)
	now := time.Now()
	old := endedRunOnHost(t, root, [32]byte{0xff, 0xff, 0xff, 0xff}, now.Add(-2*time.Hour))
	mid := endedRunOnHost(t, root, [32]byte{}, now.Add(-time.Hour))
	newest := endedRunOnHost(t, root, [32]byte{0x7f}, now)
	code, out, errs := run(t, "status", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got statusListJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Runs) != 1 || got.Runs[0].Run != newest {
		t.Fatalf("bare status: %+v %v, want only %s (%s)", got.Runs, err, newest, out)
	}
	_, out, _ = run(t, "status", "--all", "--json")
	got = statusListJSON{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, r := range got.Runs {
		order = append(order, r.Run)
	}
	if want := []string{old, mid, newest}; !slices.Equal(order, want) {
		t.Errorf("status --all order %v, want oldest first %v", order, want)
	}
}

// TestCompileJSONEnvListsAreNeverNull is agent-contract R12's --json shape: with no env: section env_deny is
// [] and env_set {}, as every other list is, where both were null; env_pass stays null, meaning the agent
// inherits the environment, and [] is a contract that passes nothing.
func TestCompileJSONEnvListsAreNeverNull(t *testing.T) {
	code, out, errs := run(t, "compile", filepath.Join("testdata", "minimal.yaml"), "--json", "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	for _, want := range []string{`"env_pass":null`, `"env_deny":[]`, `"env_set":{}`} {
		if !strings.Contains(out, want) {
			t.Errorf("--json lacks %s:\n%s", want, out)
		}
	}
}

// TestDriftAggregateLoadsTheConfigOnceAndSkipsOtherAgents:--aggregate resolves the machine config once
// per invocation (R24), printing a config warning once however many runs it sums, and never recompiles the
// contract of another agent's run. It recompiled every run under the root before comparing agents, and
// printed each warning and each other agent's "no longer loads" line once per run.
func TestDriftAggregateLoadsTheConfigOnceAndSkipsOtherAgents(t *testing.T) {
	root := gcRoot(t)
	cfg := os.Getenv("TEGO_CONFIG")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\nprivileged_binary: /nowhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var mine []string
	for i := range 3 {
		mine = append(mine, endedRunAs(t, root, [32]byte{}, "tester", now.Add(time.Duration(i-5)*time.Minute)))
	}
	other := endedRunAs(t, root, [32]byte{}, "someone-else", now)
	for _, id := range append(slices.Clone(mine), other) {
		if err := os.WriteFile(filepath.Join(root, id, ledger.ContractFile), []byte("{not: [a contract\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := run(t, "drift", mine[0], "--aggregate")
	if code == identity.ExitError || code == identity.ExitUsage {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if n := strings.Count(errs, "privileged_binary is honoured"); n != 1 {
		t.Errorf("the config warning printed %d times, want once:\n%s", n, errs)
	}
	if strings.Contains(errs, other) {
		t.Errorf("another agent's run was recompiled:\n%s", errs)
	}
	if n := strings.Count(errs, "no longer loads"); n != len(mine) {
		t.Errorf("%d \"no longer loads\" lines, want one per run of this agent (%d):\n%s", n, len(mine), errs)
	}
}
