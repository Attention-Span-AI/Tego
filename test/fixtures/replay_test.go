// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// killTests are the kill tests that run an agent under tego and so have a ledger to record, each by the
// prefix its fixtures carry (test/e2e/kt*.sh, kt_save_fixture), with what recording one needs when the
// kill test has no half that runs today. Kill tests 3 and 5 are timing harnesses, whose runs are samples and
// are not kept: kill test 3's are timing samples of kill test 4's workloads, and kill test 5's, which has a harness
// since E13's asks shipped (test/e2e/kt5-ask.sh; docs/FEATURES.md, "Kill test 5 (R7)"), are the 20-step agent of
// kill test 2 and the pip build of kill test 4, each run ten times under a contract with two ask entries the workload
// never touches and ten under the same contract without them, to compare their wall time.
var killTests = []struct{ prefix, blockedUntil string }{
	{"kt1-", ""},
	{"kt2-", ""},
	{"kt4-", ""},
	{"kt6-", ""},
	{"kt7-", ""},
}

// fixture is one recorded run: a directory holding events.jsonl, and contract.yaml, blobs/ and the run's
// chain.log line when the run had them.
type fixture struct {
	name string
	dir  string
}

// recorded lists the kill-test fixtures under test/fixtures/ledger, plus the frozen M0 fixture every view
// is specified against (spec/record/v1/fixtures, staged here as a run directory), so this one test is the
// replay of every fixture.
func recorded(t *testing.T) []fixture {
	t.Helper()
	var out []fixture
	// The frozen fixtures by name, each its events and its anchor: the M0 run; the profiles run (ADR 0066 D6), whose
	// run_start lists the profiles its contract merged; the run identity run (ADR 0073), whose run_start carries who
	// launched it, its host, its parent run, labels, role and contract revision; the held-reads run (ADR 0069), whose
	// reads were held; the reason-reads run (ADR 0077), whose read Landlock refused is a line.
	for _, fz := range []struct{ name, events, anchor string }{
		{"m0-frozen", "run-fixture.jsonl", "chain.log"},
		{"profiles-frozen", "profiles.jsonl", "profiles.chain.log"},
		{"run-identity-frozen", "run-identity.jsonl", "run-identity.chain.log"},
		{"held-reads-frozen", "held-reads.jsonl", "held-reads.chain.log"},
		{"reason-reads-frozen", "reason-reads.jsonl", "reason-reads.chain.log"},
	} {
		dir := t.TempDir()
		for src, dst := range map[string]string{fz.events: ledger.EventsFile, fz.anchor: ledger.ChainLogFile} {
			b, err := os.ReadFile(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", src))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, dst), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out = append(out, fixture{fz.name, dir})
	}
	dirs, err := os.ReadDir("ledger")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if d.IsDir() {
			out = append(out, fixture{d.Name(), filepath.Join("ledger", d.Name())})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// TestEveryKillTestHasAFixture is P0-DESIGN §10's "every kill test adds a recorded fixture": a kill test
// whose runs were never recorded is a shape of ledger no view has been shown.
func TestEveryKillTestHasAFixture(t *testing.T) {
	fs := recorded(t)
	var blocked []string
	for _, kt := range killTests {
		n := 0
		for _, f := range fs {
			if strings.HasPrefix(f.name, kt.prefix) {
				n++
			}
		}
		switch {
		case n > 0:
		case kt.blockedUntil != "":
			// Not a pass: the test reports it as a skip naming what recording one needs, and stops
			// skipping the moment a fixture is saved.
			blocked = append(blocked, kt.prefix+"*: needs "+kt.blockedUntil)
		default:
			t.Errorf("no fixture under test/fixtures/ledger is named %s*: record one with "+
				"test/vm/matrix.sh --save-fixtures <row>", kt.prefix)
		}
	}
	if len(blocked) > 0 && !t.Failed() {
		t.Skipf("no fixture yet for %s", strings.Join(blocked, "; "))
	}
}

// runRoot copies a fixture into a fresh ledger root as <root>/<run id>/, which is where `status` looks a
// run up, and returns the root and the run's id. The copy leaves the checked-in files untouched by
// anything a view writes beside a run.
func runRoot(t *testing.T, f fixture) (root, id string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := bytes.Cut(data, []byte("\n"))
	e, err := record.Decode(first)
	if err != nil {
		t.Fatalf("%s: first line: %v", f.name, err)
	}
	id = e.Run
	root = t.TempDir()
	if err := os.CopyFS(filepath.Join(root, id), os.DirFS(f.dir)); err != nil {
		t.Fatal(err)
	}
	return root, id
}

// TestFixturesVerify walks each recorded ledger's hash chain and checks its head against the run's
// chain.log line: a fixture is only a fixture if it is byte for byte what the writer wrote.
func TestFixturesVerify(t *testing.T) {
	for _, f := range recorded(t) {
		t.Run(f.name, func(t *testing.T) {
			r, err := ledger.OpenReader(f.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			// Without the anchor line a ledger cut short after its writer closed it still walks as an intact
			// chain (record-ledger.md E29), so a fixture carries its run's line of chain.log.
			if _, err := os.Stat(filepath.Join(f.dir, ledger.ChainLogFile)); err != nil {
				t.Fatalf("no %s beside the ledger: %v", ledger.ChainLogFile, err)
			}
			anchor := ledger.NewFileChainAnchor(filepath.Join(f.dir, ledger.ChainLogFile))
			rep, err := r.Verify(context.Background(), anchor)
			if err != nil {
				t.Fatalf("does not verify: %v", err)
			}
			if !rep.Started || !rep.Ended {
				t.Errorf("a kill test's run is recorded whole, run_start to run_end: started %v ended %v",
					rep.Started, rep.Ended)
			}
			if !rep.Anchored {
				t.Error("the chain.log line does not name the ledger's head")
			}
		})
	}
}

// view is one command a fixture is replayed through, and the exit codes that mean it rendered: 0, or 1
// where the command reports a finding about the run (drift found, a status that is not clean).
type view struct {
	args     func(dir, id string) []string
	findings bool
}

var views = map[string]view{
	"events":        {args: func(dir, _ string) []string { return []string{"events", dir} }},
	"events --last": {args: func(dir, _ string) []string { return []string{"events", dir, "--last"} }},
	"measure":       {args: func(dir, _ string) []string { return []string{"measure", dir} }},
	"drift":         {args: func(dir, _ string) []string { return []string{"drift", dir} }, findings: true},
	"status":        {args: func(_, id string) []string { return []string{"status", id} }, findings: true},
}

// TestFixturesRenderInEveryView replays each fixture through status, drift, measure and events, the four
// views P0-DESIGN §12.5 names, through the CLI a user types them into. A view that exits with an error, or
// writes nothing, on a ledger a real run wrote has broken on real data.
func TestFixturesRenderInEveryView(t *testing.T) {
	for _, f := range recorded(t) {
		t.Run(f.name, func(t *testing.T) {
			root, id := runRoot(t, f)
			cfgDir := t.TempDir()
			// config.Load skips a layer whose directory others may write; t.TempDir is 0775 under umask 002.
			if err := os.Chmod(cfgDir, 0o755); err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(cfgDir, "config.yaml")
			if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+root+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEGO_CONFIG", cfg)
			dir := filepath.Join(root, id)
			for name, v := range views {
				var out, errb bytes.Buffer
				code := cli.Main(append([]string{"tego"}, v.args(dir, id)...), &out, &errb)
				ok := code == identity.ExitOK || (v.findings && code == identity.ExitFinding)
				if !ok {
					t.Errorf("%s: exit %d\nstderr: %s", name, code, errb.String())
					continue
				}
				if strings.TrimSpace(out.String()) == "" && name != "events --last" {
					t.Errorf("%s rendered nothing (stderr: %s)", name, errb.String())
				}
			}

			// --json is the stored bytes, line for line (R29): a fixture read back is the fixture.
			var out, errb bytes.Buffer
			if code := cli.Main([]string{"tego", "events", dir, "--json"}, &out, &errb); code != identity.ExitOK {
				t.Fatalf("events --json: exit %d: %s", code, errb.String())
			}
			src, err := os.ReadFile(filepath.Join(f.dir, ledger.EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimRight(src, "\n"), bytes.TrimRight(out.Bytes(), "\n")) {
				t.Error("events --json is not the recorded ledger byte for byte")
			}
		})
	}
}

// accountMarks are what a checked-in fixture may not contain, the rule kt_save_fixture applies when it
// records one (test/e2e/lib.sh), in two kinds. The shapes are account paths of any account, matched
// wherever they appear: any home directory, any uid's /run/user/<uid>, and a home path flattened into
// one directory name, which is how a TMPDIR derived from a home names the account without saying /home/
// (Claude Code's /tmp/claude-<uid>/-home-<name>-<project>/, for one). The names are those of the account
// running this test, each matched as a whole name (holdsName). The M0 fixture is written by hand, and its
// /home/u is nobody's.
func accountMarks() (shapes, names []string) {
	shapes = []string{"/home/", "/run/user/", "/-home-"}
	candidates := []string{os.Getenv("USER"), os.Getenv("LOGNAME"), os.Getenv("SUDO_USER")}
	if u, err := user.Current(); err == nil {
		candidates = append(candidates, u.Username)
	}
	for _, n := range candidates {
		if n != "" && n != "root" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return shapes, names
}

// holdsName returns the offset of the first occurrence of name in b that stands as a whole name, or -1:
// one bounded on each side by the start or end of b or by a byte no account name can hold. A user name is
// made of the portable filename characters (POSIX, "User Name": A-Z a-z 0-9 . _ -), so name inside a longer
// run of them is another word, not the account. The check runs as whatever account runs the tests, and
// that is not the account a fixture was recorded under: on GitHub's runners it is runner, and
// kt4-pip-landlock, recorded elsewhere, holds pytest's own _pytest/runner.py, which a match anywhere
// reported as the account. What a whole-name match cannot see is a name run into a longer one (<name>-tmp,
// <name>.XXXX); kt_save_fixture refuses those at recording time, where the name it looks for is the
// recording account's own and any occurrence of it counts, and the one such shape known to reach a ledger,
// a flattened home, is a shape above.
func holdsName(b []byte, name string) int {
	nameByte := func(c byte) bool {
		return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-'
	}
	for from := 0; from < len(b); {
		i := bytes.Index(b[from:], []byte(name))
		if i < 0 {
			return -1
		}
		i += from
		j := i + len(name)
		if (i == 0 || !nameByte(b[i-1])) && (j == len(b) || !nameByte(b[j])) {
			return i
		}
		from = i + 1
	}
	return -1
}

// TestHoldsName pins what counts as the account's name in a fixture: the name standing alone, not the
// same letters inside a longer word, and never a flattened home, which the shapes catch for every account.
func TestHoldsName(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{`"path":"/tmp/w/lib/python/_pytest/runner.py"`, false},
		{`__pycache__/runner.cpython-313.pyc`, false},
		{`test-runner`, false},
		{`"USER=runner"`, true},
		{`/var/mail/runner`, true},
		{`runner`, true},
		{`owner runner:runner`, true},
		{`runner@host`, true},
	} {
		if got := holdsName([]byte(tc.in), "runner") >= 0; got != tc.want {
			t.Errorf("holdsName(%q, runner) = %v, want %v", tc.in, got, tc.want)
		}
	}
	shapes, _ := accountMarks()
	flat := []byte(`"cwd":"/tmp/claude-1000/-home-dev-proj/w"`)
	if !slices.ContainsFunc(shapes, func(m string) bool { return bytes.Contains(flat, []byte(m)) }) {
		t.Errorf("a home flattened into a TMPDIR is not caught by any shape %q", shapes)
	}
}

// TestFixturesNameNoAccount is the redaction the fixtures get: a recorded ledger is checked in, so it must
// not name the account or home directory of the machine it was recorded on. kt_save_fixture refuses to
// save one that does; this catches a fixture copied in by hand, or recorded by a kt_save_fixture that let
// one through.
func TestFixturesNameNoAccount(t *testing.T) {
	shapes, names := accountMarks()
	for _, f := range recorded(t) {
		if f.name == "m0-frozen" {
			continue
		}
		err := filepath.WalkDir(f.dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			found := func(m string, i int) error {
				start, end := max(0, i-20), min(len(b), i+40)
				return errors.New(p + " names " + m + ": " + string(b[start:end]))
			}
			for _, m := range shapes {
				if i := bytes.Index(b, []byte(m)); i >= 0 {
					return found(m, i)
				}
			}
			for _, m := range names {
				if i := holdsName(b, m); i >= 0 {
					return found(m, i)
				}
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	}
}
