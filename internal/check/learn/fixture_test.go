// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"flag"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var update = flag.Bool("update", false, "rewrite the golden proposals from the fixtures")

// The fixtures are the ledgers of two real observe-only runs of `tego watch` on 2026-10-06, the interactive Claude
// Code 2.1.290 and Codex 0.159.2 start-up screens (no credentials, so each stopped at its first-run screen), with
// the home directory /home/<user> written /home/user, the machine's host name and its tag in the run id replaced, and
// the names that were hashes of something on the machine, and the contract hash of a contract not kept here, set to
// fixed values. Every line's id and prev were then computed again over that text (TestFixturesVerify): a hash left from
// before the scrub would confirm a guess at the text it replaced.
const (
	claudeFixture = "testdata/claude-startup-observe.jsonl"
	codexFixture  = "testdata/codex-startup-observe.jsonl.gz"
)

// stateDirs are where the fixtures' machine kept tego's own files.
var stateDirs = []string{"/home/user/.tego"}

// fixtureLines reads a fixture ledger's lines, gzipped when its name says so.
func fixtureLines(t *testing.T, name string) [][]byte {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var in io.Reader = f
	if strings.HasSuffix(name, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = zr.Close() }()
		in = zr
	}
	var lines [][]byte
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		lines = append(lines, bytes.Clone(sc.Bytes()))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// fixtureEvents decodes a fixture ledger.
func fixtureEvents(t *testing.T, name string) []*record.Event {
	t.Helper()
	var events []*record.Event
	for _, line := range fixtureLines(t, name) {
		e, err := record.Decode(line)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		events = append(events, e)
	}
	return events
}

func fixtureProposal(t *testing.T, name string, o Options) *Proposal {
	t.Helper()
	p, err := propose(fixtureEvents(t, name), o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// golden compares the proposed contract with its reviewed file; -update rewrites the file, to be read before it is
// committed.
func golden(t *testing.T, file, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (go test -update writes it)", err)
	}
	if !bytes.Equal(want, []byte(got)) {
		t.Errorf("the proposal differs from %s (go test -update rewrites it):\n%s", file, got)
	}
}

// TestClaudeStartupProposal: the proposal for the real Claude Code start-up run. It is the reviewed golden file, and
// these are the things a person reading it would check: the model's addresses are listed as endpoints with the host
// name hint, the terminal is granted, the run's own state outside its workspace is reported and not allowed, and the
// agent is not in exec.allow.
func TestClaudeStartupProposal(t *testing.T) {
	p := fixtureProposal(t, claudeFixture, Options{StateDirs: stateDirs})
	c := p.Contract()
	golden(t, "testdata/claude-startup.golden.yaml", c)
	load(t, c)

	if got, want := entries(c, "fs"), []string{"/dev/tty"}; !slices.Equal(got, want) {
		t.Errorf("fs.write = %q, want only the terminal: the run wrote nothing under its workspace", got)
	}
	for _, want := range []string{"tcp://160.79.104.10:443", "tcp://[2607:6bc0::10]:443"} {
		if !slices.Contains(entries(c, "net"), want) {
			t.Errorf("net.allow lacks the model's address %s\n%s", want, c)
		}
	}
	for _, want := range []string{
		`for example "tcp://api.example.com:443"`,
		"never the host name it asked for",
		"outside the workspace /home/user/.cache/tego-workdir/poc-run/w1",
		"writes under /home/user/.cache/tego-workdir/poc-run/home-claude/.claude/",
		"writes under /run/user/1000/cc-socks/",
		"observed, not allowed: raw socket family(16)",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("the proposal lacks %q", want)
		}
	}
	if got := entries(c, "exec"); len(got) != 0 {
		t.Errorf("exec.allow = %q: the run started only the agent", got)
	}
	if p.Limits == nil || p.Limits.Memory != "320MiB" || p.Limits.Pids != "72" {
		t.Errorf("limits = %+v, want 320MiB and 72 from a 151 MiB and 18 pid peak", p.Limits)
	}
	assertNoDangerousAllowed(t, c)
}

// TestCodexStartupProposal: the proposal for the real Codex start-up run, which also connected to the D-Bus session
// bus and made sockets of its own.
func TestCodexStartupProposal(t *testing.T) {
	p := fixtureProposal(t, codexFixture, Options{StateDirs: stateDirs})
	c := p.Contract()
	golden(t, "testdata/codex-startup.golden.yaml", c)
	load(t, c)

	if !strings.Contains(c, "observed, not allowed: unix:/run/user/1000/bus (seen 2 times): the D-Bus session bus") {
		t.Errorf("the D-Bus session bus is not reported as observed, not allowed\n%s", c)
	}
	nets := entries(c, "net")
	for _, want := range []string{
		"unix:/var/run/nscd/socket",
		"unix:/home/user/.cache/tego-workdir/poc-run/home-codex/.codex/app-server-control/app-server-control.sock", // made by the run
	} {
		if !slices.Contains(nets, want) {
			t.Errorf("net.allow lacks %s", want)
		}
	}
	// A previously reached service is still a particular successful send next to
	// credential reads. Without a contract reference the learner cannot call it safe.
	if slices.Contains(nets, "tcp://140.82.114.3:443") || !slices.Contains(leakDests(p), "140.82.114.3:443") {
		t.Error("the later successful GitHub contact lost its secret-read warning")
	}
	if !strings.Contains(c, "a socket the run created") {
		t.Error("a socket the run made is not marked")
	}
	// Each program once, with the PATH search that found it left out: git is at /usr/bin/git, and no other directory
	// of PATH holds a getconf the run started.
	execs := entries(c, "exec")
	for _, want := range []string{"/usr/bin/git", "/usr/bin/getconf"} {
		if !slices.Contains(execs, want) {
			t.Errorf("exec.allow lacks %s", want)
		}
	}
	// Codex probes its own sandbox with bwrap, which fails inside a Landlock domain: reported, not proposed.
	if slices.Contains(execs, "/usr/bin/bwrap") || !strings.Contains(c, "observed, not allowed: /usr/bin/bwrap (seen once): it sets up a mount namespace") {
		t.Errorf("bwrap is proposed or not reported\n%s", c)
	}
	for _, e := range execs {
		if strings.HasSuffix(e, "/getconf") && e != "/usr/bin/getconf" {
			t.Errorf("exec.allow lists %s, a directory PATH was searched in", e)
		}
		if strings.HasSuffix(e, ".local/bin/codex") {
			t.Errorf("exec.allow lists the agent itself: %s", e)
		}
	}
	if p.SearchMisses == 0 {
		t.Error("no PATH search misses were counted in a run that searched PATH hundreds of times")
	}
	assertNoDangerousAllowed(t, c)
}

// assertNoDangerousAllowed is the invariant of C9 whatever a fixture holds: no net.allow entry is a socket the
// dangerous list names, none is under a runtime directory unless it was made by the run, and fs.deny_read is not a
// key of the proposal (learn never removes one).
func assertNoDangerousAllowed(t *testing.T, c string) {
	t.Helper()
	for _, e := range entries(c, "net") {
		sock, ok := strings.CutPrefix(e, "unix:")
		if !ok {
			continue
		}
		if why := dangerous(sock); why != "" {
			t.Errorf("net.allow holds %s: %s", e, why)
		}
		if runtimeDirRE.MatchString(sock) {
			t.Errorf("net.allow holds %s under the runtime directory", e)
		}
	}
	for _, l := range strings.Split(c, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "deny_read:") {
			t.Errorf("the proposal sets fs.deny_read: %q", l)
		}
	}
}

// TestFixturesVerify: every line of a fixture hashes to its own id and links to the line before it (R2). A scrub that
// rewrites the text must rewrite these too: the hash of a line it did not recompute still commits to what it removed.
func TestFixturesVerify(t *testing.T) {
	for _, name := range []string{claudeFixture, codexFixture} {
		lines := fixtureLines(t, name)
		if len(lines) == 0 {
			t.Fatalf("%s is empty", name)
		}
		var chain record.Chain
		for i, line := range lines {
			if _, err := chain.Add(line); err != nil {
				t.Fatalf("%s line %d: %v", filepath.Base(name), i+1, err)
			}
		}
	}
}

// homeRE finds a home directory however a capture wrote it: as a path, or flattened into one directory name, as Claude
// Code names a project (-home-<name>-<project>).
var homeRE = regexp.MustCompile(`(?:/home/|-home-)([A-Za-z0-9._]+)`)

// agentWords are account names this test does not look for: the fixtures are captures of these programs on a Linux
// box, so these words stand alone in them whoever recorded them, and a person may run the tests under any of them.
var agentWords = []string{"root", "user", "claude", "codex"}

// runningAccounts returns the name of the account running the test. The name is read at test time, so that no file in
// the tree has to hold a real login to keep it out of the fixtures.
func runningAccounts() []string {
	var names []string
	candidates := []string{os.Getenv("USER"), os.Getenv("LOGNAME"), os.Getenv("SUDO_USER")}
	if u, err := user.Current(); err == nil {
		candidates = append(candidates, u.Username)
	}
	for _, n := range candidates {
		if n != "" && !slices.Contains(agentWords, n) && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// fixtureHomes are the home directories a fixture may name: the scrubbed one, and /home/claude, which Claude Code
// itself probes on every machine for a remote login.
var fixtureHomes = []string{"user", "claude"}

// accountMarks returns what in raw names an account: a home directory other than fixtureHomes, or one of names standing
// as a whole name (POSIX portable filename characters do not surround it).
func accountMarks(raw []byte, names []string) []string {
	var marks []string
	for _, m := range homeRE.FindAllSubmatch(raw, -1) {
		if !slices.Contains(fixtureHomes, string(m[1])) {
			marks = append(marks, string(m[0]))
		}
	}
	for _, n := range names {
		re := regexp.MustCompile(`(?:^|[^A-Za-z0-9._-])` + regexp.QuoteMeta(n) + `(?:$|[^A-Za-z0-9._-])`)
		if re.Match(raw) {
			marks = append(marks, n)
		}
	}
	return marks
}

// TestAccountMarks: the check below finds each shape it stands for, with an invented name.
func TestAccountMarks(t *testing.T) {
	t.Setenv("USER", "quokka")
	if !slices.Contains(runningAccounts(), "quokka") {
		t.Fatalf("runningAccounts = %q: $USER is not read", runningAccounts())
	}
	names := []string{"quokka"}
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`"path":"/home/user/.cache/x"`, false},
		{`"path":"/tmp/claude-1000/-home-user-work/x"`, false},
		{`"path":"/usr/lib/quokka-tools/x"`, false}, // inside a longer word, not the account
		{`"path":"/home/robin/.cache/x"`, true},     // another account: the scrub missed it
		{`"path":"/tmp/claude-1000/-home-robin-work/x"`, true},
		{`"path":"/srv/quokka/x"`, true},
		{`"owner":"quokka"`, true},
	} {
		if got := len(accountMarks([]byte(tc.raw), names)) > 0; got != tc.want {
			t.Errorf("accountMarks(%s) found one = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// TestFixturesHaveNoHomeOfTheirAuthor: the fixtures carry no real user's name: they name no home but fixtureHomes, and
// the account running this test, the recording account on the box that recorded them, is not there.
func TestFixturesHaveNoHomeOfTheirAuthor(t *testing.T) {
	names := runningAccounts()
	for _, name := range []string{claudeFixture, codexFixture} {
		raw := bytes.Join(fixtureLines(t, name), []byte("\n"))
		if marks := accountMarks(raw, names); len(marks) > 0 {
			t.Errorf("%s names an account: %q", filepath.Base(name), marks)
		}
	}
}
