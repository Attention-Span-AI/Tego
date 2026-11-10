// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/mcprelay"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// testHome is the home TestMain gives this package's own log: tego.log is <testHome>/.tego/tego.log.
var testHome string

// TestMain gives every command this package's tests run a home of its own in a temporary directory: the
// chain anchor (<home>/.tego/chain.log), the own log (<home>/.tego/tego.log) and the machine config
// (isolateMachine). A sweep inside `gc`, `stop` or `run` would otherwise append its orphan's head to the
// developer's own ~/.tego/chain.log, every error a test provokes, the internal-error panic stack among them,
// would land in their ~/.tego/tego.log, and the built-in ledger root would be their ~/.tego/runs. The
// binary fails when anything in the real ~/.tego changed while the tests ran (testutil.GuardedLeakCheckMain).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == mcprelay.ServerCommand {
		os.Exit(mcprelay.ServerMain(os.Args[2:]))
	}
	// The test binary is doctor's plane probe child (/proc/self/exe __doctor-plane-probe), as cmd/tego is: doctor
	// and a run's tier check run that probe in this process (TestTestBinaryIsThePlaneProbesChild).
	if len(os.Args) > 1 && os.Args[1] == doctor.PlaneProbeCommand {
		os.Exit(doctor.PlaneProbeMain(os.Args[2:]))
	}
	if os.Getenv(signalHelperEnv) != "" {
		signalHelper()
	}
	if mode := os.Getenv(brokenPipeHelperEnv); mode != "" {
		brokenPipeHelper(mode)
	}
	dir, err := os.MkdirTemp("", "tego-cli-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	home := filepath.Join(dir, "home")
	if err := isolateMachine(dir, home); err != nil {
		fmt.Fprintf(os.Stderr, "machine config: %v\n", err)
		os.Exit(1)
	}
	// A `run` keeps its runtime directory under $XDG_RUNTIME_DIR/tego and sweeps that parent, which under the
	// developer's /run/user/<uid> holds their own runs' (identity-config.md R27 clause b4).
	if err := testutil.PrivateRuntimeDir(dir); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(home, ".tego", ledger.ChainLogFile), nil }
	// The governed-agent refusal reads this process's own cgroup: from a governed agent's session, or a container with
	// a private cgroup namespace, every tego unblock and widening tego rule here would be refused. governed_test.go
	// sets it to refuse and holds the refusal.
	selfInRun = func() (bool, error) { return false, nil }
	testHome = home
	ownLogHomeOf = func(int) string { return home }
	// The process's appender is built once, by the first command that logs (processOwnLog), from ownLogHomeOf as it is
	// then. It is built here so it is this home's whatever order the tests run in. A test that points ownLogHomeOf at a
	// home of its own (userStateFor) and runs first would otherwise bind it to that test's temporary directory for the
	// rest of the binary, and every later line, the ones the own-log and retention tests read, was lost with it.
	processOwnLog()
	code := testutil.GuardedLeakCheckMain(m)
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// isolateMachine keeps every machine config this package's tests load out of the invoking user's own:
// tego reads the per-user layer and expands ~/ against the passwd home, never $HOME, so a test that set
// HOME, or TEGO_CONFIG to "", still resolved the built-in ledger_root to the developer's real
// ~/.tego/runs — doctor's ledger check read it and a run that stopped at a missing contract made it. Here
// the passwd home is home (its ~/.tego/config.yaml absent, so a test with TEGO_CONFIG="" gets the
// built-in config over it), /etc/tego/config.yaml is not read, $TEGO_CONFIG defaults to a 0600 config
// naming <dir>/runs, and a ledger root inside the real ~/.tego panics the test that resolved it.
func isolateMachine(dir, home string) error {
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	cfg := filepath.Join(dir, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(dir, "runs")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Setenv(config.EnvConfigVar, cfg); err != nil {
		return err
	}
	machineSources = func(uid int, secure bool) (config.Sources, string, []config.Diagnostic) {
		src, _, diags := config.Resolve(uid, secure)
		src.Etc = ""
		src.User = filepath.Join(home, config.UserRelPath)
		return src, home, diags
	}
	resolve := ledgerRootOf
	ledgerRootOf = func(m *config.Machine) (string, error) {
		root, err := resolve(m)
		if err == nil && testutil.UnderRealTego(root) {
			panic("test resolved the ledger root " + root + ", inside the invoking user's real ~/.tego")
		}
		return root, err
	}
	return nil
}

// useAnchor makes the commands a test runs check and append to path.
func useAnchor(t *testing.T, path string) {
	t.Helper()
	prev := anchorPath
	anchorPath = func(*config.Machine) (string, error) { return path, nil }
	t.Cleanup(func() { anchorPath = prev })
}

// verifiedRun is a closed run under a fresh ledger root whose anchor the commands will consult,
// returning the run id and the run directory.
func verifiedRun(t *testing.T) (string, string) {
	t.Helper()
	root := gcRoot(t)
	id := endedRun(t, root, time.Now()) // anchored at the ledger's default, beside the root
	useAnchor(t, ledger.DefaultAnchorPath(filepath.Join(root, id)))
	return id, filepath.Join(root, id)
}

// TestVerifyCleanRun: an untouched closed run verifies, and the line says what was checked.
func TestVerifyCleanRun(t *testing.T) {
	id, _ := verifiedRun(t)
	code, out, errs := run(t, "events", id, "--verify")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	for _, want := range []string{id + ": verified 2 lines", "run_start to run_end", "anchored in"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}
}

// TestVerifyFindings is R25 for --verify: a tampered line, a truncated tail and a missing anchor are
// each a finding, exit 1, never a clean report.
func TestVerifyFindings(t *testing.T) {
	cases := []struct {
		name   string
		damage func(t *testing.T, dir, anchor string)
		want   string
	}{
		{"a changed byte", func(t *testing.T, dir, _ string) {
			p := filepath.Join(dir, ledger.EventsFile)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b = bytes.Replace(b, []byte(`"cwd":"/"`), []byte(`"cwd":"~"`), 1)
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "id does not match"},
		{"run_end removed", func(t *testing.T, dir, _ string) {
			dropLastLine(t, filepath.Join(dir, ledger.EventsFile))
		}, "anchored head"},
		{"the anchor line gone", func(t *testing.T, _, anchor string) {
			if err := os.Remove(anchor); err != nil {
				t.Fatal(err)
			}
		}, "no chain anchor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, dir := verifiedRun(t)
			anchor := ledger.DefaultAnchorPath(dir)
			tc.damage(t, dir, anchor)
			code, out, errs := run(t, "events", id, "--verify")
			if code != identity.ExitFinding {
				t.Fatalf("exit %d, want 1\nstdout %s\nstderr %s", code, out, errs)
			}
			if !strings.Contains(errs, "does not verify") || !strings.Contains(errs, tc.want) ||
				!strings.Contains(errs, "["+codeUnverified+"]") {
				t.Errorf("stderr lacks the finding %q: %s", tc.want, errs)
			}
			if strings.Contains(out, "verified") {
				t.Errorf("a ledger that does not verify printed %q", out)
			}
		})
	}
}

// TestVerifyLiveRun: a run that has not ended owes no anchor line, and the line says the head was
// not checked against one.
func TestVerifyLiveRun(t *testing.T) {
	root := gcRoot(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "tester"},
		ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) }()
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	useAnchor(t, filepath.Join(t.TempDir(), ledger.ChainLogFile))
	code, out, errs := run(t, "events", string(id), "--verify")
	if code != identity.ExitOK || !strings.Contains(out, "not ended") || !strings.Contains(out, "no anchor yet") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestVerifyJSON is one object whatever the outcome.
func TestVerifyJSON(t *testing.T) {
	id, dir := verifiedRun(t)
	code, out, _ := run(t, "events", id, "--verify", "--json")
	var got verifyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != identity.ExitOK || !got.Verified || !got.Anchored || got.Lines != 2 {
		t.Fatalf("exit %d %+v %v\n%s", code, got, err, out)
	}
	dropLastLine(t, filepath.Join(dir, ledger.EventsFile))
	code, out, _ = run(t, "events", id, "--verify", "--json")
	got = verifyJSON{}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != identity.ExitFinding || got.Verified || got.Error == "" {
		t.Fatalf("exit %d %+v %v\n%s", code, got, err, out)
	}
}

// TestVerifyUsageAndReadErrors: a filter beside --verify is a usage error, and an anchor that cannot
// be read is Tego's own failure (125), never a verdict about the ledger.
func TestVerifyUsageAndReadErrors(t *testing.T) {
	id, _ := verifiedRun(t)
	if code, _, errs := run(t, "events", id, "--verify", "--kind", "exec"); code != identity.ExitUsage {
		t.Fatalf("--verify --kind: exit %d, want 2 (%s)", code, errs)
	}
	unreadable := filepath.Join(t.TempDir(), "chain.log")
	if err := os.Mkdir(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	useAnchor(t, unreadable)
	if code, out, errs := run(t, "events", id, "--verify"); code != identity.ExitError {
		t.Fatalf("unreadable anchor: exit %d, want 125\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestVerifySwappedLedger: a ledger another anchored run wrote, copied over this run's events.jsonl,
// is a complete and correctly anchored chain in its own right. It verified — against the other run's
// anchor line, reported under the other run's id — so whoever could write the run directory could
// replace an incriminating record with a clean one. The run verified is the one the directory names.
func TestVerifySwappedLedger(t *testing.T) {
	a, dirA := verifiedRun(t)
	b := endedRun(t, filepath.Dir(dirA), time.Now())
	clean, err := os.ReadFile(filepath.Join(filepath.Dir(dirA), b, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirA, ledger.EventsFile), clean, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "events", a, "--verify")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d, want 1\nstdout %s\nstderr %s", code, out, errs)
	}
	if !strings.Contains(errs, a+" does not verify") || !strings.Contains(errs, `line 0 is run "`+b+`"`) {
		t.Errorf("stderr does not name the run asked about and the run the ledger belongs to: %s", errs)
	}
	if strings.Contains(out, "verified") {
		t.Errorf("a swapped ledger printed %q", out)
	}
	code, out, _ = run(t, "events", a, "--verify", "--json")
	var got verifyJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != identity.ExitFinding || got.Verified || got.Run != a {
		t.Fatalf("--json: exit %d %+v %v\n%s", code, got, err, out)
	}
}

// TestVerifyDeletedLedger: chain.log holds a line for the run, so its ledger — or its whole directory —
// being gone is the record's loss, a finding (exit 1), not a run that never existed (125).
func TestVerifyDeletedLedger(t *testing.T) {
	for name, remove := range map[string]func(dir string) error{
		"events.jsonl":      func(dir string) error { return os.Remove(filepath.Join(dir, ledger.EventsFile)) },
		"the run directory": os.RemoveAll,
	} {
		t.Run(name, func(t *testing.T) {
			id, dir := verifiedRun(t)
			if err := remove(dir); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, "events", id, "--verify")
			if code != identity.ExitFinding {
				t.Fatalf("exit %d, want 1\nstdout %s\nstderr %s", code, out, errs)
			}
			if !strings.Contains(errs, id+" does not verify") || !strings.Contains(errs, "ledger is missing") ||
				!strings.Contains(errs, "["+codeUnverified+"]") {
				t.Errorf("stderr lacks the finding: %s", errs)
			}
		})
	}
	t.Run("an empty events.jsonl", func(t *testing.T) {
		id, dir := verifiedRun(t)
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, out, errs := run(t, "events", id, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "anchored head") {
			t.Fatalf("exit %d, want 1 naming the anchored head\nstdout %s\nstderr %s", code, out, errs)
		}
	})
}

// TestVerifyThroughAPathThatIsNotTheRunID is R29's "the run directory's own id, never the id the ledger
// claims" for a run named by a path whose last component is not its id: "." inside the run directory, or
// a link to it under another name. The id used to be that last component, and with
// none there Verify fell back to the id on the ledger's first line: another run's ledger copied over this
// one verified clean, in this run's directory, against the other run's anchor line, and a deleted ledger
// was "no run record" (125) rather than the anchored run's missing record (1).
func TestVerifyThroughAPathThatIsNotTheRunID(t *testing.T) {
	refs := map[string]func(t *testing.T, dir string) string{
		".": func(t *testing.T, dir string) string { t.Chdir(dir); return "." },
		"a link under another name": func(t *testing.T, dir string) string {
			link := filepath.Join(t.TempDir(), "latest")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
	}
	for name, ref := range refs {
		t.Run(name+", a swapped ledger", func(t *testing.T) {
			a, dirA := verifiedRun(t)
			b := endedRun(t, filepath.Dir(dirA), time.Now())
			clean, err := os.ReadFile(filepath.Join(filepath.Dir(dirA), b, ledger.EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dirA, ledger.EventsFile), clean, 0o600); err != nil {
				t.Fatal(err)
			}
			path := ref(t, dirA)
			code, out, errs := run(t, "events", path, "--verify")
			if code != identity.ExitFinding {
				t.Fatalf("events %s --verify: exit %d, want 1\nstdout %s\nstderr %s", path, code, out, errs)
			}
			if !strings.Contains(errs, a+" does not verify") || !strings.Contains(errs, `line 0 is run "`+b+`"`) {
				t.Errorf("stderr does not name the run directory's own run and the run the ledger belongs to: %s", errs)
			}
			code, out, _ = run(t, "events", path, "--verify", "--json")
			var got verifyJSON
			if err := json.Unmarshal([]byte(out), &got); err != nil || code != identity.ExitFinding || got.Verified || got.Run != a {
				t.Fatalf("--json: exit %d %+v %v\n%s", code, got, err, out)
			}
		})
		t.Run(name+", a deleted ledger", func(t *testing.T) {
			id, dir := verifiedRun(t)
			if err := os.Remove(filepath.Join(dir, ledger.EventsFile)); err != nil {
				t.Fatal(err)
			}
			path := ref(t, dir)
			code, out, errs := run(t, "events", path, "--verify")
			if code != identity.ExitFinding || !strings.Contains(errs, id+" does not verify") ||
				!strings.Contains(errs, "ledger is missing") {
				t.Fatalf("events %s --verify: exit %d, want 1 naming the missing ledger\nstdout %s\nstderr %s",
					path, code, out, errs)
			}
		})
	}
}

// TestVerifyARunDirectoryReplacedByALink is R29's "the run directory's own id, never the id the ledger
// claims" for <root>/<A> replaced by a link to <root>/<B>, another anchored run: A is named, A's record is
// gone, and the verdict is A's — exit 1, B's lines refused — whether A is reached by id, by path, through
// "." after a cd through the link, or through a link to the link. Resolving every symlink before taking
// the name verified B's ledger against B's anchor line and printed "B: verified", exit 0, for each.
func TestVerifyARunDirectoryReplacedByALink(t *testing.T) {
	refs := map[string]func(t *testing.T, a, dirA string) string{
		"by id":   func(_ *testing.T, a, _ string) string { return a },
		"by path": func(_ *testing.T, _, dirA string) string { return dirA },
		"through . after a cd through the link": func(t *testing.T, _, dirA string) string {
			t.Chdir(dirA)
			return "."
		},
		"through a link to the link": func(t *testing.T, _, dirA string) string {
			link := filepath.Join(t.TempDir(), "latest")
			if err := os.Symlink(dirA, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
	}
	for name, ref := range refs {
		t.Run(name, func(t *testing.T) {
			a, dirA := verifiedRun(t)
			b := endedRun(t, filepath.Dir(dirA), time.Now())
			if err := os.RemoveAll(dirA); err != nil {
				t.Fatal(err)
			}
			// A relative target, as `ln -s <B> <A>` inside the ledger root makes it.
			if err := os.Symlink(b, dirA); err != nil {
				t.Fatal(err)
			}
			path := ref(t, a, dirA)
			code, out, errs := run(t, "events", path, "--verify")
			if code != identity.ExitFinding {
				t.Fatalf("events %s --verify: exit %d, want 1\nstdout %s\nstderr %s", path, code, out, errs)
			}
			if !strings.Contains(errs, a+" does not verify") || !strings.Contains(errs, `line 0 is run "`+b+`"`) {
				t.Errorf("stderr does not name the run asked about and the run the ledger belongs to: %s", errs)
			}
			if strings.Contains(out, "verified") {
				t.Errorf("a run directory replaced by a link printed %q", out)
			}
			code, out, _ = run(t, "events", path, "--verify", "--json")
			var got verifyJSON
			if err := json.Unmarshal([]byte(out), &got); err != nil || code != identity.ExitFinding || got.Verified || got.Run != a {
				t.Fatalf("--json: exit %d %+v %v\n%s", code, got, err, out)
			}
		})
	}
}

// TestVerifyUnknownRun: a run id with neither a directory nor an anchor line names no run at all — the
// caller's typo, a usage error as every other command reports it (it was 125), never a
// verdict about a ledger. A directory the caller named that holds no record and no anchor line is still
// 125: a statement about what tego could find there.
func TestVerifyUnknownRun(t *testing.T) {
	_, dir := verifiedRun(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "events", string(id), "--verify")
	if code != identity.ExitUsage || !strings.Contains(errs, "no such run (no directory at "+filepath.Join(filepath.Dir(dir), string(id))) {
		t.Fatalf("exit %d, want 2 [no such run]\nstdout %s\nstderr %s", code, out, errs)
	}
	empty := filepath.Join(filepath.Dir(dir), string(id))
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "events", empty, "--verify")
	if code != identity.ExitError || !strings.Contains(errs, "no run record at "+empty) {
		t.Fatalf("empty directory: exit %d, want 125 [no run record]\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestRunRefusesAnAnchorItCannotOpen: `tego run` opens its chain anchor for append before the run
// directory exists, so an anchor the run could not extend at Close refuses the run with 125 up front —
// the agent never started — rather than an ErrAnchorWrite after the agent ran. The ledger root is a
// regular file, so a run that got past the probe fails at once creating its run directory, with its own
// message, instead of starting a launcher inside the test binary.
func TestRunRefusesAnAnchorItCannotOpen(t *testing.T) {
	root := gcRoot(t)
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	notADir := filepath.Join(work, "home")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	useAnchor(t, filepath.Join(notADir, ".tego", ledger.ChainLogFile))
	contract := filepath.Join(work, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: tester\ncommand: [\"/bin/sh\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(work, "ran")
	code, _, errs := run(t, "run", "--observe", contract, "--", "/bin/sh", "-c", "touch "+marker)
	if code != identity.ExitLauncher || !strings.Contains(errs, "chain anchor") {
		t.Fatalf("exit %d, want 125 naming the chain anchor\nstderr %s", code, errs)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the agent ran although its head had nowhere to go")
	}
}

// TestRunRefusedForContractOverlapExits125 is agent-contract E36 end to end: a contract whose fs.write entry
// is the directory holding the contract file is R10's contradiction, and `tego run` refuses it with exit 125
// (identity.ExitLauncher) and the diagnostic code [contradiction], never the 210 it once had, before the
// agent starts.
func TestRunRefusedForContractOverlapExits125(t *testing.T) {
	gcRoot(t)
	work := t.TempDir()
	useAnchor(t, filepath.Join(t.TempDir(), "chain.log"))
	contract := filepath.Join(work, "agent.yaml")
	body := "version: 0\nname: overlap\ncommand: [\"/bin/sh\"]\nfs:\n  write: [\"" + work + "\"]\n"
	if err := os.WriteFile(contract, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(work, "ran")
	code, _, errs := run(t, "run", "--observe", contract, "--", "/bin/sh", "-c", "touch "+marker)
	if code != identity.ExitLauncher || !strings.Contains(errs, "contradiction") {
		t.Fatalf("exit %d, want 125 with [contradiction]\nstderr %s", code, errs)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the agent ran although its contract was refused")
	}
}
