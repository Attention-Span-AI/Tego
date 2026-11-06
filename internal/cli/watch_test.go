// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"gopkg.in/yaml.v3"
)

var contractNameRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// A contract name is always one the schema accepts, whatever the command is called.
func TestWatchNameFitsTheSchema(t *testing.T) {
	for argv0, want := range map[string]string{
		"codex":                   "watch-codex",
		"/usr/local/bin/Claude":   "watch-claude",
		"./my agent (v2).sh":      "watch-my-agent-v2-sh",
		"--weird--":               "watch-weird",
		"":                        "watch",
		"...":                     "watch",
		strings.Repeat("a", 100):  "watch-" + strings.Repeat("a", 34),
		"naïve-agent":             "watch-na-ve-agent",
		"a/b/../../etc/passwd":    "watch-passwd",
		strings.Repeat("ab-", 30): "watch-" + strings.Repeat("ab-", 11) + "a",
	} {
		got := watchName(argv0)
		if !contractNameRE.MatchString(got) {
			t.Errorf("watchName(%q) = %q, which the schema refuses", argv0, got)
		}
		if got != want {
			t.Errorf("watchName(%q) = %q, want %q", argv0, got, want)
		}
	}
}

// The generic contract carries the program exactly, whatever it is called, restricts nothing, and loads through
// the real loader. The arguments are not in it: they reach the agent from the command line (the launch-path test).
func TestGenericContractCarriesTheProgramExactly(t *testing.T) {
	for _, program := range []string{"codex", "/opt/my agent/bin/run", "a: b", "- c", "# not a comment", "'quoted'", "\"dq\"", "~", "null", "true", "0x1F"} {
		command := []string{program, "--model", "o3 mini", ""}
		data, err := genericContractYAML(command)
		if err != nil {
			t.Fatal(err)
		}
		var back genericContract
		if err := yaml.Unmarshal(data, &back); err != nil {
			t.Fatalf("%q: the generated YAML does not parse: %v\n%s", program, err, data)
		}
		if !slices.Equal(back.Command, []string{program}) || back.Version != 0 || back.Record != "full" || !contractNameRE.MatchString(back.Name) {
			t.Fatalf("%q: round trip = %+v\n%s", program, back, data)
		}
		for _, key := range []string{"fs:", "net:", "exec:", "limits:", "env:", "ask:"} {
			if strings.Contains(string(data), key) {
				t.Errorf("%q: the generic contract has %s: it must restrict nothing", program, key)
			}
		}
		path, cleanup, err := writeGenericContract(command)
		if err != nil {
			t.Fatal(err)
		}
		c, ds, err := agent.Load(path, dirProfiles{})
		cleanup()
		if err != nil || agent.HasErrors(ds) || c == nil || !slices.Equal(c.Command, []string{program}) {
			t.Fatalf("%q: agent.Load = %v, %v, %v", program, c, ds, err)
		}
	}
}

// generatedLossyPrograms are program paths yaml.Marshal (at indent 4) wrote as a block that does not load back: tab-led
// and line-break-led ones holding a line break, which the loader refused, so tego watch and tego adopt refused to run
// them; and a space-led one ("  agent\n"), which loaded back as another program ("agent\n"). The rest sit beside them
// as block strings that always loaded back.
var generatedLossyPrograms = []string{"\tagent\n", "\t/opt/a b\nc", "\nagent\n", "\n\nagent", "\n\tagent\n", " agent\nx", "  agent\n", "a\nb\n"}

// A watch contract and an adoption contract carry such a program exactly: both are written by agent.EncodeYAML,
// Canonical's writer, and load back through the real loader with the program as it was.
func TestGeneratedContractsCarryAProgramWithABreakExactly(t *testing.T) {
	for _, program := range generatedLossyPrograms {
		path, cleanup, err := writeGenericContract([]string{program, "--flag"})
		if err != nil {
			t.Fatal(err)
		}
		c, ds, err := agent.Load(path, dirProfiles{})
		cleanup()
		if err != nil || c == nil || !slices.Equal(c.Command, []string{program}) {
			t.Errorf("watch contract for %q: agent.Load = %v, %v\n%v", program, c, err, ds)
		}
		path, cleanup, err = writeAdoptContract(adopt.Process{Exe: program, Comm: "agent"}, "")
		if err != nil {
			t.Fatal(err)
		}
		c, ds, err = agent.Load(path, nil)
		cleanup()
		if err != nil || c == nil || !slices.Equal(c.Command, []string{program}) {
			t.Errorf("adopt contract for %q: agent.Load = %v, %v\n%v", program, c, err, ds)
		}
	}
}

// The temporary contract is private and is gone after cleanup.
func TestWriteGenericContractIsPrivateAndCleanedUp(t *testing.T) {
	path, cleanup, err := writeGenericContract([]string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("contract file: %v, %v", fi, err)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("contract directory: %v, %v", di, err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("the contract directory survived cleanup: %v", err)
	}
}

// Everything after "--" is the agent's, verbatim: its own flags, even ones named like tego's, are never read as
// tego's.
func TestWatchLeavesTheAgentsFlagsAlone(t *testing.T) {
	cmd := cmdWatch()
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cmd.Flags(fs)
	args := []string{"--record", "summary", "--boundary", "b.yaml", "--", "codex", "--tier", "x", "--boundary=y", "--", "-h"}
	if err := parseArgs(fs, args, cmd.CommandAfter); err != nil {
		t.Fatal(err)
	}
	if want := []string{"codex", "--tier", "x", "--boundary=y", "--", "-h"}; !slices.Equal(fs.Args(), want) {
		t.Fatalf("command = %q, want %q", fs.Args(), want)
	}
	if got := fs.Lookup("record").Value.String(); got != "summary" {
		t.Errorf("--record = %q", got)
	}
	if got := fs.Lookup("boundary").Value.String(); got != "b.yaml" {
		t.Errorf("--boundary = %q", got)
	}
}

// launched is what a sandboxed launch was asked to start.
type launched struct {
	command []string
	name    string
	record  agent.RecordMode
	tier    backend.Tier
	// source is the run_start contract_source the run was handed (agent-contract.md R26).
	source *record.ContractSource
}

// sandboxedLaunch isolates a test from the machine: a scratch machine config and chain anchor, a probe that
// answers "Landlock" and a launcher that records what it was asked to run instead of starting anything. A test
// that can reach runRun without it risks a real run, and under `go test` the launcher re-executes the test binary
// as its child stage: every watch test goes through this.
func sandboxedLaunch(t *testing.T) *[]launched {
	t.Helper()
	requireLandlockABI(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder := probeMachine, anchorPath, startRun, captureFor, recorderFor
	t.Cleanup(func() {
		probeMachine, anchorPath, startRun, captureFor, recorderFor = prevProbe, prevAnchor, prevRun, prevCapture, prevRecorder
	})
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	anchorPath = func(*config.Machine) (string, error) { return filepath.Join(base, "chain.log"), nil }
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	calls := new([]launched)
	startRun = func(_ context.Context, rt *agent.RuleTable, command []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		*calls = append(*calls, launched{slices.Clone(command), rt.Contract.Name, rt.Record, d.Enforce.Tier(), d.ContractSource})
		return tegoruntime.Result{RunID: "r-test-run", Reason: "exit"}, nil
	}
	return calls
}

func TestWatchUsageErrors(t *testing.T) {
	calls := sandboxedLaunch(t)
	for name, argv := range map[string][]string{
		"no command":                  {"tego", "watch"},
		"flags but no command":        {"tego", "watch", "--record", "full", "--"},
		"an empty command":            {"tego", "watch", "--", ""},
		"a tier without a boundary":   {"tego", "watch", "--tier", "landlock", "--", "true"},
		"an empty boundary":           {"tego", "watch", "--boundary", "", "--", "true"},
		"an empty boundary with =":    {"tego", "watch", "--boundary=", "--", "true"},
		"a record level no run takes": {"tego", "watch", "--record", "loud", "--", "true"},
	} {
		var errs bytes.Buffer
		if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitUsage {
			t.Errorf("%s: exit %d, want %d (usage)\n%s", name, code, identity.ExitUsage, errs.String())
		}
		if len(*calls) != 0 {
			t.Fatalf("%s: a usage error still started a run: %+v", name, *calls)
		}
	}
}

// TestWatchTypoNamesTheCommandLine: `tego watch -- typo` is the likeliest mistake with this command, and it was told
// about a line of a temporary file, /tmp/tego-watch-123/watch.yaml:4:7, removed before the reader could look.
func TestWatchTypoNamesTheCommandLine(t *testing.T) {
	code, _, errs := run(t, "watch", "--", "tego-no-such-program")
	if code != identity.ExitLauncher {
		t.Fatalf("exit %d, want %d; stderr %q", code, identity.ExitLauncher, errs)
	}
	if strings.Contains(errs, "watch.yaml") || !strings.Contains(errs, agent.CommandLineFile+":") || !strings.Contains(errs, "tego-no-such-program") {
		t.Errorf("stderr %q: want the finding on the command line, naming the program", errs)
	}
}

// The notice is the only thing between a person and the belief that a recording is a cage, and between "nothing
// is refused" and what the fixed syscall guards still refuse, so each claim of the full text (watch -v) is pinned to
// what the observe backend does (internal/runtime/enforce/observe/doc.go): the guards, the unrecorded calls, and the
// record level in force.
func TestWatchNoticeSaysWhatIsRecordedRefusedAndNotStopped(t *testing.T) {
	always := []string{
		"No rule refuses anything", "not a cage", "--boundary <agent.yaml> -- codex", "tego run <agent.yaml> -- codex",
		"still refused, and not recorded", "io_uring", "openat2", "clone3", "open_by_handle_at", "TIOCSTI", "TIOCLINUX", "MPTCP",
		"the warnings that follow", "D-Bus",
	}
	notRecorded := "truncate, chmod, chown, setxattr, a unix socket bound to a path"
	for name, tc := range map[string]struct {
		record     agent.RecordMode
		want, deny []string
	}{
		"full":    {agent.RecordFull, []string{"(reads included)", notRecorded}, []string{"only reads", "only that it ran"}},
		"default": {"", []string{"(reads included)", notRecorded}, []string{"only reads", "only that it ran"}},
		"summary": {agent.RecordSummary, []string{"A file it only", "is not recorded (--record full records reads)", notRecorded}, []string{"reads included", "only that it ran"}},
		"off":     {agent.RecordOff, []string{"only that it ran", "Nothing it does is recorded"}, []string{"reads included", "every file it", notRecorded}},
	} {
		got := strings.ReplaceAll(watchNotice("codex", false, tc.record, true, true), "\n  ", " ") // a wrapped line, one sentence
		for _, want := range append(always[:len(always):len(always)], tc.want...) {
			if !strings.Contains(got, want) {
				t.Errorf("%s: the no-boundary notice lacks %q:\n%s", name, want, got)
			}
		}
		for _, bad := range append([]string{"nothing blocked", "nothing is refused", "warnings above"}, tc.deny...) {
			if strings.Contains(got, bad) {
				t.Errorf("%s: the no-boundary notice says %q, which is not so:\n%s", name, bad, got)
			}
		}
	}
	bound := watchNotice("codex", true, agent.RecordOff, false, false)
	for _, bad := range []string{"No rule refuses anything", "not a cage", "nothing blocked", "still refused"} {
		if strings.Contains(bound, bad) {
			t.Errorf("a bounded run's notice says %q:\n%s", bad, bound)
		}
	}
	if !strings.Contains(bound, "boundary contract") {
		t.Errorf("a bounded run's notice does not say whose rules apply:\n%s", bound)
	}
	if got := watchReport(tegoruntime.Result{}); got != "" {
		t.Errorf("a run with no id reported %q", got)
	}
	if got := watchReport(tegoruntime.Result{RunID: "r-abc"}); !strings.Contains(got, "tego events r-abc") || !strings.Contains(got, "tego status r-abc") {
		t.Errorf("the report does not say how to read the record:\n%s", got)
	}
}

// Without -v the notice is at most four lines: what is recorded and that no rule refuses anything, not a cage,
// and how to confine the command; the sentence about sockets only when a socket warning follows.
func TestWatchNoticeIsShortWithoutVerbose(t *testing.T) {
	for _, rec := range []agent.RecordMode{"", agent.RecordFull, agent.RecordSummary, agent.RecordOff} {
		for _, sockets := range []bool{false, true} {
			got := watchNotice("codex", false, rec, false, sockets)
			if n := strings.Count(got, "\n"); n > 4 {
				t.Errorf("record %q sockets %v: %d lines, want at most 4:\n%s", rec, sockets, n, got)
			}
			for _, want := range []string{"No rule refuses anything", "not a cage", "tego run <agent.yaml> -- codex",
				"tego watch --boundary <agent.yaml> -- codex", "tego watch -v -- codex"} {
				if !strings.Contains(got, want) {
					t.Errorf("record %q: the short notice lacks %q:\n%s", rec, want, got)
				}
			}
			if has := strings.Contains(got, "the warnings that follow name the sockets"); has != sockets {
				t.Errorf("record %q sockets %v: the sockets sentence is there: %v\n%s", rec, sockets, has, got)
			}
			if strings.Contains(got, "io_uring") || strings.Contains(got, "nothing is refused") {
				t.Errorf("record %q: the short notice carries the full text or a false claim:\n%s", rec, got)
			}
		}
	}
	if got := watchNotice("codex", false, "", true, false); strings.Contains(got, "sockets it can reach") {
		t.Errorf("the full notice names sockets though none follow:\n%s", got)
	}
}

// A watch prints no "tego run:" line: R29's --observe warning is not printed (watch's own notice says so), and the
// run path's own lines name tego watch (runOptions.cmd), a bounded watch's refusals of a --tier and of a name the
// registries do not hold included; the held-label disclosure is a note tagged [held-label]. Each line is written
// with that name, not rewritten on its way out by a writer around stderr, so how its writes are split cannot change
// a name either: no split taken after the command's stderr could tell such a writer from the name in the text, and
// TestWatchQuotesTheCommandLineAsTyped is the test a rewriting writer fails.
func TestWatchSpeaksAsWatch(t *testing.T) {
	sandboxedLaunch(t)
	prev := startRun
	startRun = func(ctx context.Context, rt *agent.RuleTable, command []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		d.Warn(tegoruntime.WarnHeldLabel, "on AppArmor a file read that tego checks and opens for the agent requires matching security labels")
		return prev(ctx, rt, command, d)
	}
	var errs bytes.Buffer
	if code := mainWith(t.Context(), []string{"tego", "watch", "--offline", "--", "true"}, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK {
		t.Fatalf("watch exit %d:\n%s", code, errs.String())
	}
	out := errs.String()
	if strings.Contains(out, "tego run:") || strings.Contains(out, "--observe is in effect") {
		t.Errorf("tego watch printed a tego run line:\n%s", out)
	}
	note := strings.Index(out, "note: tego watch: on AppArmor a file read that tego checks and opens for the agent requires matching security labels [held-label]")
	if note < 0 {
		t.Fatalf("the held-label note is missing or mislabelled:\n%s", out)
	}
	if n := strings.Count(out[:note], "\n"); n > 4 {
		t.Errorf("the notice before the run is %d lines:\n%s", n, out)
	}

	// The run path's refusals of a bounded watch: a --tier no run takes, and a name in no registry.
	newRegistryWorld(t)
	for _, c := range []struct {
		flags []string
		code  int
		want  []string
	}{
		{[]string{"--boundary", "agent.yaml", "--tier", "bogus"}, identity.ExitUsage,
			[]string{`tego watch: --tier "bogus" is not auto, landlock, cgroup or bpflsm [usage]`}},
		{[]string{"--boundary", "no-such-name"}, identity.ExitLauncher, []string{"tego watch: ", "[agent-not-found]"}},
	} {
		errs.Reset()
		argv := append(append([]string{"tego", "watch", "--offline"}, c.flags...), "--", "true")
		code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdWatch()})
		out := errs.String()
		for _, want := range c.want {
			if code != c.code || !strings.Contains(out, want) || strings.Contains(out, "tego run") {
				t.Errorf("%q: exit %d, want %d naming tego watch (%q), never tego run:\n%s", argv[2:], code, c.code, want, out)
			}
		}
	}
}

// tego watch names itself on its own lines and leaves what a line quotes as it is: its lines went through a writer that
// turned every "tego run: " into "tego watch: ", so the finding about a program whose path holds those words named a
// program that does not exist either.
func TestWatchQuotesTheCommandLineAsTyped(t *testing.T) {
	calls := sandboxedLaunch(t)
	program := filepath.Join(t.TempDir(), "tego run: agent")
	var errs bytes.Buffer
	code := mainWith(t.Context(), []string{"tego", "watch", "--offline", "--", program}, io.Discard, &errs, []Command{cmdWatch()})
	if code != identity.ExitLauncher || len(*calls) != 0 {
		t.Fatalf("a watch of a missing program: exit %d, %d launches, want 125 and none:\n%s", code, len(*calls), errs.String())
	}
	var finding string
	for _, line := range strings.Split(errs.String(), "\n") {
		if strings.Contains(line, agent.CommandLineFile+":") {
			finding += line + "\n"
		}
	}
	if !strings.Contains(finding, program) || strings.Contains(finding, "tego watch: agent") {
		t.Errorf("the finding does not name the program as typed, %q:\n%s", program, errs.String())
	}
}

// -v prints the full notice.
func TestWatchVerbosePrintsTheFullNotice(t *testing.T) {
	sandboxedLaunch(t)
	var errs bytes.Buffer
	if code := mainWith(t.Context(), []string{"tego", "watch", "--offline", "-v", "--", "true"}, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK {
		t.Fatalf("watch -v exit %d:\n%s", code, errs.String())
	}
	for _, want := range []string{"still refused, and not recorded", "TIOCSTI", "not recorded: truncate"} {
		if !strings.Contains(errs.String(), want) {
			t.Errorf("watch -v lacks %q:\n%s", want, errs.String())
		}
	}
}

// The record level a person asks for without a boundary reaches the run, and the notice says what that level keeps.
func TestWatchRecordLevelReachesTheRunAndTheNotice(t *testing.T) {
	for _, tc := range []struct {
		flag   string
		record agent.RecordMode
		says   string
	}{
		{"summary", agent.RecordSummary, "is not recorded (--record full records reads)"},
		{"off", agent.RecordOff, "only that it ran"},
		{"full", agent.RecordFull, "(reads included)"},
	} {
		calls := sandboxedLaunch(t)
		var errs bytes.Buffer
		argv := []string{"tego", "watch", "--offline", "--record", tc.flag, "--", "true"}
		if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK {
			t.Fatalf("--record %s: exit %d:\n%s", tc.flag, code, errs.String())
		}
		if len(*calls) != 1 || (*calls)[0].record != tc.record || (*calls)[0].tier != backend.TierObserve {
			t.Fatalf("--record %s: the launcher saw %+v, want one observe run recording %s", tc.flag, *calls, tc.record)
		}
		if got := strings.ReplaceAll(errs.String(), "\n  ", " "); !strings.Contains(got, tc.says) {
			t.Errorf("--record %s: the notice lacks %q:\n%s", tc.flag, tc.says, errs.String())
		}
	}
}

// Through the real loader, compiler and tier selection, with only the launcher stubbed: a watch with no
// boundary runs the command given, as a record-only observe run under the generic contract at the full record,
// and says where the record is; with a boundary it is an enforcing run under that contract.
func TestWatchRunsThroughTheLaunchPath(t *testing.T) {
	calls := sandboxedLaunch(t)
	var errs bytes.Buffer
	argv := []string{"tego", "watch", "--offline", "--", "true", "--tier", "landlock", "", "a: b", "x y"}
	if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK {
		t.Fatalf("watch exit %d:\n%s", code, errs.String())
	}
	want := launched{[]string{"true", "--tier", "landlock", "", "a: b", "x y"}, "watch-true", agent.RecordFull, backend.TierObserve, nil}
	if len(*calls) != 1 || !slices.Equal((*calls)[0].command, want.command) || (*calls)[0].name != want.name || (*calls)[0].record != want.record || (*calls)[0].tier != want.tier {
		t.Fatalf("the launcher saw %+v, want %+v", *calls, want)
	}
	for _, s := range []string{"No rule refuses anything", "(reads included)", "tego events r-test-run"} {
		if !strings.Contains(errs.String(), s) {
			t.Errorf("stderr lacks %q:\n%s", s, errs.String())
		}
	}

	// A boundary turns it into an enforcing run under the user's contract, the command still the one given.
	boundary := filepath.Join(t.TempDir(), "boundary.yaml")
	if err := os.WriteFile(boundary, []byte("version: 0\nname: caged\ncommand: [\"true\"]\nnet: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	*calls, errs = nil, bytes.Buffer{}
	argv = []string{"tego", "watch", "--offline", "--boundary", boundary, "--", "true"}
	if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK {
		t.Fatalf("watch --boundary exit %d:\n%s", code, errs.String())
	}
	if len(*calls) != 1 || (*calls)[0].name != "caged" || (*calls)[0].tier == backend.TierObserve || strings.Contains(errs.String(), "No rule refuses anything") {
		t.Fatalf("with a boundary the launcher saw %+v\n%s", *calls, errs.String())
	}
	if strings.Contains(errs.String(), "--record off is in effect") {
		t.Errorf("a bounded watch at the contract's record level warned of --record off:\n%s", errs.String())
	}

	// A bounded watch's notice names only the contract, so a --record off is still said, in watch's voice; the
	// observe half of R29 is not (the run enforces).
	*calls, errs = nil, bytes.Buffer{}
	argv = []string{"tego", "watch", "--offline", "--boundary", boundary, "--record", "off", "--", "true"}
	if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK {
		t.Fatalf("watch --boundary --record off exit %d:\n%s", code, errs.String())
	}
	out := errs.String()
	if len(*calls) != 1 || (*calls)[0].record != agent.RecordOff {
		t.Fatalf("with --record off the launcher saw %+v\n%s", *calls, out)
	}
	if !strings.Contains(out, "warning: tego watch: --record off is in effect") || strings.Contains(out, "--observe is in effect") || strings.Contains(out, "tego run:") {
		t.Errorf("a bounded watch at --record off did not say so in watch's voice:\n%s", out)
	}
}
