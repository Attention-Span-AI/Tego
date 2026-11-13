// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestStatusByAgent(t *testing.T) {
	root := gcRoot(t)
	a := endedRunAs(t, root, [32]byte{}, "one", time.Now().Add(-2*time.Hour))
	b := endedRunAs(t, root, [32]byte{}, "one", time.Now().Add(-time.Hour))
	other := endedRunAs(t, root, [32]byte{}, "two", time.Now())
	for _, json := range []bool{false, true} {
		args := []string{"status", "--agent", "one"}
		if json {
			args = append(args, "--json")
		}
		code, out, errs := run(t, args...)
		if code != 0 || errs != "" || !strings.Contains(out, b) || strings.Contains(out, a) || strings.Contains(out, other) {
			t.Fatalf("latest: %d %s %s", code, out, errs)
		}
		code, out, errs = run(t, append(args, "--all")...)
		if code != 0 || errs != "" || !strings.Contains(out, a) || !strings.Contains(out, b) || strings.Contains(out, other) {
			t.Fatalf("all: %d %s %s", code, out, errs)
		}
	}
	for _, args := range [][]string{{"status", "--agent", ""}, {"status", "--agent", "Not valid"}, {"status", "--agent", "one", b}} {
		if code, _, _ := run(t, args...); code != identity.ExitUsage {
			t.Fatalf("%q: %d", args, code)
		}
	}
	if code, out, _ := run(t, "status", "--agent", "missing", "--json"); code != 0 || out != "{\"runs\":[]}\n" {
		t.Fatalf("empty: %d %s", code, out)
	}
}

func TestBlockSuggestionIsOneLiteralShellArgument(t *testing.T) {
	for _, value := range []string{"/a/a b", "/a/a'$(exit 9);*", "/a/-n"} {
		words := execWords("r-test", value, liveblock.ExecReach{Names: 2})
		_, cmd, ok := strings.Cut(words, "tego block ")
		if !ok {
			t.Fatalf("no suggested command: %s", words)
		}
		// The suggestion ends at the sentence's period. There are no shell commands in the value
		// except a command substitution that would exit 9 if quoting were broken.
		cmd = strings.TrimSuffix(cmd, ".")
		script := "set -- " + cmd + "; test \"$#\" = 4 && printf '%s' \"$4\""
		out, err := exec.Command("/bin/sh", "-c", script).Output()
		if err != nil || string(out) != filepath.Base(value) {
			t.Fatalf("suggestion %q: %v %q", words, err, out)
		}
	}
}

func TestBlockPathHintsAreLiteral(t *testing.T) {
	const id = "r-11111111-0000000000000-abcdef"
	for _, value := range []string{"/a/path with spaces", "/a/path'$(exit 9);*", "/a/new\nline"} {
		var notes []string
		for _, err := range []error{liveblock.ErrOldLauncher, liveblock.ErrReadsUnseen} {
			var out bytes.Buffer
			blockRefused("block", id, true, value, err, &out)
			notes = append(notes, out.String())
		}
		notes = append(notes, realWords(id, liveblock.KindPath, "/a/link", liveblock.RealOutcome{Uncovered: value}))
		for _, note := range notes {
			_, cmd, ok := strings.Cut(note, "tego block ")
			if strings.ContainsRune(value, '\n') {
				if ok {
					t.Fatalf("terminal control became a pasteable command: %q", note)
				}
				continue
			}
			if !ok {
				t.Fatalf("missing suggested command: %q", note)
			}
			cmd, _, _ = strings.Cut(cmd, "), ")
			out, err := exec.Command("/bin/sh", "-c", "set -- "+cmd+"; printf '%s\\0' \"$@\"").Output()
			want := id + "\x00path\x00--\x00" + value + "\x00"
			if err != nil || string(out) != want {
				t.Fatalf("hint %q: %v %q, want %q", note, err, out, want)
			}
		}
	}
}

func TestServiceStopExit(t *testing.T) {
	for _, tc := range []struct {
		reason     string
		code, want int
		err        error
	}{
		{record.RunEndStopped, 137, 143, nil}, {record.RunEndStopped, 143, 143, nil},
		{record.RunEndOOM, 137, 137, nil}, {record.RunEndPids, 137, 137, nil},
		{record.RunEndLimit, 124, 124, nil}, {record.RunEndExit, 7, 7, nil},
		{record.RunEndStopped, 137, 125, errors.New("disk full")},
	} {
		var errs bytes.Buffer
		res := tegoruntime.Result{Reason: tc.reason, ExitCode: tc.code, RecordErr: tc.err}
		if got := serviceExitCode(&errs, "tego run", res, true); got != tc.want {
			t.Errorf("%+v: %d", tc, got)
		}
		if tc.err == nil && serviceExitCode(&errs, "tego run", res, false) != tc.code {
			t.Fatal("normal exit changed")
		}
	}
}

func TestVerifyAbbreviatedDeletedAnchoredRun(t *testing.T) {
	id, dir := verifiedRun(t)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{id, id[len(id)-6:], id[:len(id)-7]} {
		code, out, errs := run(t, "events", ref, "--verify", "--json")
		if code != identity.ExitFinding || !strings.Contains(out, `"run":"`+id+`"`) || !strings.Contains(errs, "[ledger-corrupt]") {
			t.Errorf("%s: %d %s %s", ref, code, out, errs)
		}
	}
	// A deleted anchor match must also make a surviving-directory match ambiguous.
	root := filepath.Dir(dir)
	other := identity.RunID("r-11111111-0000000000000-" + id[len(id)-6:])
	endedRunNamed(t, root, other, "tester")
	if code, _, errs := run(t, "events", id[len(id)-6:], "--verify"); code != identity.ExitUsage || !strings.Contains(errs, "more than one run") {
		t.Fatalf("ambiguity: %d %s", code, errs)
	}
}

func TestInitAgentAndPrompt(t *testing.T) {
	gcRoot(t)
	fixedEnviron(t)
	bin := t.TempDir()
	for _, name := range []string{"claude", "codex"} {
		if err := os.Symlink("/bin/true", filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	for _, name := range []string{"claude-code", "codex"} {
		t.Run(name, func(t *testing.T) {
			dir := presetProject(t)
			const task = "Explain 'this' project; $(touch SHOULD-NOT-EXIST)\nthen stop"
			code, out, errs := run(t, "init", "--agent", name, "--prompt", task)
			if code != 0 || strings.Contains(errs, "[env-runtime-reserved]") || strings.Contains(errs, "[mount]") || !strings.Contains(out, "no-secrets also passes these login variables") {
				t.Fatalf("init: %d %s %s", code, out, errs)
			}
			code, merged, errs := run(t, "compile", "agent.yaml", "--offline", "--merged")
			if code != 0 || !strings.Contains(merged, "models:") || !strings.Contains(merged, "harness: "+name) {
				t.Fatalf("compile: %d %s %s", code, merged, errs)
			}
			if code, out, _ := run(t, "init", "--agent", name); code != 0 || !strings.Contains(out, "--agent and --prompt were not applied") {
				t.Fatalf("repeated agent init: %d %s", code, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "SHOULD-NOT-EXIST")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("prompt executed as shell")
			}
		})
	}
	for _, args := range [][]string{{"init", "--agent", "unknown"}, {"init", "--agent", ""}, {"init", "--prompt", "task"}, {"init", "--agent", "codex", "--command", "sh"}} {
		if code, _, _ := run(t, args...); code != identity.ExitUsage {
			t.Fatalf("%q: %d", args, code)
		}
	}
	if code, out, _ := run(t, "init", "--list"); code != 0 || !strings.Contains(out, "claude-code") || !strings.Contains(out, "CODEX_API_KEY") {
		t.Fatalf("list: %d %s", code, out)
	}
}

func TestEmptyFirstHourCommandsNameTheNextCommand(t *testing.T) {
	gcRoot(t)
	t.Chdir(t.TempDir())
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"status"}, 0, "no runs\nnext: tego setup\n"},
		{[]string{"receipt", "--last"}, 125, "then tego run agent.yaml"},
		{[]string{"events"}, 2, "tego status --all lists the ids, then tego events <run>"},
	} {
		code, out, errs := run(t, tc.args...)
		if code != tc.code || !strings.Contains(out+errs, tc.want) {
			t.Errorf("%q: %d %s %s", tc.args, code, out, errs)
		}
	}
	// The no-runs line names tego setup (slice 2); status --json is byte for byte what it was.
	if code, out, errs := run(t, "status", "--json"); code != 0 || out != "{\"runs\":[]}\n" || errs != "" {
		t.Errorf("status --json with no runs: %d %q %q", code, out, errs)
	}
}

func TestBlockSuggestionKeepsAFlagLikeProgramNameLiteral(t *testing.T) {
	_, id, _ := liveRun(t)
	note := execWords(id, "/a/--json", liveblock.ExecReach{Names: 2})
	_, command, ok := strings.Cut(note, "tego block ")
	if !ok {
		t.Fatal(note)
	}
	args, err := exec.Command("/bin/sh", "-c", "set -- "+command+"; printf '%s\\0' \"$@\"").Output()
	if err != nil {
		t.Fatal(err)
	}
	argv := append([]string{"block"}, strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")...)
	code, out, errs := run(t, argv...)
	if code != 0 || !strings.HasPrefix(out, id+": blocked ") || !strings.Contains(out, "live.block[exec:--json]") {
		t.Fatalf("suggested command %q: exit %d\n%s\n%s", command, code, out, errs)
	}
}

func TestInitKeepsActionableWarnings(t *testing.T) {
	gcRoot(t)
	fixedEnviron(t)
	presetProject(t)
	code, out, errs := run(t, "init", "--preset", "no-secrets", "--write", "/dev")
	// Where /dev/mqueue is mounted (every systemd host) a grant on /dev reaches that kernel filesystem and is refused
	// (ADR 0059, second amendment of 2026-11-11); the /dev warning still says what the grant was.
	mi, _ := os.ReadFile("/proc/self/mountinfo")
	if strings.Contains(string(mi), " - mqueue ") && strings.Contains(string(mi), " /dev/mqueue ") {
		if code == 0 || !strings.Contains(errs, "[kernel-fs-write]") || !strings.Contains(errs, "reaches the mqueue filesystem mounted at /dev/mqueue") {
			t.Fatalf("init with /dev/mqueue mounted: %d\n%s\n%s", code, out, errs)
		}
		return
	}
	if code != 0 || !strings.Contains(errs, "[kernel-fs-write]") {
		t.Fatalf("init: %d\n%s\n%s", code, out, errs)
	}
}
